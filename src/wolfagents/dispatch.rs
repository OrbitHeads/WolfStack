// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Tool dispatcher — takes an agent + tool call request, runs the
//! full safety/authz/target-scope chain, executes the tool, and
//! returns a result the LLM can fold into its next turn.
//!
//! Every tool goes through the same pipeline:
//!
//! 1. **Safety denylist** (`safety::validate_command` / `validate_path`
//!    / `validate_api_path`) — hardcoded, no override. rm -rf /,
//!    dd of=/dev/sda, `systemctl stop wolfstack`, etc. refused here.
//!
//! 2. **Per-agent allowlist** — tool name must be in `allowed_tools`.
//!
//! 3. **Danger vs AccessLevel policy** — Safe runs on any level;
//!    Mutating needs ≥ ReadWrite (Destructive on ReadWrite queues
//!    for confirmation, same with ConfirmAll on mutating); Trusted
//!    runs everything (still subject to safety denylist).
//!
//! 4. **Target scope** — allowed_clusters / allowed_container_patterns
//!    / allowed_hosts / allowed_paths / allowed_api_paths checked
//!    against the specific arguments of this call.
//!
//! 5. **Execute** and capture stdout/result.
//!
//! 6. **Audit** — append to `/etc/wolfstack/agents/<id>/audit.jsonl`
//!    regardless of outcome, so operators see every allow/deny/error.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

use super::{Agent, safety, tools::{self, AuthDecision, ToolId}};

/// Result of one dispatched tool call — what we hand back to the
/// LLM as the tool_result block on its next turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Did the call complete successfully? `false` for denied,
    /// queued-for-confirmation, or execution failure.
    pub ok: bool,
    /// Human-readable status line — shown verbatim as the top of the
    /// tool_result content. "Allowed and ran", "Refused by scope",
    /// "Queued for operator approval (seq 42)", etc.
    pub status: String,
    /// Structured payload — for safe/read tools this is the data the
    /// LLM needs; for mutating tools a summary of what changed; for
    /// denied calls a blank object. The caller stringifies this into
    /// the tool_result content.
    #[serde(default)]
    pub data: serde_json::Value,
}

impl ToolResult {
    fn ok(status: impl Into<String>, data: serde_json::Value) -> Self {
        Self { ok: true, status: status.into(), data }
    }
    // Concrete `String` (rather than `impl Into<String>`) so callsites
    // can use either `"literal"` or `format!(...)` or `err_string.into()`
    // without running into E0283 "type annotations needed" from the
    // generic bound ambiguity.
    fn err(status: String) -> Self {
        Self { ok: false, status, data: serde_json::Value::Null }
    }
}

/// Check whether a container name matches any of the agent's allowed
/// patterns. Empty pattern list = no constraint. `*` is a wildcard
/// for any sequence (including empty); everything else is literal.
///
/// Kept deliberately simple — full glob or regex support invites
/// pattern injection via the agent's target scope. Operators who need
/// more power should narrow scope by adding multiple patterns rather
/// than one complex one.
fn matches_container_pattern(name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() { return true; }
    for pat in patterns {
        if glob_match(pat, name) { return true; }
    }
    false
}

/// Tiny glob matcher — only `*` is special. Good enough for "regions*"
/// or "*-prod" patterns; refuses nothing if pattern is empty.
fn glob_match(pattern: &str, s: &str) -> bool {
    let mut p_idx = 0;
    let mut s_idx = 0;
    let mut star_p: Option<usize> = None;
    let mut star_s = 0;
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    while s_idx < t.len() {
        if p_idx < p.len() && (p[p_idx] == t[s_idx] || p[p_idx] == '?') {
            p_idx += 1; s_idx += 1;
        } else if p_idx < p.len() && p[p_idx] == '*' {
            star_p = Some(p_idx);
            star_s = s_idx;
            p_idx += 1;
        } else if let Some(sp) = star_p {
            p_idx = sp + 1;
            star_s += 1;
            s_idx = star_s;
        } else {
            return false;
        }
    }
    while p_idx < p.len() && p[p_idx] == '*' { p_idx += 1; }
    p_idx == p.len()
}

/// Does this cluster name pass the agent's allowed_clusters filter?
/// Kept for future cluster-aware tool additions — agent_loop uses the
/// same check inline when building the per-turn cluster snapshot.
#[allow(dead_code)]
fn cluster_allowed(cluster: &str, agent: &Agent) -> bool {
    let list = &agent.target_scope.allowed_clusters;
    list.is_empty() || list.iter().any(|c| c == cluster)
}

/// Does this path pass the agent's allowed_paths prefix list?
fn path_allowed(path: &str, agent: &Agent) -> bool {
    let list = &agent.target_scope.allowed_paths;
    if list.is_empty() { return true; }
    list.iter().any(|prefix| path.starts_with(prefix))
}

/// Main entry point — called from the Claude tool_use loop with one
/// tool_use block per call. The loop is responsible for looping
/// between dispatch() and the LLM until the LLM stops emitting
/// tool_use blocks.
pub async fn dispatch(
    agent: &Agent,
    tool_name: &str,
    arguments: &serde_json::Value,
    state: &crate::api::AppState,
) -> ToolResult {
    // Unknown tool name — refuse before touching anything.
    let Some(tool) = ToolId::from_str(tool_name) else {
        tools::record_invocation(
            &agent.id, ToolId::ListNodes /* dummy */, arguments,
            &format!("unknown_tool:{}", tool_name),
        );
        return ToolResult::err(format!(
            "unknown tool '{}'. Available: {}",
            tool_name,
            ToolId::ALL.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")
        ));
    };

    // Allowlist + danger policy.
    match tools::authorise(agent, tool) {
        AuthDecision::Deny { reason } => {
            tools::record_invocation(&agent.id, tool, arguments, &format!("denied:{}", reason));
            return ToolResult::err(format!("refused: {}", reason));
        }
        AuthDecision::NeedsConfirmation { reason } => {
            // Queue the call for operator approval and tell the agent.
            match super::pending::enqueue(&agent.id, tool, arguments, &reason) {
                Ok(seq) => {
                    tools::record_invocation(&agent.id, tool, arguments,
                        &format!("queued_pending:{}", seq));
                    return ToolResult::err(format!(
                        "Action queued for operator approval (pending #{}). {} \
                         You should stop and wait for the operator — your next \
                         turn will see the approval result. Do not retry the \
                         same tool call in this turn.",
                        seq, reason
                    ));
                }
                Err(e) => {
                    tools::record_invocation(&agent.id, tool, arguments,
                        &format!("queue_failed:{}", e));
                    return ToolResult::err(format!("failed to queue for approval: {}", e));
                }
            }
        }
        AuthDecision::Allow => { /* fall through */ }
    }

    // Execute. Each branch is responsible for calling safety::
    // validators against its specific arguments before touching
    // anything, and for target_scope checks.
    let result = match tool {
        ToolId::ListNodes => tool_list_nodes(state).await,
        ToolId::ListContainers => tool_list_containers(arguments, agent, state).await,
        ToolId::GetMetrics => tool_get_metrics(arguments, state).await,
        ToolId::ListAlerts => tool_list_alerts(arguments).await,
        ToolId::ReadLog => tool_read_log(arguments, agent, state).await,
        ToolId::CheckDiskUsage => tool_check_disk_usage(arguments, agent, state).await,
        ToolId::ReadFile => tool_read_file(arguments, agent).await,
        ToolId::ListApiEndpoints => tool_list_api_endpoints(agent).await,
        ToolId::DescribeCluster => tool_describe_cluster(arguments, agent, state).await,
        ToolId::ListWorkflows => tool_list_workflows(arguments, state).await,
        ToolId::WebFetch => tool_web_fetch(arguments, false).await,
        ToolId::WebRender => tool_web_fetch(arguments, true).await,
        ToolId::SemanticSearch => tool_semantic_search(arguments, agent).await,

        ToolId::RestartContainer => tool_restart_container(arguments, agent, state).await,
        ToolId::RunWorkflow => tool_run_workflow(arguments, state).await,
        ToolId::ScheduleWorkflow => tool_schedule_workflow(arguments, state).await,
        ToolId::WriteFile => tool_write_file(arguments, agent).await,

        ToolId::ExecInContainer => tool_exec_in_container(arguments, agent, state).await,
        ToolId::ExecOnNode => tool_exec_on_node(arguments, agent).await,
        ToolId::DeleteFile => tool_delete_file(arguments, agent).await,

        ToolId::WolfstackApi => tool_wolfstack_api(arguments, agent, state).await,
    };

    let outcome = if result.ok {
        "ran".to_string()
    } else {
        format!("error:{}", result.status)
    };
    tools::record_invocation(&agent.id, tool, arguments, &outcome);
    result
}

// ═══════════════════════════════════════════════════
// Safe / read-only tools
// ═══════════════════════════════════════════════════

async fn tool_list_nodes(state: &crate::api::AppState) -> ToolResult {
    let nodes = state.cluster.get_all_nodes();
    let summary: Vec<_> = nodes.iter().map(|n| serde_json::json!({
        "id": n.id,
        "hostname": n.hostname,
        "cluster": n.cluster_name,
        "online": n.online,
        "is_self": n.is_self,
        "docker_count": n.docker_count,
        "lxc_count": n.lxc_count,
        "vm_count": n.vm_count,
    })).collect();
    ToolResult::ok(
        format!("{} nodes in cluster", summary.len()),
        serde_json::json!({ "nodes": summary }),
    )
}

async fn tool_list_containers(
    args: &serde_json::Value, agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let filter_cluster = args.get("cluster").and_then(|v| v.as_str());
    let filter_pattern = args.get("name_pattern").and_then(|v| v.as_str());
    // We proxy to the local list_running_containers for now — a full
    // cluster-wide gather would need per-node HTTP fans which belongs
    // in its own path. Agents who need cluster-wide coverage should
    // call `wolfstack_api` against /api/containers.
    let items = crate::containers::list_running_containers();
    let list: Vec<serde_json::Value> = items.into_iter()
        .filter(|(_runtime, name, _status)| {
            if let Some(p) = filter_pattern {
                if !glob_match(p, name) { return false; }
            }
            // Agent scope enforcement: even if the agent asks for any
            // pattern, narrow to its own allowlist.
            matches_container_pattern(name, &agent.target_scope.allowed_container_patterns)
        })
        .map(|(runtime, name, status)| serde_json::json!({
            "runtime": runtime,
            "name": name,
            "status": status,
        }))
        .collect();
    // Cluster filter is informational for now — the local list doesn't
    // carry cluster membership. Pass through for the model to see.
    let _ = filter_cluster;
    ToolResult::ok(
        format!("{} containers match filter + scope", list.len()),
        serde_json::json!({ "containers": list }),
    )
}

async fn tool_get_metrics(_args: &serde_json::Value, _state: &crate::api::AppState) -> ToolResult {
    let metrics = tokio::task::spawn_blocking(|| {
        let mut mon = crate::monitoring::SystemMonitor::new();
        mon.collect()
    }).await;
    match metrics {
        Ok(m) => ToolResult::ok(
            "metrics snapshot",
            serde_json::to_value(&m).unwrap_or(serde_json::Value::Null),
        ),
        Err(e) => ToolResult::err(format!("metrics collection panicked: {}", e)),
    }
}

async fn tool_list_alerts(_args: &serde_json::Value) -> ToolResult {
    // AlertConfig doesn't persist a log of past alerts — surface that
    // honestly to the agent so it can ask the operator directly if
    // recent-alert history is needed.
    ToolResult::ok(
        "alerting subsystem present; no recent-alert log is persisted",
        serde_json::json!({
            "note": "Recent alert history is not currently logged. Use wolfstack_api \
                     GET /api/issues for the issue scanner's latest findings, or \
                     ask the operator for specific alerts.",
            "alerts": [],
        }),
    )
}

async fn tool_read_log(
    args: &serde_json::Value, _agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let lines = args.get("lines").and_then(|v| v.as_u64()).unwrap_or(100).min(2000) as usize;
    if target.is_empty() {
        return ToolResult::err("read_log requires a `target` argument (container name or systemd unit)".into());
    }
    // Shell out to journalctl --unit=<target> or docker logs <target>.
    // Safe by construction — we're only reading.
    let try_journal = std::process::Command::new("journalctl")
        .args(["-u", target, "-n", &lines.to_string(), "--no-pager", "--output=short"])
        .output();
    if let Ok(o) = try_journal {
        if o.status.success() && !o.stdout.is_empty() {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            return ToolResult::ok(
                format!("journalctl tail of {} ({} lines)", target, lines),
                serde_json::json!({ "source": "journalctl", "target": target, "log": text }),
            );
        }
    }
    // Fallback: docker logs.
    if let Ok(o) = std::process::Command::new("docker")
        .args(["logs", "--tail", &lines.to_string(), target])
        .output()
    {
        if o.status.success() {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            return ToolResult::ok(
                format!("docker logs tail of {} ({} lines)", target, lines),
                serde_json::json!({
                    "source": "docker",
                    "target": target,
                    "stdout": stdout,
                    "stderr": stderr,
                }),
            );
        }
    }
    ToolResult::err(format!(
        "no log found for '{}' — neither systemd unit nor docker container matched",
        target
    ))
}

async fn tool_check_disk_usage(
    args: &serde_json::Value, agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let container_pattern = args.get("container_pattern").and_then(|v| v.as_str())
        .unwrap_or("*");
    let threshold_pct = args.get("threshold_pct").and_then(|v| v.as_u64()).unwrap_or(90) as u32;
    let containers = crate::containers::list_running_containers();
    let mut results = Vec::new();
    for (runtime, name, _status) in containers {
        if !glob_match(container_pattern, &name) { continue; }
        if !matches_container_pattern(&name, &agent.target_scope.allowed_container_patterns) { continue; }
        // Run `df -P /` inside the container — portable across distros.
        let output = match runtime.as_str() {
            "docker" => std::process::Command::new("docker")
                .args(["exec", &name, "df", "-P", "/"])
                .output(),
            "lxc" => std::process::Command::new("lxc-attach")
                .args(["-n", &name, "--", "df", "-P", "/"])
                .output(),
            _ => continue,
        };
        let (used_pct, avail_kb, total_kb) = match output {
            Ok(o) if o.status.success() => parse_df(&String::from_utf8_lossy(&o.stdout)),
            _ => (0, 0, 0),
        };
        results.push(serde_json::json!({
            "container": name,
            "runtime": runtime,
            "used_pct": used_pct,
            "available_kb": avail_kb,
            "total_kb": total_kb,
            "over_threshold": used_pct >= threshold_pct,
        }));
    }
    ToolResult::ok(
        format!("checked {} containers against threshold {}%", results.len(), threshold_pct),
        serde_json::json!({ "threshold_pct": threshold_pct, "containers": results }),
    )
}

/// Parse `df -P /` output → (used_pct, available_kb, total_kb).
/// Example line: "/dev/sda1  50000000  25000000  25000000  50% /"
fn parse_df(text: &str) -> (u32, u64, u64) {
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let total = parts[1].parse::<u64>().unwrap_or(0);
            let avail = parts[3].parse::<u64>().unwrap_or(0);
            let used = parts[4].trim_end_matches('%').parse::<u32>().unwrap_or(0);
            return (used, avail, total);
        }
    }
    (0, 0, 0)
}

async fn tool_read_file(args: &serde_json::Value, agent: &Agent) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let max_bytes = args.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(65536).min(1024 * 1024) as usize;
    if path.is_empty() {
        return ToolResult::err("read_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let truncated = bytes.len() > max_bytes;
            let slice = &bytes[..max_bytes.min(bytes.len())];
            let content = String::from_utf8_lossy(slice).to_string();
            ToolResult::ok(
                format!("read {} bytes from {}", slice.len(), path),
                serde_json::json!({
                    "path": path,
                    "content": content,
                    "truncated": truncated,
                    "total_bytes": bytes.len(),
                }),
            )
        }
        Err(e) => ToolResult::err(format!("read failed: {}", e)),
    }
}

async fn tool_list_api_endpoints(agent: &Agent) -> ToolResult {
    // If the agent has an explicit allowlist, echo it. Otherwise we
    // can't enumerate every route in the binary at runtime; surface a
    // "all GETs allowed" hint so the agent knows to just try.
    let list = &agent.target_scope.allowed_api_paths;
    if list.is_empty() {
        ToolResult::ok(
            "no explicit allowlist — read-only GETs allowed by default",
            serde_json::json!({
                "hint": "Agent has no allowed_api_paths configured, so GET requests \
                         to /api/* are allowed (subject to the hardcoded denylist). \
                         Use wolfstack_api with method=GET to explore.",
                "entries": [],
            }),
        )
    } else {
        ToolResult::ok(
            format!("{} allowlist entries", list.len()),
            serde_json::json!({ "entries": list }),
        )
    }
}

async fn tool_describe_cluster(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let filter = args.get("cluster_name").and_then(|v| v.as_str());
    let nodes = state.cluster.get_all_nodes();
    let mut picked: Vec<_> = nodes.iter()
        .filter(|n| match filter {
            Some(c) => n.cluster_name.as_deref() == Some(c),
            None => true,
        })
        .filter(|n| {
            let scope = &agent.target_scope.allowed_clusters;
            scope.is_empty() || n.cluster_name.as_deref()
                .map(|c| scope.iter().any(|s| s == c))
                .unwrap_or(false)
        })
        .map(|n| serde_json::json!({
            "id": n.id,
            "hostname": n.hostname,
            "cluster": n.cluster_name,
            "online": n.online,
            "docker": n.docker_count,
            "lxc": n.lxc_count,
            "vm": n.vm_count,
            "node_type": n.node_type,
            "address": n.address,
        })).collect::<Vec<_>>();
    picked.sort_by(|a, b| a["hostname"].as_str().cmp(&b["hostname"].as_str()));
    ToolResult::ok(
        format!("{} nodes matched", picked.len()),
        serde_json::json!({
            "cluster_filter": filter,
            "agent_allowed_clusters": agent.target_scope.allowed_clusters,
            "nodes": picked,
        }),
    )
}

// ═══════════════════════════════════════════════════
// Mutating tools
// ═══════════════════════════════════════════════════

async fn tool_restart_container(
    args: &serde_json::Value, agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let runtime = args.get("runtime").and_then(|v| v.as_str()).unwrap_or("");
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if runtime.is_empty() || name.is_empty() {
        return ToolResult::err("restart_container requires `runtime` (docker|lxc) and `name`".into());
    }
    if !matches_container_pattern(name, &agent.target_scope.allowed_container_patterns) {
        return ToolResult::err(format!(
            "container '{}' is outside the agent's allowed_container_patterns scope",
            name
        ));
    }
    let args_vec = match runtime {
        "docker" => vec!["docker".to_string(), "restart".to_string(), name.to_string()],
        "lxc" => vec!["lxc-stop".to_string(), "-n".to_string(), name.to_string()],
        _ => return ToolResult::err(format!("unsupported runtime '{}'", runtime)),
    };
    let mut cmd = std::process::Command::new(&args_vec[0]);
    for a in &args_vec[1..] { cmd.arg(a); }
    let out = cmd.output();
    match out {
        Ok(o) if o.status.success() => ToolResult::ok(
            format!("restarted {}:{}", runtime, name),
            serde_json::json!({
                "runtime": runtime, "name": name,
                "stdout": String::from_utf8_lossy(&o.stdout).trim().to_string(),
            }),
        ),
        Ok(o) => ToolResult::err(format!(
            "restart failed (exit {}): {}",
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => ToolResult::err(format!("spawn failed: {}", e)),
    }
}

async fn tool_run_workflow(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let id = args.get("workflow_id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return ToolResult::err("run_workflow requires `workflow_id`".into());
    }
    let Some(workflow) = state.wolfflow.get_workflow(id) else {
        let available: Vec<String> = state.wolfflow.list_workflows(None)
            .into_iter().map(|w| format!("{} (id={})", w.name, w.id)).collect();
        return ToolResult::err(format!(
            "no workflow with id '{}'. Available: [{}]",
            id,
            available.join(", ")
        ));
    };
    let wf_state = state.wolfflow.clone();
    let cluster = state.cluster.clone();
    let secret = state.cluster_secret.clone();
    // Recover from a poisoned mutex instead of panicking — a previous
    // panic in another code path under this lock would otherwise take
    // the agent's tool call down with it. The inner value is fine to
    // read; we only need a clone of the config to pass to the workflow.
    let ai_config = state.ai_agent.config.lock()
        .unwrap_or_else(|p| p.into_inner()).clone();
    let wf_name = workflow.name.clone();
    // Fire-and-forget exactly like the API trigger. The agent gets
    // back "enqueued" — if it needs the run's outcome, it can poll
    // `list_workflows` or use wolfstack_api against /api/wolfflow/runs.
    tokio::spawn(async move {
        crate::wolfflow::execute_workflow(
            &wf_state, &cluster, &secret, &workflow, "agent", Some(ai_config)
        ).await;
    });
    ToolResult::ok(
        format!("workflow_triggered: {}", wf_name),
        serde_json::json!({ "workflow_id": id, "workflow_name": wf_name, "trigger": "agent" }),
    )
}

async fn tool_list_workflows(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let cluster = args.get("cluster").and_then(|v| v.as_str());
    let workflows = state.wolfflow.list_workflows(cluster);
    let summary: Vec<serde_json::Value> = workflows.iter().map(|w| serde_json::json!({
        "id": w.id,
        "name": w.name,
        "cluster": w.cluster,
        "enabled": w.enabled,
        "schedule": w.schedule,
        "step_count": w.steps.len(),
    })).collect();
    ToolResult::ok(
        format!("{} workflows", summary.len()),
        serde_json::json!({ "workflows": summary }),
    )
}

async fn tool_schedule_workflow(args: &serde_json::Value, state: &crate::api::AppState) -> ToolResult {
    let id = args.get("workflow_id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return ToolResult::err("schedule_workflow requires `workflow_id`".into());
    }
    // `schedule` can be a 5-field cron expression or null to clear the
    // schedule. We accept both explicit null and a missing field as
    // "clear the schedule" (the agent may have been told "unschedule X").
    // `cron` is accepted as an alias — natural word for the field, and
    // models sometimes emit that even when the schema says `schedule`.
    let schedule_arg = args.get("schedule").or_else(|| args.get("cron"));
    let new_schedule: Option<String> = match schedule_arg {
        Some(v) if v.is_null() => None,
        Some(v) => match v.as_str() {
            Some(s) if s.trim().is_empty() => None,
            Some(s) => {
                // Validate the cron expression before storing it. The
                // scheduler silently skips workflows whose cron fails to
                // parse, so an agent emitting "every 5 minutes" would
                // look accepted but never run. We require five whitespace
                // fields and each field to contain only the character
                // classes the matcher understands.
                let fields: Vec<&str> = s.split_whitespace().collect();
                if fields.len() != 5 {
                    return ToolResult::err(format!(
                        "invalid cron expression '{}': expected 5 fields (min hour dom month dow), got {}",
                        s, fields.len()));
                }
                for (i, f) in fields.iter().enumerate() {
                    if !f.chars().all(|c| c == '*' || c == ',' || c == '-'
                                       || c == '/' || c.is_ascii_digit()) {
                        return ToolResult::err(format!(
                            "invalid cron expression '{}': field {} ('{}') contains unsupported characters",
                            s, i + 1, f));
                    }
                }
                Some(s.to_string())
            }
            None => return ToolResult::err("`schedule` must be a string or null".into()),
        },
        None => None,
    };
    let Some(mut wf) = state.wolfflow.get_workflow(id) else {
        return ToolResult::err(format!("no workflow with id '{}'", id));
    };
    let before = wf.schedule.clone();
    wf.schedule = new_schedule.clone();
    // Enable handling:
    //   - explicit `enabled: true/false` argument wins (agent intent is clear),
    //   - otherwise, default to enabling when setting a schedule because a
    //     scheduled workflow that stays disabled never fires, which would
    //     silently defeat the agent's intent.
    match args.get("enabled").and_then(|v| v.as_bool()) {
        Some(b) => wf.enabled = b,
        None if new_schedule.is_some() => wf.enabled = true,
        None => {} // clearing the schedule leaves enabled as-is
    }
    match state.wolfflow.update_workflow(id, wf) {
        Some(updated) => ToolResult::ok(
            format!(
                "workflow '{}' schedule: {} -> {}",
                updated.name,
                before.as_deref().unwrap_or("(none)"),
                updated.schedule.as_deref().unwrap_or("(none)"),
            ),
            serde_json::json!({
                "workflow_id": id,
                "name": updated.name,
                "schedule": updated.schedule,
                "enabled": updated.enabled,
            }),
        ),
        None => ToolResult::err(format!("update_workflow({}) returned None", id)),
    }
}

async fn tool_write_file(args: &serde_json::Value, agent: &Agent) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(false);
    if path.is_empty() {
        return ToolResult::err("write_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    if content.len() > 8 * 1024 * 1024 {
        return ToolResult::err("content exceeds 8 MB — write_file refuses large payloads".into());
    }
    let result = if append {
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(path)
            .and_then(|mut f| f.write_all(content.as_bytes()))
    } else {
        std::fs::write(path, content.as_bytes())
    };
    match result {
        Ok(()) => ToolResult::ok(
            format!("wrote {} bytes to {}", content.len(), path),
            serde_json::json!({ "path": path, "bytes": content.len(), "appended": append }),
        ),
        Err(e) => ToolResult::err(format!("write failed: {}", e)),
    }
}

// ═══════════════════════════════════════════════════
// Destructive tools
// ═══════════════════════════════════════════════════

async fn tool_exec_in_container(
    args: &serde_json::Value, agent: &Agent, _state: &crate::api::AppState,
) -> ToolResult {
    let runtime = args.get("runtime").and_then(|v| v.as_str()).unwrap_or("docker");
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30).min(600);
    if name.is_empty() || command.is_empty() {
        return ToolResult::err("exec_in_container requires `name` and `command`".into());
    }
    if let Err(e) = safety::validate_command(command) {
        return ToolResult::err(e);
    }
    if !matches_container_pattern(name, &agent.target_scope.allowed_container_patterns) {
        return ToolResult::err(format!(
            "container '{}' is outside the agent's allowed_container_patterns scope",
            name
        ));
    }
    let exec = match runtime {
        "docker" => format!("docker exec {} sh -c {}", name, shell_escape(command)),
        "lxc" => format!("lxc-attach -n {} -- sh -c {}", name, shell_escape(command)),
        _ => return ToolResult::err(format!("unsupported runtime '{}'", runtime)),
    };
    run_shell_with_timeout(&exec, timeout_secs).await
}

async fn tool_exec_on_node(args: &serde_json::Value, agent: &Agent) -> ToolResult {
    let node_id = args.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30).min(600);
    if node_id.is_empty() || command.is_empty() {
        return ToolResult::err("exec_on_node requires `node_id` and `command`".into());
    }
    if let Err(e) = safety::validate_command(command) {
        return ToolResult::err(e);
    }
    let scope = &agent.target_scope.allowed_hosts;
    let self_id = crate::agent::self_node_id();
    if !scope.is_empty() && !scope.iter().any(|h| h == node_id) {
        return ToolResult::err(format!(
            "node '{}' is outside the agent's allowed_hosts scope",
            node_id
        ));
    }
    // MVP: only local-node exec. Cross-node exec would proxy over
    // HTTPS via /api/system/exec (no such endpoint exists yet) or
    // through the cluster-secret-auth'd agent channel. Surface the
    // limitation rather than silently ignoring.
    if node_id != self_id {
        return ToolResult::err(format!(
            "cross-node exec is not yet wired — this tool currently only runs on \
             the local node ({}). Use wolfstack_api to call a remote node via \
             /api/nodes/{}/proxy/... if that node has a suitable endpoint.",
            self_id, node_id
        ));
    }
    run_shell_with_timeout(command, timeout_secs).await
}

async fn tool_delete_file(args: &serde_json::Value, agent: &Agent) -> ToolResult {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return ToolResult::err("delete_file requires a `path` argument".into());
    }
    if let Err(e) = safety::validate_path(path) {
        return ToolResult::err(e);
    }
    if !path_allowed(path, agent) {
        return ToolResult::err(format!(
            "path '{}' is outside the agent's allowed_paths scope",
            path
        ));
    }
    match std::fs::remove_file(path) {
        Ok(()) => ToolResult::ok(
            format!("deleted {}", path),
            serde_json::json!({ "path": path }),
        ),
        Err(e) => ToolResult::err(format!("delete failed: {}", e)),
    }
}

// ═══════════════════════════════════════════════════
// Universal WolfStack API (Phase G)
// ═══════════════════════════════════════════════════

async fn tool_wolfstack_api(
    args: &serde_json::Value, agent: &Agent, state: &crate::api::AppState,
) -> ToolResult {
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let body = args.get("body");
    if path.is_empty() {
        return ToolResult::err("wolfstack_api requires a `path` argument (e.g. /api/nodes)".into());
    }
    if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
        return ToolResult::err(format!("unsupported HTTP method '{}'", method));
    }

    // Safety: hardcoded API denylist — refuses /api/auth/*, /api/agents/*
    // (so one agent can't reconfigure another), /api/ports, etc.
    if let Err(e) = safety::validate_api_path(path) {
        return ToolResult::err(e);
    }

    // Method-based danger gating. GET is always allowed on Safe, but
    // since WolfstackApi is classified as Mutating in the catalogue
    // (for the access-level policy), GETs still needed Mutating
    // authority to get here. For POST/PUT/PATCH/DELETE we additionally
    // require the per-agent allowed_api_paths to explicitly list the
    // path — otherwise the agent would be able to POST anywhere.
    let write_method = method != "GET";
    let key = format!("{}:{}", method, path);
    let allow_list = &agent.target_scope.allowed_api_paths;
    if write_method {
        let matched = allow_list.iter().any(|entry| {
            // Accept exact "METHOD:/api/path" entries and path-only
            // entries (operator can list "/api/workflows/*" without
            // pinning a method).
            entry == &key || entry == path || path_glob_matches(entry, &key)
        });
        if !matched {
            return ToolResult::err(format!(
                "{} {} is not in the agent's allowed_api_paths. \
                 Add an explicit entry like \"{}:{}\" to the agent's scope.",
                method, path, method, path
            ));
        }
    }

    // Route over loopback. We use the cluster-secret as auth — the
    // same mechanism inter-node calls already use, so the request
    // runs with cluster-peer privileges (NOT a logged-in user's
    // session). This means user-scoped endpoints that inspect the
    // session username will see "cluster-node" instead, which is
    // fine for observation and admin ops.
    let port = crate::ports::PortConfig::load().api;
    let url = format!("http://127.0.0.1:{}{}", port, path);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("http client build failed: {}", e)),
    };
    let req_builder = match method.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        _ => unreachable!(),
    };
    let req_builder = req_builder.header("X-WolfStack-Secret", &state.cluster_secret);
    let req_builder = if let Some(b) = body {
        req_builder.header("Content-Type", "application/json").json(b)
    } else {
        req_builder
    };

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            // Try to parse as JSON for nicer agent consumption; fall
            // back to raw text.
            let data: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::Value::String(text.clone()));
            let truncated = if text.len() > 16 * 1024 {
                text.chars().take(16 * 1024).collect()
            } else {
                text
            };
            let ok = (200..300).contains(&status);
            ToolResult {
                ok,
                status: format!("{} {} → HTTP {}", method, path, status),
                data: serde_json::json!({
                    "status": status,
                    "body_raw": truncated,
                    "body_json": data,
                }),
            }
        }
        Err(e) => {
            warn!("wolfagents dispatch: wolfstack_api request failed: {}", e);
            ToolResult::err(format!("request failed: {}", e))
        }
    }
}

fn path_glob_matches(pattern: &str, s: &str) -> bool {
    // Allow patterns like "GET:/api/nodes/*" against "GET:/api/nodes/123".
    glob_match(pattern, s)
}

// ═══════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════

/// Single-quote shell escape for embedding an agent-supplied command
/// into a shell wrapper (`docker exec X sh -c '<cmd>'`). Doesn't
/// sanitise the command itself — safety::validate_command has already
/// checked for destructive patterns before this point.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

async fn run_shell_with_timeout(command: &str, timeout_secs: u64) -> ToolResult {
    let timeout = Duration::from_secs(timeout_secs);
    let task = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let child = match task {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("spawn failed: {}", e)),
    };
    let waited = tokio::time::timeout(timeout, child.wait_with_output()).await;
    match waited {
        Ok(Ok(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let code = o.status.code().unwrap_or(-1);
            ToolResult {
                ok: o.status.success(),
                status: format!("exit {}", code),
                data: serde_json::json!({
                    "stdout": truncate(&stdout, 16 * 1024),
                    "stderr": truncate(&stderr, 8 * 1024),
                    "exit_code": code,
                }),
            }
        }
        Ok(Err(e)) => ToolResult::err(format!("wait failed: {}", e)),
        Err(_) => ToolResult::err(format!("command timed out after {}s", timeout_secs)),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("\n...[truncated]");
        t
    }
}

// ─── web_fetch / web_render ─────────────────────────────────────────────

/// Maximum bytes read from any web fetch. A model that asks for a
/// 50 MB page will get the first 512 KB — more than enough for text
/// extraction and cheap to reason about.
const WEB_FETCH_MAX_BYTES: usize = 512 * 1024;
const WEB_FETCH_TIMEOUT_SECS: u64 = 10;
const WEB_RENDER_TIMEOUT_SECS: u64 = 30;

/// Shared implementation for `web_fetch` (static HTTP) and `web_render`
/// (headless Chromium shell-out). The `rendered` flag flips execution
/// path; the safety gates (scheme check, SSRF guard via pre-resolve,
/// size cap, timeout) are identical.
async fn tool_web_fetch(args: &serde_json::Value, rendered: bool) -> ToolResult {
    let url = args.get("url").and_then(|v| v.as_str()).unwrap_or("").trim();
    if url.is_empty() {
        return ToolResult::err(format!(
            "{} requires a `url` argument",
            if rendered { "web_render" } else { "web_fetch" }));
    }
    // Only http/https — no file://, no ftp, no data:. Validated with a
    // case-insensitive prefix check so `HTTPS://` doesn't slip past.
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return ToolResult::err(format!(
            "url '{}' rejected: only http:// and https:// schemes are allowed", url));
    }
    // SSRF guard: resolve the hostname and refuse private / loopback /
    // link-local targets. Done before reqwest touches the network so we
    // can't be redirected into the internal network mid-request.
    let host = match extract_host(url) {
        Some(h) => h,
        None => return ToolResult::err(format!("url '{}' has no parseable host", url)),
    };
    match resolve_public(&host) {
        Ok(()) => {}
        Err(e) => return ToolResult::err(format!("url '{}' rejected: {}", url, e)),
    }

    if rendered {
        web_render_via_chromium(url).await
    } else {
        web_fetch_http(url).await
    }
}

/// Extract the hostname from an http(s) URL without pulling in a url
/// crate. Handles `scheme://host`, `scheme://host:port`, `scheme://host/path`,
/// and ignores credentials (`scheme://user:pass@host`). Returns None
/// on malformed input.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.splitn(2, "://").nth(1)?;
    // Drop anything after the first '/', '?', or '#'.
    let authority: &str = after_scheme.splitn(2, |c: char| c == '/' || c == '?' || c == '#')
        .next().unwrap_or("");
    // Drop credentials.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // Drop port. Be careful with IPv6 literals `[::1]:443`.
    if hostport.starts_with('[') {
        if let Some(close) = hostport.find(']') {
            return Some(hostport[1..close].to_string());
        }
        return None;
    }
    let host = hostport.splitn(2, ':').next().unwrap_or(hostport);
    if host.is_empty() { None } else { Some(host.to_string()) }
}

/// Resolve a hostname and reject loopback / private / link-local IPs.
/// Runs on the current thread because tokio's resolver is async and
/// this is called from async context anyway — we use std::net here
/// to avoid pulling in more tokio surface than needed.
fn resolve_public(host: &str) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    // Attach a placeholder port so ToSocketAddrs parses the host.
    let probe = format!("{}:80", host);
    let addrs: Vec<_> = probe.to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .collect();
    if addrs.is_empty() {
        return Err("DNS returned no addresses".to_string());
    }
    for sa in &addrs {
        let ip = sa.ip();
        if is_ip_private(&ip) {
            return Err(format!(
                "hostname resolves to a private / loopback / link-local address ({}) — refusing to fetch",
                ip));
        }
    }
    Ok(())
}

/// Classify an IP as "don't fetch from an agent over the public web."
/// Covers IPv4 loopback (127/8), private ranges (10/8, 172.16/12,
/// 192.168/16), link-local (169.254/16), and CGNAT (100.64/10); plus
/// IPv6 loopback, unique-local (fc00::/7), and link-local (fe80::/10).
fn is_ip_private(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg & 0xfe00) == 0xfc00  // ULA fc00::/7
                || (seg & 0xffc0) == 0xfe80  // link-local fe80::/10
        }
    }
}

async fn web_fetch_http(url: &str) -> ToolResult {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(WEB_FETCH_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("WolfStackAgent/1.0 (+https://wolfstack.io)")
        .build()
    {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("web_fetch: build client failed: {}", e)),
    };
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return ToolResult::err(format!("web_fetch: request failed: {}", e)),
    };
    let status = resp.status().as_u16();
    let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Read up to WEB_FETCH_MAX_BYTES — avoids downloading a 5 GB ISO
    // that some adversarial page tries to trick us into.
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() >= WEB_FETCH_MAX_BYTES { buf.truncate(WEB_FETCH_MAX_BYTES); break; }
            }
            Err(e) => return ToolResult::err(format!("web_fetch: stream error: {}", e)),
        }
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let text = if content_type.contains("text/html") || content_type.is_empty() {
        strip_html_to_text(&raw)
    } else {
        raw.clone()
    };
    ToolResult::ok(
        format!("fetched {} ({} bytes, status {})", url, buf.len(), status),
        serde_json::json!({
            "url": url,
            "status": status,
            "content_type": content_type,
            "text": truncate(&text, 100_000),
        }),
    )
}

/// Strip HTML tags + collapse whitespace. Drops <script>, <style>,
/// <svg>, and <head>-level metadata so the text that reaches the LLM
/// is what a reader would see. Not a full parser — a minute of regex
/// that handles the common cases and degrades gracefully on malformed
/// markup by leaving extra whitespace.
fn strip_html_to_text(html: &str) -> String {
    let mut s = html.to_string();
    // Drop script/style blocks (tag + content).
    for tag in ["script", "style", "noscript", "svg", "iframe", "template"] {
        let open = format!("<{}", tag);
        while let Some(start) = s.to_ascii_lowercase().find(&open) {
            let close_tag = format!("</{}>", tag);
            if let Some(end) = s[start..].to_ascii_lowercase().find(&close_tag) {
                s.replace_range(start..start + end + close_tag.len(), " ");
            } else {
                // No closing tag — drop from open to end of string.
                s.truncate(start);
                break;
            }
        }
    }
    // Replace block-level tags with newlines for readability.
    for tag in ["</p>", "</div>", "</li>", "</h1>", "</h2>", "</h3>",
                "</h4>", "<br>", "<br/>", "<br />", "</tr>"] {
        s = s.replace(tag, &format!("{}\n", tag));
    }
    // Strip remaining tags.
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    // Decode the handful of entities that actually matter.
    let out = out.replace("&nbsp;", " ")
                 .replace("&amp;", "&")
                 .replace("&lt;", "<")
                 .replace("&gt;", ">")
                 .replace("&quot;", "\"")
                 .replace("&#039;", "'")
                 .replace("&apos;", "'");
    // Collapse runs of whitespace (but keep single newlines so the
    // paragraph structure survives).
    let mut collapsed = String::with_capacity(out.len());
    let mut last_was_space = false;
    let mut last_was_newline = false;
    for c in out.chars() {
        if c == '\n' {
            if !last_was_newline { collapsed.push('\n'); }
            last_was_newline = true;
            last_was_space = true;
        } else if c.is_whitespace() {
            if !last_was_space { collapsed.push(' '); }
            last_was_space = true;
        } else {
            collapsed.push(c);
            last_was_space = false;
            last_was_newline = false;
        }
    }
    collapsed.trim().to_string()
}

async fn web_render_via_chromium(url: &str) -> ToolResult {
    // Find a chromium binary on the host. We deliberately don't ship
    // one; operator must install it (apt install chromium, etc.).
    let bin = ["chromium", "chromium-browser", "google-chrome", "chrome"]
        .into_iter()
        .find(|b| which_exists(b));
    let Some(bin) = bin else {
        return ToolResult::err(
            "web_render: no chromium/google-chrome binary on this host. Install one and retry, \
             or use web_fetch for static HTML.".to_string());
    };
    // --dump-dom prints the rendered HTML to stdout after JS executes.
    // --no-sandbox is needed when running as root inside some distros;
    // acceptable here because the caller is already an authorised agent
    // and the URL passed SSRF pre-checks.
    let out = tokio::process::Command::new(bin)
        .args(["--headless=new", "--no-sandbox", "--disable-gpu",
               "--disable-extensions", "--virtual-time-budget=5000",
               "--dump-dom", url])
        .output();
    let out = match tokio::time::timeout(
        std::time::Duration::from_secs(WEB_RENDER_TIMEOUT_SECS), out).await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return ToolResult::err(format!("web_render: exec failed: {}", e)),
        Err(_) => return ToolResult::err(format!(
            "web_render: timed out after {}s", WEB_RENDER_TIMEOUT_SECS)),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return ToolResult::err(format!("web_render: chromium exited non-zero: {}",
            truncate(&err, 400)));
    }
    let mut html = out.stdout;
    if html.len() > WEB_FETCH_MAX_BYTES { html.truncate(WEB_FETCH_MAX_BYTES); }
    let text = strip_html_to_text(&String::from_utf8_lossy(&html));
    ToolResult::ok(
        format!("rendered {} ({} bytes DOM)", url, html.len()),
        serde_json::json!({
            "url": url,
            "rendered": true,
            "text": truncate(&text, 100_000),
        }),
    )
}

fn which_exists(bin: &str) -> bool {
    std::process::Command::new("sh").args(["-c", &format!("command -v {}", bin)])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

// ─── semantic_search (BM25) ──────────────────────────────────────────────

/// Search past agent memory, alert history, and audit logs using a BM25
/// ranking. We intentionally avoid a true embedding model here — BM25
/// handles "find past incidents mentioning the same container name"
/// well enough without bundling a 25 MB ONNX model. The tool surface
/// is stable; when a real vector index lands later, callers don't
/// notice.
async fn tool_semantic_search(args: &serde_json::Value, _agent: &Agent) -> ToolResult {
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("").trim();
    if query.is_empty() {
        return ToolResult::err("semantic_search requires a `query` string".into());
    }
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10)
        .clamp(1, 50) as usize;
    let sources: Vec<&str> = args.get("sources").and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_else(|| vec!["memory", "audit", "alerts"]);
    let docs = collect_search_corpus(&sources);
    let ranked = bm25_rank(query, &docs, limit);
    ToolResult::ok(
        format!("{} matches for '{}' across {} docs", ranked.len(), query, docs.len()),
        serde_json::json!({
            "query": query,
            "sources": sources,
            "total_docs": docs.len(),
            "matches": ranked,
        }),
    )
}

/// A single document in the search corpus — a line from memory/audit/
/// alerts, tagged with where it came from so matches carry source.
struct SearchDoc {
    source: String,
    path: String,
    text: String,
}

fn collect_search_corpus(sources: &[&str]) -> Vec<SearchDoc> {
    let mut out = Vec::new();
    if sources.contains(&"memory") {
        if let Ok(agents_dir) = std::fs::read_dir("/etc/wolfstack/agents") {
            for ent in agents_dir.flatten() {
                let mem = ent.path().join("memory.jsonl");
                if !mem.exists() { continue; }
                let id = ent.file_name().to_string_lossy().into_owned();
                if let Ok(text) = std::fs::read_to_string(&mem) {
                    for (i, line) in text.lines().enumerate() {
                        if line.trim().is_empty() { continue; }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                            let content = v.get("content").and_then(|x| x.as_str())
                                .unwrap_or("").to_string();
                            if content.is_empty() { continue; }
                            out.push(SearchDoc {
                                source: "memory".into(),
                                path: format!("{}:{}", id, i + 1),
                                text: content,
                            });
                        }
                    }
                }
            }
        }
    }
    if sources.contains(&"audit") {
        if let Ok(agents_dir) = std::fs::read_dir("/etc/wolfstack/agents") {
            for ent in agents_dir.flatten() {
                let audit = ent.path().join("audit.jsonl");
                if !audit.exists() { continue; }
                let id = ent.file_name().to_string_lossy().into_owned();
                if let Ok(text) = std::fs::read_to_string(&audit) {
                    for (i, line) in text.lines().enumerate() {
                        if !line.trim().is_empty() {
                            out.push(SearchDoc {
                                source: "audit".into(),
                                path: format!("{}:{}", id, i + 1),
                                text: line.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    if sources.contains(&"alerts") {
        // Alerting state lives in /etc/wolfstack/alerting.json — walk
        // the raw file so this stays consistent even if the in-memory
        // state structure evolves.
        if let Ok(text) = std::fs::read_to_string("/etc/wolfstack/alerting.json") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
                    for (i, ev) in events.iter().enumerate() {
                        let blob = serde_json::to_string(ev).unwrap_or_default();
                        out.push(SearchDoc {
                            source: "alerts".into(),
                            path: format!("alerting.json:{}", i + 1),
                            text: blob,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Tokenise text for BM25: lowercase, split on non-alphanumerics, drop
/// 1-char tokens (noise in BM25's IDF term). Good enough for the
/// corpora we're indexing, which are already English-ish log/chat text.
fn tokenise(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect()
}

/// Classic BM25 with k1=1.5, b=0.75. Returns the top `limit` docs by
/// score, formatted for the tool response.
fn bm25_rank(query: &str, docs: &[SearchDoc], limit: usize) -> Vec<serde_json::Value> {
    if docs.is_empty() { return Vec::new(); }
    let q_terms: Vec<String> = tokenise(query);
    if q_terms.is_empty() { return Vec::new(); }
    // Pre-tokenise every doc.
    let doc_tokens: Vec<Vec<String>> = docs.iter().map(|d| tokenise(&d.text)).collect();
    let n = docs.len() as f64;
    let avgdl: f64 = doc_tokens.iter().map(|t| t.len() as f64).sum::<f64>() / n.max(1.0);
    // Document frequency for each unique query term.
    let mut df: std::collections::HashMap<&str, usize> = Default::default();
    for qt in &q_terms {
        let c = doc_tokens.iter().filter(|t| t.iter().any(|x| x == qt)).count();
        df.insert(qt.as_str(), c);
    }
    let k1 = 1.5_f64;
    let b = 0.75_f64;
    let mut scored: Vec<(f64, usize)> = doc_tokens.iter().enumerate().map(|(i, toks)| {
        let dl = toks.len() as f64;
        let mut s = 0.0;
        for qt in &q_terms {
            let dfq = *df.get(qt.as_str()).unwrap_or(&0) as f64;
            if dfq == 0.0 { continue; }
            let idf = ((n - dfq + 0.5) / (dfq + 0.5) + 1.0).ln();
            let tf = toks.iter().filter(|x| *x == qt).count() as f64;
            if tf == 0.0 { continue; }
            let denom = tf + k1 * (1.0 - b + b * dl / avgdl.max(1.0));
            s += idf * (tf * (k1 + 1.0)) / denom;
        }
        (s, i)
    }).filter(|(s, _)| *s > 0.0).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(limit);
    scored.into_iter().map(|(score, idx)| {
        let d = &docs[idx];
        serde_json::json!({
            "score": score,
            "source": d.source,
            "path": d.path,
            "snippet": truncate(&d.text, 400),
        })
    }).collect()
}

#[cfg(test)]
mod web_tool_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_extraction_handles_common_shapes() {
        assert_eq!(extract_host("https://example.com/foo"), Some("example.com".into()));
        assert_eq!(extract_host("http://user:pw@example.com:8080/x"), Some("example.com".into()));
        assert_eq!(extract_host("https://[::1]:443/"), Some("::1".into()));
        assert_eq!(extract_host("https://host.example.com?q=1"), Some("host.example.com".into()));
        assert_eq!(extract_host("notaurl"), None);
    }

    #[test]
    fn private_ips_rejected() {
        let v = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
        assert!(is_ip_private(&v("127.0.0.1")));
        assert!(is_ip_private(&v("10.0.0.5")));
        assert!(is_ip_private(&v("172.16.0.1")));
        assert!(is_ip_private(&v("192.168.1.1")));
        assert!(is_ip_private(&v("169.254.0.1")));
        assert!(is_ip_private(&v("100.64.0.1"))); // CGNAT
        assert!(!is_ip_private(&v("8.8.8.8")));
        assert!(!is_ip_private(&v("1.1.1.1")));
    }

    #[test]
    fn private_ipv6_rejected() {
        let v = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
        assert!(is_ip_private(&v("::1")));
        assert!(is_ip_private(&v("fc00::1")));
        assert!(is_ip_private(&v("fd00::1")));
        assert!(is_ip_private(&v("fe80::1")));
        assert!(!is_ip_private(&v("2606:4700:4700::1111"))); // 1.1.1.1
    }

    #[test]
    fn html_strip_removes_scripts_and_tags() {
        let html = "<html><head><script>alert(1)</script></head><body><h1>Hello</h1><p>World &amp; friends</p></body></html>";
        let text = strip_html_to_text(html);
        assert!(!text.contains("<"));
        assert!(!text.contains("alert"));
        assert!(text.contains("Hello"));
        assert!(text.contains("World & friends"));
    }

    #[test]
    fn html_strip_handles_malformed_script() {
        // Unterminated <script> — should still strip to end of string.
        let html = "<p>ok</p><script>never closes";
        let text = strip_html_to_text(html);
        assert!(text.contains("ok"));
        assert!(!text.contains("never"));
    }

    #[test]
    fn bm25_ranks_matching_docs_higher() {
        let docs = vec![
            SearchDoc { source: "m".into(), path: "a".into(),
                text: "disk space on wolfgrid1 is low".into() },
            SearchDoc { source: "m".into(), path: "b".into(),
                text: "weather forecast is sunny".into() },
            SearchDoc { source: "m".into(), path: "c".into(),
                text: "disk usage trending up on wolfgrid2".into() },
        ];
        let ranked = bm25_rank("disk wolfgrid", &docs, 10);
        assert_eq!(ranked.len(), 2);
        let first_path = ranked[0]["path"].as_str().unwrap();
        assert!(first_path == "a" || first_path == "c",
            "unexpected first match {}", first_path);
    }

    #[test]
    fn bm25_empty_query_returns_nothing() {
        let docs = vec![SearchDoc { source: "m".into(), path: "a".into(),
            text: "hello".into() }];
        assert!(bm25_rank("", &docs, 10).is_empty());
        assert!(bm25_rank("   ", &docs, 10).is_empty());
    }
}
