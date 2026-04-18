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

async fn tool_run_workflow(args: &serde_json::Value, _state: &crate::api::AppState) -> ToolResult {
    let id = args.get("workflow_id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return ToolResult::err("run_workflow requires `workflow_id`".into());
    }
    // We can't easily run_workflow from here without AppState.wolfflow
    // — delegate to the API via wolfstack_api. For now surface the
    // hint to use that tool instead.
    ToolResult::err(format!(
        "direct workflow dispatch not wired yet — use wolfstack_api with \
         method=POST path=/api/wolfflow/workflows/{}/run",
        id
    ))
}

async fn tool_schedule_workflow(args: &serde_json::Value, _state: &crate::api::AppState) -> ToolResult {
    let _ = args;
    ToolResult::err("schedule_workflow not wired yet — use wolfstack_api against \
                     the workflow's cron field (PUT /api/wolfflow/workflows/<id>) \
                     to set a schedule.".into())
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
