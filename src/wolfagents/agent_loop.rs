// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Multi-round tool_use loop for WolfAgents.
//!
//! `simple_chat` is a one-shot prompt → text call — fine for stateless
//! AiInvoke workflow steps, useless for agents that need to look up
//! cluster state and take action. This loop implements Anthropic's
//! tool_use protocol end-to-end:
//!
//! 1. Build tool definitions from the agent's allowed_tools list.
//! 2. POST /v1/messages with `tools: [...]` and the conversation so far.
//! 3. Parse response blocks. If `stop_reason == "tool_use"`:
//!    a. For each tool_use block, dispatch via `dispatch::dispatch`.
//!    b. Build matching tool_result blocks.
//!    c. Append both the assistant turn AND the tool_result turn to
//!       the conversation and loop.
//! 4. Stop when `stop_reason` is `end_turn` / `max_tokens` / reach the
//!    per-turn round cap (so a bad response can't spin forever).
//! 5. Return the final assistant text + a compact trace of tool calls
//!    the caller can log/display.
//!
//! For Gemini / OpenRouter / local providers we fall back to
//! `simple_chat` — their function-calling wire formats differ enough
//! that reusing Claude's pipeline wholesale doesn't work. That means
//! agents on non-Claude providers lose tool access but keep basic
//! chat; documenting this in the UI is the operator's safety net.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{Agent, dispatch, tools::{ToolId, Danger}};

/// Summary of one completed agent turn. Returned to the caller (REST
/// API handler or WolfFlow AgentChat) so they can render the final
/// assistant text plus an audit trail of what the agent did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTurn {
    /// Model's final text response to the user.
    pub response: String,
    /// Per-round tool invocations, in order. Useful for the UI's
    /// "show what the agent did" panel.
    pub tool_calls: Vec<ToolCallTrace>,
    /// Why the loop ended. "end_turn" (normal), "max_rounds"
    /// (hit the guard), "error:...", or "fallback_no_tools" when the
    /// provider doesn't support tool use.
    pub stop_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallTrace {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub ok: bool,
    pub status: String,
}

/// Max rounds of the tool_use ping-pong per user turn. Claude rarely
/// needs more than 3-4 for realistic ops tasks; 6 is a safety cap so
/// a misbehaving prompt can't melt the AI budget.
const MAX_ROUNDS: usize = 6;

/// Drive a full agent turn. Assembles the conversation (history +
/// optional cluster context + this user message), chooses the provider
/// path, and returns an AgentTurn summary.
pub async fn run_turn(
    agent: &Agent,
    history: Vec<crate::ai::ChatMessage>,
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let mut cfg = crate::ai::AiConfig::load();
    // Per-agent override (empty = inherit from global settings).
    if !agent.provider.is_empty() { cfg.provider = agent.provider.clone(); }
    if !agent.model.is_empty() { cfg.model = agent.model.clone(); }
    if !cfg.is_configured() {
        return Err("AI not configured — set provider/key in Settings → AI Agent".to_string());
    }

    let system_prompt = build_system_prompt(agent, state).await;

    // Only Claude gets the full tool_use loop in this ship. Everyone
    // else falls back to plain chat without tool access.
    match cfg.provider.as_str() {
        "claude" => {
            claude_tool_loop(agent, &cfg, &system_prompt, &history, user_message, state).await
        }
        _ => {
            let reply = crate::ai::simple_chat(&cfg, &system_prompt, &history, user_message).await?;
            Ok(AgentTurn {
                response: reply,
                tool_calls: Vec::new(),
                stop_reason: "fallback_no_tools".to_string(),
            })
        }
    }
}

/// Compose the per-turn system prompt. Order: agent's personality
/// prompt (operator-authored) first, then — when enabled — the
/// WolfStack knowledge base and a live cluster snapshot. Keeping the
/// operator's text at the top means the model reads its role before
/// the platform details, which matters for behaviour on
/// tiny-context-window models.
async fn build_system_prompt(agent: &Agent, state: &crate::api::AppState) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(agent.system_prompt.clone());

    if agent.include_cluster_context {
        parts.push(wolfstack_kb_section());
        parts.push(cluster_snapshot_section(agent, state).await);
        parts.push(agent_scope_section(agent));
    }
    parts.join("\n\n---\n\n")
}

/// Embed the WolfStack knowledge base — bundled at compile time.
/// The same file the existing AI Agent uses, so there's a single
/// authoritative description of WolfStack in the binary.
fn wolfstack_kb_section() -> String {
    const KB: &str = include_str!("../ai/wolfstack-kb.md");
    format!("## WolfStack Knowledge Base\n{}", KB)
}

/// Live-ish snapshot of cluster state — recomputed per turn so the
/// model always sees current membership + container counts without
/// spending a tool call to get them.
async fn cluster_snapshot_section(agent: &Agent, state: &crate::api::AppState) -> String {
    let nodes = state.cluster.get_all_nodes();
    let mut clusters: std::collections::BTreeMap<String, Vec<_>> = Default::default();
    for n in &nodes {
        let cname = n.cluster_name.clone().unwrap_or_else(|| "WolfStack".into());
        // Respect the agent's scope when building the snapshot — an
        // agent with allowed_clusters=["wolfgrid"] shouldn't see
        // nodes from other clusters in its system context.
        if !agent.target_scope.allowed_clusters.is_empty()
            && !agent.target_scope.allowed_clusters.iter().any(|c| c == &cname)
        { continue; }
        clusters.entry(cname).or_default().push(n);
    }
    let mut out = String::from("## Live Cluster Snapshot\n");
    out.push_str(&format!("(captured at {} — refreshed each turn)\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    if clusters.is_empty() {
        out.push_str("No clusters visible within this agent's allowed scope.\n");
        return out;
    }
    for (cname, ns) in &clusters {
        let online = ns.iter().filter(|n| n.online).count();
        let docker: u32 = ns.iter().map(|n| n.docker_count).sum();
        let lxc: u32 = ns.iter().map(|n| n.lxc_count).sum();
        let vm: u32 = ns.iter().map(|n| n.vm_count).sum();
        out.push_str(&format!(
            "### Cluster `{}` — {} nodes ({} online), {} docker + {} lxc + {} vm\n",
            cname, ns.len(), online, docker, lxc, vm
        ));
        for n in ns {
            out.push_str(&format!(
                "- `{}` ({}{}) — {}docker: {}, lxc: {}, vm: {}\n",
                n.hostname,
                n.id,
                if n.is_self { ", SELF" } else { "" },
                if n.online { "" } else { "OFFLINE — " },
                n.docker_count, n.lxc_count, n.vm_count
            ));
        }
        out.push('\n');
    }
    out
}

/// Describe the agent's own target scope so it knows what it's
/// allowed to see and act on. Prevents the model wasting tool calls
/// on containers it can't touch.
fn agent_scope_section(agent: &Agent) -> String {
    let scope = &agent.target_scope;
    let mut out = String::from("## Your Scope\n");
    // Enumerate safe tools live from the tool registry so the hint stays
    // correct when new tools are added — no risk of the prompt drifting
    // from the authoriser's classification.
    let safe_tools: Vec<&str> = ToolId::ALL.iter()
        .filter(|t| t.danger() == Danger::Safe)
        .map(|t| t.as_str())
        .collect();
    let level_hint = match agent.access_level {
        crate::wolfagents::AccessLevel::ReadOnly => format!(
            "read_only — safe/read tools run freely ({}). Mutating and destructive \
             tools are refused. This is NOT a chat-only agent — you SHOULD call \
             read tools to answer questions about the cluster.",
            safe_tools.join(", ")),
        crate::wolfagents::AccessLevel::ReadWrite =>
            "read_write — safe and mutating tools run freely. Destructive tools \
             queue for operator approval.".to_string(),
        crate::wolfagents::AccessLevel::ConfirmAll =>
            "confirm_all — every non-read tool queues for operator approval.".to_string(),
        crate::wolfagents::AccessLevel::Trusted =>
            "trusted — all tools run freely, subject only to the hardcoded safety denylist.".to_string(),
    };
    out.push_str(&format!("- access_level: `{:?}` — {}\n", agent.access_level, level_hint));
    if scope.allowed_clusters.is_empty() {
        out.push_str("- clusters: (all)\n");
    } else {
        out.push_str(&format!("- clusters: {}\n", scope.allowed_clusters.join(", ")));
    }
    if scope.allowed_container_patterns.is_empty() {
        out.push_str("- container patterns: (all)\n");
    } else {
        out.push_str(&format!(
            "- container patterns: {}\n",
            scope.allowed_container_patterns.join(", ")
        ));
    }
    if scope.allowed_hosts.is_empty() {
        out.push_str("- specific hosts: (all within scope)\n");
    } else {
        out.push_str(&format!("- specific hosts: {}\n", scope.allowed_hosts.join(", ")));
    }
    if scope.allowed_paths.is_empty() {
        out.push_str("- filesystem paths: (none — write/exec tools may still refuse)\n");
    } else {
        out.push_str(&format!(
            "- filesystem paths: {}\n",
            scope.allowed_paths.join(", ")
        ));
    }
    out.push_str(&format!(
        "- allowed tools: {}\n",
        if agent.allowed_tools.is_empty() { "(none — chat only)".to_string() }
        else { agent.allowed_tools.join(", ") }
    ));
    out.push_str("\nA hardcoded safety denylist (`rm -rf /`, disk wipes, firewall flush, etc.) always applies regardless of your access level.\n");
    out.push_str(
        "\nIMPORTANT: the access level and scope above are the CURRENT values as of this turn. \
         If earlier messages in this conversation show you refusing an action based on a stricter \
         setting, that refusal is outdated — the operator has since adjusted your permissions. \
         Re-evaluate the current request against the values above, not against your prior replies.\n"
    );
    out
}

/// The core ping-pong loop against Anthropic's /v1/messages endpoint.
/// Sends the conversation + tool schemas, parses tool_use blocks,
/// dispatches them through our gatekeeper, appends tool_result blocks,
/// sends the whole lot back — repeat until stop_reason is terminal.
async fn claude_tool_loop(
    agent: &Agent,
    cfg: &crate::ai::AiConfig,
    system_prompt: &str,
    history: &[crate::ai::ChatMessage],
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    // Build the initial messages array. Claude's format uses role +
    // content blocks (content can be a string for simple turns).
    let mut messages: Vec<serde_json::Value> = Vec::new();
    for m in history {
        // Skip anything that isn't a plain user/assistant text turn —
        // old memory may have additional shapes.
        if m.role != "user" && m.role != "assistant" { continue; }
        messages.push(serde_json::json!({
            "role": m.role,
            "content": m.content,
        }));
    }
    messages.push(serde_json::json!({
        "role": "user",
        "content": user_message,
    }));

    let tools_json = build_claude_tools(agent);
    let mut trace: Vec<ToolCallTrace> = Vec::new();

    for round in 0..MAX_ROUNDS {
        let mut body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": messages,
        });
        if !tools_json.is_empty() {
            body["tools"] = serde_json::json!(tools_json);
        }

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &cfg.claude_api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Claude API error: {}", e))?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("read body: {}", e))?;
        if !status.is_success() {
            return Err(format!("Claude API {} — {}", status, text));
        }

        let payload: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("parse response: {} — body: {}", e, text.chars().take(200).collect::<String>()))?;

        let stop_reason = payload.get("stop_reason").and_then(|v| v.as_str()).unwrap_or("");
        let content = payload.get("content").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        // Extract terminal text (if any) and tool_use blocks.
        let mut text_pieces: Vec<String> = Vec::new();
        let mut tool_uses: Vec<(String, String, serde_json::Value)> = Vec::new(); // (id, name, input)
        for block in &content {
            let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match btype {
                "text" => {
                    if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                        text_pieces.push(t.to_string());
                    }
                }
                "tool_use" => {
                    let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let input = block.get("input").cloned().unwrap_or(serde_json::json!({}));
                    tool_uses.push((id, name, input));
                }
                _ => {} // ignore other block types
            }
        }

        // If the model didn't ask for any tools, we're done.
        if tool_uses.is_empty() {
            return Ok(AgentTurn {
                response: text_pieces.join("\n"),
                tool_calls: trace,
                stop_reason: stop_reason.to_string(),
            });
        }

        // Append the assistant turn (with tool_use blocks intact) to
        // the message history — Claude requires this before the
        // tool_result turn or it returns 400.
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": content,
        }));

        // Dispatch each tool_use, collect tool_result blocks.
        let mut tool_result_blocks: Vec<serde_json::Value> = Vec::new();
        for (use_id, name, input) in &tool_uses {
            let result = dispatch::dispatch(agent, name, input, state).await;
            trace.push(ToolCallTrace {
                tool: name.clone(),
                arguments: input.clone(),
                ok: result.ok,
                status: result.status.clone(),
            });
            // Pack the result as MCP-style content: single text block
            // containing a compact JSON summary so Claude can parse it.
            let content_text = serde_json::to_string(&serde_json::json!({
                "status": result.status,
                "ok": result.ok,
                "data": result.data,
            })).unwrap_or_else(|_| result.status.clone());
            tool_result_blocks.push(serde_json::json!({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": content_text,
                "is_error": !result.ok,
            }));
        }

        // Append the user turn carrying all tool_result blocks.
        messages.push(serde_json::json!({
            "role": "user",
            "content": tool_result_blocks,
        }));

        // If Claude signalled end_turn despite emitting tool_use (rare
        // but possible when max_tokens cuts off mid-turn), stop.
        if stop_reason == "end_turn" {
            // Collect any text pieces we saw and call it done.
            let last_text = text_pieces.join("\n");
            return Ok(AgentTurn {
                response: if last_text.is_empty() {
                    "(agent ran tools but returned no text; see tool_calls for the result)".into()
                } else {
                    last_text
                },
                tool_calls: trace,
                stop_reason: stop_reason.to_string(),
            });
        }

        // Otherwise loop — next round sends the tool_result back up
        // and we wait for the model's next move.
        let _ = round;
    }

    warn!("wolfagents: agent {} hit MAX_ROUNDS ({}) — abandoning turn", agent.id, MAX_ROUNDS);
    Ok(AgentTurn {
        response: format!(
            "(agent aborted after {} tool-use rounds — increase the round cap or \
             tighten the system prompt so the agent reaches a conclusion faster)",
            MAX_ROUNDS
        ),
        tool_calls: trace,
        stop_reason: "max_rounds".to_string(),
    })
}

/// Build Anthropic tool schemas from the agent's allowed_tools list.
/// Each schema includes a JSON Schema for inputs so Claude knows what
/// shape to emit. Hand-maintained per-tool; a shared source-of-truth
/// would be nice but the schemas are small and stable enough that
/// duplication is cheaper than the abstraction.
fn build_claude_tools(agent: &Agent) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for name in &agent.allowed_tools {
        let Some(tool) = ToolId::from_str(name) else { continue; };
        let schema = input_schema_for(tool);
        let description = tool.risk_note();
        out.push(serde_json::json!({
            "name": tool.as_str(),
            "description": format!("{} — {}", tool.label(), description),
            "input_schema": schema,
        }));
    }
    out
}

/// Input JSON Schema per tool — mirrors the arguments the dispatcher
/// actually reads.
fn input_schema_for(tool: ToolId) -> serde_json::Value {
    match tool {
        ToolId::ListNodes | ToolId::ListAlerts | ToolId::GetMetrics
        | ToolId::ListApiEndpoints => serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        ToolId::ListContainers => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster": { "type": "string", "description": "Optional cluster-name filter" },
                "name_pattern": { "type": "string", "description": "Optional glob, e.g. 'regions*'" }
            }
        }),
        ToolId::ReadLog => serde_json::json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string", "description": "Container name or systemd unit" },
                "lines": { "type": "integer", "minimum": 1, "maximum": 2000 }
            }
        }),
        ToolId::CheckDiskUsage => serde_json::json!({
            "type": "object",
            "properties": {
                "container_pattern": { "type": "string", "description": "Glob, e.g. 'regions*'" },
                "threshold_pct": { "type": "integer", "minimum": 0, "maximum": 100 }
            }
        }),
        ToolId::ReadFile => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string" },
                "max_bytes": { "type": "integer", "minimum": 1, "maximum": 1048576 }
            }
        }),
        ToolId::DescribeCluster => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster_name": { "type": "string" }
            }
        }),
        ToolId::RestartContainer => serde_json::json!({
            "type": "object",
            "required": ["runtime", "name"],
            "properties": {
                "runtime": { "type": "string", "enum": ["docker", "lxc"] },
                "name": { "type": "string" }
            }
        }),
        ToolId::ListWorkflows => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster": { "type": "string", "description": "Optional cluster name filter" }
            }
        }),
        ToolId::WebFetch => serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "description": "http:// or https:// URL. Private/loopback/link-local addresses are refused." }
            }
        }),
        ToolId::WebRender => serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "description": "URL to render via headless Chromium. Use for JS-heavy sites when web_fetch returns empty text. Requires chromium on the host." }
            }
        }),
        ToolId::SemanticSearch => serde_json::json!({
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "description": "Natural-language keywords. BM25 ranked." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                "sources": {
                    "type": "array",
                    "items": { "type": "string", "enum": ["memory", "audit", "alerts"] },
                    "description": "Which corpora to search. Default: all three."
                }
            }
        }),
        ToolId::RunWorkflow => serde_json::json!({
            "type": "object",
            "required": ["workflow_id"],
            "properties": { "workflow_id": { "type": "string" } }
        }),
        ToolId::ScheduleWorkflow => serde_json::json!({
            "type": "object",
            "required": ["workflow_id"],
            "properties": {
                "workflow_id": { "type": "string" },
                "schedule": {
                    "type": ["string", "null"],
                    "description": "5-field cron expression (min hour dom month dow), or null to clear the schedule"
                },
                "enabled": {
                    "type": "boolean",
                    "description": "Explicit enable/disable. Omit to enable automatically when setting a schedule, or leave the workflow's current state when clearing one."
                }
            }
        }),
        ToolId::WriteFile => serde_json::json!({
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": { "type": "string" },
                "content": { "type": "string" },
                "append": { "type": "boolean", "default": false }
            }
        }),
        ToolId::ExecInContainer => serde_json::json!({
            "type": "object",
            "required": ["name", "command"],
            "properties": {
                "runtime": { "type": "string", "enum": ["docker", "lxc"], "default": "docker" },
                "name": { "type": "string" },
                "command": { "type": "string", "description": "Shell command, run via sh -c inside the container" },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600 }
            }
        }),
        ToolId::ExecOnNode => serde_json::json!({
            "type": "object",
            "required": ["node_id", "command"],
            "properties": {
                "node_id": { "type": "string" },
                "command": { "type": "string" },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600 }
            }
        }),
        ToolId::DeleteFile => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": { "path": { "type": "string" } }
        }),
        ToolId::WolfstackApi => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "default": "GET"
                },
                "path": { "type": "string", "description": "Path starting with /api/... or /cluster-home, etc." },
                "body": { "description": "Optional JSON body for POST/PUT/PATCH" }
            }
        }),
    }
}
