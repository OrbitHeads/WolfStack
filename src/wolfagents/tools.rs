// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Agent tool registry — the set of WolfStack operations an agent is
//! allowed to invoke during a chat turn.
//!
//! Two layers of safety:
//!
//! 1. **Fixed catalogue**. Each tool is a named variant in `ToolId`.
//!    An agent's `allowed_tools` stores these names as strings; an
//!    unknown name is rejected before we even look at arguments. This
//!    means the tool surface is finite and auditable — no free-form
//!    shell escape hatch.
//!
//! 2. **Per-agent allowlist**. `validate_for_agent(agent, tool_id)`
//!    returns Ok only when the tool name is present in the agent's
//!    allowed list. The UI drives this — operators tick the specific
//!    tools an agent can use. Default on new agents is empty, so a
//!    freshly-created agent can chat but can't act until tools are
//!    deliberately granted.
//!
//! Every successful invocation appends a JSONL entry to
//! `/etc/wolfstack/agents/<id>/audit.jsonl` so operators can scroll
//! back and see exactly what the agent did and when.

// The tool registry is public infrastructure that the API surface +
// future LLM tool-use loops call into. Some items read as unused
// during the current build because the agent loop doesn't yet emit
// tool calls — the validator and audit helpers are wired in but not
// exercised until Phase 6+ adds Claude tool_use integration. Keep the
// machinery intact so Phase 6 can drop in without revisiting this
// file.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Agent;

/// Canonical tool identifiers. String form is what agents pass when
/// they emit a tool-use request, and what operators see as checkboxes
/// in the Edit Agent modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolId {
    /// List every cluster node (id, hostname, status). No args.
    ListNodes,
    /// List containers/VMs cluster-wide with basic state. No args.
    ListContainers,
    /// Get current metrics snapshot for one node (CPU, mem, disk).
    GetMetrics,
    /// Restart a specific container by (runtime, name). Restricted
    /// to runtimes "docker"/"lxc"; VM restart is deliberately separate
    /// (it's destructive enough to deserve its own permission).
    RestartContainer,
    /// Run a named WolfFlow workflow. No args beyond the workflow id.
    RunWorkflow,
    /// Return recent alerts (last 50) from /api/alerts.
    ListAlerts,
    /// Read one line of a VM or container's log tail. Argument-gated
    /// so the agent can explain what happened, not dump raw streams.
    ReadLog,
}

impl ToolId {
    /// Lowercase stable string — what's persisted in
    /// `Agent.allowed_tools` and what the LLM emits.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolId::ListNodes => "list_nodes",
            ToolId::ListContainers => "list_containers",
            ToolId::GetMetrics => "get_metrics",
            ToolId::RestartContainer => "restart_container",
            ToolId::RunWorkflow => "run_workflow",
            ToolId::ListAlerts => "list_alerts",
            ToolId::ReadLog => "read_log",
        }
    }

    /// Human label for the UI checklist.
    pub fn label(self) -> &'static str {
        match self {
            ToolId::ListNodes => "List nodes",
            ToolId::ListContainers => "List containers & VMs",
            ToolId::GetMetrics => "Read metrics (CPU/mem/disk)",
            ToolId::RestartContainer => "Restart container (Docker/LXC)",
            ToolId::RunWorkflow => "Run a WolfFlow workflow",
            ToolId::ListAlerts => "List recent alerts",
            ToolId::ReadLog => "Read container/VM logs",
        }
    }

    /// Short sentence describing what granting this tool implies. The
    /// UI shows this under each checkbox so operators know what they
    /// just enabled.
    pub fn risk_note(self) -> &'static str {
        match self {
            ToolId::ListNodes | ToolId::ListContainers | ToolId::GetMetrics
            | ToolId::ListAlerts | ToolId::ReadLog =>
                "Read-only — the agent can observe but not change cluster state.",
            ToolId::RestartContainer =>
                "The agent can restart containers by name on any node. Can be disruptive.",
            ToolId::RunWorkflow =>
                "The agent can trigger any workflow you have. Inherits whatever permissions that workflow has.",
        }
    }

    pub fn from_str(s: &str) -> Option<ToolId> {
        match s {
            "list_nodes" => Some(ToolId::ListNodes),
            "list_containers" => Some(ToolId::ListContainers),
            "get_metrics" => Some(ToolId::GetMetrics),
            "restart_container" => Some(ToolId::RestartContainer),
            "run_workflow" => Some(ToolId::RunWorkflow),
            "list_alerts" => Some(ToolId::ListAlerts),
            "read_log" => Some(ToolId::ReadLog),
            _ => None,
        }
    }

    /// Every tool known to the runtime. Driven by `ALL` so the UI,
    /// validator, and invoker stay in lockstep — add one variant here
    /// and it shows up everywhere.
    pub const ALL: &'static [ToolId] = &[
        ToolId::ListNodes,
        ToolId::ListContainers,
        ToolId::GetMetrics,
        ToolId::RestartContainer,
        ToolId::RunWorkflow,
        ToolId::ListAlerts,
        ToolId::ReadLog,
    ];
}

/// Serialised view of one tool, used by the API to feed the frontend's
/// "allowed tools" checklist.
#[derive(Debug, Serialize)]
pub struct ToolDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub risk_note: &'static str,
}

/// List every tool in the registry — used by `GET /api/agents/tools`
/// so the UI can render the Edit Agent checklist without hardcoding.
pub fn catalogue() -> Vec<ToolDescriptor> {
    ToolId::ALL.iter().map(|t| ToolDescriptor {
        id: t.as_str(),
        label: t.label(),
        risk_note: t.risk_note(),
    }).collect()
}

/// Single audit-log entry — persisted JSONL at
/// `/etc/wolfstack/agents/<id>/audit.jsonl`. Append-only, never
/// rotated by us (let the operator decide via log rotation tooling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: u64,
    pub agent_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
    pub outcome: String,            // "allowed" | "denied"
    #[serde(default)]
    pub reason: Option<String>,     // filled on "denied"
}

/// Authorise an agent to invoke a specific tool. Returns Ok on yes,
/// Err with a human-readable reason on no. Audit entry written in
/// BOTH cases so operators can see denied attempts — an agent
/// repeatedly asking for a tool it doesn't have is a useful signal.
pub fn validate_for_agent(
    agent: &Agent,
    tool: ToolId,
    arguments: &serde_json::Value,
) -> Result<(), String> {
    let tool_name = tool.as_str();
    if !agent.allowed_tools.iter().any(|t| t == tool_name) {
        let reason = format!(
            "tool '{}' is not in the agent's allowed_tools list",
            tool_name);
        append_audit(&agent.id, &AuditEntry {
            ts: unix_seconds(),
            agent_id: agent.id.clone(),
            tool: tool_name.to_string(),
            arguments: arguments.clone(),
            outcome: "denied".to_string(),
            reason: Some(reason.clone()),
        });
        return Err(reason);
    }
    Ok(())
}

/// Record that a tool call was run (or not). Call this AFTER
/// `validate_for_agent` passes and the tool has been dispatched, with
/// the outcome string summarising what happened. Separate from the
/// validator so the audit log captures the full before/after picture.
pub fn record_invocation(
    agent_id: &str,
    tool: ToolId,
    arguments: &serde_json::Value,
    outcome: &str,
) {
    append_audit(agent_id, &AuditEntry {
        ts: unix_seconds(),
        agent_id: agent_id.to_string(),
        tool: tool.as_str().to_string(),
        arguments: arguments.clone(),
        outcome: outcome.to_string(),
        reason: None,
    });
}

fn audit_path(agent_id: &str) -> PathBuf {
    PathBuf::from("/etc/wolfstack/agents").join(agent_id).join("audit.jsonl")
}

fn append_audit(agent_id: &str, entry: &AuditEntry) {
    let path = audit_path(agent_id);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        // 0o700 the agent dir — audit log can reveal operational
        // detail (what actions the agent took, when, which arguments)
        // that shouldn't leak to other local users.
        tighten_dir_perms_unix(parent, 0o700);
    }
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
        tracing::warn!("wolfagents: cannot open audit log at {}", path.display());
        return;
    };
    match serde_json::to_string(entry) {
        Ok(line) => { let _ = writeln!(f, "{}", line); }
        Err(e) => tracing::warn!("wolfagents: failed to serialize audit entry: {}", e),
    }
    // 0o600 the log file — idempotent so rotation tools can't leave
    // it world-readable between rotations.
    tighten_file_perms_unix(&path, 0o600);
}

#[cfg(unix)]
fn tighten_dir_perms_unix(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_dir_perms_unix(_path: &std::path::Path, _mode: u32) {}

#[cfg(unix)]
fn tighten_file_perms_unix(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn tighten_file_perms_unix(_path: &std::path::Path, _mode: u32) {}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the last N audit entries for an agent (newest last). Used by
/// the UI's "audit" tab in the Edit Agent modal so operators can see
/// what the agent has been up to.
pub fn tail_audit(agent_id: &str, limit: usize) -> Vec<AuditEntry> {
    let path = audit_path(agent_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(limit);
    lines[start..].iter()
        .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
        .collect()
}
