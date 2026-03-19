// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfFlow — Workflow Automation Engine for WolfStack
//!
//! Provides server management workflow automation:
//! - Define multi-step workflows (update packages, restart services, prune Docker, etc.)
//! - Target local, all nodes, specific cluster, or named nodes
//! - Cron-based scheduling with a minimal built-in matcher (no external crate)
//! - Sequential step execution with configurable failure policies
//! - Remote execution via inter-node API calls

use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use chrono::Utc;
use tracing::{info, warn, error};

use crate::agent::ClusterState;

// ─── Constants ───

const WOLFFLOW_DIR: &str = "/etc/wolfstack/wolfflow";
const WORKFLOWS_FILE: &str = "/etc/wolfstack/wolfflow/workflows.json";
const RUNS_FILE: &str = "/etc/wolfstack/wolfflow/runs.json";

/// Maximum number of runs to keep in history
const MAX_RUNS: usize = 500;

// ─── Default helpers ───

fn default_channel() -> String { "master".to_string() }
fn default_timeout() -> u64 { 300 }
fn default_true() -> bool { true }

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

/// An action to perform in a workflow step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionType {
    /// Run the system package manager update + upgrade
    UpdatePackages,
    /// Pull and run the WolfStack installer for a given channel
    UpdateWolfstack {
        #[serde(default = "default_channel")]
        channel: String,
    },
    /// Restart a systemd service by name
    RestartService {
        service_name: String,
    },
    /// Run an arbitrary shell command with a timeout
    RunCommand {
        command: String,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    /// Vacuum systemd journal logs
    CleanLogs {
        #[serde(default)]
        max_size_mb: Option<u32>,
    },
    /// Check disk space on specified mount point (defaults to all)
    CheckDiskSpace {
        #[serde(default)]
        warn_threshold_pct: Option<u32>,
        /// Mount point to check e.g. "/" or "/var" or "all" (default: all)
        #[serde(default)]
        mount_point: Option<String>,
    },
    /// Restart a Docker or LXC container
    RestartContainer {
        runtime: String,
        name: String,
    },
    /// Prune all unused Docker resources
    DockerPrune,
}

/// What to do when a step fails
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Continue to the next step
    Continue,
    /// Abort the entire workflow
    Abort,
    /// Log an alert and continue
    Alert,
}

impl Default for OnFailure {
    fn default() -> Self { OnFailure::Abort }
}

/// Target scope for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Target {
    /// Execute only on the local node
    Local,
    /// Execute on all online nodes in the cluster
    AllNodes,
    /// Execute on all nodes in a named cluster
    Cluster {
        cluster_name: String,
    },
    /// Execute on specific nodes by ID
    Nodes {
        node_ids: Vec<String>,
    },
    /// Execute on specific containers/VMs/LXCs
    /// Each entry is "node_id:runtime:name" e.g. "node-abc:docker:nginx"
    Containers {
        #[serde(default)]
        targets: Vec<ContainerTarget>,
    },
}

/// A specific container/VM/LXC target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerTarget {
    pub node_id: String,
    pub runtime: String, // "docker", "lxc", "vm"
    pub name: String,
}

/// A single step within a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub action: ActionType,
    #[serde(default)]
    pub on_failure: OnFailure,
    #[serde(default)]
    pub target_override: Option<Target>,
}

/// A complete workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub cluster: String,
    pub steps: Vec<WorkflowStep>,
    pub target: Target,
    /// Optional cron expression (5-field: min hour dom month dow)
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub last_run: Option<String>,
    /// Email address to send results to (optional — uses SMTP settings from alerting config)
    #[serde(default)]
    pub email_results: Option<String>,
}

/// Status of a workflow run or individual step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    PartialFailure,
}

/// Result of executing a single step on a single node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_name: String,
    pub node_id: String,
    pub node_hostname: String,
    pub status: RunStatus,
    pub output: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
}

/// A complete workflow execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub status: RunStatus,
    pub trigger: String,
    pub steps: Vec<StepResult>,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub duration_ms: u64,
    /// Email delivery status (shown in task log)
    #[serde(default)]
    pub email_status: Option<String>,
}

// ═══════════════════════════════════════════════
// ─── State Management ───
// ═══════════════════════════════════════════════

pub struct WolfFlowState {
    workflows: RwLock<Vec<Workflow>>,
    runs: RwLock<Vec<WorkflowRun>>,
}

impl WolfFlowState {
    pub fn new() -> Self {
        let state = Self {
            workflows: RwLock::new(Vec::new()),
            runs: RwLock::new(Vec::new()),
        };
        state.load_workflows();
        state.load_runs();
        state
    }

    // ─── Persistence ───

    fn load_workflows(&self) {
        if let Ok(data) = std::fs::read_to_string(WORKFLOWS_FILE) {
            if let Ok(wfs) = serde_json::from_str::<Vec<Workflow>>(&data) {
                let mut workflows = self.workflows.write().unwrap();
                *workflows = wfs;
            }
        }
    }

    fn save_workflows(&self) {
        let wfs = self.workflows.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*wfs) {
            let _ = std::fs::create_dir_all(WOLFFLOW_DIR);
            if let Err(e) = std::fs::write(WORKFLOWS_FILE, json) {
                warn!("WolfFlow: failed to save workflows: {}", e);
            }
        }
    }

    fn load_runs(&self) {
        if let Ok(data) = std::fs::read_to_string(RUNS_FILE) {
            if let Ok(runs) = serde_json::from_str::<Vec<WorkflowRun>>(&data) {
                let mut r = self.runs.write().unwrap();
                *r = runs;
            }
        }
    }

    fn save_runs(&self) {
        let runs = self.runs.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*runs) {
            let _ = std::fs::create_dir_all(WOLFFLOW_DIR);
            if let Err(e) = std::fs::write(RUNS_FILE, json) {
                warn!("WolfFlow: failed to save runs: {}", e);
            }
        }
    }

    // ─── Workflow CRUD ───

    pub fn list_workflows(&self, cluster: Option<&str>) -> Vec<Workflow> {
        let wfs = self.workflows.read().unwrap();
        match cluster {
            Some(c) => wfs.iter().filter(|w| w.cluster == c).cloned().collect(),
            None => wfs.clone(),
        }
    }

    pub fn get_workflow(&self, id: &str) -> Option<Workflow> {
        let wfs = self.workflows.read().unwrap();
        wfs.iter().find(|w| w.id == id).cloned()
    }

    pub fn create_workflow(&self, workflow: Workflow) -> Workflow {
        let mut wfs = self.workflows.write().unwrap();
        wfs.push(workflow.clone());
        drop(wfs);
        self.save_workflows();
        workflow
    }

    pub fn update_workflow(&self, id: &str, mut updated: Workflow) -> Option<Workflow> {
        let mut wfs = self.workflows.write().unwrap();
        if let Some(existing) = wfs.iter_mut().find(|w| w.id == id) {
            updated.id = id.to_string();
            updated.created_at = existing.created_at.clone();
            updated.updated_at = Utc::now().to_rfc3339();
            *existing = updated.clone();
            drop(wfs);
            self.save_workflows();
            Some(updated)
        } else {
            None
        }
    }

    pub fn delete_workflow(&self, id: &str) -> Option<Workflow> {
        let mut wfs = self.workflows.write().unwrap();
        let idx = wfs.iter().position(|w| w.id == id);
        let removed = idx.map(|i| wfs.remove(i));
        drop(wfs);
        if removed.is_some() {
            self.save_workflows();
        }
        removed
    }

    /// Mark a workflow's last_run timestamp
    pub fn mark_last_run(&self, id: &str) {
        let mut wfs = self.workflows.write().unwrap();
        if let Some(wf) = wfs.iter_mut().find(|w| w.id == id) {
            wf.last_run = Some(Utc::now().to_rfc3339());
        }
        drop(wfs);
        self.save_workflows();
    }

    // ─── Run management ───

    pub fn list_runs(&self, workflow_id: Option<&str>) -> Vec<WorkflowRun> {
        let runs = self.runs.read().unwrap();
        match workflow_id {
            Some(wid) => runs.iter().filter(|r| r.workflow_id == wid).cloned().collect(),
            None => runs.clone(),
        }
    }

    pub fn add_run(&self, run: WorkflowRun) {
        let mut runs = self.runs.write().unwrap();
        runs.push(run);
        // Trim to keep only the most recent runs
        if runs.len() > MAX_RUNS {
            let drain = runs.len() - MAX_RUNS;
            runs.drain(..drain);
        }
        drop(runs);
        self.save_runs();
    }

    pub fn update_run(&self, run_id: &str, updated: WorkflowRun) {
        let mut runs = self.runs.write().unwrap();
        if let Some(existing) = runs.iter_mut().find(|r| r.id == run_id) {
            *existing = updated;
        }
        drop(runs);
        self.save_runs();
    }

    /// Get workflows that are due to run based on their cron schedule.
    /// Compares the cron expression against the current UTC time.
    pub fn get_due_workflows(&self) -> Vec<Workflow> {
        let now = Utc::now().naive_utc();
        let now_minute = now.format("%Y-%m-%d %H:%M").to_string();
        let wfs = self.workflows.read().unwrap();
        let runs = self.runs.read().unwrap();
        wfs.iter()
            .filter(|w| {
                if !w.enabled || w.schedule.is_none() { return false; }
                if !cron_matches(w.schedule.as_deref().unwrap(), &now) { return false; }
                // Skip if already ran in this same minute (prevent duplicate execution)
                let already_ran = runs.iter().any(|r| {
                    r.workflow_id == w.id
                        && r.trigger == "scheduled"
                        && r.started_at.starts_with(&now_minute)
                });
                !already_ran
            })
            .cloned()
            .collect()
    }

    /// Rename all cluster references from old_name to new_name.
    #[allow(dead_code)]
    pub fn rename_cluster(&self, old_name: &str, new_name: &str) -> usize {
        let mut wfs = self.workflows.write().unwrap();
        let mut count = 0;
        for wf in wfs.iter_mut() {
            if wf.cluster == old_name {
                wf.cluster = new_name.to_string();
                count += 1;
            }
        }
        drop(wfs);
        if count > 0 {
            self.save_workflows();
        }
        count
    }
}

// ═══════════════════════════════════════════════
// ─── Cron Matcher ───
// ═══════════════════════════════════════════════

/// Minimal 5-field cron expression matcher.
///
/// Format: `minute hour day-of-month month day-of-week`
///
/// Supports:
/// - `*` (any value)
/// - Single values: `5`
/// - Comma-separated: `1,15,30`
/// - Ranges: `1-5`
/// - Steps: `*/15`, `1-30/5`
pub fn cron_matches(expr: &str, now: &chrono::NaiveDateTime) -> bool {
    use chrono::{Datelike, Timelike};

    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }

    let minute = now.minute();
    let hour = now.hour();
    let dom = now.day();
    let month = now.month();
    // chrono: Monday=0 .. Sunday=6 — cron uses Sunday=0, Monday=1 .. Saturday=6
    let dow_chrono = now.weekday().num_days_from_sunday(); // Sunday=0

    field_matches(fields[0], minute, 0, 59)
        && field_matches(fields[1], hour, 0, 23)
        && field_matches(fields[2], dom, 1, 31)
        && field_matches(fields[3], month, 1, 12)
        && field_matches(fields[4], dow_chrono, 0, 7) // 0 and 7 both mean Sunday
}

/// Check if a single cron field matches a given value.
/// Handles `*`, single values, comma-separated lists, ranges, and step values.
fn field_matches(field: &str, value: u32, min: u32, max: u32) -> bool {
    // Comma-separated entries: "1,15,30"
    for part in field.split(',') {
        if single_field_matches(part.trim(), value, min, max) {
            return true;
        }
    }
    false
}

/// Match a single cron field segment (no commas).
fn single_field_matches(part: &str, value: u32, min: u32, max: u32) -> bool {
    // Step: "*/15" or "1-30/5"
    if let Some((range_part, step_str)) = part.split_once('/') {
        let step: u32 = match step_str.parse() {
            Ok(s) if s > 0 => s,
            _ => return false,
        };
        let (range_min, range_max) = if range_part == "*" {
            (min, max)
        } else if let Some((lo, hi)) = range_part.split_once('-') {
            match (lo.parse::<u32>(), hi.parse::<u32>()) {
                (Ok(lo), Ok(hi)) => (lo, hi),
                _ => return false,
            }
        } else {
            return false;
        };
        // Value must be in range and on a step boundary from range_min
        if value < range_min || value > range_max {
            return false;
        }
        return (value - range_min) % step == 0;
    }

    // Wildcard
    if part == "*" {
        return true;
    }

    // Range: "1-5"
    if let Some((lo_str, hi_str)) = part.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo_str.parse::<u32>(), hi_str.parse::<u32>()) {
            return value >= lo && value <= hi;
        }
        return false;
    }

    // Single value
    if let Ok(v) = part.parse::<u32>() {
        // For day-of-week, treat 7 as Sunday (same as 0)
        if min == 0 && max == 7 {
            let normalised_value = if value == 7 { 0 } else { value };
            let normalised_v = if v == 7 { 0 } else { v };
            return normalised_value == normalised_v;
        }
        return value == v;
    }

    false
}

// ═══════════════════════════════════════════════
// ─── Action Execution (Local) ───
// ═══════════════════════════════════════════════

/// Detect the system package manager
fn detect_package_manager() -> &'static str {
    if std::path::Path::new("/usr/bin/apt").exists()
        || std::path::Path::new("/usr/bin/apt-get").exists()
    {
        "apt"
    } else if std::path::Path::new("/usr/bin/dnf").exists() {
        "dnf"
    } else if std::path::Path::new("/usr/bin/pacman").exists() {
        "pacman"
    } else if std::path::Path::new("/usr/bin/zypper").exists() {
        "zypper"
    } else {
        "apt" // fallback
    }
}

/// Execute a single action on the local machine.
/// Returns Ok(output) on success, Err(error_message) on failure.
pub async fn execute_action_local(action: &ActionType) -> Result<String, String> {
    match action {
        ActionType::UpdatePackages => {
            let pm = detect_package_manager();
            let (cmd, args): (&str, Vec<&str>) = match pm {
                "apt" => ("bash", vec!["-c", "apt-get update -y && apt-get upgrade -y"]),
                "dnf" => ("bash", vec!["-c", "dnf upgrade -y"]),
                "pacman" => ("bash", vec!["-c", "pacman -Syu --noconfirm"]),
                "zypper" => ("bash", vec!["-c", "zypper refresh && zypper update -y"]),
                _ => ("bash", vec!["-c", "apt-get update -y && apt-get upgrade -y"]),
            };
            run_command(cmd, &args, 600).await
        }

        ActionType::UpdateWolfstack { channel } => {
            let script = format!(
                "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/{}/setup.sh | bash",
                channel
            );
            run_command("bash", &["-c", &script], 600).await
        }

        ActionType::RestartService { service_name } => {
            // Validate service name to prevent injection
            if service_name.contains(';')
                || service_name.contains('&')
                || service_name.contains('|')
                || service_name.contains('`')
                || service_name.contains('$')
            {
                return Err("Invalid service name".to_string());
            }
            run_command("systemctl", &["restart", service_name], 60).await
        }

        ActionType::RunCommand { command, timeout_secs } => {
            run_command("bash", &["-c", command], *timeout_secs).await
        }

        ActionType::CleanLogs { max_size_mb } => {
            let size = max_size_mb.unwrap_or(500);
            let arg = format!("--vacuum-size={}M", size);
            run_command("journalctl", &[&arg], 120).await
        }

        ActionType::CheckDiskSpace { warn_threshold_pct, mount_point } => {
            let threshold = warn_threshold_pct.unwrap_or(90);
            let mp = mount_point.as_deref().unwrap_or("all");

            if mp == "all" || mp.is_empty() {
                // Run df -h excluding network filesystems (NFS/CIFS can hang)
                let output = run_command("df", &["-h", "-x", "nfs", "-x", "nfs4", "-x", "cifs", "-x", "sshfs", "-x", "fuse.sshfs"], 10).await?;
                // Quick scan for any partition over threshold
                let mut over = Vec::new();
                for line in output.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 6 {
                        if let Ok(pct) = fields[4].trim_end_matches('%').parse::<u32>() {
                            if pct > threshold {
                                over.push(format!("{} at {}%", fields[5], pct));
                            }
                        }
                    }
                }
                if over.is_empty() {
                    Ok(output)
                } else {
                    Err(format!("Over {}%: {}\n\n{}", threshold, over.join(", "), output))
                }
            } else {
                // Check specific mount point
                let output = run_command("df", &["-h", mp], 10).await?;
                let lines: Vec<&str> = output.lines().collect();
                if lines.len() < 2 {
                    return Err(format!("Mount point '{}' not found", mp));
                }
                let fields: Vec<&str> = lines[1].split_whitespace().collect();
                if fields.len() < 5 {
                    return Err("Unexpected df output format".to_string());
                }
                let pct_str = fields[4].trim_end_matches('%');
                let pct: u32 = pct_str.parse().map_err(|_| "Could not parse disk usage".to_string())?;
                if pct > threshold {
                    Err(format!("{}: {}% exceeds threshold {}%\n\n{}", mp, pct, threshold, output))
                } else {
                    Ok(output)
                }
            }
        }

        ActionType::RestartContainer { runtime, name } => {
            // Validate name
            if name.contains(';') || name.contains('&') || name.contains('|') || name.contains('`') {
                return Err("Invalid container name".to_string());
            }
            match runtime.to_lowercase().as_str() {
                "docker" => {
                    run_command("docker", &["restart", name], 120).await
                }
                "lxc" => {
                    // Stop then start for LXC
                    let stop_result = run_command("lxc-stop", &["-n", name], 60).await;
                    if let Err(e) = &stop_result {
                        // If stop fails because it's already stopped, continue
                        if !e.contains("not running") {
                            warn!("WolfFlow: lxc-stop failed for {}: {}", name, e);
                        }
                    }
                    run_command("lxc-start", &["-n", name], 60).await
                }
                _ => Err(format!("Unknown runtime: {}", runtime)),
            }
        }

        ActionType::DockerPrune => {
            run_command("docker", &["system", "prune", "-af"], 300).await
        }
    }
}

/// Run a command with a timeout, capturing stdout+stderr
async fn run_command(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    use tokio::process::Command;

    // Use timeout wrapper — kill_on_drop ensures process is cleaned up
    let child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn '{}': {}", cmd, e))?;

    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        child.wait_with_output(),
    ).await {
        Ok(r) => r,
        Err(_) => return Err(format!("Command '{}' timed out after {}s", cmd, timeout_secs)),
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout
            } else if stdout.is_empty() {
                stderr
            } else {
                format!("{}\n{}", stdout, stderr)
            };

            if output.status.success() {
                Ok(combined)
            } else {
                Err(format!(
                    "Command exited with code {}: {}",
                    output.status.code().unwrap_or(-1),
                    combined.chars().take(2000).collect::<String>()
                ))
            }
        }
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

// ═══════════════════════════════════════════════
// ─── Workflow Execution ───
// ═══════════════════════════════════════════════

/// Resolve target nodes for execution.
/// Returns Vec<(node_id, node_hostname, node_address, node_port, is_self)>.
fn resolve_targets(
    cluster: &ClusterState,
    target: &Target,
) -> Vec<(String, String, String, u16, bool)> {
    let nodes = cluster.get_all_nodes();

    match target {
        Target::Local => {
            // Only the self node
            nodes.iter()
                .filter(|n| n.is_self)
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, true))
                .collect()
        }
        Target::AllNodes => {
            nodes.iter()
                .filter(|n| n.online && n.node_type == "wolfstack")
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Cluster { cluster_name } => {
            nodes.iter()
                .filter(|n| {
                    n.online
                        && n.node_type == "wolfstack"
                        && n.cluster_name.as_deref().unwrap_or("WolfStack") == cluster_name.as_str()
                })
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Nodes { node_ids } => {
            nodes.iter()
                .filter(|n| n.online && node_ids.contains(&n.id))
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Containers { targets } => {
            // For container targets, resolve to the nodes that host them
            // The container-specific execution is handled in execute_workflow
            let mut result = Vec::new();
            let mut seen_nodes = std::collections::HashSet::new();
            for ct in targets {
                if seen_nodes.contains(&ct.node_id) { continue; }
                if let Some(n) = nodes.iter().find(|n| n.id == ct.node_id && n.online) {
                    result.push((n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self));
                    seen_nodes.insert(ct.node_id.clone());
                }
            }
            result
        }
    }
}

/// Execute a workflow across target nodes.
///
/// Steps are executed sequentially. For each step, all target nodes are
/// executed (in parallel per node), then results are collected before
/// moving to the next step.
pub async fn execute_workflow(
    state: &Arc<WolfFlowState>,
    cluster: &Arc<ClusterState>,
    cluster_secret: &str,
    workflow: &Workflow,
    trigger: &str,
    ai_config: Option<crate::ai::AiConfig>,
) -> WorkflowRun {
    let run_id = format!("run-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let started_at = Utc::now().to_rfc3339();

    let mut run = WorkflowRun {
        id: run_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        status: RunStatus::Running,
        trigger: trigger.to_string(),
        steps: Vec::new(),
        started_at: started_at.clone(),
        finished_at: None,
        duration_ms: 0,
        email_status: None,
    };

    // Persist initial run state
    state.add_run(run.clone());

    info!("WolfFlow: starting workflow '{}' ({}), trigger: {}", workflow.name, workflow.id, trigger);

    let run_start = std::time::Instant::now();
    let mut had_failure = false;
    let mut aborted = false;

    // Build HTTP client for remote calls
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .ok();

    for step in &workflow.steps {
        if aborted {
            break;
        }

        // Determine target: step override or workflow default
        let target = step.target_override.as_ref().unwrap_or(&workflow.target);
        let targets = resolve_targets(cluster, target);

        if targets.is_empty() {
            warn!("WolfFlow: step '{}' has no target nodes — skipping", step.name);
            run.steps.push(StepResult {
                step_name: step.name.clone(),
                node_id: "none".to_string(),
                node_hostname: "none".to_string(),
                status: RunStatus::Failed,
                output: "No target nodes found".to_string(),
                started_at: Utc::now().to_rfc3339(),
                finished_at: Utc::now().to_rfc3339(),
                duration_ms: 0,
            });
            had_failure = true;
            match step.on_failure {
                OnFailure::Abort => {
                    aborted = true;
                    break;
                }
                OnFailure::Alert => {
                    error!("WolfFlow: ALERT — step '{}' failed: no target nodes", step.name);
                }
                OnFailure::Continue => {}
            }
            continue;
        }

        // Execute on each target node
        let mut step_futures = Vec::new();
        for (node_id, node_hostname, node_address, node_port, is_self) in &targets {
            let action = step.action.clone();
            let step_name = step.name.clone();
            let node_id = node_id.clone();
            let node_hostname = node_hostname.clone();
            let node_address = node_address.clone();
            let node_port = *node_port;
            let is_self = *is_self;
            let secret = cluster_secret.to_string();
            let client = http_client.clone();

            step_futures.push(tokio::spawn(async move {
                let step_start = std::time::Instant::now();
                let started = Utc::now().to_rfc3339();

                let result = if is_self {
                    // Execute locally
                    execute_action_local(&action).await
                } else {
                    // Execute remotely via API
                    execute_action_remote(
                        &client,
                        &node_address,
                        node_port,
                        &secret,
                        &action,
                    )
                    .await
                };

                let elapsed = step_start.elapsed().as_millis() as u64;
                let finished = Utc::now().to_rfc3339();

                match result {
                    Ok(output) => StepResult {
                        step_name,
                        node_id,
                        node_hostname,
                        status: RunStatus::Completed,
                        output: output.chars().take(5000).collect(),
                        started_at: started,
                        finished_at: finished,
                        duration_ms: elapsed,
                    },
                    Err(err) => StepResult {
                        step_name,
                        node_id,
                        node_hostname,
                        status: RunStatus::Failed,
                        output: err.chars().take(5000).collect(),
                        started_at: started,
                        finished_at: finished,
                        duration_ms: elapsed,
                    },
                }
            }));
        }

        // Collect results from all nodes for this step
        let mut step_had_failure = false;
        for future in step_futures {
            match future.await {
                Ok(result) => {
                    if result.status == RunStatus::Failed {
                        step_had_failure = true;
                        had_failure = true;
                    }
                    run.steps.push(result);
                }
                Err(e) => {
                    // Task panicked or was cancelled
                    step_had_failure = true;
                    had_failure = true;
                    run.steps.push(StepResult {
                        step_name: step.name.clone(),
                        node_id: "unknown".to_string(),
                        node_hostname: "unknown".to_string(),
                        status: RunStatus::Failed,
                        output: format!("Task error: {}", e),
                        started_at: Utc::now().to_rfc3339(),
                        finished_at: Utc::now().to_rfc3339(),
                        duration_ms: 0,
                    });
                }
            }
        }

        // Handle failure policy
        if step_had_failure {
            match step.on_failure {
                OnFailure::Abort => {
                    error!("WolfFlow: step '{}' failed — aborting workflow '{}'", step.name, workflow.name);
                    aborted = true;
                }
                OnFailure::Alert => {
                    error!("WolfFlow: ALERT — step '{}' failed in workflow '{}'", step.name, workflow.name);
                }
                OnFailure::Continue => {
                    warn!("WolfFlow: step '{}' failed — continuing workflow '{}'", step.name, workflow.name);
                }
            }
        }

        // Update run in-progress
        run.duration_ms = run_start.elapsed().as_millis() as u64;
        state.update_run(&run_id, run.clone());
    }

    // Determine final status
    run.status = if aborted {
        RunStatus::Failed
    } else if had_failure {
        RunStatus::PartialFailure
    } else {
        RunStatus::Completed
    };
    run.finished_at = Some(Utc::now().to_rfc3339());
    run.duration_ms = run_start.elapsed().as_millis() as u64;

    // Persist final run state
    state.update_run(&run_id, run.clone());
    state.mark_last_run(&workflow.id);

    info!(
        "WolfFlow: workflow '{}' finished — status: {:?}, duration: {}ms, steps: {}",
        workflow.name, run.status, run.duration_ms, run.steps.len()
    );

    // Send email with results if configured
    if let Some(ref email) = workflow.email_results {
        if !email.is_empty() {
            let subject = format!("[WolfFlow] {} — {:?}", workflow.name, run.status);
            let mut body = format!(
                "Workflow: {}\nTrigger: {}\nStatus: {:?}\nDuration: {}ms\nSteps: {}\n\n",
                workflow.name, trigger, run.status, run.duration_ms, run.steps.len()
            );
            for step in &run.steps {
                body.push_str(&format!(
                    "Step: {} | Node: {} | Status: {:?} | {}ms\n",
                    step.step_name, step.node_hostname, step.status, step.duration_ms
                ));
                if !step.output.is_empty() {
                    let output_preview = if step.output.len() > 500 {
                        format!("{}...", &step.output[..500])
                    } else {
                        step.output.clone()
                    };
                    body.push_str(&format!("  Output: {}\n", output_preview));
                }
                body.push('\n');
            }
            // Send email — EXACTLY the same way the daily report does it
            let mut config = ai_config.clone().unwrap_or_else(crate::ai::AiConfig::load);
            // Override recipient if workflow specifies one
            if !email.is_empty() {
                config.email_to = email.clone();
            }
            if config.smtp_host.is_empty() || config.email_to.is_empty() {
                run.email_status = Some("Failed: SMTP not configured in Settings → AI Agent".to_string());
            } else {
                let html_body = format!(
                    "<html><body style='font-family:sans-serif;'>\
                    <h2>[WolfFlow] {} &mdash; {:?}</h2>\
                    <p>Trigger: {} | Duration: {}ms | Steps: {}</p>\
                    <table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-size:13px;'>\
                    <tr><th>Step</th><th>Node</th><th>Status</th><th>Duration</th><th>Output</th></tr>{}</table>\
                    </body></html>",
                    workflow.name, run.status, trigger, run.duration_ms, run.steps.len(),
                    run.steps.iter().map(|s| format!(
                        "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}ms</td><td><pre>{}</pre></td></tr>",
                        s.step_name, s.node_hostname, s.status, s.duration_ms,
                        if s.output.len() > 500 { format!("{}...", &s.output[..500]) } else { s.output.clone() }
                    )).collect::<Vec<_>>().join("")
                );
                // Call EXACTLY like the daily report does — no spawn_blocking, just call it
                match crate::ai::send_html_email(&config, &subject, &html_body) {
                    Ok(_) => run.email_status = Some(format!("Sent to {}", config.email_to)),
                    Err(e) => run.email_status = Some(format!("Failed: {}", e)),
                }
            }
            state.update_run(&run_id, run.clone());
        }
    }

    run
}

/// Execute an action on a remote node via the WolfFlow exec API endpoint.
async fn execute_action_remote(
    client: &Option<reqwest::Client>,
    address: &str,
    port: u16,
    secret: &str,
    action: &ActionType,
) -> Result<String, String> {
    let client = client.as_ref().ok_or_else(|| "HTTP client not available".to_string())?;

    let urls = crate::api::build_node_urls(address, port, "/api/wolfflow/exec");

    let body = serde_json::to_value(action).map_err(|e| format!("Serialization error: {}", e))?;

    for url in &urls {
        match client
            .post(url)
            .header("X-WolfStack-Secret", secret)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let result = resp
                        .json::<serde_json::Value>()
                        .await
                        .map_err(|e| format!("Failed to parse response: {}", e))?;

                    if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
                        return Err(error.to_string());
                    }
                    let output = result
                        .get("output")
                        .and_then(|o| o.as_str())
                        .unwrap_or("OK")
                        .to_string();
                    return Ok(output);
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(format!("Remote node returned {}: {}", status, body));
                }
            }
            Err(_) => continue, // Try next URL variant
        }
    }

    Err(format!("Could not reach node at {}:{}", address, port))
}

// ═══════════════════════════════════════════════
// ─── Toolbox ───
// ═══════════════════════════════════════════════

/// Returns a JSON array describing each action type's form fields
/// for the frontend workflow builder UI.
pub fn toolbox_actions() -> serde_json::Value {
    serde_json::json!([
        {
            "action": "update_packages",
            "label": "Update System Packages",
            "description": "Run the system package manager to update and upgrade all packages",
            "icon": "fa-arrow-up",
            "fields": []
        },
        {
            "action": "update_wolfstack",
            "label": "Update WolfStack",
            "description": "Pull and install the latest WolfStack build from a given channel",
            "icon": "fa-download",
            "fields": [
                { "name": "channel", "label": "Channel", "type": "text", "default": "master", "placeholder": "master" }
            ]
        },
        {
            "action": "restart_service",
            "label": "Restart Systemd Service",
            "description": "Restart a systemd service by name",
            "icon": "fa-rotate",
            "fields": [
                { "name": "service_name", "label": "Service Name", "type": "text", "required": true, "placeholder": "nginx" }
            ]
        },
        {
            "action": "run_command",
            "label": "Run Shell Command",
            "description": "Execute an arbitrary shell command with a timeout",
            "icon": "fa-terminal",
            "fields": [
                { "name": "command", "label": "Command", "type": "textarea", "required": true, "placeholder": "echo hello" },
                { "name": "timeout_secs", "label": "Timeout (seconds)", "type": "number", "default": 300 }
            ]
        },
        {
            "action": "clean_logs",
            "label": "Clean Journal Logs",
            "description": "Vacuum systemd journal logs to a maximum size",
            "icon": "fa-broom",
            "fields": [
                { "name": "max_size_mb", "label": "Max Size (MB)", "type": "number", "default": 500, "placeholder": "500" }
            ]
        },
        {
            "action": "check_disk_space",
            "label": "Check Disk Space",
            "description": "Check disk usage on a specific mount point or all mounts",
            "icon": "fa-hard-drive",
            "fields": [
                { "name": "warn_threshold_pct", "label": "Threshold (%)", "type": "number", "default": 90, "placeholder": "90" },
                { "name": "mount_point", "label": "Mount Point", "type": "text", "placeholder": "/ or /var or all (default: all)" }
            ]
        },
        {
            "action": "restart_container",
            "label": "Restart Container",
            "description": "Restart a Docker or LXC container by name",
            "icon": "fa-cube",
            "fields": [
                { "name": "runtime", "label": "Runtime", "type": "select", "options": ["docker", "lxc"], "required": true },
                { "name": "name", "label": "Container Name", "type": "text", "required": true }
            ]
        },
        {
            "action": "docker_prune",
            "label": "Docker Prune",
            "description": "Remove all unused Docker images, containers, volumes, and networks",
            "icon": "fa-trash-can",
            "fields": []
        }
    ])
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    fn make_dt(year: i32, month: u32, day: u32, hour: u32, min: u32) -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, min, 0)
            .unwrap()
    }

    #[test]
    fn cron_wildcard() {
        let dt = make_dt(2026, 3, 19, 14, 30);
        assert!(cron_matches("* * * * *", &dt));
    }

    #[test]
    fn cron_exact_match() {
        let dt = make_dt(2026, 3, 19, 14, 30);
        assert!(cron_matches("30 14 19 3 *", &dt));
        assert!(!cron_matches("31 14 19 3 *", &dt));
    }

    #[test]
    fn cron_step() {
        let dt = make_dt(2026, 1, 1, 0, 15);
        assert!(cron_matches("*/15 * * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 0, 7);
        assert!(!cron_matches("*/15 * * * *", &dt2));
    }

    #[test]
    fn cron_range() {
        let dt = make_dt(2026, 1, 1, 9, 0);
        assert!(cron_matches("0 9-17 * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 8, 0);
        assert!(!cron_matches("0 9-17 * * *", &dt2));
    }

    #[test]
    fn cron_comma_list() {
        let dt = make_dt(2026, 1, 1, 0, 0);
        assert!(cron_matches("0,15,30,45 * * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 0, 10);
        assert!(!cron_matches("0,15,30,45 * * * *", &dt2));
    }

    #[test]
    fn cron_day_of_week() {
        // 2026-03-19 is a Thursday = 4 in cron (Sunday=0)
        let dt = make_dt(2026, 3, 19, 12, 0);
        assert!(cron_matches("0 12 * * 4", &dt));
        assert!(!cron_matches("0 12 * * 1", &dt));
    }

    #[test]
    fn cron_sunday_7() {
        // 2026-03-22 is a Sunday
        let dt = make_dt(2026, 3, 22, 0, 0);
        assert!(cron_matches("0 0 * * 0", &dt));
        assert!(cron_matches("0 0 * * 7", &dt)); // 7 is also Sunday
    }

    #[test]
    fn cron_invalid_fields() {
        let dt = make_dt(2026, 1, 1, 0, 0);
        assert!(!cron_matches("* * *", &dt)); // Too few fields
        assert!(!cron_matches("* * * * * *", &dt)); // Too many fields
    }

    #[test]
    fn cron_range_with_step() {
        let dt0 = make_dt(2026, 1, 1, 1, 0);
        let dt5 = make_dt(2026, 1, 1, 1, 5);
        let dt3 = make_dt(2026, 1, 1, 1, 3);
        assert!(cron_matches("0-30/5 * * * *", &dt0));
        assert!(cron_matches("0-30/5 * * * *", &dt5));
        assert!(!cron_matches("0-30/5 * * * *", &dt3));
    }

    #[test]
    fn action_serde_round_trip() {
        let action = ActionType::RunCommand {
            command: "echo hello".to_string(),
            timeout_secs: 60,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: ActionType = serde_json::from_str(&json).unwrap();
        match parsed {
            ActionType::RunCommand { command, timeout_secs } => {
                assert_eq!(command, "echo hello");
                assert_eq!(timeout_secs, 60);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn action_serde_defaults() {
        // UpdateWolfstack with no channel should default to "master"
        let json = r#"{"action":"update_wolfstack"}"#;
        let parsed: ActionType = serde_json::from_str(json).unwrap();
        match parsed {
            ActionType::UpdateWolfstack { channel } => {
                assert_eq!(channel, "master");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn on_failure_default_is_abort() {
        let default: OnFailure = Default::default();
        assert_eq!(default, OnFailure::Abort);
    }

    #[test]
    fn target_serde_round_trip() {
        let target = Target::Nodes {
            node_ids: vec!["node-1".to_string(), "node-2".to_string()],
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: Target = serde_json::from_str(&json).unwrap();
        match parsed {
            Target::Nodes { node_ids } => {
                assert_eq!(node_ids.len(), 2);
                assert_eq!(node_ids[0], "node-1");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn toolbox_returns_all_actions() {
        let actions = toolbox_actions();
        let arr = actions.as_array().unwrap();
        assert_eq!(arr.len(), 8);
        // Check that each action has required fields
        for a in arr {
            assert!(a.get("action").is_some());
            assert!(a.get("label").is_some());
            assert!(a.get("description").is_some());
            assert!(a.get("fields").is_some());
        }
    }
}
