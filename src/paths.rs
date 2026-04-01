// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Centralised file location configuration.
//!
//! Every WolfStack path constant goes through this module so users can
//! override defaults via `/etc/wolfstack/paths.json` or the Settings UI.

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

const PATHS_CONFIG_FILE: &str = "/etc/wolfstack/paths.json";

/// All configurable file locations with their defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLocations {
    // ── Core config directory ─────────────────────
    #[serde(default = "default_config_dir")]
    pub config_dir: String,

    // ── Backup ────────────────────────────────────
    #[serde(default = "default_backup_config")]
    pub backup_config: String,
    #[serde(default = "default_backup_staging_dir")]
    pub backup_staging_dir: String,
    #[serde(default = "default_backup_received_dir")]
    pub backup_received_dir: String,

    // ── Storage ───────────────────────────────────
    #[serde(default = "default_storage_config")]
    pub storage_config: String,
    #[serde(default = "default_storage_mount_base")]
    pub storage_mount_base: String,
    #[serde(default = "default_s3_credentials_dir")]
    pub s3_credentials_dir: String,
    #[serde(default = "default_s3_cache_dir")]
    pub s3_cache_dir: String,

    // ── Cluster / Nodes ───────────────────────────
    #[serde(default = "default_nodes_config")]
    pub nodes_config: String,
    #[serde(default = "default_deleted_nodes_config")]
    pub deleted_nodes_config: String,
    #[serde(default = "default_self_cluster_config")]
    pub self_cluster_config: String,
    #[serde(default = "default_node_id_file")]
    pub node_id_file: String,

    // ── Alerting ──────────────────────────────────
    #[serde(default = "default_alerts_config")]
    pub alerts_config: String,

    // ── Status pages ──────────────────────────────
    #[serde(default = "default_statuspage_config")]
    pub statuspage_config: String,
    #[serde(default = "default_statuspage_uptime")]
    pub statuspage_uptime: String,

    // ── AI Agent ──────────────────────────────────
    #[serde(default = "default_ai_config")]
    pub ai_config: String,

    // ── WolfRun ───────────────────────────────────
    #[serde(default = "default_wolfrun_dir")]
    pub wolfrun_dir: String,
    #[serde(default = "default_wolfrun_services")]
    pub wolfrun_services: String,
    #[serde(default = "default_wolfrun_failover_events")]
    pub wolfrun_failover_events: String,

    // ── WolfFlow ──────────────────────────────────
    #[serde(default = "default_wolfflow_dir")]
    pub wolfflow_dir: String,
    #[serde(default = "default_wolfflow_workflows")]
    pub wolfflow_workflows: String,
    #[serde(default = "default_wolfflow_runs")]
    pub wolfflow_runs: String,

    // ── Kubernetes ────────────────────────────────
    #[serde(default = "default_kubernetes_config")]
    pub kubernetes_config: String,

    // ── App Store ─────────────────────────────────
    #[serde(default = "default_appstore_dir")]
    pub appstore_dir: String,
    #[serde(default = "default_appstore_installed")]
    pub appstore_installed: String,
    #[serde(default = "default_appstore_pending_dir")]
    pub appstore_pending_dir: String,

    // ── Ceph ──────────────────────────────────────
    #[serde(default = "default_ceph_config")]
    pub ceph_config: String,

    // ── VMs ───────────────────────────────────────
    #[serde(default = "default_vms_dir")]
    pub vms_dir: String,

    // ── TLS ───────────────────────────────────────
    #[serde(default = "default_tls_cert")]
    pub tls_cert: String,
    #[serde(default = "default_tls_key")]
    pub tls_key: String,

    // ── Auth ──────────────────────────────────────
    #[serde(default = "default_cluster_secret")]
    pub cluster_secret: String,

    // ── Patreon ───────────────────────────────────
    #[serde(default = "default_patreon_config")]
    pub patreon_config: String,

    // ── IP Mappings ───────────────────────────────
    #[serde(default = "default_ip_mappings")]
    pub ip_mappings: String,

    // ── LXC Paths ─────────────────────────────────
    #[serde(default = "default_lxc_paths")]
    pub lxc_paths: String,

    // ── Containers ────────────────────────────────
    #[serde(default = "default_cluster_containers_dir")]
    pub cluster_containers_dir: String,

    // ── Icon Packs ────────────────────────────────
    #[serde(default = "default_icon_packs_dir")]
    pub icon_packs_dir: String,

    // ── PBS ───────────────────────────────────────
    #[serde(default = "default_pbs_config")]
    pub pbs_config: String,

    // ── WolfNote ───────────────────────────────────
    #[serde(default = "default_wolfnote_config")]
    pub wolfnote_config: String,

    // ── Web UI ────────────────────────────────────
    #[serde(default = "default_web_dir")]
    pub web_dir: String,
}

// ── Default value functions ──────────────────────────

fn default_config_dir() -> String { "/etc/wolfstack".into() }

fn default_backup_config() -> String { "/etc/wolfstack/backups.json".into() }
fn default_backup_staging_dir() -> String { "/tmp/wolfstack-backups".into() }
fn default_backup_received_dir() -> String { "/var/lib/wolfstack/backups/received".into() }

fn default_storage_config() -> String { "/etc/wolfstack/storage.json".into() }
fn default_storage_mount_base() -> String { "/mnt/wolfstack".into() }
fn default_s3_credentials_dir() -> String { "/etc/wolfstack/s3".into() }
fn default_s3_cache_dir() -> String { "/var/cache/wolfstack/s3".into() }

fn default_nodes_config() -> String { "/etc/wolfstack/nodes.json".into() }
fn default_deleted_nodes_config() -> String { "/etc/wolfstack/deleted_nodes.json".into() }
fn default_self_cluster_config() -> String { "/etc/wolfstack/self_cluster.json".into() }
fn default_node_id_file() -> String { "/etc/wolfstack/node_id".into() }

fn default_alerts_config() -> String { "/etc/wolfstack/alerts.json".into() }

fn default_statuspage_config() -> String { "/etc/wolfstack/statuspage.json".into() }
fn default_statuspage_uptime() -> String { "/etc/wolfstack/statuspage-uptime.json".into() }

fn default_ai_config() -> String { "/etc/wolfstack/ai-config.json".into() }

fn default_wolfrun_dir() -> String { "/etc/wolfstack/wolfrun".into() }
fn default_wolfrun_services() -> String { "/etc/wolfstack/wolfrun/services.json".into() }
fn default_wolfrun_failover_events() -> String { "/etc/wolfstack/wolfrun/failover-events.json".into() }

fn default_wolfflow_dir() -> String { "/etc/wolfstack/wolfflow".into() }
fn default_wolfflow_workflows() -> String { "/etc/wolfstack/wolfflow/workflows.json".into() }
fn default_wolfflow_runs() -> String { "/etc/wolfstack/wolfflow/runs.json".into() }

fn default_kubernetes_config() -> String { "/etc/wolfstack/kubernetes.json".into() }

fn default_appstore_dir() -> String { "/etc/wolfstack/appstore".into() }
fn default_appstore_installed() -> String { "/etc/wolfstack/appstore/installed.json".into() }
fn default_appstore_pending_dir() -> String { "/etc/wolfstack/appstore/pending".into() }

fn default_ceph_config() -> String { "/etc/wolfstack/ceph.json".into() }

fn default_vms_dir() -> String { "/var/lib/wolfstack/vms".into() }

fn default_tls_cert() -> String { "/etc/wolfstack/cert.pem".into() }
fn default_tls_key() -> String { "/etc/wolfstack/key.pem".into() }

fn default_cluster_secret() -> String { "/etc/wolfstack/custom-cluster-secret".into() }

fn default_patreon_config() -> String { "/etc/wolfstack/patreon.json".into() }

fn default_ip_mappings() -> String { "/etc/wolfstack/ip-mappings.json".into() }

fn default_lxc_paths() -> String { "/etc/wolfstack/lxc-paths.json".into() }

fn default_cluster_containers_dir() -> String { "/etc/wolfstack/cluster-containers".into() }

fn default_icon_packs_dir() -> String { "/etc/wolfstack/icon-packs".into() }

fn default_pbs_config() -> String { "/etc/wolfstack/pbs/config.json".into() }

fn default_wolfnote_config() -> String { "/etc/wolfstack/wolfnote.json".into() }

fn default_web_dir() -> String { "/opt/wolfstack/web".into() }

impl Default for FileLocations {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

// ── Global singleton ─────────────────────────────────

static LOCATIONS: LazyLock<RwLock<FileLocations>> = LazyLock::new(|| {
    let locs = load_from_disk();
    RwLock::new(locs)
});

fn load_from_disk() -> FileLocations {
    match std::fs::read_to_string(PATHS_CONFIG_FILE) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => FileLocations::default(),
    }
}

/// Get a snapshot of the current file locations.
pub fn get() -> FileLocations {
    LOCATIONS.read().unwrap().clone()
}

/// Update file locations and persist to disk.
pub fn update(locs: FileLocations) -> Result<(), String> {
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    let json = serde_json::to_string_pretty(&locs)
        .map_err(|e| format!("Failed to serialize paths config: {}", e))?;
    std::fs::write(PATHS_CONFIG_FILE, json)
        .map_err(|e| format!("Failed to write paths config: {}", e))?;
    *LOCATIONS.write().unwrap() = locs;
    Ok(())
}
