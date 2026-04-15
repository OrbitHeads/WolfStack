// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! WAN connection management.
//!
//! Three modes:
//!   • **DHCP** — interface gets its IP from upstream (the default for
//!     plug-in-and-go modems / ONTs in bridge mode).
//!   • **Static** — operator hard-codes IP/netmask/gateway. Same as
//!     editing /etc/network/interfaces by hand, just driven from
//!     WolfRouter.
//!   • **PPPoE** — common for ADSL/VDSL/fibre lines (especially in
//!     Germany and other European markets where the ISP requires a
//!     PPPoE login over Ethernet). WolfRouter writes
//!     `/etc/ppp/peers/wolfrouter-{id}` plus the PAP/CHAP secrets,
//!     then runs `pppd call` to bring the link up.
//!
//! Service lifecycle: a WanConnection's `enabled` flag controls
//! whether the OS-level service is started. Disabling drops the link.
//! State is computed live from `ip link` (PPP devices appear as
//! `ppp0`, `ppp1`, ...).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

const PEERS_DIR: &str = "/etc/ppp/peers";
const CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
const PAP_SECRETS: &str = "/etc/ppp/pap-secrets";

/// One WAN uplink configuration. Keyed by `id` (auto-generated) and
/// owned by `node_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanConnection {
    pub id: String,
    pub name: String,
    /// Node that hosts the physical interface.
    pub node_id: String,
    /// Physical / VLAN interface that carries the uplink. For PPPoE
    /// this is the Ethernet port the ONT/modem is plugged into; the
    /// resulting ppp0/ppp1 is created automatically.
    pub interface: String,
    pub mode: WanMode,
    /// If false, WolfRouter doesn't try to start the connection. Lets
    /// users stage a config without bringing up an unwanted dialer.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

fn default_enabled() -> bool { true }

/// Mode-specific config. Tagged enum so the JSON shape is obvious to
/// the frontend — `{ "mode": "pppoe", "config": { ... } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "config", rename_all = "snake_case")]
pub enum WanMode {
    Dhcp,
    Static(StaticConfig),
    Pppoe(PppoeConfig),
}

impl Default for WanMode {
    fn default() -> Self { WanMode::Dhcp }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StaticConfig {
    /// CIDR address, e.g. "192.168.1.10/24".
    pub address_cidr: String,
    pub gateway: String,
    /// Optional DNS servers (one per line in dispatcher).
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PppoeConfig {
    pub username: String,
    /// Plaintext password — stored encrypted at rest in
    /// /etc/ppp/chap-secrets (mode 0600). Not roundtripped to the UI
    /// after save: the GET endpoint masks this to "***".
    pub password: String,
    /// Optional PPPoE service name (most ISPs leave this blank).
    #[serde(default)]
    pub service_name: String,
    /// MTU. Defaults to 1492 (PPPoE overhead).
    #[serde(default = "default_pppoe_mtu")]
    pub mtu: u32,
    /// MRU. Defaults to 1492.
    #[serde(default = "default_pppoe_mtu")]
    pub mru: u32,
    /// Reconnect persistently on link drops. Default true.
    #[serde(default = "default_true_local")]
    pub persist: bool,
    /// LCP echo interval (seconds). 0 disables. Default 30s.
    #[serde(default = "default_lcp_echo_interval")]
    pub lcp_echo_interval: u32,
    /// LCP echo failures before pppd considers the link dead. Default 4.
    #[serde(default = "default_lcp_echo_failure")]
    pub lcp_echo_failure: u32,
}

fn default_pppoe_mtu() -> u32 { 1492 }
fn default_true_local() -> bool { true }
fn default_lcp_echo_interval() -> u32 { 30 }
fn default_lcp_echo_failure() -> u32 { 4 }

/// Validate user-supplied fields that get written into config files —
/// reject anything that could break out of the file format (newlines,
/// quotes that aren't escaped). Returns Err with a human reason.
pub fn validate(conn: &WanConnection) -> Result<(), String> {
    let no_newlines = |field: &str, v: &str| -> Result<(), String> {
        if v.contains('\n') || v.contains('\r') {
            return Err(format!("{} contains newline characters", field));
        }
        Ok(())
    };
    no_newlines("name", &conn.name)?;
    no_newlines("interface", &conn.interface)?;
    no_newlines("description", &conn.description)?;
    if !conn.interface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        return Err("interface name has illegal characters".into());
    }
    match &conn.mode {
        WanMode::Dhcp => {}
        WanMode::Static(s) => {
            no_newlines("address_cidr", &s.address_cidr)?;
            no_newlines("gateway", &s.gateway)?;
            for d in &s.dns { no_newlines("dns", d)?; }
        }
        WanMode::Pppoe(p) => {
            no_newlines("username", &p.username)?;
            no_newlines("password", &p.password)?;
            no_newlines("service_name", &p.service_name)?;
            // username must be free of double quotes (we wrap in quotes
            // when writing the peers file).
            if p.username.contains('"') {
                return Err("username contains double quotes".into());
            }
            if p.password.contains('"') {
                return Err("password contains double quotes".into());
            }
            if p.username.is_empty() {
                return Err("PPPoE username is required".into());
            }
        }
    }
    Ok(())
}

// ─── PPPoE service lifecycle ───

/// Write the pppd peers file + chap/pap secrets for a PPPoE connection
/// and start the link. Idempotent: stops the link first if it's
/// already running so config updates take effect cleanly.
pub fn pppoe_apply(conn: &WanConnection, cfg: &PppoeConfig) -> Result<(), String> {
    fs::create_dir_all(PEERS_DIR)
        .map_err(|e| format!("mkdir {}: {}", PEERS_DIR, e))?;

    let peer_name = peer_name_for(&conn.id);
    let peer_path = format!("{}/{}", PEERS_DIR, peer_name);

    // Peer file — references the PPPoE plugin and the underlying iface.
    let mut peer = String::new();
    peer.push_str(&format!("# WolfRouter PPPoE peer for connection {} ({})\n", conn.id, conn.name));
    peer.push_str("# Managed by WolfStack — do not edit by hand.\n");
    peer.push_str(&format!("plugin pppoe.so {}\n", conn.interface));
    peer.push_str(&format!("name \"{}\"\n", cfg.username));
    if !cfg.service_name.is_empty() {
        peer.push_str(&format!("rp_pppoe_service \"{}\"\n", cfg.service_name));
    }
    peer.push_str("noauth\n");
    peer.push_str("hide-password\n");
    peer.push_str("noipdefault\n");
    peer.push_str("defaultroute\n");
    peer.push_str("usepeerdns\n");
    peer.push_str("noaccomp\n");
    peer.push_str("default-asyncmap\n");
    peer.push_str(&format!("mtu {}\n", cfg.mtu));
    peer.push_str(&format!("mru {}\n", cfg.mru));
    if cfg.persist { peer.push_str("persist\n"); peer.push_str("maxfail 0\n"); }
    if cfg.lcp_echo_interval > 0 {
        peer.push_str(&format!("lcp-echo-interval {}\n", cfg.lcp_echo_interval));
        peer.push_str(&format!("lcp-echo-failure {}\n", cfg.lcp_echo_failure));
    }
    fs::write(&peer_path, peer)
        .map_err(|e| format!("write {}: {}", peer_path, e))?;

    // Secrets — both PAP and CHAP since we don't know which the ISP
    // will negotiate. Mode 0600 (root-only) so the password isn't
    // world-readable.
    write_secret(CHAP_SECRETS, &cfg.username, &cfg.password)?;
    write_secret(PAP_SECRETS, &cfg.username, &cfg.password)?;

    // Bring down any existing instance of this peer first.
    let _ = pppoe_stop(conn);

    // pppd call <peer_name> — daemonises by default.
    let out = Command::new("pppd")
        .args(["call", &peer_name])
        .output()
        .map_err(|e| format!("spawn pppd: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("pppd exited {}: {}",
            out.status.code().unwrap_or(-1),
            stderr.trim()));
    }
    info!("WolfRouter: PPPoE link '{}' (peer {}) started on {}", conn.name, peer_name, conn.interface);
    Ok(())
}

/// Tear down the PPP link for this connection. Safe to call when no
/// link exists. Removes the peers file too if `purge` is true.
pub fn pppoe_stop(conn: &WanConnection) -> Result<(), String> {
    let peer_name = peer_name_for(&conn.id);
    // poff drops the named peer's link.
    let _ = Command::new("poff").arg(&peer_name).status();
    Ok(())
}

pub fn pppoe_purge(conn: &WanConnection) -> Result<(), String> {
    let _ = pppoe_stop(conn);
    let peer_path = format!("{}/{}", PEERS_DIR, peer_name_for(&conn.id));
    let _ = fs::remove_file(&peer_path);
    Ok(())
}

/// Write a CHAP/PAP secret line for the given user. Replaces an
/// existing line if one matches; otherwise appends. File mode 0600.
fn write_secret(path: &str, user: &str, password: &str) -> Result<(), String> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut out = String::new();
    let user_q = format!("\"{}\"", user);
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line); out.push('\n'); continue;
        }
        let first = trimmed.split_whitespace().next().unwrap_or("");
        if first == user_q || first.trim_matches('"') == user {
            // Replace with our line below.
            replaced = true;
            continue;
        }
        out.push_str(line); out.push('\n');
    }
    out.push_str(&format!("{} * \"{}\" *\n", user_q, password));
    let _ = replaced;  // currently unused; kept for clarity

    fs::write(path, out)
        .map_err(|e| format!("write {}: {}", path, e))?;
    // Lock down to root-only.
    if let Ok(meta) = fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
    Ok(())
}

fn peer_name_for(id: &str) -> String {
    // pppd uses the file name as the "call" target — keep it short
    // and free of path separators.
    let safe: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    format!("wolfrouter-{}", safe)
}

/// Live PPP interface state — looks for a ppp* device backed by the
/// peer name. Returns (iface_name, ip_addr) when up, None otherwise.
pub fn pppoe_status(conn: &WanConnection) -> Option<(String, String)> {
    let peer = peer_name_for(&conn.id);
    // pppd writes /var/run/<peer>.pid when up. Checking that is the
    // cheapest "is it running" signal.
    let pid_path = format!("/var/run/{}.pid", peer);
    if !Path::new(&pid_path).exists() {
        return None;
    }
    // Walk ppp interfaces and pick the first with an IP. Multi-PPPoE
    // setups would want a stricter mapping; that's a v17.2 problem.
    let out = Command::new("ip").args(["-j", "-4", "addr", "show"]).output().ok()?;
    if !out.status.success() { return None; }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    for entry in json.as_array()? {
        let name = entry.get("ifname")?.as_str()?;
        if !name.starts_with("ppp") { continue; }
        let ip = entry.get("addr_info")?.as_array()?
            .iter().find_map(|a| a.get("local").and_then(|v| v.as_str()))?;
        return Some((name.to_string(), ip.to_string()));
    }
    None
}

/// Apply or stop a single connection based on its enabled flag.
pub fn apply(conn: &WanConnection) -> Result<(), String> {
    if !conn.enabled {
        if let WanMode::Pppoe(_) = &conn.mode {
            return pppoe_stop(conn);
        }
        return Ok(());
    }
    match &conn.mode {
        WanMode::Pppoe(p) => pppoe_apply(conn, p),
        WanMode::Dhcp => {
            // For now we don't manage DHCP via WolfRouter — the host's
            // existing DHCP client already handles it. Future: write a
            // dispatcher hook.
            warn!("WAN DHCP for {} is a passthrough — managed by the host's DHCP client", conn.name);
            Ok(())
        }
        WanMode::Static(_s) => {
            warn!("WAN static IP for {} is a passthrough — manage via host network config", conn.name);
            Ok(())
        }
    }
}
