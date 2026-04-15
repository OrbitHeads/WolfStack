// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfRouter — native router/firewall/DHCP/DNS module.
//!
//! Replaces the OPNsense-in-a-VM pattern with a host-native stack built
//! on iptables (filter table for stateful rules, already-wired `nat`
//! table for DNAT/SNAT) plus dnsmasq (per-LAN DHCP + DNS).
//!
//! Three user-visible concepts:
//!   • **Zone** — named policy group (`Wan`, `Lan(N)`, `Dmz`, `Wolfnet`,
//!     `Trusted`, `Custom`). Every interface/bridge/VLAN gets a zone.
//!     Rules talk about zones, not interfaces.
//!   • **LAN segment** — a subnet served by WolfRouter. Bound to a
//!     bridge or interface; dnsmasq hands out DHCP leases and answers
//!     DNS with upstream forwarders.
//!   • **Firewall rule** — zone-to-zone or specific-endpoint allow/deny
//!     with state tracking. Translated to iptables atomically via
//!     `iptables-restore --test` then swap.
//!
//! All state persists to `/etc/wolfstack/router/` as JSON so it survives
//! restarts. Topology (live view of ports/bridges/wires/devices) is
//! computed on demand from system state — never persisted.

pub mod firewall;
pub mod dhcp;
pub mod dns;
pub mod topology;
pub mod api;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

const ROUTER_DIR: &str = "/etc/wolfstack/router";

/// Named policy group. Interfaces and bridges belong to a zone; firewall
/// rules are written in terms of zones so admins don't have to remember
/// "is enp3s0 the LAN or the WAN today?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum Zone {
    Wan,
    Lan(u32),
    Dmz,
    Wolfnet,
    Trusted,
    Custom(String),
}

impl Zone {
    /// Short slug used for ipset names and log tags. Must be <= 24 chars
    /// (ipset's limit minus our "wr-zone-" prefix).
    pub fn slug(&self) -> String {
        match self {
            Zone::Wan => "wan".into(),
            Zone::Lan(n) => format!("lan{}", n),
            Zone::Dmz => "dmz".into(),
            Zone::Wolfnet => "wolfnet".into(),
            Zone::Trusted => "trusted".into(),
            Zone::Custom(s) => {
                let clean: String = s.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .take(16)
                    .collect();
                if clean.is_empty() { "custom".into() } else { clean }
            }
        }
    }

    pub fn human(&self) -> String {
        match self {
            Zone::Wan => "WAN".into(),
            Zone::Lan(n) => format!("LAN {}", n),
            Zone::Dmz => "DMZ".into(),
            Zone::Wolfnet => "WolfNet".into(),
            Zone::Trusted => "Trusted".into(),
            Zone::Custom(s) => s.clone(),
        }
    }
}

/// A DHCP pool + static reservations + options bundle for one LAN.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpConfig {
    /// DHCP pool start (e.g. "192.168.10.100").
    pub pool_start: String,
    /// DHCP pool end (e.g. "192.168.10.250").
    pub pool_end: String,
    /// Lease time, e.g. "12h" or "1d".
    #[serde(default = "default_lease_time")]
    pub lease_time: String,
    /// Static MAC → IP (+ hostname) reservations.
    #[serde(default)]
    pub reservations: Vec<DhcpReservation>,
    /// DHCP options to push (3=gateway, 6=DNS, 42=NTP, etc.). Left blank
    /// by default because dnsmasq fills in gateway/DNS from the LAN's
    /// router_ip automatically.
    #[serde(default)]
    pub extra_options: Vec<String>,
    /// Whether DHCP is enabled. If false, the LAN still exists (routed,
    /// firewall applies) but clients must configure statically.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_lease_time() -> String { "12h".into() }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservation {
    pub mac: String,           // "aa:bb:cc:dd:ee:ff"
    pub ip: String,            // must be within the LAN subnet
    pub hostname: Option<String>,
}

/// DNS resolver config for one LAN. dnsmasq handles both DHCP and DNS,
/// so this is applied to the same per-LAN instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    /// Upstream forwarders. If empty, falls back to host's /etc/resolv.conf.
    #[serde(default)]
    pub forwarders: Vec<String>,
    /// Local A records (hostname → IP) served authoritatively to this LAN.
    /// Useful for giving VMs/services local DNS names without an external
    /// DNS server.
    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
    /// Enable DNS cache. dnsmasq caches by default; this toggle lets an
    /// admin disable it for debugging.
    #[serde(default = "default_true")]
    pub cache_enabled: bool,
    /// Block ad/tracker domains. Pulls from a pluggable hosts list.
    #[serde(default)]
    pub block_ads: bool,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        DnsServerConfig {
            forwarders: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            local_records: vec![],
            cache_enabled: true,
            block_ads: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDnsRecord {
    pub hostname: String,
    pub ip: String,
}

/// A LAN segment served by WolfRouter on one node. Bound to a bridge or
/// physical interface; dnsmasq listens on that interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanSegment {
    pub id: String,
    pub name: String,
    /// Node that hosts this LAN (serves DHCP/DNS from here).
    pub node_id: String,
    /// Interface/bridge name on that node (e.g. "br-lan0", "enp3s0",
    /// "eth0.100" for a VLAN).
    pub interface: String,
    pub zone: Zone,
    /// Subnet in CIDR form, e.g. "192.168.10.0/24".
    pub subnet_cidr: String,
    /// Router IP within the subnet (typically .1 or .254).
    pub router_ip: String,
    pub dhcp: DhcpConfig,
    pub dns: DnsServerConfig,
    #[serde(default)]
    pub description: String,
}

/// Firewall rule action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Log,
}

/// Which chain does this rule apply to?
///   • `Forward` — traffic between interfaces (99% of home firewall rules)
///   • `Input`   — traffic destined for the WolfStack host itself
///   • `Output`  — traffic originating from the WolfStack host
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Forward,
    Input,
    Output,
}

/// What the rule matches at the "from" or "to" end.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Endpoint {
    Any,
    Zone { zone: Zone },
    Interface { name: String },
    Ip { cidr: String },       // single IP or CIDR
    Vm { name: String },       // resolved at apply-time to the VM's IP
    Container { name: String },
    Lan { id: String },        // resolves to the LAN's subnet
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol { Any, Tcp, Udp, Icmp, Tcpudp }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    /// Single port ("80") or range ("8000-8100").
    pub port: String,
    /// Dst (the common case) or Src side of the match.
    #[serde(default)]
    pub side: PortSide,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortSide { #[default] Dst, Src }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub order: i32,
    pub action: Action,
    pub direction: Direction,
    pub from: Endpoint,
    pub to: Endpoint,
    pub protocol: Protocol,
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Add `-m conntrack --ctstate NEW` (with ESTABLISHED,RELATED a single
    /// jump-accept rule installed by the engine, users don't write this).
    #[serde(default = "default_true")]
    pub state_track: bool,
    /// Copy matches to NFLOG so they show up in the Logs view.
    #[serde(default)]
    pub log_match: bool,
    #[serde(default)]
    pub comment: String,
    /// Node that owns this rule. Rules can be cluster-scoped (applied
    /// to every node) by setting node_id = None; typically rules are
    /// node-scoped because they reference node-local interfaces.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// Which interface/bridge on which node belongs to which zone. Used by
/// the firewall engine to build ipsets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneAssignments {
    /// (node_id, interface_name) → Zone
    #[serde(default)]
    pub assignments: HashMap<String, HashMap<String, Zone>>,
}

impl ZoneAssignments {
    pub fn get(&self, node_id: &str, iface: &str) -> Option<&Zone> {
        self.assignments.get(node_id).and_then(|m| m.get(iface))
    }

    pub fn set(&mut self, node_id: &str, iface: &str, zone: Zone) {
        self.assignments
            .entry(node_id.to_string())
            .or_default()
            .insert(iface.to_string(), zone);
    }

    pub fn remove(&mut self, node_id: &str, iface: &str) {
        if let Some(m) = self.assignments.get_mut(node_id) {
            m.remove(iface);
        }
    }

    /// All (node_id, iface) pairs that are members of a given zone on a
    /// given node — used to populate the zone's ipset.
    pub fn members_for_zone_on_node(&self, node_id: &str, zone: &Zone) -> Vec<String> {
        self.assignments
            .get(node_id)
            .map(|m| m.iter().filter(|(_, z)| *z == zone).map(|(n, _)| n.clone()).collect())
            .unwrap_or_default()
    }
}

// ─── Persistence ───

/// Router config on disk. A single file so atomic writes are simple.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouterConfig {
    #[serde(default)]
    pub zones: ZoneAssignments,
    #[serde(default)]
    pub lans: Vec<LanSegment>,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    /// Global setting: apply rules immediately or require explicit "Apply".
    /// Homelabbers will want immediate; sysadmins will want explicit so
    /// they can stage changes.
    #[serde(default = "default_true")]
    pub auto_apply: bool,
    /// Safe-mode rollback window. If > 0, every firewall apply starts a
    /// timer — if the user doesn't confirm before the timer fires, rules
    /// are reverted. Prevents lockout. 0 disables.
    #[serde(default = "default_safe_mode_seconds")]
    pub safe_mode_seconds: u32,
}

fn default_safe_mode_seconds() -> u32 { 30 }

impl RouterConfig {
    pub fn path() -> String { format!("{}/config.json", ROUTER_DIR) }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(ROUTER_DIR)
            .map_err(|e| format!("Failed to create router dir: {}", e))?;
        let tmp = format!("{}.tmp", Self::path());
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialize failed: {}", e))?;
        std::fs::write(&tmp, json)
            .map_err(|e| format!("Write failed: {}", e))?;
        std::fs::rename(&tmp, Self::path())
            .map_err(|e| format!("Atomic rename failed: {}", e))?;
        Ok(())
    }
}

/// In-memory state, wrapped in AppState. RwLock because topology reads
/// are frequent (every poll) and writes are rare (user edits).
pub struct RouterState {
    pub config: RwLock<RouterConfig>,
    /// Last committed ruleset's iptables dump — used for safe-mode rollback.
    pub last_applied_rules: RwLock<Option<String>>,
    /// Live pending-rollback timer: when a user applies rules with safe-mode
    /// on, this is set to the epoch second at which we auto-revert if they
    /// haven't confirmed.
    pub rollback_deadline: RwLock<Option<u64>>,
    /// Per-node topology snapshots populated by the agent tick. Keyed by
    /// node_id. The local node is computed on demand, not cached here.
    pub remote_topologies: RwLock<HashMap<String, topology::NodeTopology>>,
}

impl RouterState {
    pub fn new() -> Self {
        RouterState {
            config: RwLock::new(RouterConfig::load()),
            last_applied_rules: RwLock::new(None),
            rollback_deadline: RwLock::new(None),
            remote_topologies: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for RouterState {
    fn default() -> Self { Self::new() }
}

/// Background safe-mode tick — checks whether the rollback deadline has
/// elapsed without the user confirming, and reverts the firewall if so.
/// Spawn this once per process from main; it sleeps 1s between checks.
pub fn spawn_rollback_watcher(state: std::sync::Arc<RouterState>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let deadline = *state.rollback_deadline.read().unwrap();
            if let Some(d) = deadline {
                if now >= d {
                    // Time's up — revert and clear the deadline.
                    let prev = state.last_applied_rules.read().unwrap().clone();
                    if let Some(p) = prev {
                        if let Err(e) = firewall::revert(&p) {
                            tracing::error!("WolfRouter safe-mode revert failed: {}", e);
                        } else {
                            tracing::warn!("WolfRouter safe-mode triggered: rules reverted");
                        }
                    }
                    *state.rollback_deadline.write().unwrap() = None;
                }
            }
        }
    });
}

// ─── Helpers used across submodules ───

/// Generate a short random ID for new rules/segments.
pub fn gen_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}-{:x}", prefix, nanos & 0xFFFFFFFF)
}

/// Parse a CIDR into (network, prefix). Returns None on malformed input.
pub fn parse_cidr(cidr: &str) -> Option<(String, u32)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 { return None; }
    // Rough validation: four dotted octets.
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return None; }
    for p in &parts {
        let n: u32 = p.parse().ok()?;
        if n > 255 { return None; }
    }
    Some((ip.to_string(), prefix))
}
