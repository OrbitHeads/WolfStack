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
pub mod wan;
pub mod host_dns;
pub mod proxy;

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

#[allow(dead_code)]
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

/// Who actually serves DNS on this LAN. Default is WolfRouter's own
/// dnsmasq (the existing behaviour). `External` means the operator is
/// running their own DNS box on the LAN (AdGuard Home in a container,
/// Pi-hole on a Pi, etc.) and just wants WolfRouter's DHCP to point
/// clients there.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// WolfRouter's dnsmasq binds port `listen_port` on the LAN
    /// interface and DHCP option 6 advertises the router IP.
    WolfRouter,
    /// WolfRouter's dnsmasq runs DHCP only (port=0 = DNS off) and DHCP
    /// option 6 advertises `external_server` to clients.
    External,
}

impl Default for DnsMode {
    fn default() -> Self { DnsMode::WolfRouter }
}

/// DNS resolver config for one LAN. dnsmasq handles both DHCP and DNS,
/// so this is applied to the same per-LAN instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    /// How DNS is served on this LAN. `WolfRouter` (default) = dnsmasq
    /// answers on port 53; `External` = dnsmasq yields port 53 and
    /// DHCP points clients at the operator's DNS server.
    #[serde(default)]
    pub mode: DnsMode,
    /// Port dnsmasq binds for DNS on this LAN's interface when
    /// `mode = WolfRouter`. Default 53. Moving this to 5353 lets a
    /// containerised resolver (AdGuard Home, etc.) claim port 53 on
    /// the same interface — in that case set `external_server` too so
    /// DHCP option 6 still advertises a resolver clients can actually
    /// reach on the standard port. Ignored when `mode = External`
    /// (DNS is disabled there via `port=0`).
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,
    /// DNS server advertised to DHCP clients (option 6). Required when
    /// `mode = External`. Optional when `mode = WolfRouter`: if set,
    /// takes precedence over the router IP (useful when `listen_port`
    /// isn't 53).
    #[serde(default)]
    pub external_server: Option<String>,
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
    /// If true, dnsmasq logs every query to a per-LAN file at
    /// /var/lib/wolfstack-router/lan-<id>.log. Debug-only — leaves a
    /// growing log file on disk while enabled. The DNS Tools tab
    /// toggles this so admins can watch LAN clients' queries land (or
    /// not) in real time.
    #[serde(default)]
    pub query_log: bool,
    /// Forward the original client IP to upstream forwarders via EDNS
    /// Client Subnet (RFC 7871). Adds `add-subnet=32,128` to dnsmasq so
    /// upstreams like AdGuard, Pi-hole, or NextDNS can attribute queries
    /// to individual LAN clients instead of seeing them all come from
    /// the router. Off by default because ECS leaks client subnets to
    /// the upstream — enable only when you trust the upstream.
    #[serde(default)]
    pub forward_client_subnet: bool,
}

fn default_dns_port() -> u16 { 53 }

impl Default for DnsServerConfig {
    fn default() -> Self {
        DnsServerConfig {
            mode: DnsMode::WolfRouter,
            listen_port: 53,
            external_server: None,
            forwarders: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            local_records: vec![],
            cache_enabled: true,
            block_ads: false,
            query_log: false,
            forward_client_subnet: false,
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

/// A subnet route for reaching remote networks via WolfNet or other tunnels.
/// Allows traffic destined for the subnet to be routed through a gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetRoute {
    pub id: String,
    /// Destination subnet in CIDR form (e.g. "10.20.0.0/16").
    pub subnet_cidr: String,
    /// Gateway IP — the next-hop to reach this subnet (typically a WolfNet tunnel endpoint).
    pub gateway: String,
    /// Node that owns this route. If None, applied cluster-wide.
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    /// WAN uplink configurations — DHCP, static, or PPPoE per port.
    #[serde(default)]
    pub wan_connections: Vec<wan::WanConnection>,
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
    /// Reverse-proxy entries. Each one maps an incoming domain to a
    /// backend (custom IP:port, a VM, or a container). The runtime
    /// generates one nginx site config per entry on the node that
    /// owns it. See `proxy::apply_for_node` for the generator.
    #[serde(default)]
    pub proxies: Vec<proxy::ProxyEntry>,
    /// Subnet routes for reaching remote networks via WolfNet or other tunnels.
    /// Each entry defines a destination subnet and the gateway to reach it.
    #[serde(default)]
    pub subnet_routes: Vec<SubnetRoute>,
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

/// Apply the persisted router config on startup. Before this existed,
/// a host booting with WolfStack-as-router lost its WAN link, LAN
/// DHCP, and firewall rules every reboot — Docker and Proxmox both
/// autostart their payloads, but WolfStack only *loaded* the router
/// config on startup and required a human to click Apply in the UI
/// before anything came back up. Clients got leases but no internet.
///
/// Runs each subsystem best-effort: a WAN that fails to dial still
/// lets the LAN come up; a broken firewall rule still lets WAN and
/// LAN stand. Order matters:
///   1. WAN first — PPPoE ip-up hooks install MASQUERADE on the
///      dynamic ppp iface, and LAN/firewall may reference WAN zones.
///   2. LAN dnsmasq next — can only bind once its interface exists.
///   3. Firewall last — rules reference interfaces from 1+2.
/// Safe-mode is explicitly OFF: unattended boot has no human to
/// confirm rules within the 30s window, and auto-reverting on every
/// reboot would be worse than "rules applied with no rollback".
pub fn apply_on_startup(state: std::sync::Arc<RouterState>, self_node_id: &str) {
    let cfg = state.config.read().unwrap().clone();

    // Skip entirely when the user hasn't configured WolfRouter on this
    // node. firewall::build_ruleset + apply would still produce a valid
    // "empty" ruleset, but applying it flushes the built-in INPUT /
    // FORWARD / OUTPUT chains and with them any jumps that Docker / VM
    // managers / other subsystems installed for their own forwarding.
    // Those subsystems re-install their rules on their own events, but
    // doing that pointless churn on every reboot isn't free. If this
    // node has nothing to say about routing, stay out of the way.
    let applies_here = cfg.wan_connections.iter()
        .any(|c| c.enabled && c.node_id == self_node_id)
        || cfg.lans.iter().any(|l| l.node_id == self_node_id)
        || cfg.rules.iter().any(|r| r.enabled
            && r.node_id.as_deref().map(|n| n == self_node_id).unwrap_or(true))
        || cfg.proxies.iter().any(|p| p.enabled && p.node_id == self_node_id);
    if !applies_here {
        tracing::debug!(
            "WolfRouter startup: no router config bound to this node — skipping apply"
        );
        return;
    }

    let mut wan_ok = 0usize;
    let mut wan_err = 0usize;
    for conn in &cfg.wan_connections {
        if conn.node_id != self_node_id { continue; }
        if !conn.enabled { continue; }
        match wan::apply(conn) {
            Ok(()) => { wan_ok += 1; }
            Err(e) => {
                wan_err += 1;
                tracing::error!(
                    "WolfRouter startup: WAN '{}' apply failed: {}",
                    conn.name, e
                );
            }
        }
    }
    if wan_ok + wan_err > 0 {
        tracing::info!(
            "WolfRouter startup: {} WAN connection(s) applied, {} failed",
            wan_ok, wan_err
        );
    }

    // dhcp::start_all_for_node already skips LANs bound to other
    // nodes and logs per-LAN failures. No return value to aggregate.
    dhcp::start_all_for_node(&cfg, self_node_id);

    // Firewall — only if the user actually has rules. On a fresh
    // install with empty rules the build produces an empty chain
    // dump that's technically valid but emitting an info line just
    // so sysadmins see activity at boot.
    let ruleset = firewall::build_ruleset(&cfg, self_node_id);
    match firewall::apply(&ruleset, false) {
        Ok(prev) => {
            *state.last_applied_rules.write().unwrap() = Some(prev);
            tracing::info!(
                "WolfRouter startup: firewall rules applied ({} user rule(s))",
                cfg.rules.len()
            );
        }
        Err(e) => {
            tracing::error!("WolfRouter startup: firewall apply failed: {}", e);
        }
    }

    // Reverse-proxy vhosts — regenerate nginx site configs for every
    // proxy bound to this node. Skip entirely when no proxies target
    // this node, so a bare install without nginx doesn't log scary
    // "nginx not installed" warnings on every boot.
    if cfg.proxies.iter().any(|p| p.enabled && p.node_id == self_node_id) {
        let warnings = proxy::apply_for_node(&cfg.proxies, self_node_id);
        if warnings.is_empty() {
            tracing::info!(
                "WolfRouter startup: {} reverse-proxy vhost(s) regenerated",
                cfg.proxies.iter().filter(|p| p.enabled && p.node_id == self_node_id).count()
            );
        } else {
            for w in &warnings {
                tracing::warn!("WolfRouter startup: proxy apply: {}", w);
            }
        }
    }

    // Subnet routes — apply kernel routing entries for remote subnets
    // accessible via WolfNet or other tunnels.
    let subnet_routes: Vec<_> = cfg.subnet_routes.iter()
        .filter(|r| r.enabled && route_targets_self(r, self_node_id))
        .collect();

    if !subnet_routes.is_empty() {
        for route in subnet_routes {
            // Startup: we don't carry "previous gateway" state across
            // process restart, so pass None. Idempotent if the kernel
            // already has our route; refuses if the kernel has someone
            // else's route for the same CIDR.
            match apply_subnet_route(route, None) {
                Ok(()) => {
                    tracing::info!(
                        "WolfRouter startup: subnet route applied: {} via {}",
                        route.subnet_cidr, route.gateway
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "WolfRouter startup: subnet route failed: {} via {}: {}",
                        route.subnet_cidr, route.gateway, e
                    );
                }
            }
        }
    }
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

/// Apply a single subnet route to the kernel.
///
/// `previous_gateway`: when this is an UPDATE/edit, pass the gateway value
/// that WolfStack previously installed for this CIDR. The kernel doesn't
/// track ownership, so we use this to distinguish "the existing route is
/// ours, swap it" from "someone else owns the existing route, leave it
/// alone" (Codex P1, v20.11.2). Pass `None` for fresh creates and for
/// startup.
///
/// Behaviour:
///   • No existing kernel route → `ip route add`.
///   • Existing route's gateway == our new gateway → no-op (idempotent).
///   • Existing route's gateway == `previous_gateway` (ours, edited) →
///     `ip route replace` — atomic swap.
///   • Existing route's gateway is anything else → REFUSE. That route was
///     installed outside WolfStack (a VPN client, admin static, another
///     routing daemon); silently replacing it would break the operator.
///
/// `pub` because the API handlers (create/update) and the cluster replication
/// handler (config_receive) all need to apply at runtime — not just at
/// process startup. Prior to v20.11.2 only the startup path applied routes,
/// so newly-created routes never reached the kernel.
pub fn apply_subnet_route(route: &SubnetRoute, previous_gateway: Option<&str>) -> Result<(), String> {
    use std::process::Command;

    if parse_cidr(&route.subnet_cidr).is_none() {
        return Err(format!("Invalid subnet CIDR: {}", route.subnet_cidr));
    }
    if route.gateway.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid gateway IP: {}", route.gateway));
    }

    let existing = read_kernel_route_gateway(&route.subnet_cidr)
        .map_err(|e| format!("Failed to inspect existing route: {}", e))?;

    match existing {
        // No route currently — install ours.
        None => {
            let output = Command::new("ip")
                .arg("route").arg("add")
                .arg(&route.subnet_cidr).arg("via").arg(&route.gateway)
                .output()
                .map_err(|e| format!("Failed to execute ip command: {}", e))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // "File exists" here means the destination IS routed but
                // `read_kernel_route_gateway` couldn't parse the entry into
                // a `<dest> via <gw>` form — connected `dev` routes,
                // blackhole/unreachable, or a multipath. Refuse with a
                // clear error rather than recursing (Codex P1, v20.11.2).
                // A naive retry-on-File-exists would loop forever because
                // the parser would keep returning None.
                if stderr.contains("File exists") {
                    Err(format!(
                        "Route to {} already exists in an unsupported form (e.g. dev/blackhole/multipath). Inspect with `ip route show {}` and resolve before WolfStack can manage it.",
                        route.subnet_cidr, route.subnet_cidr
                    ))
                } else {
                    Err(format!("ip route add failed: {}", stderr.trim()))
                }
            }
        }
        // Already exactly what we want — no-op.
        Some(gw) if gw == route.gateway => Ok(()),
        // It's our previous entry — atomic swap with `ip route replace`.
        Some(gw) if previous_gateway.map_or(false, |pgw| pgw == gw) => {
            let output = Command::new("ip")
                .arg("route").arg("replace")
                .arg(&route.subnet_cidr).arg("via").arg(&route.gateway)
                .output()
                .map_err(|e| format!("Failed to execute ip command: {}", e))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("ip route replace failed: {}", stderr.trim()))
            }
        }
        // Someone else owns this destination. Refuse.
        Some(gw) => Err(format!(
            "Route to {} already exists via {} (installed outside WolfStack). Refusing to overwrite — remove the existing route first if you want WolfStack to manage it.",
            route.subnet_cidr, gw
        )),
    }
}

/// Read the gateway of an existing kernel route for the given CIDR, if any.
/// Parses the first non-empty line of `ip route show <cidr>` looking for
/// `via <ip>`. Returns Ok(None) if no route exists, or if the format is
/// not the simple `<dest> via <ip> ...` shape we install ourselves
/// (multi-path routes, blackhole, unreachable, etc. — caller treats the
/// unparseable case conservatively).
fn read_kernel_route_gateway(cidr: &str) -> Result<Option<String>, String> {
    let raw = read_kernel_route_raw(cidr)?;
    Ok(parse_route_gateway(&raw))
}

/// Capture the raw stdout of `ip route show <cidr>`. Used both by the
/// gateway-extracting helper above and by the diagnostics endpoint, which
/// shows operators the unparsed output so they can reason about routes
/// that don't fit our `<dest> via <gw>` shape (dev-only, blackhole,
/// multipath).
pub fn read_kernel_route_raw(cidr: &str) -> Result<String, String> {
    use std::process::Command;
    let out = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg(cidr)
        .output()
        .map_err(|e| format!("ip route show: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ip route show failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Capture the entire IPv4 routing table — what `ip route` prints with
/// no arguments. Used by diagnostics so operators can see the full
/// kernel state when a configured route is missing.
pub fn read_kernel_route_table() -> Result<String, String> {
    use std::process::Command;
    let out = Command::new("ip")
        .arg("route")
        .output()
        .map_err(|e| format!("ip route: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("ip route failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Public alias for the parser so the diagnostics API can compose the
/// raw `ip route show` capture with our gateway-extraction logic without
/// re-running the command.
pub fn parse_kernel_route_gateway_for_diagnostics(raw: &str) -> Option<String> {
    parse_route_gateway(raw)
}

/// Extract the `via <gw>` from the first non-empty line of an `ip route
/// show` capture. Returns None when the format is not our simple `<dest>
/// via <ip> ...` shape (dev-only, blackhole, multipath).
fn parse_route_gateway(raw: &str) -> Option<String> {
    let line = raw.lines().find(|l| !l.trim().is_empty())?;
    let mut tokens = line.split_whitespace();
    while let Some(t) = tokens.next() {
        if t == "via" {
            if let Some(gw) = tokens.next() {
                if gw.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(gw.to_string());
                }
            }
        }
    }
    None
}

/// Remove a subnet route from the kernel via `ip route del`.
///
/// Idempotent: "No such process" / "does not exist" are treated as success.
///
/// Codex P1 (v20.11.2): we ALSO check that the kernel route's gateway still
/// matches `route.gateway` before deleting. If the kernel currently has a
/// different gateway for the same destination, that route was installed by
/// something outside WolfStack (or replaced after our state diverged) — we
/// must not delete it, or we'd break the operator's connectivity.
pub fn remove_subnet_route(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    // Inspect first. If the kernel has a different (or no) gateway for this
    // CIDR, we have nothing to remove that's safely ours.
    match read_kernel_route_gateway(&route.subnet_cidr) {
        Ok(None) => return Ok(()),                       // already absent
        Ok(Some(gw)) if gw != route.gateway => {
            tracing::warn!(
                "remove_subnet_route: kernel route for {} now uses gateway {} (we expected {}); leaving it in place",
                route.subnet_cidr, gw, route.gateway
            );
            return Ok(());
        }
        Ok(Some(_)) => { /* matches — proceed with del */ }
        Err(e) => {
            // If the inspect failed, fall through to a conservative del
            // attempt with explicit `via` so we only target our entry.
            tracing::warn!("remove_subnet_route: pre-check failed: {} — attempting targeted del", e);
        }
    }

    let output = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg(&route.subnet_cidr)
        .arg("via")
        .arg(&route.gateway)
        .output()
        .map_err(|e| format!("Failed to execute ip command: {}", e))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such process") || stderr.contains("does not exist") {
        return Ok(());
    }
    Err(format!("ip route del failed: {}", stderr.trim()))
}

/// True when the route should be installed on the node identified by
/// `self_node_id`. Encapsulates the "None == cluster-wide, Some(id) == that
/// node only" rule so all callers (startup, create, update, config_receive)
/// agree.
pub fn route_targets_self(route: &SubnetRoute, self_node_id: &str) -> bool {
    route.node_id.is_none() || route.node_id.as_deref() == Some(self_node_id)
}
