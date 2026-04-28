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
///   4. Subnet routes — kernel route entries on consumer nodes,
///      forwarding plumbing (ip_forward / FORWARD ACCEPT / MASQUERADE
///      / rp_filter loose) on gateway nodes. Runs even when no other
///      router config is bound to this node, so a pure-gateway VPS
///      gets its plumbing reinstalled after every restart/update.
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

    // WAN/DHCP/firewall/proxy work — only when this node owns at least
    // one of those. Subnet-route plumbing is handled below regardless,
    // because a node can be a pure subnet-route gateway (e.g. a VPS
    // forwarding a remote LAN onto WolfNet) with no WolfRouter LAN /
    // WAN / firewall config of its own. Sponsor klasSponsor 2026-04-28:
    // pre-fix, a reinstall on a pure-gateway node returned early here
    // and never re-applied ip_forward / FORWARD / MASQUERADE — the
    // route survived but the forwarding plumbing didn't.
    if applies_here {
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
    } else {
        tracing::debug!(
            "WolfRouter startup: no LAN/WAN/firewall/proxy bound here — skipping those (subnet routes still checked below)"
        );
    }

    // Subnet routes — apply kernel routing entries for remote subnets
    // accessible via WolfNet or other tunnels.
    //
    // Filter through node_handles_route so the gateway node is included
    // even when the user pinned the route to a specific consumer node:
    // apply_subnet_route inspects each role internally and installs only
    // what's needed (kernel route on the consumer, forwarding plumbing
    // on the gateway). v20.11.6 fix — pre-fix the gateway was excluded
    // and never got the iptables/sysctl rules required for forwarding.
    let subnet_routes: Vec<_> = cfg.subnet_routes.iter()
        .filter(|r| r.enabled && node_handles_route(r, self_node_id))
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

    // Gateway-side dispatch (sponsor klasSponsor 2026-04-27, v20.11.6):
    // when this node OWNS the route's gateway IP, it's the forwarder —
    // packets arrive on its wolfnet0 from peers and need to be NAT'd out
    // to the LAN. Installing the route entry on this node would mean
    // `ip route add 10.10.0.0/16 via <my-own-wolfnet0-ip>`, which the
    // kernel rejects (and even if it accepted it, the route would loop
    // back into the same interface). All this node needs is the
    // forwarding plumbing — ip_forward, FORWARD ACCEPT, MASQUERADE.
    //
    // The previous version installed plumbing only on the configured
    // node (route_targets_self) — which is the consumer, where the
    // plumbing is a no-op. The gateway never got it, so packets reached
    // the LAN host but replies couldn't make it back. That's why
    // klasSponsor saw a green health check but `ping 10.10.10.10` failed.
    if node_is_route_gateway(route) {
        return enable_subnet_route_forwarding(route);
    }

    let existing = read_kernel_route_gateway(&route.subnet_cidr)
        .map_err(|e| format!("Failed to inspect existing route: {}", e))?;

    let route_result: Result<(), String> = match existing {
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
    };

    // Consumer role only here (gateway role short-circuited at top of
    // function). The consumer doesn't forward — it's just the source —
    // so it needs the kernel route entry but NO iptables/sysctl
    // plumbing. v20.11.5 installed plumbing on consumers too: it was
    // a harmless no-op (consumer's egress src IP is already wolfnet0's
    // IP, so MASQUERADE rewrites src to itself) but it caused a race on
    // gateway-changed updates where remove(old) would strip rules that
    // apply(new) had just put back. Plumbing belongs only on the gateway.
    route_result
}

/// Install the kernel-forwarding plumbing required for a subnet route to
/// actually pass traffic. Idempotent: every step checks for the existing
/// state before mutating, so calling this on every `apply_subnet_route`
/// is safe.
///
/// Steps:
///   1. sysctl ip_forward=1 (global) — kernel won't forward without it.
///   2. sysctl rp_filter=0 on wolfnet iface + all — loose mode so
///      WolfNet-sourced packets aren't dropped by reverse-path checks.
///   3. iptables FORWARD ACCEPT both ways between wolfnet iface and the
///      subnet — Docker/firewalld DROP defaults are otherwise fatal.
///   4. iptables NAT POSTROUTING MASQUERADE for traffic destined to the
///      subnet — so LAN hosts reply via their normal gateway instead of
///      trying to route back to a WolfNet peer they can't reach.
pub fn enable_subnet_route_forwarding(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    // 1. ip_forward — fire-and-forget; sysctl returns non-zero in some
    //    locked-down containers, but if it's already 1 we don't care.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // 2. rp_filter loose mode on wolfnet + all. /proc writes don't error
    //    if the file is already at the target value.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/rp_filter", wn_iface),
        "0",
    );
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    // Per-iface forwarding flag — global ip_forward implies all but some
    // distros gate per-iface via /proc/sys/net/ipv4/conf/<iface>/forwarding.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/forwarding", wn_iface),
        "1",
    );

    // 3. FORWARD ACCEPT both ways. We use -C to test for an existing
    //    rule before -I, so we don't duplicate on every reconcile. Errors
    //    on the -I are reported back to the caller (which logs them).
    let mut errors: Vec<String> = Vec::new();
    let forward_rules: [&[&str]; 2] = [
        &["-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"],
        &["-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"],
    ];
    for rule in &forward_rules {
        let mut check_args: Vec<&str> = vec!["-C", "FORWARD"];
        check_args.extend_from_slice(rule);
        let exists = Command::new("iptables")
            .args(&check_args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !exists {
            let mut add_args: Vec<&str> = vec!["-I", "FORWARD"];
            add_args.extend_from_slice(rule);
            let out = Command::new("iptables")
                .args(&add_args)
                .output()
                .map_err(|e| format!("iptables FORWARD insert exec failed: {}", e))?;
            if !out.status.success() {
                errors.push(format!(
                    "FORWARD {}: {}",
                    rule.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
    }

    // 4. POSTROUTING MASQUERADE for traffic destined into the subnet.
    //    We deliberately don't pin -o <egress>: the kernel routes the
    //    packet first, MASQUERADE then picks the egress iface's primary
    //    IP for the new source. -d <subnet> scopes the rule so we never
    //    masquerade unrelated traffic.
    let masq_check = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !masq_check {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
            .output()
            .map_err(|e| format!("iptables MASQUERADE exec failed: {}", e))?;
        if !out.status.success() {
            errors.push(format!(
                "POSTROUTING -d {} MASQUERADE: {}",
                route.subnet_cidr,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Snapshot of the kernel forwarding plumbing for a single subnet route —
/// inspected by the diagnostics endpoint so the operator can see WHY a
/// route is in the table but traffic isn't passing. Sponsor klasSponsor
/// (2026-04-27) reported "health says OK but ping doesn't work" because
/// pre-v20.11.4 we only checked the route entry, not the forwarding
/// plumbing it depends on.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForwardingState {
    /// Global net.ipv4.ip_forward value as a string ("1" / "0").
    pub ip_forward: Option<String>,
    /// rp_filter on the wolfnet iface (and on `all`); strict mode (1)
    /// silently drops WolfNet-sourced traffic in some topologies.
    pub rp_filter_wolfnet: Option<String>,
    pub rp_filter_all: Option<String>,
    /// True when iptables FORWARD has an ACCEPT rule for traffic from
    /// the wolfnet iface destined to the subnet.
    pub forward_in: bool,
    /// True when iptables FORWARD has an ACCEPT rule for return traffic
    /// from the subnet going back out the wolfnet iface.
    pub forward_out: bool,
    /// True when iptables NAT POSTROUTING has the MASQUERADE rule that
    /// rewrites WolfNet source IPs so the LAN host can reply normally.
    pub masquerade: bool,
    /// Wolfnet iface name we inspected against (for the operator to
    /// double-check the right interface was probed).
    pub wolfnet_iface: String,
    /// Egress interface the kernel would use to send a packet INTO the
    /// subnet from this node — derived from `ip route get <first IP in
    /// subnet>`. On the gateway this MUST be a LAN-side iface that's
    /// physically connected to the subnet; if it's the wolfnet iface
    /// we'd loop, and if it's the default-route iface the gateway has
    /// no actual path to the LAN. v22.0.2 — added after sponsor
    /// klasSponsor's diagnostics page went all-green but pings still
    /// failed because the gateway VPS had no LAN-side route to
    /// 10.10.0.0/16 (the WolfStack plumbing was correct; the gateway
    /// box itself wasn't physically wired into the LAN).
    pub subnet_egress_iface: Option<String>,
    /// Source IP the kernel would pick for that egress.
    pub subnet_egress_src: Option<String>,
}

/// Inspect the kernel forwarding state for a given subnet route. Pure
/// read — never mutates. Each field corresponds to one of the four
/// plumbing requirements `enable_subnet_route_forwarding` installs.
pub fn read_forwarding_state(route: &SubnetRoute) -> ForwardingState {
    use std::process::Command;
    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    let read = |path: &str| std::fs::read_to_string(path).ok().map(|s| s.trim().to_string());
    let ip_forward = read("/proc/sys/net/ipv4/ip_forward");
    let rp_filter_all = read("/proc/sys/net/ipv4/conf/all/rp_filter");
    let rp_filter_wolfnet = read(&format!("/proc/sys/net/ipv4/conf/{}/rp_filter", wn_iface));

    let check = |args: &[&str]| -> bool {
        Command::new("iptables")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    let forward_in = check(&["-C", "FORWARD", "-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"]);
    let forward_out = check(&["-C", "FORWARD", "-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"]);
    let masquerade = check(&["-t", "nat", "-C", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"]);

    // Probe how the kernel would actually send a packet into the subnet.
    // We run `ip route get` against a representative address (the network
    // address + 1, which is in-range for any sensible CIDR). The result
    // tells us the real egress iface and source IP — on the gateway,
    // anything other than a LAN-facing iface is a problem WolfStack's
    // four other checks can't detect.
    let (subnet_egress_iface, subnet_egress_src) = inspect_subnet_egress(&route.subnet_cidr);

    ForwardingState {
        ip_forward,
        rp_filter_wolfnet,
        rp_filter_all,
        forward_in,
        forward_out,
        masquerade,
        wolfnet_iface: wn_iface,
        subnet_egress_iface,
        subnet_egress_src,
    }
}

/// First usable address in a CIDR, suitable as a probe target for
/// `ip route get`. Returns None on malformed CIDR. For /24+ the network
/// address has a 0 last octet, so +1 is the conventional first host;
/// for narrower prefixes we'd hit edge cases, but those subnets
/// (a /31 or /32) aren't realistic destinations for subnet routing.
pub fn first_addr_in_cidr(cidr: &str) -> Option<String> {
    let (net, _prefix) = parse_cidr(cidr)?;
    let parts: Vec<u8> = net.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    let last = parts[3].saturating_add(1);
    Some(format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], last))
}

/// Run `ip -4 route get <first-in-subnet>` and pull out the egress iface
/// + source IP. Returns (None, None) if anything failed (parse error,
/// command error, kernel said unreachable). Pure read.
fn inspect_subnet_egress(cidr: &str) -> (Option<String>, Option<String>) {
    use std::process::Command;
    let probe_ip = match first_addr_in_cidr(cidr) {
        Some(ip) => ip,
        None => return (None, None),
    };
    let out = Command::new("ip")
        .args(["-4", "route", "get", &probe_ip])
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&stdout);
    // Format examples:
    //   "10.10.0.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0 \n    cache"
    //   "10.10.0.1 dev wolfnet0 src 10.100.10.30 uid 0 \n    cache"
    // We walk tokens looking for "dev <X>" and "src <Y>".
    let mut iface = None;
    let mut src = None;
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        match tok {
            "dev" => iface = tokens.next().map(|s| s.to_string()),
            "src" => src = tokens.next().map(|s| s.to_string()),
            _ => {}
        }
    }
    (iface, src)
}

/// Tear down the iptables rules that `enable_subnet_route_forwarding`
/// installed. Idempotent: missing rules are not an error. We deliberately
/// leave sysctl knobs (ip_forward, rp_filter) alone — other WolfStack
/// features (wolfrun, WolfNet proxies, VM bridges) depend on them and
/// flipping them back to defaults would break unrelated traffic.
pub fn disable_subnet_route_forwarding(route: &SubnetRoute) -> Result<(), String> {
    use std::process::Command;

    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());

    // Loop on -D for each rule so duplicates (from older buggy versions
    // that lacked the -C guard) all get cleaned up. Cap the loop so a
    // pathological state can't spin forever.
    let forward_rules: [&[&str]; 2] = [
        &["-i", &wn_iface, "-d", &route.subnet_cidr, "-j", "ACCEPT"],
        &["-s", &route.subnet_cidr, "-o", &wn_iface, "-j", "ACCEPT"],
    ];
    for rule in &forward_rules {
        for _ in 0..16 {
            let mut args: Vec<&str> = vec!["-D", "FORWARD"];
            args.extend_from_slice(rule);
            let out = Command::new("iptables").args(&args).output();
            match out {
                Ok(o) if o.status.success() => continue, // try again — may be a duplicate
                _ => break,
            }
        }
    }

    for _ in 0..16 {
        let out = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-d", &route.subnet_cidr, "-j", "MASQUERADE"])
            .output();
        match out {
            Ok(o) if o.status.success() => continue,
            _ => break,
        }
    }

    Ok(())
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

    // Gateway-side dispatch (mirrors apply_subnet_route, v20.11.6): if
    // this node OWNS the gateway IP we never installed a kernel route
    // entry — only the forwarding plumbing. Strip that and we're done.
    if node_is_route_gateway(route) {
        return disable_subnet_route_forwarding(route);
    }

    // Consumer role: only a kernel route entry to remove. We never
    // installed plumbing on the consumer (post-v20.11.6) so there's
    // nothing to clean on the iptables side. Older versions (v20.11.5)
    // did install plumbing here — the next gateway-side apply will
    // replace those rules and any leftover consumer rules are harmless
    // (MASQUERADE -d <subnet> on a non-forwarding node is a no-op).
    match read_kernel_route_gateway(&route.subnet_cidr) {
        Ok(None) => return Ok(()),
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

/// True when this node owns the wolfnet0 address listed as the route's
/// gateway. The gateway-owning node is the forwarder — its wolfnet0
/// receives packets from peers, and its LAN interface delivers them to
/// the destination subnet. We install iptables/sysctl plumbing on the
/// forwarder rather than a kernel route entry (an `ip route add ... via
/// <my-own-ip>` is rejected by the kernel and would loop anyway).
///
/// Implementation: shells out to `ip -4 addr show <wolfnet-iface>` and
/// scans for `inet <addr>/...` lines. We don't cache because wolfnet0
/// addresses can change at runtime when WolfNet reconfigures, and this
/// is called only from apply/remove paths and the diagnostics endpoint.
pub fn node_is_route_gateway(route: &SubnetRoute) -> bool {
    use std::process::Command;
    let wn_iface = crate::networking::detect_wolfnet_iface()
        .unwrap_or_else(|| "wolfnet0".to_string());
    let out = match Command::new("ip")
        .args(["-4", "addr", "show", &wn_iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        let rest = match trimmed.strip_prefix("inet ") {
            Some(r) => r,
            None => continue,
        };
        let addr_with_prefix = match rest.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let addr = addr_with_prefix.split('/').next().unwrap_or("");
        if addr == route.gateway {
            return true;
        }
    }
    false
}

/// True when this node has any role to play in installing a subnet route
/// — either as a configured target (it gets the kernel route entry) or
/// as the gateway (it gets the forwarding plumbing). All apply/remove
/// call sites filter through this so the gateway never gets skipped.
pub fn node_handles_route(route: &SubnetRoute, self_node_id: &str) -> bool {
    route_targets_self(route, self_node_id) || node_is_route_gateway(route)
}

/// True when the route should be installed on the node identified by
/// `self_node_id`. Encapsulates the "None == cluster-wide, Some(id) == that
/// node only" rule so all callers (startup, create, update, config_receive)
/// agree.
pub fn route_targets_self(route: &SubnetRoute, self_node_id: &str) -> bool {
    route.node_id.is_none() || route.node_id.as_deref() == Some(self_node_id)
}
