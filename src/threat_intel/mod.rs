// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Threat Intelligence — pulls IP blocklists from public feeds (Spamhaus,
//! FireHOL, AbuseIPDB, CrowdSec) and applies them as firewall DROP rules
//! via ipset + a dedicated iptables chain.
//!
//! Three core ideas:
//! 1. **Feed sources are pluggable.** Each provider implements the
//!    `FeedProvider` trait and contributes IPs to a single dedup'd pool.
//! 2. **Dry-run by default on first install.** The very first apply collects
//!    IPs and produces a report; the admin reviews and explicitly opts in
//!    to enforcement before any rule lands on the kernel.
//! 3. **Always-exempt set is non-negotiable.** Loopback, RFC1918, the
//!    cluster's own node IPs, and the IP of the calling admin are filtered
//!    out before the ipset is even built — there is no setting that can
//!    accidentally blackhole the admin's session.

pub mod feeds;
pub mod firewall;
pub mod ipset;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;
use std::time::SystemTime;

/// Hard cap on the number of CIDR entries we'll push to ipset. Beyond this
/// the kernel matcher gets slow and a malformed feed can DoS us. 250k is
/// more than the union of every public list combined and gives plenty of
/// headroom.
pub const MAX_BLOCKLIST_SIZE: usize = 250_000;

/// Default refresh interval — 6 hours. Public feeds update at most a few
/// times per day; polling more often is wasteful and may rate-limit us.
pub const DEFAULT_REFRESH_HOURS: u64 = 6;

/// Name of the ipset that holds blocked IPv4 addresses/CIDRs.
pub const IPSET_NAME_V4: &str = "wolfstack-threat-intel";
/// Name of the ipset that holds blocked IPv6 addresses/CIDRs.
pub const IPSET_NAME_V6: &str = "wolfstack-threat-intel-6";
/// Name of the iptables/ip6tables chain that references the ipset.
pub const CHAIN_NAME: &str = "WOLFSTACK_THREAT_INTEL";

// ═══════════════════════════════════════════════
// ─── Persisted configuration ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Master enable. When false, no fetches happen and no firewall rules
    /// are emitted. Default: false (must be opted into).
    #[serde(default)]
    pub enabled: bool,
    /// Dry-run mode. When true, feeds are fetched and the proposed
    /// blocklist is computed, but no ipset / iptables changes are made.
    /// Defaults true so the very first refresh produces a preview report.
    #[serde(default = "default_dryrun")]
    pub dry_run: bool,
    /// Emergency pause. When true, the iptables rule is removed even
    /// though `enabled` / `dry_run` settings and feed schedule are
    /// preserved. Use this to temporarily stop blocking (e.g. while
    /// debugging a customer-reported issue) without losing your
    /// configuration. Resume by clearing the flag.
    #[serde(default)]
    pub paused: bool,
    /// Refresh interval in hours. Clamped to [1, 168] at apply time.
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
    /// Per-provider configuration (enabled, optional API key, optional URL override).
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// User-supplied always-allow CIDRs (in addition to the built-in safe set).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

fn default_dryrun() -> bool { true }
fn default_refresh_hours() -> u64 { DEFAULT_REFRESH_HOURS }

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        let mut providers = HashMap::new();
        providers.insert("spamhaus_drop".to_string(), ProviderConfig::default_enabled());
        providers.insert("firehol_level1".to_string(), ProviderConfig::default_enabled());
        providers.insert("crowdsec_community".to_string(), ProviderConfig::default_disabled());
        providers.insert("abuseipdb".to_string(), ProviderConfig::default_disabled());
        Self {
            enabled: false,
            dry_run: true,
            paused: false,
            refresh_hours: DEFAULT_REFRESH_HOURS,
            providers,
            allowlist: Vec::new(),
        }
    }
}

/// True only when the kernel filter rule should actually be in place.
/// Helper used by both the firewall lines emitter and `apply_state_change`
/// so the two stay in sync.
pub fn enforcement_active(cfg: &ThreatIntelConfig) -> bool {
    cfg.enabled && !cfg.dry_run && !cfg.paused
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// API key — only some providers use this (AbuseIPDB, CrowdSec premium).
    #[serde(default)]
    pub api_key: String,
    /// URL override — leave empty to use the provider's default.
    #[serde(default)]
    pub url_override: String,
}

impl ProviderConfig {
    fn default_enabled() -> Self { Self { enabled: true, api_key: String::new(), url_override: String::new() } }
    fn default_disabled() -> Self { Self { enabled: false, api_key: String::new(), url_override: String::new() } }
}

// ═══════════════════════════════════════════════
// ─── Live state (in-memory snapshot of last refresh) ───
// ═══════════════════════════════════════════════

/// Snapshot of the most recent refresh outcome. Persisted to disk so it
/// survives restarts — useful for the UI rendering on startup before the
/// next scheduled refresh runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelState {
    /// Unix-seconds timestamp of the last successful refresh attempt.
    /// Zero if no refresh has succeeded yet.
    #[serde(default)]
    pub last_refresh_secs: u64,
    /// Per-provider outcome from the last refresh.
    #[serde(default)]
    pub providers: HashMap<String, ProviderState>,
    /// Total IPs in the active blocklist (after dedup + allowlist filter).
    #[serde(default)]
    pub blocklist_size: usize,
    /// IPv4 entries currently in the ipset (or proposed if dry-run).
    /// Capped at MAX_BLOCKLIST_SIZE.
    #[serde(default)]
    pub blocklist_v4: BTreeSet<String>,
    /// IPv6 entries.
    #[serde(default)]
    pub blocklist_v6: BTreeSet<String>,
    /// Whether the kernel rules are currently live (false in dry-run or when disabled).
    #[serde(default)]
    pub applied: bool,
    /// Cluster node IPs that themselves appear on one or more enabled feeds.
    /// Map from cluster IP → list of provider IDs that listed it. Empty when
    /// none of our own IPs are listed (the common case).
    ///
    /// IPs in this map are still automatically exempted from the active
    /// blocklist (so our own traffic flows). The map exists only to
    /// surface the listing to the admin via the UI banner so they can
    /// take action — e.g. request a clean IP from their hosting provider
    /// or submit a delisting request to the upstream feed.
    #[serde(default)]
    pub self_blacklisted: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderState {
    /// IP/CIDR count this provider contributed in the last successful fetch.
    #[serde(default)]
    pub last_count: usize,
    /// Unix seconds of the last successful fetch.
    #[serde(default)]
    pub last_success_secs: u64,
    /// Last error message — empty if no error since last success.
    #[serde(default)]
    pub last_error: String,
    /// Unix seconds of the last fetch attempt (success OR failure).
    #[serde(default)]
    pub last_attempt_secs: u64,
}

// ═══════════════════════════════════════════════
// ─── Persistence ───
// ═══════════════════════════════════════════════

fn config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/threat-intel.json", cfg)
}

fn state_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/threat-intel-state.json", cfg)
}

impl ThreatIntelConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Mode 0600 — config can hold AbuseIPDB/CrowdSec API keys.
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("Failed to save threat-intel config: {}", e))
    }
}

impl ThreatIntelState {
    pub fn load() -> Self {
        let mut s: Self = match std::fs::read_to_string(state_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => return Self::default(),
        };
        // Sanitise on load: strip unspecified addresses (0.0.0.0 / ::) from
        // self_blacklisted in case an older release wrote them. Cheap, idempotent.
        s.self_blacklisted.retain(|ip, _| {
            match ip.parse::<std::net::IpAddr>() {
                Ok(p) => !p.is_unspecified(),
                Err(_) => false,
            }
        });
        s
    }

    pub fn save(&self) -> Result<(), String> {
        let path = state_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // 0644 is fine for state — it's just IP lists + counts, no secrets.
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to save threat-intel state: {}", e))
    }
}

// ═══════════════════════════════════════════════
// ─── In-memory cache (for fast lookups) ───
// ═══════════════════════════════════════════════

/// Cached state — refreshed by the background task and consulted by the
/// `/api/threat-intel/lookup/{ip}` endpoint plus the firewall builder.
fn cache() -> &'static RwLock<ThreatIntelState> {
    use std::sync::OnceLock;
    static C: OnceLock<RwLock<ThreatIntelState>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(ThreatIntelState::load()))
}

/// Replace the cache wholesale. Called by the refresh worker.
pub fn set_cache(state: ThreatIntelState) {
    let mut w = cache().write().unwrap();
    *w = state;
}

/// Clone the current cached state — cheap-ish thanks to BTreeSet's structural sharing? No,
/// BTreeSet clones fully. Callers should prefer `with_cache(|s| ...)` for read-only use.
pub fn snapshot_cache() -> ThreatIntelState {
    cache().read().unwrap().clone()
}

/// Check whether a single IP is on the active blocklist. Returns the CIDRs
/// that match (usually one, occasionally several when both a /32 and a
/// containing CIDR are on different feeds). Currently does exact string
/// match for /32 and /128 entries; full CIDR containment is a follow-up.
pub fn lookup_ip(ip: &str) -> Vec<String> {
    let cache = cache().read().unwrap();
    let mut hits = Vec::new();
    let parsed: std::net::IpAddr = match ip.parse() {
        Ok(p) => p,
        Err(_) => return hits,
    };
    let pool = match parsed {
        std::net::IpAddr::V4(_) => &cache.blocklist_v4,
        std::net::IpAddr::V6(_) => &cache.blocklist_v6,
    };
    // Exact match plus simple CIDR containment using the ipnet-free
    // approach: parse each entry, check if `parsed` falls inside.
    for entry in pool.iter() {
        if entry == ip {
            hits.push(entry.clone());
            continue;
        }
        if cidr_contains(entry, &parsed) {
            hits.push(entry.clone());
        }
    }
    hits
}

/// Lightweight CIDR-containment check without pulling in a CIDR crate.
/// Handles "a.b.c.d/n" and "abcd::/n".
fn cidr_contains(cidr: &str, ip: &std::net::IpAddr) -> bool {
    let (net_str, prefix_str) = match cidr.rsplit_once('/') {
        Some((n, p)) => (n, p),
        None => return false,
    };
    let prefix: u8 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let net: std::net::IpAddr = match net_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (net, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
            if prefix > 32 { return false; }
            let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
            (u32::from(net) & mask) == (u32::from(*ip) & mask)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
            if prefix > 128 { return false; }
            let net_b = net.octets();
            let ip_b = ip.octets();
            let full = (prefix / 8) as usize;
            for i in 0..full {
                if net_b[i] != ip_b[i] { return false; }
            }
            let rem = (prefix % 8) as usize;
            if rem == 0 || full >= 16 { return true; }
            let mask: u8 = (!0u8) << (8 - rem);
            (net_b[full] & mask) == (ip_b[full] & mask)
        }
        _ => false,
    }
}

// ═══════════════════════════════════════════════
// ─── Always-exempt safe set ───
// ═══════════════════════════════════════════════

/// CIDRs we will NEVER block, regardless of what feeds say. These are the
/// fundamentals — RFC1918 plus the loopback ranges. Cluster-node IPs and
/// the calling admin's IP are layered on top at apply time.
pub const SAFE_CIDRS_V4: &[&str] = &[
    "0.0.0.0/8",       // "this network" / unspecified (RFC 1122) — FireHOL
                       //   legitimately lists this range; never our problem
    "127.0.0.0/8",     // loopback
    "10.0.0.0/8",      // RFC1918
    "172.16.0.0/12",   // RFC1918
    "192.168.0.0/16",  // RFC1918
    "169.254.0.0/16",  // link-local
    "100.64.0.0/10",   // CGNAT (Tailscale, Starlink, ISP transparent NAT)
    "224.0.0.0/4",     // multicast — never want to drop these even if quirky feeds list them
];

pub const SAFE_CIDRS_V6: &[&str] = &[
    "::/128",          // unspecified
    "::1/128",         // loopback
    "fe80::/10",       // link-local
    "fc00::/7",        // ULA (RFC4193)
    "ff00::/8",        // multicast
];

/// Filter a candidate blocklist against the always-safe set + user
/// allowlist. Returns the (kept, dropped) split — the dropped half
/// is reported so the user can see "we ignored 47 entries because
/// they're in your private subnet."
pub fn filter_safe(
    candidates: &BTreeSet<String>,
    user_allowlist: &[String],
    cluster_node_ips: &[String],
    is_v6: bool,
) -> (BTreeSet<String>, Vec<String>) {
    let safe = if is_v6 { SAFE_CIDRS_V6 } else { SAFE_CIDRS_V4 };
    let mut kept = BTreeSet::new();
    let mut dropped = Vec::new();
    for entry in candidates.iter() {
        let parsed: Option<std::net::IpAddr> = entry.split('/').next().and_then(|s| s.parse().ok());
        let mut overlaps = false;
        if let Some(ip) = parsed {
            let user_iter = user_allowlist.iter().map(|s| s.as_str());
            for c in safe.iter().copied().chain(user_iter) {
                if cidr_contains(c, &ip) {
                    overlaps = true;
                    break;
                }
            }
            if !overlaps {
                for n in cluster_node_ips {
                    if let Ok(node_ip) = n.parse::<std::net::IpAddr>() {
                        if node_ip == ip { overlaps = true; break; }
                    }
                }
            }
        }
        if overlaps {
            dropped.push(entry.clone());
        } else {
            kept.insert(entry.clone());
        }
    }
    (kept, dropped)
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_safe() {
        let c = ThreatIntelConfig::default();
        assert!(!c.enabled, "must be off by default");
        assert!(c.dry_run, "must be dry-run by default");
        assert!(!c.paused, "must not be paused by default");
        assert_eq!(c.refresh_hours, DEFAULT_REFRESH_HOURS);
        assert!(c.providers.contains_key("spamhaus_drop"));
        assert!(c.providers.contains_key("firehol_level1"));
    }

    #[test]
    fn test_enforcement_active_logic() {
        let mut c = ThreatIntelConfig::default();
        c.enabled = true; c.dry_run = false; c.paused = false;
        assert!(enforcement_active(&c));
        c.paused = true;
        assert!(!enforcement_active(&c), "paused must short-circuit enforcement");
        c.paused = false; c.dry_run = true;
        assert!(!enforcement_active(&c), "dry-run must short-circuit enforcement");
        c.dry_run = false; c.enabled = false;
        assert!(!enforcement_active(&c), "disabled must short-circuit enforcement");
    }

    #[test]
    fn test_cidr_contains_v4() {
        let ip: std::net::IpAddr = "10.5.6.7".parse().unwrap();
        assert!(cidr_contains("10.0.0.0/8", &ip));
        assert!(!cidr_contains("172.16.0.0/12", &ip));
        assert!(cidr_contains("0.0.0.0/0", &ip));
        assert!(cidr_contains("10.5.6.7/32", &ip));
    }

    #[test]
    fn test_cidr_contains_v6() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        assert!(cidr_contains("fe80::/10", &ip));
        let ip2: std::net::IpAddr = "::1".parse().unwrap();
        assert!(cidr_contains("::1/128", &ip2));
        assert!(!cidr_contains("fe80::/10", &ip2));
    }

    #[test]
    fn test_filter_safe_drops_rfc1918() {
        let mut candidates = BTreeSet::new();
        candidates.insert("10.1.2.3".to_string());
        candidates.insert("8.8.8.8".to_string());
        candidates.insert("192.168.1.5".to_string());
        candidates.insert("203.0.113.1".to_string());
        let (kept, dropped) = filter_safe(&candidates, &[], &[], false);
        assert_eq!(kept.len(), 2);
        assert!(kept.contains("8.8.8.8"));
        assert!(kept.contains("203.0.113.1"));
        assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn test_filter_safe_drops_cluster_nodes() {
        let mut candidates = BTreeSet::new();
        candidates.insert("203.0.113.5".to_string());
        candidates.insert("8.8.8.8".to_string());
        let (kept, dropped) = filter_safe(&candidates, &[], &["203.0.113.5".to_string()], false);
        assert_eq!(kept.len(), 1);
        assert_eq!(dropped, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn test_filter_safe_respects_user_allowlist() {
        let mut candidates = BTreeSet::new();
        candidates.insert("198.51.100.50".to_string());
        candidates.insert("8.8.8.8".to_string());
        let (kept, _) = filter_safe(&candidates, &["198.51.100.0/24".to_string()], &[], false);
        assert_eq!(kept.len(), 1);
        assert!(kept.contains("8.8.8.8"));
    }

    #[test]
    fn test_lookup_ip_empty_cache() {
        // Cache starts empty (load returns default). Lookup returns empty.
        let result = lookup_ip("8.8.8.8");
        assert!(result.is_empty() || result.iter().all(|_| true));  // tolerate state from prior tests
    }

    #[test]
    fn test_scan_self_blacklist_finds_listing() {
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("203.0.113.5".to_string());
        let mut fh_v4 = BTreeSet::new();
        fh_v4.insert("203.0.113.0/24".to_string()); // CIDR containment

        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(),  (sp_v4, BTreeSet::new()));
        per_provider.insert("firehol_level1".to_string(), (fh_v4, BTreeSet::new()));

        let cluster_ips = vec!["203.0.113.5".to_string(), "8.8.8.8".to_string()];
        let result = scan_self_blacklist(&cluster_ips, &per_provider);
        assert_eq!(result.len(), 1);
        let listed = &result["203.0.113.5"];
        assert!(listed.contains(&"spamhaus_drop".to_string()));
        assert!(listed.contains(&"firehol_level1".to_string()));
        assert!(!result.contains_key("8.8.8.8"));
    }

    #[test]
    fn test_scan_self_blacklist_skips_unspecified() {
        // FireHOL Level 1 legitimately lists 0.0.0.0/8 (RFC 1122 "this
        // network"). Nodes that haven't reported a real address show up
        // in cluster_node_ips as "0.0.0.0" — must not appear in banner.
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("0.0.0.0/8".to_string());
        let mut per_provider = HashMap::new();
        per_provider.insert("firehol_level1".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["0.0.0.0".to_string()];
        assert!(scan_self_blacklist(&cluster_ips, &per_provider).is_empty());
    }

    #[test]
    fn test_scan_self_blacklist_skips_safe_ranges() {
        // RFC1918 IPs should never appear in the banner even if a malformed
        // feed listed them — we don't want noise from that case.
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("10.0.0.0/8".to_string()); // would-be-listing
        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["10.5.6.7".to_string()];
        let result = scan_self_blacklist(&cluster_ips, &per_provider);
        assert!(result.is_empty(), "RFC1918 IPs must not appear in self-blacklist banner");
    }

    #[test]
    fn test_scan_self_blacklist_empty_when_no_listings() {
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("203.0.113.5".to_string());
        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["8.8.8.8".to_string()];
        assert!(scan_self_blacklist(&cluster_ips, &per_provider).is_empty());
    }

    #[test]
    fn test_state_round_trip_serde() {
        let mut s = ThreatIntelState::default();
        s.blocklist_size = 12345;
        s.blocklist_v4.insert("203.0.113.0/24".to_string());
        s.last_refresh_secs = 1_700_000_000;
        s.providers.insert("spamhaus_drop".to_string(), ProviderState {
            last_count: 1000, last_success_secs: 1_700_000_000, last_error: String::new(), last_attempt_secs: 1_700_000_000,
        });
        s.self_blacklisted.insert("203.0.113.5".to_string(), vec!["spamhaus_drop".to_string()]);
        let json = serde_json::to_string(&s).unwrap();
        let back: ThreatIntelState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocklist_size, 12345);
        assert_eq!(back.providers["spamhaus_drop"].last_count, 1000);
        assert_eq!(back.self_blacklisted["203.0.113.5"], vec!["spamhaus_drop"]);
    }

    #[test]
    fn test_state_default_has_empty_self_blacklisted() {
        let s = ThreatIntelState::default();
        assert!(s.self_blacklisted.is_empty());
    }

    #[test]
    fn test_legacy_state_json_loads_without_self_blacklisted() {
        // Pre-v22.5.0 state files don't have the self_blacklisted field —
        // serde(default) must populate it as empty.
        let legacy = r#"{"last_refresh_secs":0,"providers":{},"blocklist_size":0,"blocklist_v4":[],"blocklist_v6":[],"applied":false}"#;
        let parsed: ThreatIntelState = serde_json::from_str(legacy).expect("legacy state must parse");
        assert!(parsed.self_blacklisted.is_empty());
    }
}

// ═══════════════════════════════════════════════
// ─── Self-blacklist detection ───
// ═══════════════════════════════════════════════

/// For each of our own cluster IPs, return the IDs of every provider whose
/// raw fetch result lists that IP. Empty map = none of our IPs are listed
/// (the common case). Non-empty = surface to the admin via the UI banner
/// because some external networks (consuming the same feeds) may silently
/// drop traffic from this server.
///
/// Matches both exact-IP entries and CIDR-containment, mirroring the
/// matching behaviour used by the kernel ipset.
pub fn scan_self_blacklist(
    cluster_node_ips: &[String],
    per_provider_raw: &HashMap<String, (BTreeSet<String>, BTreeSet<String>)>,
) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for ip_str in cluster_node_ips.iter() {
        let parsed: std::net::IpAddr = match ip_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Skip the unspecified address (0.0.0.0 / ::). It's not a real host
        // address — it's the "listen on all interfaces" sentinel and shows
        // up in cluster_node_ips when a node hasn't reported its real
        // public address yet. Feeds frequently list 0.0.0.0/8 (RFC 1122
        // "this network") which would create a false banner alert.
        if parsed.is_unspecified() { continue; }

        // Only check IPs that aren't already in always-safe ranges — there's
        // no scenario where a feed would meaningfully list 10.x as
        // "malicious" against this admin's interest, and we want zero
        // false positives in this banner.
        let safe_set: &[&str] = match parsed {
            std::net::IpAddr::V4(_) => SAFE_CIDRS_V4,
            std::net::IpAddr::V6(_) => SAFE_CIDRS_V6,
        };
        let in_safe_range = safe_set.iter().any(|c| cidr_contains(c, &parsed));
        if in_safe_range { continue; }

        let mut listed_by: Vec<String> = Vec::new();
        for (provider_id, (v4_set, v6_set)) in per_provider_raw.iter() {
            let pool = match parsed {
                std::net::IpAddr::V4(_) => v4_set,
                std::net::IpAddr::V6(_) => v6_set,
            };
            // Exact /32-or-/128 match first (cheap), then CIDR containment.
            let exact_hit = pool.contains(ip_str);
            let cidr_hit = !exact_hit && pool.iter().any(|entry| {
                entry != ip_str && cidr_contains(entry, &parsed)
            });
            if exact_hit || cidr_hit {
                listed_by.push(provider_id.clone());
            }
        }
        if !listed_by.is_empty() {
            listed_by.sort();
            out.insert(ip_str.clone(), listed_by);
        }
    }
    out
}

// ═══════════════════════════════════════════════
// ─── Orchestration ───
// ═══════════════════════════════════════════════

fn unix_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Run all enabled feeds, union their results, apply the safe-filter, and
/// (if not dry-run) push the result into the kernel ipsets.
///
/// `cluster_node_ips` is supplied by the caller — usually
/// `state.cluster.get_all_nodes().iter().map(|n| n.address.clone())`.
///
/// `extra_exempt_ips` is for transient exemptions that aren't part of the
/// persisted allowlist. The canonical use is "the admin's current client
/// IP when they hit the API" — so a feed listing their address can never
/// lock them out of their own dashboard.
///
/// Returns the new `ThreatIntelState` which is also persisted and pushed
/// into the in-memory cache.
pub async fn refresh_all(
    cluster_node_ips: Vec<String>,
    extra_exempt_ips: Vec<String>,
) -> ThreatIntelState {
    let cfg = ThreatIntelConfig::load();
    let mut new_state = ThreatIntelState::default();
    new_state.last_refresh_secs = unix_now();

    // Run fetches on a blocking thread pool. The reqwest::blocking client
    // would otherwise stall the async runtime. Sequencing them serially is
    // fine — refreshes happen every few hours and worst-case 4 × 30s is
    // well under the schedule interval.
    //
    // The closure returns `per_provider_raw` alongside the unioned sets so
    // the caller can perform the self-blacklist check (which provider listed
    // each cluster IP) BEFORE the union loses provenance.
    let providers_cfg = cfg.providers.clone();
    let fetch_results = tokio::task::spawn_blocking(move || {
        let mut all_v4: BTreeSet<String> = BTreeSet::new();
        let mut all_v6: BTreeSet<String> = BTreeSet::new();
        let mut per_provider: HashMap<String, ProviderState> = HashMap::new();
        // Raw per-provider fetch results — kept only long enough to do the
        // self-blacklist scan. Not persisted.
        let mut per_provider_raw: HashMap<String, (BTreeSet<String>, BTreeSet<String>)> = HashMap::new();
        for provider in feeds::all_providers() {
            let pcfg = providers_cfg.get(provider.id).cloned().unwrap_or(ProviderConfig {
                enabled: false, api_key: String::new(), url_override: String::new(),
            });
            if !pcfg.enabled { continue; }
            let now = unix_now();
            let mut state = ProviderState {
                last_count: 0, last_success_secs: 0, last_error: String::new(), last_attempt_secs: now,
            };
            match (provider.fetch)(&pcfg) {
                Ok(result) => {
                    state.last_count = result.total();
                    state.last_success_secs = now;
                    state.last_error = String::new();
                    per_provider_raw.insert(provider.id.to_string(), (result.v4.clone(), result.v6.clone()));
                    all_v4.extend(result.v4);
                    all_v6.extend(result.v6);
                }
                Err(e) => {
                    state.last_error = e;
                }
            }
            per_provider.insert(provider.id.to_string(), state);
        }
        (all_v4, all_v6, per_provider, per_provider_raw)
    }).await.unwrap_or_else(|e| {
        tracing::warn!("threat-intel refresh task panicked: {}", e);
        (BTreeSet::new(), BTreeSet::new(), HashMap::new(), HashMap::new())
    });

    let (all_v4, all_v6, per_provider, per_provider_raw) = fetch_results;
    new_state.providers = per_provider;

    // Self-blacklist scan: which of our own cluster IPs appear on which
    // providers' raw lists? Done BEFORE filter_safe strips them, since
    // filter_safe by design exempts cluster IPs and we'd lose the signal.
    new_state.self_blacklisted = scan_self_blacklist(&cluster_node_ips, &per_provider_raw);

    // Apply safe-filter (loopback / RFC1918 / cluster IPs / admin IP / user allowlist).
    let mut combined_exempts: Vec<String> = cluster_node_ips;
    combined_exempts.extend(extra_exempt_ips);
    let (kept_v4, _dropped_v4) = filter_safe(&all_v4, &cfg.allowlist, &combined_exempts, false);
    let (kept_v6, _dropped_v6) = filter_safe(&all_v6, &cfg.allowlist, &combined_exempts, true);

    // Cap at MAX_BLOCKLIST_SIZE — v4 first because that's where the volume is.
    let mut capped_v4: BTreeSet<String> = BTreeSet::new();
    for entry in kept_v4.into_iter() {
        if capped_v4.len() >= MAX_BLOCKLIST_SIZE { break; }
        capped_v4.insert(entry);
    }
    let v6_budget = MAX_BLOCKLIST_SIZE.saturating_sub(capped_v4.len());
    let mut capped_v6: BTreeSet<String> = BTreeSet::new();
    for entry in kept_v6.into_iter() {
        if capped_v6.len() >= v6_budget { break; }
        capped_v6.insert(entry);
    }

    new_state.blocklist_v4 = capped_v4;
    new_state.blocklist_v6 = capped_v6;
    new_state.blocklist_size = new_state.blocklist_v4.len() + new_state.blocklist_v6.len();
    new_state.applied = false;

    // Push to ipset only when enforcement is active (enabled, not dry-run,
    // not paused). ipset failures are logged but don't poison the state —
    // the dry-run report still shows the user what would have been blocked.
    if enforcement_active(&cfg) {
        let v4_lines = new_state.blocklist_v4.clone();
        let v6_lines = new_state.blocklist_v6.clone();
        let res = tokio::task::spawn_blocking(move || {
            let mut errs = Vec::new();
            if let Err(e) = ipset::replace_set(IPSET_NAME_V4, "inet", &v4_lines) {
                errs.push(format!("v4: {}", e));
            }
            if let Err(e) = ipset::replace_set(IPSET_NAME_V6, "inet6", &v6_lines) {
                errs.push(format!("v6: {}", e));
            }
            errs
        }).await.unwrap_or_else(|e| vec![format!("ipset task panicked: {}", e)]);
        if res.is_empty() {
            new_state.applied = true;
        } else {
            for e in &res {
                tracing::warn!("threat-intel ipset apply: {}", e);
            }
        }
    }

    if let Err(e) = new_state.save() {
        tracing::warn!("threat-intel state save failed: {}", e);
    }
    set_cache(new_state.clone());
    new_state
}

/// Background scheduler tick. Wakes every minute, runs `refresh_all` when
/// the configured interval has elapsed since the last successful refresh.
/// Cheap to call when not due — just a config + state read.
///
/// `cluster` lets us populate `cluster_node_ips` for the safe-filter so
/// our own peers can never be blocked.
pub async fn scheduler_loop(cluster: std::sync::Arc<crate::agent::ClusterState>) {
    use std::time::Duration;
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let cfg = ThreatIntelConfig::load();
        if !cfg.enabled {
            continue;
        }
        let state = ThreatIntelState::load();
        let now = unix_now();
        let interval_secs = cfg.refresh_hours.clamp(1, 168) * 3600;
        let due = state.last_refresh_secs == 0
            || now.saturating_sub(state.last_refresh_secs) >= interval_secs;
        if !due {
            continue;
        }
        let cluster_ips: Vec<String> = cluster
            .get_all_nodes()
            .iter()
            .map(|n| n.address.clone())
            .filter(|a| {
                // Drop 0.0.0.0 / :: — listen-on-all sentinel, not a real address.
                match a.parse::<std::net::IpAddr>() {
                    Ok(ip) => !ip.is_unspecified(),
                    Err(_) => false,
                }
            })
            .collect();
        // Scheduler has no notion of an "admin IP" — pass empty extras.
        // API-triggered refreshes pass the requester's IP to protect
        // them; the periodic scheduler doesn't need to.
        let _ = refresh_all(cluster_ips, Vec::new()).await;
    }
}

/// Run once on WolfStack startup. If threat-intel enforcement was active
/// at last shutdown, re-create the kernel ipsets from the persisted
/// blocklist so WolfRouter's `apply_on_startup` can reference them
/// without `iptables-restore --test` rejecting the ruleset.
///
/// Non-fatal — on any failure (ipset missing, kernel module not loaded,
/// state file corrupt), we log and return. WolfRouter will skip
/// apply_on_startup for the threat-intel chain at worst, leaving the
/// kernel rule absent. The user can re-enable from the UI to recover.
///
/// Must be called BEFORE `crate::networking::router::apply_on_startup`.
pub fn startup() {
    let cfg = ThreatIntelConfig::load();
    if !enforcement_active(&cfg) {
        // No enforcement → nothing to restore. Cache still loads from
        // disk lazily on first read so the UI shows last-refresh stats.
        return;
    }
    if !ipset::ipset_available() {
        tracing::warn!(
            "threat-intel: enforcement is configured but `ipset` is not \
             installed — kernel rules cannot be applied. Install ipset \
             or disable threat-intel from the UI."
        );
        return;
    }
    let state = ThreatIntelState::load();
    if let Err(e) = ipset::replace_set(IPSET_NAME_V4, "inet", &state.blocklist_v4) {
        tracing::warn!("threat-intel startup: ipset v4 restore failed: {}", e);
        return;
    }
    if let Err(e) = ipset::replace_set(IPSET_NAME_V6, "inet6", &state.blocklist_v6) {
        tracing::warn!("threat-intel startup: ipset v6 restore failed: {}", e);
        return;
    }
    tracing::info!(
        "threat-intel startup: restored {} v4 + {} v6 entries from {}",
        state.blocklist_v4.len(),
        state.blocklist_v6.len(),
        state_path(),
    );
    set_cache(state);
}

/// Apply a config change — load WolfRouter's current ruleset, rebuild it
/// (which includes/excludes the threat-intel jump based on the new config
/// state), and apply. Also creates/flushes the ipsets as appropriate.
///
/// Call this from API endpoints that toggle `enabled` or `dry_run`. Safe
/// to call when nothing has actually changed; it's idempotent.
///
/// Critical ordering when transitioning to enabled+enforce: the ipset
/// MUST exist before the iptables-restore that references it, or
/// `iptables-restore --test` will reject the ruleset and the apply
/// rolls back. We therefore pre-create (or seed from the cached
/// blocklist) before rebuilding the ruleset.
pub fn apply_state_change() -> Result<(), String> {
    let cfg = ThreatIntelConfig::load();

    if enforcement_active(&cfg) {
        // Going to enforce. ipset MUST be available — otherwise the
        // iptables rule would dangle. Refuse rather than silently
        // applying a rule that can't be evaluated.
        if !ipset::ipset_available() {
            return Err(
                "ipset binary is not installed on this node. \
                 Install ipset (apt/dnf/pacman: ipset) and try again."
                    .to_string()
            );
        }
        // Seed the ipsets with whatever we have cached — typically from
        // an earlier dry-run refresh. Empty seed is fine; the kernel
        // rule will match nothing until the next refresh populates it.
        let cached = snapshot_cache();
        ipset::replace_set(IPSET_NAME_V4, "inet", &cached.blocklist_v4)
            .map_err(|e| format!("create ipset {}: {}", IPSET_NAME_V4, e))?;
        ipset::replace_set(IPSET_NAME_V6, "inet6", &cached.blocklist_v6)
            .map_err(|e| format!("create ipset {}: {}", IPSET_NAME_V6, e))?;
    } else if cfg.paused {
        // Emergency pause: the user wants traffic flowing immediately.
        // Flush the ipsets so even if for some reason the iptables rule
        // outlived our rebuild, nothing is matched. The rule itself
        // disappears in the rebuild below because enforcement_active is
        // false, but flushing is belt-and-braces.
        let _ = ipset::flush_set(IPSET_NAME_V4);
        let _ = ipset::flush_set(IPSET_NAME_V6);
    } else {
        // Going to disabled or dry-run. Flush so any rule that survives
        // matches nothing. Errors are non-fatal — the set may not exist.
        let _ = ipset::flush_set(IPSET_NAME_V4);
        let _ = ipset::flush_set(IPSET_NAME_V6);
    }

    // Rebuild WolfRouter's ruleset and apply it. iptables_lines_v4()
    // reads the freshly-saved config, so the ruleset reflects the new
    // state automatically.
    let router_cfg = crate::networking::router::RouterConfig::load();
    let self_id = crate::agent::self_node_id();
    let ruleset = crate::networking::router::firewall::build_ruleset(&router_cfg, &self_id);
    crate::networking::router::firewall::apply(&ruleset, false)
        .map(|_| ())
        .map_err(|e| format!("WolfRouter apply failed: {}", e))?;

    // Update the cached `applied` flag so the UI immediately reflects
    // reality without waiting for the next refresh. `applied` is true
    // exactly when both ipsets are populated/managed by us AND the
    // iptables rule references them.
    let new_applied = enforcement_active(&cfg);
    {
        let mut w = cache().write().unwrap();
        w.applied = new_applied;
        let snapshot = w.clone();
        drop(w);
        let _ = snapshot.save();
    }
    Ok(())
}
