// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Reverse-proxy entries — part of WolfRouter, not a separate product.
//!
//! ## What this actually does
//!
//! This is **not** an HTTP reverse proxy. Each `ProxyEntry` maps a
//! public IP (auto-resolved from the configured domain name, or pinned
//! manually) to a single backend — a VM, a container, or any IP — and
//! forwards *every* port of *every* protocol to it. Traffic hits the
//! public IP on this host, iptables DNAT rewrites the destination to
//! the backend, and SNAT ensures the reply comes back through this
//! node. HTTP, HTTPS, SSH, SMTP, anything.
//!
//! Implementation is plain iptables — no userspace proxy involved.
//! The forwarding primitive is the same one the existing IP Mapping
//! feature uses (see `src/networking/mod.rs::apply_mapping_rules`),
//! but without a port filter, so it catches every TCP + UDP stream.
//!
//! ## DNS resolution
//!
//! If the operator configures a domain with auto-resolve, apply_for_node
//! does a single A-record lookup at write time and caches the result in
//! `resolved_public_ip`. It does NOT re-resolve on every packet. If the
//! DNS record moves, re-save the entry (or click "Re-resolve" in the
//! UI, TODO). Using the cached IP means nginx-style "follow the DNS"
//! surprises are impossible — what the operator saved is what runs.
//!
//! ## Limits
//!
//! - One domain per public IP. You can't share a public IP across
//!   multiple domain forwards — there's no port/protocol field in the
//!   packet saying which domain it's for once you're past the TLS
//!   handshake, so the kernel would have to guess. Use the port-
//!   specific IP Mapping feature if you need to multiplex.
//! - This host must be the one receiving the domain's traffic —
//!   iptables on other nodes doesn't see packets destined for a
//!   public IP they don't hold.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// A single domain-forwarding entry. Persisted as part of RouterConfig
/// so edits travel with the rest of the router config for backup/restore.
///
/// A single entry can target one backend (simple domain → IP) or many
/// backends with a load-balancing policy — the iptables `statistic`
/// module handles the distribution, matching what WolfRun VIPs already
/// do. See `apply_entry` for the generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,
    /// Public hostname that resolves to this node's public IP. Used for
    /// display and, if `resolved_public_ip` is empty, as the DNS lookup
    /// seed at apply time.
    pub domain: String,
    /// Which cluster node hosts the public IP that receives this domain's
    /// traffic. apply_for_node only touches entries bound to the local
    /// node — iptables on other nodes doesn't see these packets.
    pub node_id: String,
    /// One or more backends to distribute traffic to. If exactly one,
    /// every packet goes there (no `statistic` match). If more than one,
    /// the `lb_policy` field picks the distribution scheme.
    #[serde(default)]
    pub backends: Vec<ProxyBackend>,
    /// Load-balancing policy when `backends.len() > 1`:
    /// - `round_robin` — iptables `statistic --mode nth` cycle
    /// - `ip_hash`     — iptables `statistic --mode random` (note: this
    ///   is weighted random, not true hash-based stickiness. Matches the
    ///   existing WolfRun VIP behavior so operators see one consistent
    ///   primitive. If a future requirement needs real source-IP
    ///   stickiness, add a separate `sticky` policy and use conntrack
    ///   zones or the `hashmark` target.)
    #[serde(default = "default_lb_policy")]
    pub lb_policy: String,
    /// Public IP on this node that receives packets for `domain`. Set
    /// manually or resolved via DNS at save/apply time. Kept explicit
    /// so iptables rules don't silently shift when DNS flaps.
    #[serde(default)]
    pub resolved_public_ip: String,
    /// Disable without deleting — lets the operator toggle a forward
    /// off when debugging without losing the config.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Free-text label for the operator — shown in the UI.
    #[serde(default)]
    pub description: Option<String>,
}

fn default_lb_policy() -> String { "round_robin".into() }

/// Where the proxy forwards traffic. The `Vm` / `Container` variants
/// carry a resolved host at save time so apply doesn't need to re-query
/// the VM/container manager every time rules are rebuilt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProxyBackend {
    /// Free-form IP or hostname.
    Custom {
        host: String,
    },
    /// VM picked from the cluster.
    Vm {
        vm_id: String,
        vm_name: String,
        /// Which VM manager this came from — libvirt (WolfStack-native),
        /// proxmox, etc. Used for UI labeling and grouping.
        vm_type: String,
        host: String,
    },
    /// Docker or LXC container.
    Container {
        container_id: String,
        container_name: String,
        /// "docker" or "lxc".
        container_type: String,
        host: String,
    },
}

impl ProxyBackend {
    pub fn host(&self) -> &str {
        match self {
            ProxyBackend::Custom { host } => host,
            ProxyBackend::Vm { host, .. } => host,
            ProxyBackend::Container { host, .. } => host,
        }
    }
}

fn default_true() -> bool { true }

/// Resolve a domain to its first IPv4 via the system resolver. We
/// deliberately use getaddrinfo (via std::net::ToSocketAddrs with a
/// dummy port) so /etc/hosts, systemd-resolved, and nsswitch all get
/// a vote. Returns None on NXDOMAIN or no IPv4 answer.
fn resolve_domain_v4(domain: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let target = format!("{}:80", domain);
    target.to_socket_addrs().ok()?.find_map(|sa| match sa {
        std::net::SocketAddr::V4(v4) => Some(v4.ip().to_string()),
        _ => None,
    })
}

/// Ensure the entry has a public IP resolved. If the operator pinned
/// one, keep it; otherwise DNS-resolve the domain once. Returns the
/// effective public IP, or an error describing why resolution failed.
pub fn resolve_entry_public_ip(entry: &mut ProxyEntry) -> Result<String, String> {
    if !entry.resolved_public_ip.trim().is_empty() {
        return Ok(entry.resolved_public_ip.trim().to_string());
    }
    match resolve_domain_v4(&entry.domain) {
        Some(ip) => {
            entry.resolved_public_ip = ip.clone();
            Ok(ip)
        }
        None => Err(format!(
            "Could not resolve '{}' to an IPv4 address. \
             Configure DNS first or pin a public IP in the form.",
            entry.domain
        )),
    }
}

/// iptables comment tag used on every rule this module writes. Lets us
/// find and remove stale rules across restarts without tracking them
/// externally. Same pattern as the IP-mapping comment tag in
/// src/networking/mod.rs.
fn comment_tag(id: &str) -> String { format!("wolfstack-proxy-{}", id) }

/// Delete every iptables rule carrying a given comment, across the
/// chains/tables we actually write to. Best-effort — errors are
/// swallowed so a missing rule doesn't prevent the next apply.
fn purge_by_comment(comment: &str) {
    for (table, chain) in &[
        ("nat", "PREROUTING"),
        ("nat", "OUTPUT"),
        ("nat", "POSTROUTING"),
        ("filter", "FORWARD"),
    ] {
        loop {
            let out = Command::new("iptables")
                .args(["-t", table, "-L", chain, "--line-numbers", "-n"])
                .output();
            let text = match out {
                Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => break,
            };
            let mut found = None;
            for line in text.lines().rev() {
                if line.contains(comment) {
                    if let Some(n) = line.split_whitespace().next().and_then(|x| x.parse::<u32>().ok()) {
                        found = Some(n);
                        break;
                    }
                }
            }
            match found {
                Some(n) => {
                    let _ = Command::new("iptables")
                        .args(["-t", table, "-D", chain, &n.to_string()])
                        .output();
                }
                None => break,
            }
        }
    }
}

/// Detect this host's first routable IPv4 — used as the SNAT source
/// when the backend lives on a private network the original client
/// can't reach. Falls back to the public_ip itself if nothing obvious
/// is found (works fine when backend is on the same LAN).
fn detect_snat_source(public_ip: &str) -> String {
    // Try `ip route get <backend>` equivalent via `ip -4 route get public_ip`.
    // We just need *some* source IP on this host that shares a route with
    // the backend — the kernel picks this anyway, but asking explicitly
    // lets us bake it into the SNAT rule so conntrack has a fixed answer.
    let out = Command::new("ip").args(["-4", "route", "get", public_ip]).output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            // Expected format: "1.2.3.4 dev eth0 src 1.2.3.5 uid 0"
            if let Some(idx) = s.find(" src ") {
                let rest = &s[idx + 5..];
                if let Some(end) = rest.find(char::is_whitespace) {
                    return rest[..end].to_string();
                }
            }
        }
    }
    public_ip.to_string()
}

fn run_iptables(args: &[&str]) -> Result<(), String> {
    let out = Command::new("iptables").args(args).output()
        .map_err(|e| format!("iptables not available: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Write iptables rules for one entry across its one-or-more backends.
/// Captures TCP+UDP on every port — no --dport, no -p filter — so
/// every service the backend listens on is reachable.
///
/// Load-balancing with multiple backends uses the same approach as
/// WolfRun VIPs in `src/networking/mod.rs::apply_vip_mapping_rules`:
/// iptables `statistic --mode nth` for round-robin, `--mode random`
/// for weighted random (exposed as "ip_hash" in the UI to match the
/// existing terminology).
///
/// Return-path SNAT rewrites the source to this node's routable IP
/// so the backend's reply comes back through this host and conntrack
/// un-DNATs it correctly.
fn apply_entry(entry: &ProxyEntry, public_ip: &str) -> Result<(), String> {
    // Collect backend hosts, reject empties early. An entry with zero
    // valid backends can't forward anything.
    let hosts: Vec<String> = entry.backends.iter()
        .map(|b| b.host().trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();
    if hosts.is_empty() {
        return Err(format!(
            "no valid backend IPs for '{}' — pick a running VM/container or enter an IP",
            entry.domain
        ));
    }
    let tag = comment_tag(&entry.id);
    let lb = entry.lb_policy.as_str();
    let n = hosts.len();

    // PREROUTING + OUTPUT DNAT — one rule per backend with a statistic
    // match when n > 1. "remaining" shrinks as we advance so each
    // backend gets an equal share even though `statistic --mode nth`
    // evaluates rules top-to-bottom.
    for chain in &["PREROUTING", "OUTPUT"] {
        for (i, backend) in hosts.iter().enumerate() {
            let remaining = n - i;
            let mut args: Vec<String> = vec![
                "-t".into(), "nat".into(), "-A".into(), (*chain).to_string(),
                "-d".into(), public_ip.to_string(),
            ];
            if remaining > 1 {
                if lb == "ip_hash" {
                    // Weighted random — see module docs on policy naming.
                    let prob = 1.0 / remaining as f64;
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "random".into(),
                        "--probability".into(), format!("{:.6}", prob),
                    ]);
                } else {
                    // round_robin
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "nth".into(),
                        "--every".into(), remaining.to_string(),
                        "--packet".into(), "0".into(),
                    ]);
                }
            }
            args.extend_from_slice(&[
                "-j".into(), "DNAT".into(),
                "--to-destination".into(), backend.clone(),
                "-m".into(), "comment".into(),
                "--comment".into(), tag.clone(),
            ]);
            run_iptables_vec(&args)?;
        }
    }

    // Return path — SNAT + FORWARD accept, one pair per backend. SNAT
    // source is this host's local routable IP relative to each backend
    // (detected per-backend — they may sit on different subnets).
    for backend in &hosts {
        let snat_src = detect_snat_source(backend);
        let snat_args: Vec<String> = vec![
            "-t".into(), "nat".into(), "-A".into(), "POSTROUTING".into(),
            "-d".into(), backend.clone(),
            "-j".into(), "SNAT".into(),
            "--to-source".into(), snat_src,
            "-m".into(), "comment".into(),
            "--comment".into(), tag.clone(),
        ];
        run_iptables_vec(&snat_args)?;

        let fwd_args: Vec<String> = vec![
            "-I".into(), "FORWARD".into(), "1".into(),
            "-d".into(), backend.clone(),
            "-m".into(), "conntrack".into(),
            "--ctstate".into(), "DNAT".into(),
            "-j".into(), "ACCEPT".into(),
            "-m".into(), "comment".into(),
            "--comment".into(), tag.clone(),
        ];
        run_iptables_vec(&fwd_args)?;
    }

    Ok(())
}

fn run_iptables_vec(args: &[String]) -> Result<(), String> {
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_iptables(&str_args)
}

/// Re-apply every enabled entry bound to this node. Idempotent — every
/// call first purges the rules it owns (matched by comment tag), then
/// rewrites them fresh. Called at startup and after every edit.
/// Returns per-entry warnings; empty vec = clean apply.
pub fn apply_for_node(proxies: &[ProxyEntry], self_node_id: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // Enable IP forwarding — should already be on if WolfStack is doing
    // any NAT, but cheap insurance.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    for entry in proxies {
        // Always purge first, even for disabled entries — an operator
        // toggling `enabled=false` expects the forward to go away.
        purge_by_comment(&comment_tag(entry.id.as_str()));

        if !entry.enabled { continue; }
        if entry.node_id != self_node_id { continue; }

        // Clone so we can write the resolved IP back without fighting
        // with the caller's borrow — the real persistence happens in
        // the API handler before calling us.
        let public_ip = if !entry.resolved_public_ip.trim().is_empty() {
            entry.resolved_public_ip.clone()
        } else {
            match resolve_domain_v4(&entry.domain) {
                Some(ip) => ip,
                None => {
                    warnings.push(format!(
                        "proxy '{}' ({}): DNS resolution failed — no forwards installed for this entry",
                        entry.id, entry.domain
                    ));
                    continue;
                }
            }
        };

        if let Err(e) = apply_entry(entry, &public_ip) {
            warnings.push(format!("proxy '{}' ({}): {}", entry.id, entry.domain, e));
        }
    }

    warnings
}

/// Remove all iptables rules belonging to one entry id. Called from
/// the DELETE handler so stale rules don't linger between the config
/// write and the next apply.
pub fn remove_one(id: &str) {
    purge_by_comment(&comment_tag(id));
}
