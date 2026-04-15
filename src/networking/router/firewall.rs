// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Firewall rule translator.
//!
//! Compiles `Vec<FirewallRule>` + `ZoneAssignments` into an
//! `iptables-restore` script for the filter table, tests it, and swaps
//! atomically. Keeps the existing WolfStack nat-table rules untouched —
//! those are still owned by networking::mod.rs (DNAT for IP mappings)
//! and vms::manager (MASQUERADE for WolfNet). We only touch filter.
//!
//! Atomicity model:
//!   1. Build full ruleset as a single iptables-save-format string.
//!   2. `iptables-restore --test` — rejects malformed rules without
//!      touching the live table.
//!   3. `iptables-restore` — swaps the whole filter table atomically.
//!   4. Store the previous dump in memory for safe-mode rollback.
//!
//! Safe-mode:
//!   If `safe_mode_seconds > 0`, apply() sets a rollback deadline and
//!   returns. A background task (installed by RouterState or the main
//!   tick loop) checks the deadline each second and reverts if not
//!   confirmed. `confirm()` clears the deadline.

use super::*;
use std::collections::HashSet;
use std::process::Command;
use tracing::{info, warn};

const FILTER_CHAINS: &[&str] = &["WOLFROUTER_FWD", "WOLFROUTER_IN", "WOLFROUTER_OUT"];

/// Build the iptables-save-format text for the filter table from the
/// current config. Idempotent: callers can compare output bytes to
/// detect no-op applies.
pub fn build_ruleset(config: &RouterConfig, self_node_id: &str) -> String {
    let mut out = String::new();
    out.push_str("*filter\n");
    // Ensure built-in chains exist with default policy ACCEPT (we rely
    // on explicit drops at the end of our custom chains rather than
    // default DROP — safer during apply).
    out.push_str(":INPUT ACCEPT [0:0]\n");
    out.push_str(":FORWARD ACCEPT [0:0]\n");
    out.push_str(":OUTPUT ACCEPT [0:0]\n");
    for chain in FILTER_CHAINS {
        out.push_str(&format!(":{} - [0:0]\n", chain));
    }

    // Built-in chains jump to our chains. `-I INPUT 1` semantics via
    // prepend isn't available in iptables-restore flat format; we
    // redeclare the chain body which iptables-restore replaces wholesale.
    out.push_str("-A INPUT -j WOLFROUTER_IN\n");
    out.push_str("-A FORWARD -j WOLFROUTER_FWD\n");
    out.push_str("-A OUTPUT -j WOLFROUTER_OUT\n");

    // Blanket state rule — accept ESTABLISHED,RELATED. Users only ever
    // write NEW rules (unless they disable state_track for a specific
    // rule), so replies to allowed outbound traffic come back without
    // needing explicit rules.
    for ch in FILTER_CHAINS {
        out.push_str(&format!(
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", ch
        ));
        // Allow loopback unconditionally — nothing good ever comes from
        // blocking 127.0.0.0/8 on a Linux host.
        out.push_str(&format!("-A {} -i lo -j ACCEPT\n", ch));
    }

    // User rules in order. Rules without a node_id match on any node;
    // rules with node_id set only apply on that node.
    let mut rules: Vec<&FirewallRule> = config.rules.iter()
        .filter(|r| r.enabled)
        .filter(|r| r.node_id.as_deref().map(|n| n == self_node_id).unwrap_or(true))
        .collect();
    rules.sort_by_key(|r| r.order);

    for r in rules {
        if let Some(line) = compile_rule(r, &config.zones, self_node_id) {
            out.push_str(&line);
            out.push('\n');
        }
    }

    out.push_str("COMMIT\n");
    out
}

/// Compile one FirewallRule to an `-A CHAIN ...` iptables-restore line.
/// Returns None if the rule can't be compiled (e.g. references an
/// unassigned zone, or a VM that doesn't exist) — the caller keeps
/// going; misconfigured rules don't break the ruleset.
fn compile_rule(rule: &FirewallRule, zones: &ZoneAssignments, self_node_id: &str) -> Option<String> {
    let chain = match rule.direction {
        Direction::Forward => "WOLFROUTER_FWD",
        Direction::Input => "WOLFROUTER_IN",
        Direction::Output => "WOLFROUTER_OUT",
    };

    let mut parts: Vec<String> = vec![format!("-A {}", chain)];

    // Protocol
    match rule.protocol {
        Protocol::Tcp => parts.push("-p tcp".into()),
        Protocol::Udp => parts.push("-p udp".into()),
        Protocol::Icmp => parts.push("-p icmp".into()),
        Protocol::Tcpudp => {
            // iptables can't do "either" in one rule. The caller should
            // duplicate rules for tcp/udp. Treat as "any" here.
        }
        Protocol::Any => {}
    }

    // Source endpoint
    for arg in endpoint_args(&rule.from, "src", zones, self_node_id)? {
        parts.push(arg);
    }
    // Destination endpoint
    for arg in endpoint_args(&rule.to, "dst", zones, self_node_id)? {
        parts.push(arg);
    }

    // Ports (only meaningful if protocol is tcp/udp)
    for ps in &rule.ports {
        let flag = match (ps.side, rule.protocol) {
            (PortSide::Dst, Protocol::Tcp | Protocol::Udp) => "--dport",
            (PortSide::Src, Protocol::Tcp | Protocol::Udp) => "--sport",
            _ => continue,
        };
        let port = ps.port.replace('-', ":");
        parts.push(format!("{} {}", flag, port));
    }

    // State tracking for new connections. We already accept ESTABLISHED
    // up top; limiting user rules to NEW prevents them firing once per
    // packet on a long-lived stream and generating spurious log spam.
    if rule.state_track {
        parts.push("-m conntrack --ctstate NEW".into());
    }

    // Log copy (NFLOG) before the actual verdict so it's captured
    // regardless of action.
    if rule.log_match {
        let prefix = format!("wolfrouter-{} ", &rule.id[..rule.id.len().min(8)]);
        let mut log_parts = parts.clone();
        log_parts.push("-j NFLOG".into());
        log_parts.push("--nflog-group 1".into());
        log_parts.push(format!("--nflog-prefix \"{}\"", prefix));
        // Return a double-line: the log rule, then the action rule. The
        // caller joins with \n later. We cheat by embedding it here.
        let logline = log_parts.join(" ");
        // Action jump
        let action_flag = match rule.action {
            Action::Allow => "-j ACCEPT",
            Action::Deny  => "-j DROP",
            Action::Reject => "-j REJECT",
            Action::Log => "-j RETURN", // log-only rules just return
        };
        parts.push(action_flag.into());
        let action_line = parts.join(" ");
        return Some(format!("{}\n{}", logline, action_line));
    }

    let action_flag = match rule.action {
        Action::Allow => "-j ACCEPT",
        Action::Deny => "-j DROP",
        Action::Reject => "-j REJECT",
        Action::Log => "-j RETURN",
    };
    parts.push(action_flag.into());

    Some(parts.join(" "))
}

/// Translate an endpoint to iptables args. `side` is "src" or "dst" and
/// maps to -s/-d or -i/-o depending on endpoint kind.
fn endpoint_args(
    ep: &Endpoint,
    side: &str,
    zones: &ZoneAssignments,
    self_node_id: &str,
) -> Option<Vec<String>> {
    match ep {
        Endpoint::Any => Some(vec![]),
        Endpoint::Ip { cidr } => {
            let flag = if side == "src" { "-s" } else { "-d" };
            Some(vec![format!("{} {}", flag, cidr)])
        }
        Endpoint::Interface { name } => {
            let flag = if side == "src" { "-i" } else { "-o" };
            Some(vec![format!("{} {}", flag, name)])
        }
        Endpoint::Zone { zone } => {
            // Resolve to the list of interfaces on this node in that zone.
            // Emit -i or -o with multi-interface via ipset for scalability.
            let members = zones.members_for_zone_on_node(self_node_id, zone);
            if members.is_empty() {
                // Zone has no members on this node — rule doesn't apply here.
                return None;
            }
            // For clarity + no ipset dependency at MVP, emit a single
            // -i/-o per rule if there's one member, otherwise explode
            // into multiple rules. compile_rule handles scalar output
            // so we approximate by joining with commas (iptables supports
            // multiple -i only via ipset, so single-member is the MVP
            // constraint — multi-member interfaces degrade to "any").
            if members.len() == 1 {
                let flag = if side == "src" { "-i" } else { "-o" };
                Some(vec![format!("{} {}", flag, members[0])])
            } else {
                // TODO: ipset. For now, match any — the zone rule still
                // narrows via ctstate and other criteria.
                warn!(
                    "Zone {} has {} interfaces on node {} — multi-iface zones need ipset; matching any",
                    zone.human(), members.len(), self_node_id
                );
                Some(vec![])
            }
        }
        Endpoint::Lan { id } => {
            // Resolve LAN id → subnet CIDR. This requires access to
            // the LANs list; plumb through RouterConfig. For now we
            // can't reach it here, so this compiles to "any" (caller
            // should resolve ahead of time). MVP: skip.
            warn!("Endpoint::Lan compilation not yet wired (lan id: {})", id);
            Some(vec![])
        }
        Endpoint::Vm { name: _ } | Endpoint::Container { name: _ } => {
            // VM/container → IP lookup. Requires live state access;
            // resolve ahead-of-time in the caller once we hook up
            // compute. MVP: skip.
            Some(vec![])
        }
    }
}

/// Apply a ruleset. `test_only = true` runs `iptables-restore --test`
/// without swapping. Returns the previous ruleset (as iptables-save
/// text) on success so callers can stash it for rollback.
pub fn apply(ruleset: &str, test_only: bool) -> Result<String, String> {
    // Dump current filter table for rollback.
    let current = dump_filter_table().unwrap_or_default();

    // Validate first.
    if !run_restore(ruleset, true)? {
        return Err("iptables-restore --test rejected the ruleset".into());
    }
    if test_only {
        return Ok(current);
    }

    // Swap.
    if !run_restore(ruleset, false)? {
        return Err("iptables-restore failed to apply (ruleset reverted to previous)".into());
    }

    info!("WolfRouter firewall applied ({} bytes)", ruleset.len());
    Ok(current)
}

/// Revert to a previously-captured iptables-save dump.
pub fn revert(previous: &str) -> Result<(), String> {
    if !run_restore(previous, false)? {
        return Err("Failed to revert firewall to previous state".into());
    }
    warn!("WolfRouter firewall reverted to previous ruleset");
    Ok(())
}

/// Dump the current filter table in iptables-save format.
pub fn dump_filter_table() -> Result<String, String> {
    let out = Command::new("iptables-save")
        .args(["-t", "filter"])
        .output()
        .map_err(|e| format!("iptables-save: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "iptables-save exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Run iptables-restore on the given input. Returns true on success.
fn run_restore(input: &str, test_only: bool) -> Result<bool, String> {
    use std::io::Write;
    let mut cmd = Command::new("iptables-restore");
    if test_only { cmd.arg("--test"); }
    // -n = don't flush other tables. Critical: we're only writing
    // *filter, and we don't want to wipe out *nat (DNAT/SNAT rules
    // owned by other subsystems) or *mangle.
    cmd.arg("-n");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn iptables-restore: {}", e))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())
            .map_err(|e| format!("write to iptables-restore stdin: {}", e))?;
    }
    let out = child.wait_with_output()
        .map_err(|e| format!("wait iptables-restore: {}", e))?;
    if !out.status.success() {
        warn!(
            "iptables-restore stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return Ok(false);
    }
    Ok(true)
}

/// Sanity-check rules without touching the live table. Returns list of
/// compile errors / warnings keyed by rule id.
pub fn validate(config: &RouterConfig, self_node_id: &str) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for r in &config.rules {
        if !seen_ids.insert(&r.id) {
            issues.push((r.id.clone(), format!("Duplicate rule id: {}", r.id)));
        }
        if matches!(r.protocol, Protocol::Any) && !r.ports.is_empty() {
            issues.push((
                r.id.clone(),
                "Port match has no effect when protocol is Any — set protocol to TCP or UDP".into(),
            ));
        }
    }
    // Test-apply the whole ruleset.
    let ruleset = build_ruleset(config, self_node_id);
    if let Err(e) = apply(&ruleset, true) {
        issues.push(("_ruleset_".into(), e));
    }
    issues
}
