// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Per-LAN dnsmasq lifecycle. One dnsmasq instance per LanSegment,
//! bound to the segment's interface with its own config file, pid file,
//! and lease file.
//!
//! We use dnsmasq (not ISC DHCPD) because:
//!   • It's everywhere — already the VM TAP DHCP provider in WolfStack.
//!   • It does DHCP + DNS in one process, which is exactly the LAN model.
//!   • Config is a single flat file, easy to template safely.
//!   • Reload is a SIGHUP, no restart needed.
//!
//! Config files live in `/etc/wolfstack/router/dnsmasq.d/` — one per LAN.
//! We do NOT write into `/etc/dnsmasq.d/` because that's owned by any
//! system-global dnsmasq the distro ships; we run our own instances
//! explicitly.

use super::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

const DNSMASQ_DIR: &str = "/etc/wolfstack/router/dnsmasq.d";
const PID_DIR: &str = "/run/wolfstack-router";
const LEASE_DIR: &str = "/var/lib/wolfstack-router";
const ADBLOCK_HOSTS: &str = "/etc/wolfstack/router/adblock-hosts";

/// Ensure runtime directories exist. Idempotent.
fn ensure_dirs() -> Result<(), String> {
    for d in [DNSMASQ_DIR, PID_DIR, LEASE_DIR] {
        fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {}", d, e))?;
    }
    Ok(())
}

/// Write the dnsmasq config for one LAN. Returns the path written.
pub fn render_config(lan: &LanSegment) -> Result<String, String> {
    ensure_dirs()?;
    let path = format!("{}/lan-{}.conf", DNSMASQ_DIR, lan.id);

    let mut cfg = String::new();
    // Header so humans debugging can tell what this is.
    cfg.push_str(&format!(
        "# WolfRouter LAN: {} ({})\n# Managed by WolfStack — do not edit by hand.\n",
        lan.name, lan.id
    ));

    // Strict interface binding: only listen on the LAN's interface.
    cfg.push_str(&format!("interface={}\n", lan.interface));
    cfg.push_str("bind-interfaces\n");
    cfg.push_str("except-interface=lo\n");

    // Run as a dedicated instance with per-LAN pid/lease files.
    cfg.push_str(&format!("pid-file={}/lan-{}.pid\n", PID_DIR, lan.id));
    cfg.push_str(&format!("dhcp-leasefile={}/lan-{}.leases\n", LEASE_DIR, lan.id));

    // Don't touch /etc/resolv.conf / /etc/hosts. We're a LAN server,
    // not the host's resolver.
    cfg.push_str("no-resolv\n");
    cfg.push_str("no-hosts\n");
    cfg.push_str("no-poll\n");
    // Quiet DHCP: no broadcast of defaults we didn't ask for.
    cfg.push_str("dhcp-authoritative\n");

    // DHCP
    if lan.dhcp.enabled {
        let (_, prefix) = parse_cidr(&lan.subnet_cidr)
            .ok_or_else(|| format!("Bad subnet_cidr: {}", lan.subnet_cidr))?;
        let netmask = prefix_to_netmask(prefix);
        cfg.push_str(&format!(
            "dhcp-range={},{},{},{}\n",
            lan.dhcp.pool_start, lan.dhcp.pool_end, netmask, lan.dhcp.lease_time
        ));
        // Default gateway (option 3) = router_ip.
        cfg.push_str(&format!("dhcp-option=3,{}\n", lan.router_ip));
        // DNS (option 6) = router_ip (we also serve DNS on this LAN).
        cfg.push_str(&format!("dhcp-option=6,{}\n", lan.router_ip));

        // Static reservations.
        for r in &lan.dhcp.reservations {
            let host = r.hostname.as_deref().unwrap_or("");
            if host.is_empty() {
                cfg.push_str(&format!("dhcp-host={},{}\n", r.mac, r.ip));
            } else {
                cfg.push_str(&format!("dhcp-host={},{},{}\n", r.mac, r.ip, host));
            }
        }

        // Any extra options the admin wants to push (e.g. option 42 NTP).
        for opt in &lan.dhcp.extra_options {
            cfg.push_str(&format!("dhcp-option={}\n", opt));
        }
    }

    // DNS
    // Cache size: 0 = disabled, otherwise a reasonable 1500.
    let cache_size = if lan.dns.cache_enabled { 1500 } else { 0 };
    cfg.push_str(&format!("cache-size={}\n", cache_size));
    for fwd in &lan.dns.forwarders {
        cfg.push_str(&format!("server={}\n", fwd));
    }
    for rec in &lan.dns.local_records {
        // address= gives an A record; host-record= gives A + PTR.
        cfg.push_str(&format!("host-record={},{}\n", rec.hostname, rec.ip));
    }
    // Ad-blocking: use a shared hosts file if available. The file is
    // maintained separately (phase 4 feature) — for now it's optional.
    if lan.dns.block_ads && Path::new(ADBLOCK_HOSTS).exists() {
        cfg.push_str(&format!("addn-hosts={}\n", ADBLOCK_HOSTS));
    }

    fs::write(&path, cfg)
        .map_err(|e| format!("Write dnsmasq config {}: {}", path, e))?;
    Ok(path)
}

/// Start (or restart) the dnsmasq instance for a LAN.
pub fn start(lan: &LanSegment) -> Result<(), String> {
    // First render fresh config.
    let cfg_path = render_config(lan)?;

    // If there's an existing instance, kill it gracefully first. Our pid
    // files are per-LAN so we don't affect anyone else's dnsmasq.
    stop(lan)?;

    // Verify dnsmasq exists.
    if !Command::new("which").arg("dnsmasq").status()
        .map(|s| s.success()).unwrap_or(false)
    {
        return Err(
            "dnsmasq is not installed. Install the 'dnsmasq' package and retry.".into()
        );
    }

    // Spawn as daemon (dnsmasq's default is to daemonize). `--conf-file=`
    // (with the equals sign) is the only form dnsmasq accepts — separate
    // arg causes "junk found in command line" because dnsmasq treats
    // the path as a non-option positional. Same for --local-service.
    let out = Command::new("dnsmasq")
        .arg(format!("--conf-file={}", cfg_path))
        .arg("--local-service")
        .output()
        .map_err(|e| format!("spawn dnsmasq: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "dnsmasq failed to start for LAN '{}': {}",
            lan.name, stderr.trim()
        ));
    }
    info!("WolfRouter: dnsmasq started for LAN {} on {}", lan.name, lan.interface);
    Ok(())
}

/// Stop the dnsmasq instance for a LAN (if any). Safe to call even when
/// nothing is running.
pub fn stop(lan: &LanSegment) -> Result<(), String> {
    let pid_file = format!("{}/lan-{}.pid", PID_DIR, lan.id);
    let pid_str = match fs::read_to_string(&pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return Ok(()),
    };
    if pid_str.is_empty() { return Ok(()); }
    let _ = Command::new("kill").arg(&pid_str).status();
    // Also remove the pid file so we don't churn on stale entries.
    let _ = fs::remove_file(&pid_file);
    Ok(())
}

/// Remove all traces of a LAN's dnsmasq: stop it, delete config and lease.
pub fn purge(lan: &LanSegment) -> Result<(), String> {
    stop(lan)?;
    let cfg = format!("{}/lan-{}.conf", DNSMASQ_DIR, lan.id);
    let leases = format!("{}/lan-{}.leases", LEASE_DIR, lan.id);
    let _ = fs::remove_file(&cfg);
    let _ = fs::remove_file(&leases);
    Ok(())
}

/// One active DHCP lease as read from a dnsmasq lease file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Lease {
    pub expires: u64,
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub client_id: String,
}

/// Parse the dnsmasq lease file for a LAN. Format per-line:
/// `<expires> <mac> <ip> <hostname> <client-id>`
pub fn read_leases(lan_id: &str) -> Vec<Lease> {
    let path = format!("{}/lan-{}.leases", LEASE_DIR, lan_id);
    let text = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let expires: u64 = parts[0].parse().unwrap_or(0);
        let mac = parts[1].to_string();
        let ip = parts[2].to_string();
        let hostname = parts.get(3).map(|s| s.to_string()).unwrap_or_default();
        let client_id = parts.get(4).map(|s| s.to_string()).unwrap_or_default();
        // dnsmasq sometimes writes "*" as placeholder for missing hostname.
        let hostname = if hostname == "*" { "".into() } else { hostname };
        out.push(Lease { expires, mac, ip, hostname, client_id });
    }
    out
}

/// Convert a prefix length (e.g. 24) to a dotted-quad netmask.
fn prefix_to_netmask(prefix: u32) -> String {
    if prefix >= 32 { return "255.255.255.255".into(); }
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

/// Bring up every LAN segment owned by this node. Idempotent: if an
/// instance is already running with the same config, SIGHUP it instead
/// of restart. MVP does a stop/start cycle because it's simpler and the
/// disruption is ~100ms.
pub fn start_all_for_node(config: &RouterConfig, self_node_id: &str) {
    for lan in &config.lans {
        if lan.node_id != self_node_id { continue; }
        if let Err(e) = start(lan) {
            warn!("Failed to start LAN '{}': {}", lan.name, e);
        }
    }
}

/// Stop every LAN instance on this node (used on shutdown).
pub fn stop_all_for_node(config: &RouterConfig, self_node_id: &str) {
    for lan in &config.lans {
        if lan.node_id != self_node_id { continue; }
        let _ = stop(lan);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_conversion() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(30), "255.255.255.252");
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }
}
