// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Topology model + live sampling for the rack view.
//!
//! This module walks the local host's state (`ip -j link`, `ip -j addr`,
//! `/proc/net/dev`, bridge membership, WolfStack's own VM/container
//! lists) and emits a `NodeTopology` snapshot. The API layer aggregates
//! one of these per cluster node into a `RouterTopology` for the UI.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

/// Aggregated cluster topology for the rack view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterTopology {
    pub nodes: Vec<NodeTopology>,
    pub links: Vec<TopologyLink>,
    /// Epoch seconds when this topology was computed.
    pub generated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTopology {
    pub node_id: String,
    pub node_name: String,
    pub interfaces: Vec<PortState>,
    pub bridges: Vec<BridgeState>,
    pub vlans: Vec<VlanState>,
    /// Short list of VMs on this node with their NIC attachments.
    pub vms: Vec<DeviceAttachment>,
    pub containers: Vec<DeviceAttachment>,
    /// IDs of LAN segments hosted by this node.
    pub lan_segments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortState {
    pub name: String,              // enp2s0
    pub slot: u32,                 // rack-order index
    pub mac: String,
    pub link_up: bool,
    pub speed_mbps: Option<u32>,
    pub addresses: Vec<String>,    // "192.168.1.10/24"
    pub zone: Option<Zone>,
    pub role: PortRole,
    pub rx_bps: u64,               // live
    pub tx_bps: u64,
    pub master: Option<String>,    // bridge name if slaved
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortRole { Wan, Lan, Trunk, Management, Wolfnet, Unused }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    pub name: String,
    pub members: Vec<String>,      // interface names attached
    pub addresses: Vec<String>,
    pub zone: Option<Zone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanState {
    pub name: String,              // "eth0.100"
    pub parent: String,
    pub vlan_id: u32,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAttachment {
    pub name: String,              // VM name / container name
    pub kind: String,              // "vm", "docker", "lxc"
    pub attached_to: String,       // interface/bridge/"wolfnet"
    pub ip: Option<String>,
}

/// Logical link between two things in the topology graph. The UI renders
/// these as wires in the rack view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLink {
    pub from: EndpointRef,
    pub to: EndpointRef,
    pub kind: LinkKind,
    pub bps_live: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EndpointRef {
    Port { node: String, iface: String },
    Bridge { node: String, name: String },
    Lan { id: String },
    Vm { node: String, name: String },
    Container { node: String, name: String },
    Upstream,       // the ISP / "WAN cloud"
    Wolfnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Physical,
    Tap,
    Veth,
    Wireguard,
    Wolfnet,
    Virtual,   // LAN segment ↔ bridge
}

// ── Live BPS tracker ──
//
// /proc/net/dev gives cumulative bytes. We subtract from the previous
// sample to get bits/sec. Cache keyed by (node_id, iface) in a global.

struct BpsSample { bytes: u64, at: Instant }
struct BpsTracker {
    rx: HashMap<String, BpsSample>,
    tx: HashMap<String, BpsSample>,
}
static BPS: LazyLock<RwLock<BpsTracker>> = LazyLock::new(|| RwLock::new(BpsTracker {
    rx: HashMap::new(), tx: HashMap::new(),
}));

/// Sample /proc/net/dev and compute per-iface BPS against the previous
/// sample. Returns a map of iface → (rx_bps, tx_bps).
pub fn sample_bps() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::new();
    let text = match std::fs::read_to_string("/proc/net/dev") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let now = Instant::now();
    let mut tracker = BPS.write().unwrap();
    for line in text.lines().skip(2) {
        let line = line.trim();
        if let Some((name, rest)) = line.split_once(':') {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 9 { continue; }
            let rx_bytes: u64 = parts[0].parse().unwrap_or(0);
            let tx_bytes: u64 = parts[8].parse().unwrap_or(0);
            let iface = name.trim().to_string();

            let rx_bps = delta_bps(&mut tracker.rx, &iface, rx_bytes, now);
            let tx_bps = delta_bps(&mut tracker.tx, &iface, tx_bytes, now);
            out.insert(iface, (rx_bps, tx_bps));
        }
    }
    out
}

fn delta_bps(map: &mut HashMap<String, BpsSample>, iface: &str, bytes: u64, now: Instant) -> u64 {
    let prev = map.insert(iface.to_string(), BpsSample { bytes, at: now });
    match prev {
        Some(p) => {
            let dt = now.saturating_duration_since(p.at);
            if dt.as_millis() < 100 { return 0; } // avoid division spikes
            let dbytes = bytes.saturating_sub(p.bytes);
            (dbytes * 8 * 1000 / dt.as_millis().max(1) as u64) as u64
        }
        None => 0,
    }
}

// ── System walkers ──

/// Compute the local node's topology. API handlers on the master node
/// call this on each worker node via cluster RPC to assemble the
/// cluster-wide view.
pub fn compute_local(
    node_id: &str,
    node_name: &str,
    config: &RouterConfig,
) -> NodeTopology {
    let bps = sample_bps();
    let interfaces = walk_interfaces(&bps, config, node_id);
    let bridges = walk_bridges(config, node_id);
    let vlans = walk_vlans();
    let vms = walk_vms(node_id);
    let containers = walk_containers(node_id);
    let lan_segments = config.lans.iter()
        .filter(|l| l.node_id == node_id)
        .map(|l| l.id.clone())
        .collect();

    NodeTopology {
        node_id: node_id.into(),
        node_name: node_name.into(),
        interfaces,
        bridges,
        vlans,
        vms,
        containers,
        lan_segments,
    }
}

fn walk_interfaces(
    bps: &HashMap<String, (u64, u64)>,
    config: &RouterConfig,
    node_id: &str,
) -> Vec<PortState> {
    // Use `ip -j link` and `ip -j addr` for machine-readable output.
    let link_text = run_json(&["ip", "-j", "link"]);
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let links: Vec<serde_json::Value> = serde_json::from_str(&link_text).unwrap_or_default();
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    // Build ifname → addrs map.
    let mut addr_map: HashMap<String, Vec<String>> = HashMap::new();
    for a in &addrs {
        let name = a.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ips: Vec<String> = a.get("addr_info")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|e| {
                    let ip = e.get("local")?.as_str()?;
                    let prefix = e.get("prefixlen")?.as_u64()?;
                    Some(format!("{}/{}", ip, prefix))
                }).collect()
            })
            .unwrap_or_default();
        addr_map.insert(name, ips);
    }

    let mut out = Vec::new();
    for (slot, link) in links.iter().enumerate() {
        let name = link.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { continue; }
        // Skip loopback and obviously-virtual interfaces we don't want to
        // show as rack ports. Bridges and TAPs render elsewhere.
        if name == "lo" || name.starts_with("tap-") || name.starts_with("veth")
            || name.starts_with("br-") || name == "docker0" || name == "lxcbr0"
            || name.starts_with("wn") {
            continue;
        }
        let mac = link.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let operstate = link.get("operstate").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
        let link_up = operstate == "UP";
        let master = link.get("master").and_then(|v| v.as_str()).map(|s| s.to_string());
        let speed_mbps = read_speed_mbps(&name);
        let (rx, tx) = bps.get(&name).cloned().unwrap_or((0, 0));
        let addresses = addr_map.get(&name).cloned().unwrap_or_default();
        let zone = config.zones.get(node_id, &name).cloned();
        let role = infer_role(&name, &zone, link_up, master.is_some());

        out.push(PortState {
            name,
            slot: slot as u32,
            mac,
            link_up,
            speed_mbps,
            addresses,
            zone,
            role,
            rx_bps: rx,
            tx_bps: tx,
            master,
        });
    }
    out
}

fn walk_bridges(config: &RouterConfig, node_id: &str) -> Vec<BridgeState> {
    // `ip -j link show type bridge` lists bridges. Membership comes from
    // the `master` field of slave links.
    let text = run_json(&["ip", "-j", "link", "show", "type", "bridge"]);
    let bridges: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let all_links_text = run_json(&["ip", "-j", "link"]);
    let all_links: Vec<serde_json::Value> = serde_json::from_str(&all_links_text).unwrap_or_default();
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    let mut out = Vec::new();
    for b in bridges {
        let name = b.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { continue; }
        let members: Vec<String> = all_links.iter().filter_map(|l| {
            let master = l.get("master").and_then(|v| v.as_str())?;
            if master == name {
                l.get("ifname").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else { None }
        }).collect();
        let addresses: Vec<String> = addrs.iter().find(|a| {
            a.get("ifname").and_then(|v| v.as_str()) == Some(name.as_str())
        }).and_then(|a| a.get("addr_info"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| {
                let ip = e.get("local")?.as_str()?;
                let prefix = e.get("prefixlen")?.as_u64()?;
                Some(format!("{}/{}", ip, prefix))
            }).collect()).unwrap_or_default();
        let zone = config.zones.get(node_id, &name).cloned();
        out.push(BridgeState { name, members, addresses, zone });
    }
    out
}

fn walk_vlans() -> Vec<VlanState> {
    let text = run_json(&["ip", "-j", "-d", "link"]);
    let links: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    let mut out = Vec::new();
    for l in links {
        let linkinfo = match l.get("linkinfo") { Some(v) => v, None => continue };
        let kind = linkinfo.get("info_kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "vlan" { continue; }
        let name = l.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let parent = l.get("link").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vlan_id = linkinfo.get("info_data")
            .and_then(|d| d.get("id"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let addresses: Vec<String> = addrs.iter().find(|a| {
            a.get("ifname").and_then(|v| v.as_str()) == Some(name.as_str())
        }).and_then(|a| a.get("addr_info"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| {
                let ip = e.get("local")?.as_str()?;
                let prefix = e.get("prefixlen")?.as_u64()?;
                Some(format!("{}/{}", ip, prefix))
            }).collect()).unwrap_or_default();
        out.push(VlanState { name, parent, vlan_id, addresses });
    }
    out
}

fn walk_vms(node_id: &str) -> Vec<DeviceAttachment> {
    // VmConfig has a `host_id` field that records which node owns the
    // VM. Filter to only this node's VMs so the cluster view doesn't
    // duplicate every VM under every node.
    let vmm = crate::vms::manager::VmManager::new();
    let configs = vmm.list_vms();
    configs.into_iter()
        .filter(|c| c.host_id.as_deref().map(|h| h == node_id).unwrap_or(true))
        .map(|c| {
            let attached = if c.wolfnet_ip.is_some() { "wolfnet".to_string() }
                else if let Some(n) = c.extra_nics.first() {
                    n.passthrough_interface.clone()
                        .or_else(|| n.bridge.clone())
                        .unwrap_or_else(|| "user-mode".into())
                } else { "user-mode".into() };
            DeviceAttachment {
                name: c.name,
                kind: "vm".into(),
                attached_to: attached,
                ip: c.wolfnet_ip,
            }
        })
        .collect()
}

fn walk_containers(_node_id: &str) -> Vec<DeviceAttachment> {
    // Best-effort: list docker + lxc containers. Keep it cheap — this is
    // called on every topology poll.
    let mut out = Vec::new();
    // Docker
    if let Ok(o) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}|{{.Networks}}"])
        .output()
    {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((name, net)) = line.split_once('|') {
                    out.push(DeviceAttachment {
                        name: name.to_string(),
                        kind: "docker".into(),
                        attached_to: net.to_string(),
                        ip: None,
                    });
                }
            }
        }
    }
    // LXC
    if let Ok(o) = Command::new("lxc-ls").args(["--running"]).output() {
        if o.status.success() {
            for name in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                out.push(DeviceAttachment {
                    name: name.to_string(),
                    kind: "lxc".into(),
                    attached_to: "lxcbr0".into(),
                    ip: None,
                });
            }
        }
    }
    out
}

fn infer_role(name: &str, zone: &Option<Zone>, _link_up: bool, slaved: bool) -> PortRole {
    if let Some(z) = zone {
        return match z {
            Zone::Wan => PortRole::Wan,
            Zone::Lan(_) => PortRole::Lan,
            Zone::Wolfnet => PortRole::Wolfnet,
            _ => PortRole::Lan,
        };
    }
    if slaved { return PortRole::Lan; }
    // Heuristic: default-route interface = WAN. Cache avoided per-call
    // to keep this cheap.
    if name == crate::networking::detect_primary_interface() {
        return PortRole::Wan;
    }
    PortRole::Unused
}

fn read_speed_mbps(iface: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/speed", iface))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .map(|n| n as u32)
}

fn run_json(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|| "[]".into())
}

/// Derive logical links (wires) from a list of per-node topologies.
/// Rendered as curved SVG paths in the rack view.
pub fn derive_links(nodes: &[NodeTopology]) -> Vec<TopologyLink> {
    let mut links = Vec::new();

    for node in nodes {
        // Every up port with a WAN role connects to the Upstream "cloud".
        for port in &node.interfaces {
            if port.role == PortRole::Wan && port.link_up {
                links.push(TopologyLink {
                    from: EndpointRef::Port { node: node.node_id.clone(), iface: port.name.clone() },
                    to: EndpointRef::Upstream,
                    kind: LinkKind::Physical,
                    bps_live: Some(port.rx_bps + port.tx_bps),
                });
            }
            // Ports slaved to a bridge connect to that bridge.
            if let Some(master) = &port.master {
                links.push(TopologyLink {
                    from: EndpointRef::Port { node: node.node_id.clone(), iface: port.name.clone() },
                    to: EndpointRef::Bridge { node: node.node_id.clone(), name: master.clone() },
                    kind: LinkKind::Physical,
                    bps_live: Some(port.rx_bps + port.tx_bps),
                });
            }
        }

        // VMs attached to WolfNet → Wolfnet endpoint.
        for vm in &node.vms {
            let to = if vm.attached_to == "wolfnet" {
                EndpointRef::Wolfnet
            } else {
                // Attached to a named interface/bridge.
                EndpointRef::Bridge { node: node.node_id.clone(), name: vm.attached_to.clone() }
            };
            links.push(TopologyLink {
                from: EndpointRef::Vm { node: node.node_id.clone(), name: vm.name.clone() },
                to,
                kind: if vm.attached_to == "wolfnet" { LinkKind::Wolfnet } else { LinkKind::Tap },
                bps_live: None,
            });
        }

        for ct in &node.containers {
            links.push(TopologyLink {
                from: EndpointRef::Container { node: node.node_id.clone(), name: ct.name.clone() },
                to: EndpointRef::Bridge { node: node.node_id.clone(), name: ct.attached_to.clone() },
                kind: LinkKind::Veth,
                bps_live: None,
            });
        }
    }

    // Cross-node WolfNet mesh link (one logical edge between each pair
    // for the UI to render the overlay). The rack view treats these as
    // a shaded "WolfNet cloud" rather than individual wires.
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            links.push(TopologyLink {
                from: EndpointRef::Wolfnet,
                to: EndpointRef::Wolfnet,
                kind: LinkKind::Wolfnet,
                bps_live: None,
            });
            // Break early; one logical node-to-node link is enough.
            let _ = (i, j);
        }
    }

    links
}
