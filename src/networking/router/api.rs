// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! REST endpoints for WolfRouter. Mounted under `/api/router/*`.
//!
//! Cluster model:
//!   • **Read endpoints** (topology, leases, rules, segments) aggregate
//!     from all cluster nodes. The master node fans out per-node queries
//!     via the existing cluster-secret RPC.
//!   • **Write endpoints** (create/update/delete rule or segment) persist
//!     to config on the owning node. If the edit targets a remote node,
//!     the master proxies the call via the existing `/api/nodes/{id}/proxy`
//!     machinery.

use super::*;
use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;

type S = web::Data<crate::api::AppState>;

/// Guard helper — every WolfRouter endpoint requires either a logged-in
/// session cookie OR a valid cluster secret header. Without this, any
/// HTTP client could spray firewall rules or lock users out.
macro_rules! auth_or_return {
    ($req:expr, $state:expr) => {
        if let Err(resp) = crate::api::require_auth(&$req, &$state) { return resp; }
    };
}

/// Push the current RouterConfig to every other cluster node so the
/// firewall, LANs, and zone assignments stay in sync. Fired (in the
/// background, doesn't block the originating user request) after every
/// successful write. Each peer accepts via `/api/router/config-receive`
/// authenticated with the X-WolfStack-Secret header.
///
/// "Settings should replicate across the cluster when they are changed
/// so nothing breaks" — this is that.
fn replicate_config_to_cluster(state: S) {
    // The clone of the config and nodes happens INSIDE the spawned task,
    // by which time the caller has returned and any write lock from the
    // handler has been dropped. Calling this with the lock still held
    // would deadlock — so the indirection is intentional.
    tokio::spawn(async move {
        let cfg = state.router.config.read().unwrap().clone();
        let nodes = state.cluster.get_all_nodes();
        let secret = state.cluster_secret.clone();
        let self_id = crate::agent::self_node_id();
        let body = match serde_json::to_string(&cfg) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("router replicate: serialize failed: {}", e); return; }
        };
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)  // cluster nodes may use self-signed
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let client = match client {
            Ok(c) => c,
            Err(e) => { tracing::warn!("router replicate: client build: {}", e); return; }
        };
        for node in nodes {
            // Skip ourselves, offline nodes, and non-WolfStack nodes
            // (Proxmox-only members can't host WolfRouter).
            if node.is_self || node.id == self_id { continue; }
            if !node.online { continue; }
            if node.node_type != "wolfstack" { continue; }
            let url = format!("https://{}:{}/api/router/config-receive", node.address, node.port);
            let res = client.post(&url)
                .header("X-WolfStack-Secret", &secret)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send().await;
            match res {
                Ok(r) if r.status().is_success() => {
                    tracing::debug!("router config replicated to {}", node.id);
                }
                Ok(r) => {
                    tracing::warn!("router config replicate to {} returned {}", node.id, r.status());
                }
                Err(e) => {
                    tracing::warn!("router config replicate to {} failed: {}", node.id, e);
                }
            }
        }
    });
}

/// Receive a RouterConfig from another cluster node. Persists it,
/// re-applies firewall, restarts dnsmasq for any LANs hosted here.
/// Called by the master/originator after a local edit.
pub async fn config_receive(
    req: HttpRequest,
    state: S,
    body: web::Json<RouterConfig>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let new_cfg = body.into_inner();
    {
        let mut cur = state.router.config.write().unwrap();
        *cur = new_cfg.clone();
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().body(format!("save: {}", e));
        }
    }
    // Apply firewall locally if auto_apply is on.
    if new_cfg.auto_apply {
        let ruleset = firewall::build_ruleset(&new_cfg, &crate::agent::self_node_id());
        if let Err(e) = firewall::apply(&ruleset, false) {
            tracing::warn!("router config-receive: firewall apply failed: {}", e);
        }
    }
    // Re-render dnsmasq for LANs hosted on this node. Stops orphaned
    // instances for LANs that were removed; starts/restarts current ones.
    let self_id = crate::agent::self_node_id();
    dhcp::start_all_for_node(&new_cfg, &self_id);
    HttpResponse::Ok().body("synced")
}

/// Reject a LanSegment whose user-supplied fields contain newlines or
/// other dnsmasq directive separators. dhcp::render_config writes these
/// into a config file unescaped — without this guard a maliciously
/// crafted segment name or extra_options entry could inject directives
/// like `auth-server=` or `addn-hosts=/etc/shadow`.
fn validate_segment(seg: &LanSegment) -> Result<(), String> {
    let check = |field: &str, value: &str| -> Result<(), String> {
        if value.contains('\n') || value.contains('\r') {
            return Err(format!("{} contains newline characters", field));
        }
        Ok(())
    };
    check("name", &seg.name)?;
    check("interface", &seg.interface)?;
    check("subnet_cidr", &seg.subnet_cidr)?;
    check("router_ip", &seg.router_ip)?;
    check("dhcp.pool_start", &seg.dhcp.pool_start)?;
    check("dhcp.pool_end", &seg.dhcp.pool_end)?;
    check("dhcp.lease_time", &seg.dhcp.lease_time)?;
    for (i, r) in seg.dhcp.reservations.iter().enumerate() {
        check(&format!("reservations[{}].mac", i), &r.mac)?;
        check(&format!("reservations[{}].ip", i), &r.ip)?;
        if let Some(h) = &r.hostname { check(&format!("reservations[{}].hostname", i), h)?; }
    }
    for (i, opt) in seg.dhcp.extra_options.iter().enumerate() {
        check(&format!("extra_options[{}]", i), opt)?;
    }
    for (i, fwd) in seg.dns.forwarders.iter().enumerate() {
        check(&format!("forwarders[{}]", i), fwd)?;
    }
    for (i, rec) in seg.dns.local_records.iter().enumerate() {
        check(&format!("local_records[{}].hostname", i), &rec.hostname)?;
        check(&format!("local_records[{}].ip", i), &rec.ip)?;
    }
    // Interface name must be a syntactically plausible Linux iface name
    // (alnum, dash, dot, underscore — no shell metacharacters).
    if !seg.interface.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) {
        return Err("interface name has illegal characters".into());
    }
    Ok(())
}

/// The node's display name — hostname is the cheapest universally
/// available identifier. Falls back to node id if hostname is empty.
fn self_node_name() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(crate::agent::self_node_id)
}

// ─── Topology ───

pub async fn get_topology(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap().clone();
    let self_id = crate::agent::self_node_id();
    let self_name = self_node_name();
    let me = topology::compute_local(&self_id, &self_name, &cfg);

    // Remote nodes: walk ClusterState. Each node exposes its own
    // /api/router/topology-local which returns just its NodeTopology.
    // For now we build from local state only; the background sync
    // populates remote_topologies. MVP ships single-node aggregation;
    // multi-node is transparent once each node is running v17.1.0.
    let mut nodes = vec![me];
    // Pull cached remote topologies out of ClusterState. The agent tick
    // populates these via /api/router/topology-local on each poll.
    let remotes = state.router.remote_topologies.read().unwrap().clone();
    for t in remotes.into_values() {
        nodes.push(t);
    }

    let links = topology::derive_links(&nodes);
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    HttpResponse::Ok().json(topology::RouterTopology { nodes, links, generated_at })
}

/// Local-only topology endpoint called by other cluster nodes during
/// agent polling. Unauthenticated at the HTTP layer; authenticated via
/// the X-WolfStack-Secret header.
pub async fn get_topology_local(
    state: S,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    // Reuse the standard auth helper — accepts session cookie OR
    // X-WolfStack-Secret cluster header, same as every other endpoint.
    if let Err(resp) = crate::api::require_auth(&req, &state) {
        return resp;
    }
    let cfg = state.router.config.read().unwrap().clone();
    let self_id = crate::agent::self_node_id();
    let self_name = self_node_name();
    let t = topology::compute_local(&self_id, &self_name, &cfg);
    HttpResponse::Ok().json(t)
}

// ─── Zones ───

#[derive(Deserialize)]
pub struct ZoneAssignRequest {
    pub node_id: String,
    pub interface: String,
    pub zone: Option<Zone>,  // None = remove
}

pub async fn assign_zone(req: HttpRequest, state: S, body: web::Json<ZoneAssignRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let zones_snapshot = {
        let mut cfg = state.router.config.write().unwrap();
        let r = body.into_inner();
        match r.zone {
            Some(z) => cfg.zones.set(&r.node_id, &r.interface, z),
            None => cfg.zones.remove(&r.node_id, &r.interface),
        }
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
            let _ = firewall::apply(&ruleset, false);
        }
        cfg.zones.clone()
    }; // write lock dropped here — safe to replicate
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&zones_snapshot)
}

pub async fn get_zones(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    HttpResponse::Ok().json(&state.router.config.read().unwrap().zones)
}

// ─── LAN segments ───

pub async fn list_segments(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    HttpResponse::Ok().json(&state.router.config.read().unwrap().lans)
}

pub async fn create_segment(req: HttpRequest, state: S, body: web::Json<LanSegment>) -> HttpResponse {
    auth_or_return!(req, state);
    // Validate — no embedded newlines in any field that feeds into a
    // dnsmasq config line. See dhcp::render_config for the attack model.
    if let Err(e) = validate_segment(&body) {
        return HttpResponse::BadRequest().body(e);
    }
    let mut segment = body.into_inner();
    if segment.id.is_empty() { segment.id = gen_id("lan"); }

    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.lans.retain(|l| l.id != segment.id);
        cfg.lans.push(segment.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    // Start dnsmasq if this LAN is ours.
    if segment.node_id == crate::agent::self_node_id() {
        if let Err(e) = dhcp::start(&segment) {
            return HttpResponse::InternalServerError().body(format!("dnsmasq start failed: {}", e));
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&segment)
}

pub async fn update_segment(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<LanSegment>,
) -> HttpResponse {
    auth_or_return!(req, state);
    if let Err(e) = validate_segment(&body) {
        return HttpResponse::BadRequest().body(e);
    }
    let id = path.into_inner();
    let updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    {
        let mut cfg = state.router.config.write().unwrap();
        let idx = match cfg.lans.iter().position(|l| l.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.lans[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if updated.node_id == crate::agent::self_node_id() {
        let _ = dhcp::start(&updated);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&updated)
}

pub async fn delete_segment(req: HttpRequest, state: S, path: web::Path<String>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let removed = {
        let mut cfg = state.router.config.write().unwrap();
        let r = cfg.lans.iter().position(|l| l.id == id).map(|i| cfg.lans.remove(i));
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        r
    };
    if let Some(seg) = removed {
        if seg.node_id == crate::agent::self_node_id() {
            let _ = dhcp::purge(&seg);
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

pub async fn get_leases(req: HttpRequest, state: S, path: web::Path<String>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let cfg = state.router.config.read().unwrap();
    let seg = match cfg.lans.iter().find(|l| l.id == id) {
        Some(s) => s.clone(),
        None => return HttpResponse::NotFound().body("LAN not found"),
    };
    // If this LAN is on a remote node, proxy to it. MVP: local only.
    if seg.node_id != crate::agent::self_node_id() {
        return HttpResponse::Ok().json(Vec::<dhcp::Lease>::new());
    }
    HttpResponse::Ok().json(dhcp::read_leases(&id))
}

// ─── Firewall rules ───

pub async fn list_rules(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    HttpResponse::Ok().json(&state.router.config.read().unwrap().rules)
}

pub async fn create_rule(req: HttpRequest, state: S, body: web::Json<FirewallRule>) -> HttpResponse {
    auth_or_return!(req, state);
    let mut rule = body.into_inner();
    if rule.id.is_empty() { rule.id = gen_id("rule"); }

    {
        let mut cfg = state.router.config.write().unwrap();
        let next_order = cfg.rules.iter().map(|r| r.order).max().unwrap_or(-1) + 1;
        if rule.order == 0 { rule.order = next_order; }
        cfg.rules.retain(|r| r.id != rule.id);
        cfg.rules.push(rule.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
            if let Err(e) = firewall::apply(&ruleset, false) {
                return HttpResponse::InternalServerError().body(format!("firewall apply failed: {}", e));
            }
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&rule)
}

pub async fn update_rule(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<FirewallRule>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    {
        let mut cfg = state.router.config.write().unwrap();
        let idx = match cfg.rules.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.rules[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
            let _ = firewall::apply(&ruleset, false);
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&updated)
}

pub async fn delete_rule(req: HttpRequest, state: S, path: web::Path<String>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.rules.retain(|r| r.id != id);
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
            let _ = firewall::apply(&ruleset, false);
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

#[derive(Deserialize)]
pub struct ReorderRequest { pub order: Vec<String> }

pub async fn reorder_rules(req: HttpRequest, state: S, body: web::Json<ReorderRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();
    {
        let mut cfg = state.router.config.write().unwrap();
        let mut order_map: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        for (i, id) in r.order.iter().enumerate() {
            order_map.insert(id.clone(), i as i32);
        }
        for rule in &mut cfg.rules {
            if let Some(o) = order_map.get(&rule.id) {
                rule.order = *o;
            }
        }
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
            let _ = firewall::apply(&ruleset, false);
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("reordered")
}

pub async fn test_rules(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let issues = firewall::validate(&cfg, &crate::agent::self_node_id());
    let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
    HttpResponse::Ok().json(serde_json::json!({
        "ok": issues.is_empty(),
        "issues": issues.iter().map(|(id, msg)| serde_json::json!({"id": id, "message": msg})).collect::<Vec<_>>(),
        "preview": ruleset,
    }))
}

pub async fn apply_rules_now(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
    match firewall::apply(&ruleset, false) {
        Ok(prev) => {
            *state.router.last_applied_rules.write().unwrap() = Some(prev);
            // Safe-mode: set a rollback deadline.
            if cfg.safe_mode_seconds > 0 {
                let deadline = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
                    + cfg.safe_mode_seconds as u64;
                *state.router.rollback_deadline.write().unwrap() = Some(deadline);
            }
            HttpResponse::Ok().json(serde_json::json!({
                "applied": true,
                "rollback_in_seconds": cfg.safe_mode_seconds,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}

pub async fn confirm_rules(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    *state.router.rollback_deadline.write().unwrap() = None;
    HttpResponse::Ok().body("confirmed")
}

// ─── Connections & Logs ───

pub async fn list_connections(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let out = match std::process::Command::new("conntrack").args(["-L", "-o", "extended"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return HttpResponse::Ok().json(Vec::<serde_json::Value>::new()),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    // Parse conntrack extended format. Each line: "tcp 6 431999 ESTABLISHED src=... dst=... ..."
    for line in text.lines().take(500) {
        let mut r = serde_json::Map::new();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        r.insert("proto".into(), serde_json::Value::String(parts[0].into()));
        for part in &parts[4..] {
            if let Some((k, v)) = part.split_once('=') {
                r.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        rows.push(serde_json::Value::Object(r));
    }
    HttpResponse::Ok().json(rows)
}

/// Firewall log viewer. Reads kernel messages matching our NFLOG prefix
/// via journalctl (dmesg is not reliably available on all distros).
pub async fn list_firewall_logs(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let out = std::process::Command::new("journalctl")
        .args(["-k", "--no-pager", "-n", "300", "-g", "wolfrouter"])
        .output();
    let lines: Vec<String> = match out {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(|s| s.to_string()).collect()
        }
        _ => vec![],
    };
    HttpResponse::Ok().json(lines)
}

// ─── Mount ───

pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    cfg
        .route("/api/router/topology", web::get().to(get_topology))
        .route("/api/router/topology-local", web::get().to(get_topology_local))
        .route("/api/router/config-receive", web::post().to(config_receive))
        .route("/api/router/zones", web::get().to(get_zones))
        .route("/api/router/zones", web::post().to(assign_zone))
        .route("/api/router/segments", web::get().to(list_segments))
        .route("/api/router/segments", web::post().to(create_segment))
        .route("/api/router/segments/{id}", web::put().to(update_segment))
        .route("/api/router/segments/{id}", web::delete().to(delete_segment))
        .route("/api/router/segments/{id}/leases", web::get().to(get_leases))
        .route("/api/router/rules", web::get().to(list_rules))
        .route("/api/router/rules", web::post().to(create_rule))
        .route("/api/router/rules/{id}", web::put().to(update_rule))
        .route("/api/router/rules/{id}", web::delete().to(delete_rule))
        .route("/api/router/rules/reorder", web::post().to(reorder_rules))
        .route("/api/router/rules/test", web::post().to(test_rules))
        .route("/api/router/rules/apply", web::post().to(apply_rules_now))
        .route("/api/router/rules/confirm", web::post().to(confirm_rules))
        .route("/api/router/connections", web::get().to(list_connections))
        .route("/api/router/logs", web::get().to(list_firewall_logs));
}
