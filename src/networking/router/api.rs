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

/// Optional `?cluster=<name>` query filter — when set, the topology
/// only includes nodes belonging to that cluster. WolfRouter is
/// per-cluster so the UI passes this on every fetch.
#[derive(Deserialize)]
pub struct TopologyQuery {
    #[serde(default)]
    pub cluster: Option<String>,
}

pub async fn get_topology(
    req: HttpRequest,
    state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap().clone();
    let self_id = crate::agent::self_node_id();
    let self_name = self_node_name();
    let cluster_filter = query.cluster.clone();

    // Find self's cluster name. If a filter is set and self isn't in
    // that cluster, omit self from the result and only fan out to peers
    // in the requested cluster.
    // Cluster name normaliser — a node with no explicit cluster_name
    // is grouped as "WolfStack" in the sidebar tree (see app.js
    // `n.cluster_name || "WolfStack"`). Backend filtering must use
    // the same alias or nameless nodes leak into named-cluster views.
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(if self_cluster.is_empty() { None } else { Some(&self_cluster) });
    let include_self = match &cluster_filter {
        Some(want) => self_cluster_norm == *want,
        None => true,
    };

    let mut nodes = Vec::new();
    if include_self {
        nodes.push(topology::compute_local(&self_id, &self_name, &cfg));
    }

    // Fan out to every other online cluster node's topology-local
    // endpoint, filtered by cluster name when one was requested.
    let cluster_nodes = state.cluster.get_all_nodes();
    let secret = state.cluster_secret.clone();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build();

    // Per-peer diagnostic trail so when a node is missing from the
    // rack view, the response tells you *why* (filtered out / offline /
    // HTTP error / etc) instead of leaving you guessing.
    let mut peer_diagnostics: Vec<serde_json::Value> = Vec::new();

    if let Ok(client) = client {
        let mut futures = Vec::new();
        for node in cluster_nodes {
            // Self isn't a "peer" — it's already in the result as the
            // local node. Don't include it in diagnostics or the user
            // sees confusing "wolf: is_self" lines in the missing-peers
            // banner.
            if node.is_self || node.id == self_id { continue; }
            if node.node_type != "wolfstack" {
                peer_diagnostics.push(serde_json::json!({
                    "node_id": node.id, "hostname": node.hostname,
                    "result": "skipped", "reason": format!("node_type={} (not wolfstack)", node.node_type)
                }));
                continue;
            }
            // Cluster scoping — strict, but uses the same None→"WolfStack"
            // alias the sidebar tree uses so nameless nodes show up where
            // the user expects (the WolfStack group, not every cluster).
            if let Some(ref want) = cluster_filter {
                let node_cluster = normalize(node.cluster_name.as_deref());
                if &node_cluster != want {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": node.id, "hostname": node.hostname,
                        "result": "skipped",
                        "reason": format!("cluster_name='{}' doesn't match filter '{}'", node_cluster, want)
                    }));
                    continue;
                }
            }
            // We deliberately do NOT skip "offline" peers: last_seen
            // can be stale (polling hiccup, recent restart) but the
            // peer is reachable. WolfRouter retries up to 5 times with
            // exponential backoff per peer; if every attempt fails the
            // node still appears as a stub chassis so the user sees it
            // exists. Subsequent 3s polls fill it in once the peer
            // answers.
            let host = node.address.clone();
            let port = node.port;
            let id = node.id.clone();
            let hostname = node.hostname.clone();
            let stub_name = if hostname.is_empty() { id.clone() } else { hostname.clone() };
            let secret_h = secret.clone();
            let client_c = client.clone();
            futures.push(async move {
                let urls = [
                    format!("https://{}:{}/api/router/topology-local", host, port),
                    format!("http://{}:{}/api/router/topology-local",  host, port),
                ];
                let mut last_err = String::new();
                let mut backoff_ms = 100u64;
                for attempt in 1..=5 {
                    for url in &urls {
                        match client_c.get(url)
                            .header("X-WolfStack-Secret", &secret_h)
                            .send().await
                        {
                            Ok(r) if r.status().is_success() => {
                                return match r.json::<topology::NodeTopology>().await {
                                    Ok(mut t) => {
                                        t.status = "live".into();
                                        t.status_note = String::new();
                                        Ok(t)
                                    }
                                    Err(e) => Err((id.clone(), stub_name.clone(),
                                        format!("decode error after {} attempt(s): {}", attempt, e))),
                                };
                            }
                            Ok(r) => { last_err = format!("HTTP {} from {}", r.status(), url); }
                            Err(e) => { last_err = format!("{} ({})", e, url); }
                        }
                    }
                    if attempt < 5 {
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1500);
                    }
                }
                Err((id, stub_name, format!("5 attempts failed — last error: {}", last_err)))
            });
        }
        let results = futures::future::join_all(futures).await;
        for r in results {
            match r {
                Ok(t) => {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": t.node_id, "hostname": t.node_name,
                        "result": "ok"
                    }));
                    nodes.push(t);
                }
                Err((id, hostname, reason)) => {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": id.clone(), "hostname": hostname.clone(),
                        "result": "failed", "reason": reason.clone()
                    }));
                    // Emit a stub so the rack still draws a chassis for
                    // this peer; the next poll will overwrite it with
                    // live data once the peer responds.
                    nodes.push(topology::NodeTopology::stub(
                        id, hostname, "unreachable", reason,
                    ));
                }
            }
        }
    }

    // Cache the remotes so the next request can fall back if a node
    // goes offline mid-request. Skip self (it's regenerated each call).
    {
        let mut cache = state.router.remote_topologies.write().unwrap();
        cache.clear();
        for n in &nodes {
            if n.node_id != self_id {
                cache.insert(n.node_id.clone(), n.clone());
            }
        }
    }

    let links = topology::derive_links(&nodes);
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    // Wrap the standard topology with the per-peer diagnostics so the
    // frontend can show "tried 3 peers, got 2 responses, 1 skipped
    // because cluster_name didn't match" on the rack header.
    HttpResponse::Ok().json(serde_json::json!({
        "nodes": nodes,
        "links": links,
        "generated_at": generated_at,
        "peer_diagnostics": peer_diagnostics,
        "cluster_filter": cluster_filter,
    }))
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
    // Try `conntrack -L` (default format works fine — extended adds an
    // L3 prefix that's harder to parse). Surface the actual error if
    // it fails so the user knows whether conntrack isn't installed,
    // requires root, or some other problem.
    let result = std::process::Command::new("conntrack").args(["-L"]).output();
    let out = match result {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            return HttpResponse::Ok().json(serde_json::json!({
                "rows": [],
                "error": format!("conntrack failed (exit {}): {}",
                    o.status.code().unwrap_or(-1),
                    if stderr.is_empty() { "no output".into() } else { stderr })
            }));
        }
        Err(e) => {
            return HttpResponse::Ok().json(serde_json::json!({
                "rows": [],
                "error": format!("couldn't run 'conntrack' — {} (install the 'conntrack' package?)", e)
            }));
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    // Default format (no -o extended): the line begins with the L4
    // protocol name, then a numeric proto id, timeout, state, then the
    // tuple key=value tokens. Example:
    //   tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=44321 dport=80 ...
    for line in text.lines().take(500) {
        let mut r = serde_json::Map::new();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        r.insert("proto".into(), serde_json::Value::String(parts[0].into()));
        // parts[1] = numeric proto id (skip), parts[2] = timeout
        r.insert("timeout".into(), serde_json::Value::String(parts[2].into()));
        // State only present for tcp; UDP lines start key=value at parts[3].
        let mut start_kv = 3usize;
        if !parts[3].contains('=') {
            r.insert("state".into(), serde_json::Value::String(parts[3].into()));
            start_kv = 4;
        }
        for part in &parts[start_kv..] {
            if let Some((k, v)) = part.split_once('=') {
                // Only insert the FIRST occurrence of each key so we
                // capture the original tuple (src/dst/sport/dport),
                // not the reply tuple that conntrack appends.
                r.entry(k.to_string()).or_insert(serde_json::Value::String(v.to_string()));
            }
        }
        rows.push(serde_json::Value::Object(r));
    }
    HttpResponse::Ok().json(serde_json::json!({ "rows": rows }))
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

// ─── Integration: surface things WolfStack already manages ───

/// Read-only view of WolfStack-managed networking primitives that
/// WolfRouter doesn't own but the user needs to see in one place:
///   • IP mappings (DNAT) — configured in the per-server Networking page
///   • WolfNet status + peers — managed by the wolfnet daemon
///
/// The intent is integration, not duplication. Users keep editing IP
/// mappings on the existing page; WolfRouter just shows them here so
/// the firewall view doesn't lie about what traffic actually flows.
pub async fn get_managed_overview(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);

    // IP mappings (DNAT entries owned by networking::mod.rs).
    let ip_mappings = crate::networking::list_ip_mappings();

    // WolfNet peers — best-effort. If the file doesn't exist (wolfnet
    // not installed) we simply return null and the UI hides the panel.
    let wolfnet_status: serde_json::Value = std::fs::read_to_string("/var/run/wolfnet/status.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);

    HttpResponse::Ok().json(serde_json::json!({
        "ip_mappings": ip_mappings,
        "wolfnet_status": wolfnet_status,
    }))
}

/// Snapshot of the host's current network reality — what's actually
/// running, regardless of who configured it. WolfRouter renders this
/// in the firewall / LANs / leases tabs so the user never sees a blank
/// page; they see what's already on the host plus anything WolfRouter
/// has added on top.
pub async fn get_host_snapshot(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);

    let firewall_filter = run_capture(&["iptables-save", "-t", "filter"]);
    let firewall_nat    = run_capture(&["iptables-save", "-t", "nat"]);
    let parsed_filter   = parse_iptables(&firewall_filter, "filter");
    let parsed_nat      = parse_iptables(&firewall_nat, "nat");

    let dnsmasq_processes = list_dnsmasq_processes();
    let lease_files = list_lease_files();

    HttpResponse::Ok().json(serde_json::json!({
        "firewall": {
            "filter": parsed_filter,
            "nat": parsed_nat,
            "raw_filter_lines": firewall_filter.lines().count(),
            "raw_nat_lines": firewall_nat.lines().count(),
        },
        "dhcp": {
            "dnsmasq_processes": dnsmasq_processes,
            "lease_files": lease_files,
        },
    }))
}

fn run_capture(args: &[&str]) -> String {
    std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Parse `iptables-save` output into structured rule rows. Skips
/// chain definitions (`:CHAIN ACCEPT [0:0]`) and table headers — only
/// `-A CHAIN <args>` lines become rows. Tags each rule with its
/// "owner" by sniffing the comment / chain name (Docker, LXC,
/// WolfStack, WolfRouter, manual).
fn parse_iptables(text: &str, table: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('*')
            || l.starts_with(':') || l == "COMMIT" {
            continue;
        }
        if !l.starts_with("-A ") { continue; }
        // Extract chain name (first token after -A)
        let rest = &l[3..];
        let chain = rest.split_whitespace().next().unwrap_or("").to_string();
        // Detect owner from chain name + comment
        let owner = if chain.starts_with("DOCKER") || chain == "FORWARD" && l.contains("docker") {
            "docker"
        } else if chain.contains("LXC") || l.contains("lxc") {
            "lxc"
        } else if chain.starts_with("WOLFROUTER") {
            "wolfrouter"
        } else if l.contains("wolfstack-") {
            "wolfstack"
        } else if chain == "INPUT" || chain == "FORWARD" || chain == "OUTPUT"
                  || chain == "PREROUTING" || chain == "POSTROUTING" {
            "system"
        } else {
            "user"
        };
        out.push(serde_json::json!({
            "table": table,
            "chain": chain,
            "owner": owner,
            "raw": l,
        }));
    }
    out
}

/// Find all dnsmasq processes running on the host. Each entry includes
/// PID and the config file from the command line so the UI can group
/// instances by purpose.
fn list_dnsmasq_processes() -> Vec<serde_json::Value> {
    let out = std::process::Command::new("ps")
        .args(["-eo", "pid,args"])
        .output()
        .ok();
    let text = match out {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };
    let mut procs = Vec::new();
    for line in text.lines().skip(1) {
        let line = line.trim();
        if !line.contains("dnsmasq") { continue; }
        // Skip the grep itself if anyone added it
        if line.contains("grep") { continue; }
        let mut parts = line.splitn(2, char::is_whitespace);
        let pid = parts.next().unwrap_or("").to_string();
        let cmd = parts.next().unwrap_or("").to_string();
        // Pull --conf-file=... or -C ... if present
        let conf_file = cmd.split_whitespace().find_map(|tok| {
            if let Some(rest) = tok.strip_prefix("--conf-file=") {
                Some(rest.to_string())
            } else { None }
        }).unwrap_or_default();
        let interface = cmd.split_whitespace().find_map(|tok| {
            tok.strip_prefix("--interface=").map(|s| s.to_string())
        }).unwrap_or_default();
        procs.push(serde_json::json!({
            "pid": pid,
            "command": cmd,
            "config_file": conf_file,
            "interface": interface,
        }));
    }
    procs
}

/// Lease files from common locations: WolfRouter's own dir, system
/// dnsmasq, ISC DHCPD, dhcpcd. Each entry includes parsed leases
/// where the format is recognisable.
fn list_lease_files() -> Vec<serde_json::Value> {
    let candidates = [
        "/var/lib/wolfstack-router",
        "/var/lib/misc",         // system dnsmasq default
        "/var/lib/dnsmasq",
        "/var/lib/dhcp",         // ISC DHCPD
        "/run",                   // legacy WolfStack VM TAP DHCP
    ];
    let mut out = Vec::new();
    for dir in &candidates {
        let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".leases") && !name.contains("lease") { continue; }
            let path_str = path.to_string_lossy().to_string();
            // Parse common dnsmasq format: <expires> <mac> <ip> <host> <client-id>
            let leases: Vec<serde_json::Value> = std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() < 4 { return None; }
                    Some(serde_json::json!({
                        "expires": parts[0],
                        "mac": parts[1],
                        "ip": parts[2],
                        "hostname": if parts[3] == "*" { "" } else { parts[3] },
                    }))
                })
                .collect();
            out.push(serde_json::json!({
                "path": path_str,
                "leases": leases,
            }));
        }
    }
    out
}

/// Live packet capture (Wireshark-style). Spawns `tcpdump` on the
/// requested interface with an optional BPF filter, captures up to N
/// packets (or until the timeout fires), returns the parsed lines.
///
/// Security:
///   • Auth required (cookie or cluster secret).
///   • Interface name validated against [a-zA-Z0-9._-] — no shell
///     metacharacters can leak into the spawned process.
///   • BPF filter is passed as a single argv token to tcpdump (not
///     through a shell), so tcpdump's own parser sees it. tcpdump
///     parses BPF, not arbitrary commands; misuse = capture errors,
///     not RCE. Filter is also length-capped at 200 chars.
///   • Hard timeout via tokio::time::timeout so a runaway capture
///     can't consume resources indefinitely.
#[derive(Deserialize, Clone, Serialize)]
pub struct CaptureRequest {
    pub iface: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default = "default_capture_count")]
    pub count: u32,
    /// Optional capture timeout in seconds (default 30, max 120).
    #[serde(default = "default_capture_timeout")]
    pub timeout_seconds: u64,
    /// Target cluster node id. If unset or matches self_node_id,
    /// runs locally. Otherwise the request is proxied to that node
    /// via the cluster secret so users can capture from any rack.
    #[serde(default)]
    pub node_id: Option<String>,
}
fn default_capture_count() -> u32 { 100 }
fn default_capture_timeout() -> u64 { 30 }

pub async fn packet_capture(
    req: HttpRequest,
    state: S,
    body: web::Json<CaptureRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    // Cluster proxy: if the user picked a remote node, forward the
    // capture request to that node's WolfStack via the cluster secret.
    let self_id = crate::agent::self_node_id();
    if let Some(target) = r.node_id.as_ref() {
        if !target.is_empty() && target != &self_id {
            let nodes = state.cluster.get_all_nodes();
            let target_node = match nodes.into_iter().find(|n| &n.id == target) {
                Some(n) => n,
                None => return HttpResponse::NotFound().body(format!("node '{}' not found in cluster", target)),
            };
            let secret = state.cluster_secret.clone();
            // Strip node_id from the proxied body so the remote node
            // doesn't recursively proxy back to us if a misconfigured
            // self_id mismatch happens.
            let mut proxy_body = r.clone();
            proxy_body.node_id = None;
            // Try HTTPS first then HTTP, mirroring the topology fan-out.
            let urls = [
                format!("https://{}:{}/api/router/capture", target_node.address, target_node.port),
                format!("http://{}:{}/api/router/capture",  target_node.address, target_node.port),
            ];
            let client = match reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(r.timeout_seconds + 10))
                .build()
            {
                Ok(c) => c,
                Err(e) => return HttpResponse::InternalServerError().body(format!("client build: {}", e)),
            };
            for url in &urls {
                match client.post(url)
                    .header("X-WolfStack-Secret", &secret)
                    .json(&proxy_body)
                    .send().await
                {
                    Ok(resp) if resp.status().is_success() => {
                        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
                        return HttpResponse::Ok().json(val);
                    }
                    Ok(resp) => {
                        let txt = resp.text().await.unwrap_or_default();
                        return HttpResponse::Ok().json(serde_json::json!({
                            "lines": [], "error": format!("remote node returned {}: {}", target_node.id, txt)
                        }));
                    }
                    Err(_) => continue,  // try next URL
                }
            }
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [], "error": format!("couldn't reach node '{}' (tried HTTPS then HTTP)", target_node.id)
            }));
        }
    }

    // Interface allowlist: alnum + . _ -. Any other character means a
    // shell metachar attempt or an unsupported iface name; reject.
    if r.iface.is_empty() || r.iface.len() > 32
        || !r.iface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return HttpResponse::BadRequest().body("invalid interface name");
    }
    if r.filter.len() > 200 {
        return HttpResponse::BadRequest().body("filter too long (max 200 chars)");
    }
    let count = r.count.clamp(1, 5000);
    let timeout = std::time::Duration::from_secs(r.timeout_seconds.clamp(1, 120));

    let mut args: Vec<String> = vec![
        "-nn".into(), "-l".into(),
        "-i".into(), r.iface.clone(),
        "-c".into(), count.to_string(),
        "-tttt".into(),  // human-readable timestamp
    ];
    if !r.filter.trim().is_empty() {
        args.push(r.filter.trim().to_string());
    }

    // Run tcpdump with timeout. Output is captured wholesale — for a
    // live-streaming variant we'd need SSE; this MVP is "give me N
    // packets that match".
    let cmd = tokio::process::Command::new("tcpdump")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(timeout, cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [], "error": format!("couldn't run 'tcpdump' — {} (install the 'tcpdump' package, and the WolfStack binary needs CAP_NET_RAW or root to capture)", e),
            }));
        }
        Err(_) => {
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [], "error": format!("capture timed out after {}s with fewer than {} packets matching", r.timeout_seconds, count),
            }));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

    if lines.is_empty() && !output.status.success() {
        return HttpResponse::Ok().json(serde_json::json!({
            "lines": [],
            "error": format!("tcpdump exited {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()),
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "lines": lines,
        "count": lines.len(),
        "iface": r.iface,
        "filter": r.filter,
    }))
}

/// Best-effort install of a network tool when WolfRouter detects it's
/// missing (currently used for tcpdump and conntrack). Detects the
/// host's package manager and runs the appropriate install command.
/// Requires WolfStack to be running as root or via sudo without
/// password — typical for managed appliances.
///
/// Allowlist of tool names — keeps the package name parameter from
/// becoming a shell-injection foothold.
#[derive(Deserialize)]
pub struct InstallToolRequest { pub tool: String }

pub async fn install_tool(
    req: HttpRequest,
    state: S,
    body: web::Json<InstallToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    // Allowlist: only tools WolfRouter actually uses. Maps tool name
    // → package name (often identical, but e.g. some distros split).
    let pkg = match r.tool.as_str() {
        "tcpdump"   => "tcpdump",
        "conntrack" => "conntrack",
        "iptables"  => "iptables",
        "dnsmasq"   => "dnsmasq",
        _ => return HttpResponse::BadRequest().body(
            "tool must be one of: tcpdump, conntrack, iptables, dnsmasq"
        ),
    };

    // Already installed? Short-circuit with a friendly message.
    if std::process::Command::new("which").arg(pkg).status()
        .map(|s| s.success()).unwrap_or(false)
    {
        return HttpResponse::Ok().json(serde_json::json!({
            "success": true, "message": format!("'{}' is already installed", pkg)
        }));
    }

    // Detect package manager. Order matters — apt-get exists on
    // Debian-derived (most common), then dnf, yum, pacman, zypper.
    let install: Option<(&str, Vec<&str>)> = if which("apt-get") {
        Some(("apt-get", vec!["install", "-y", pkg]))
    } else if which("dnf") {
        Some(("dnf", vec!["install", "-y", pkg]))
    } else if which("yum") {
        Some(("yum", vec!["install", "-y", pkg]))
    } else if which("pacman") {
        // pacman wants --noconfirm to skip prompts and -Sy to refresh
        Some(("pacman", vec!["-Sy", "--noconfirm", pkg]))
    } else if which("zypper") {
        Some(("zypper", vec!["install", "-y", pkg]))
    } else {
        None
    };
    let (cmd, args) = match install {
        Some(p) => p,
        None => return HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("no supported package manager found — install '{}' manually", pkg)
        })),
    };

    let out = match tokio::process::Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
    {
        Ok(o) => o,
        Err(e) => return HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("couldn't run {}: {}", cmd, e),
        })),
    };

    if out.status.success() {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("installed '{}' via {}", pkg, cmd),
        }))
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("{} install failed: {}", cmd, stderr),
        }))
    }
}

fn which(cmd: &str) -> bool {
    std::process::Command::new("which").arg(cmd).status()
        .map(|s| s.success()).unwrap_or(false)
}

// ─── WAN connections (DHCP / Static / PPPoE) ───

pub async fn list_wan(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    // Mask passwords on the way out — never roundtrip plaintext to UI.
    let masked: Vec<wan::WanConnection> = cfg.wan_connections.iter().map(|c| {
        let mut clone = c.clone();
        if let wan::WanMode::Pppoe(ref mut p) = clone.mode {
            if !p.password.is_empty() { p.password = "***".into(); }
        }
        clone
    }).collect();
    HttpResponse::Ok().json(masked)
}

pub async fn create_wan(req: HttpRequest, state: S, body: web::Json<wan::WanConnection>) -> HttpResponse {
    auth_or_return!(req, state);
    let mut conn = body.into_inner();
    if conn.id.is_empty() { conn.id = gen_id("wan"); }
    if let Err(e) = wan::validate(&conn) {
        return HttpResponse::BadRequest().body(e);
    }
    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.wan_connections.retain(|c| c.id != conn.id);
        cfg.wan_connections.push(conn.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if conn.node_id == crate::agent::self_node_id() || conn.node_id.is_empty() {
        // PPPoE prerequisite: ppp + pppoe packages.
        if matches!(conn.mode, wan::WanMode::Pppoe(_)) {
            ensure_pppoe_installed_async();
        }
        if let Err(e) = wan::apply(&conn) {
            tracing::warn!("WAN apply failed for {}: {}", conn.name, e);
        }
    }
    replicate_config_to_cluster(state);
    // Mask password before returning — never echo plaintext back to UI.
    let mut response = conn.clone();
    if let wan::WanMode::Pppoe(ref mut p) = response.mode {
        if !p.password.is_empty() { p.password = "***".into(); }
    }
    HttpResponse::Ok().json(&response)
}

pub async fn update_wan(
    req: HttpRequest, state: S,
    path: web::Path<String>, body: web::Json<wan::WanConnection>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let mut updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    if let Err(e) = wan::validate(&updated) {
        return HttpResponse::BadRequest().body(e);
    }
    // Preserve the existing password if the UI sent the masked "***"
    // sentinel (PUT bodies don't carry plaintext passwords back).
    {
        let mut cfg = state.router.config.write().unwrap();
        if let wan::WanMode::Pppoe(ref mut new_p) = updated.mode {
            if new_p.password == "***" {
                if let Some(existing) = cfg.wan_connections.iter().find(|c| c.id == id) {
                    if let wan::WanMode::Pppoe(ref old_p) = existing.mode {
                        new_p.password = old_p.password.clone();
                    }
                }
            }
        }
        let idx = match cfg.wan_connections.iter().position(|c| c.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.wan_connections[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if updated.node_id == crate::agent::self_node_id() || updated.node_id.is_empty() {
        let _ = wan::apply(&updated);
    }
    replicate_config_to_cluster(state);
    // Mask password before returning — never echo plaintext back to UI.
    let mut response = updated.clone();
    if let wan::WanMode::Pppoe(ref mut p) = response.mode {
        if !p.password.is_empty() { p.password = "***".into(); }
    }
    HttpResponse::Ok().json(&response)
}

pub async fn delete_wan(req: HttpRequest, state: S, path: web::Path<String>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let removed = {
        let mut cfg = state.router.config.write().unwrap();
        let r = cfg.wan_connections.iter().position(|c| c.id == id)
            .map(|i| cfg.wan_connections.remove(i));
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        r
    };
    if let Some(c) = removed {
        if matches!(c.mode, wan::WanMode::Pppoe(_)) {
            let _ = wan::pppoe_purge(&c);
        }
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

pub async fn wan_status(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let self_id = crate::agent::self_node_id();
    let entries: Vec<serde_json::Value> = cfg.wan_connections.iter()
        .filter(|c| c.node_id == self_id || c.node_id.is_empty())
        .map(|c| {
            let (iface, ip) = match &c.mode {
                wan::WanMode::Pppoe(_) => wan::pppoe_status(c)
                    .map(|(i, p)| (Some(i), Some(p)))
                    .unwrap_or((None, None)),
                _ => (None, None),
            };
            serde_json::json!({
                "id": c.id, "name": c.name, "interface": c.interface,
                "enabled": c.enabled,
                "live_iface": iface, "live_ip": ip,
            })
        }).collect();
    HttpResponse::Ok().json(entries)
}

/// Spawn a background task that ensures `ppp` and `pppoe` are
/// installed. Used right after a PPPoE connection is created so the
/// first apply has the binaries it needs.
fn ensure_pppoe_installed_async() {
    tokio::spawn(async {
        for tool in ["pppd", "pppoe"] {
            let installed = std::process::Command::new("which").arg(tool)
                .status().map(|s| s.success()).unwrap_or(false);
            if installed { continue; }
            // pkg name = same as binary on Debian/Ubuntu (ppp + pppoe);
            // RHEL family uses `ppp` and `rp-pppoe`. Try the common
            // package names — we don't require strict success here.
            let pkg_candidates: &[&str] = match tool {
                "pppd"  => &["ppp"],
                "pppoe" => &["pppoe", "rp-pppoe"],
                _ => &[],
            };
            for pkg in pkg_candidates {
                if which_install(pkg).await { break; }
            }
        }
    });
}

async fn which_install(pkg: &str) -> bool {
    let mgr = if which("apt-get") { Some(("apt-get", vec!["install", "-y", pkg])) }
        else if which("dnf")     { Some(("dnf", vec!["install", "-y", pkg])) }
        else if which("yum")     { Some(("yum", vec!["install", "-y", pkg])) }
        else if which("pacman")  { Some(("pacman", vec!["-Sy", "--noconfirm", pkg])) }
        else if which("zypper")  { Some(("zypper", vec!["install", "-y", pkg])) }
        else { None };
    let (cmd, args) = match mgr { Some(p) => p, None => return false };
    tokio::process::Command::new(cmd).args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map(|o| o.status.success()).unwrap_or(false)
}

/// Bring an interface up (`ip link set <iface> up`). Deliberately
/// one-way — there's no "Bring Down" companion. Bringing a link down
/// from the WolfRouter UI is a good way for operators to accidentally
/// take themselves offline over a remote session.
///
/// If `node_id` targets a remote cluster node, the request is proxied
/// there via the cluster secret (same pattern as packet capture).
///
/// Security: iface name is allowlisted to alnum + `.-_` so it can
/// never carry shell metachars, and tokio::process::Command is invoked
/// with a fixed argv (no shell involvement at all).
#[derive(Deserialize)]
pub struct InterfaceUpRequest {
    pub iface: String,
    #[serde(default)]
    pub node_id: Option<String>,
}

pub async fn interface_up(
    req: HttpRequest,
    state: S,
    body: web::Json<InterfaceUpRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    if r.iface.is_empty() || r.iface.len() > 32
        || !r.iface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return HttpResponse::BadRequest().body("invalid interface name");
    }

    // Proxy to remote node when requested.
    let self_id = crate::agent::self_node_id();
    if let Some(target) = r.node_id.as_ref() {
        if !target.is_empty() && target != &self_id {
            let nodes = state.cluster.get_all_nodes();
            let target_node = match nodes.into_iter().find(|n| &n.id == target) {
                Some(n) => n,
                None => return HttpResponse::NotFound().body(format!("node '{}' not found", target)),
            };
            let secret = state.cluster_secret.clone();
            let body_json = serde_json::json!({ "iface": r.iface });
            let client = match reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(10)).build()
            {
                Ok(c) => c,
                Err(e) => return HttpResponse::InternalServerError().body(format!("client build: {}", e)),
            };
            let urls = [
                format!("https://{}:{}/api/router/interface-up", target_node.address, target_node.port),
                format!("http://{}:{}/api/router/interface-up", target_node.address, target_node.port),
            ];
            for url in &urls {
                if let Ok(resp) = client.post(url)
                    .header("X-WolfStack-Secret", &secret)
                    .json(&body_json).send().await
                {
                    if resp.status().is_success() {
                        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
                        return HttpResponse::Ok().json(val);
                    }
                    let txt = resp.text().await.unwrap_or_default();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "success": false,
                        "error": format!("remote node returned: {}", txt)
                    }));
                }
            }
            return HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": "couldn't reach target node (tried HTTPS then HTTP)"
            }));
        }
    }

    // Local: run `ip link set <iface> up`.
    let out = tokio::process::Command::new("ip")
        .args(["link", "set", &r.iface, "up"])
        .output().await
        .map_err(|e| format!("spawn ip: {}", e));
    match out {
        Ok(o) if o.status.success() => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("brought '{}' up", r.iface)
        })),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": format!("ip link set up failed: {}", stderr),
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": e,
        })),
    }
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
        .route("/api/router/logs", web::get().to(list_firewall_logs))
        .route("/api/router/managed-overview", web::get().to(get_managed_overview))
        .route("/api/router/host-snapshot", web::get().to(get_host_snapshot))
        .route("/api/router/capture", web::post().to(packet_capture))
        .route("/api/router/install-tool", web::post().to(install_tool))
        .route("/api/router/wan",          web::get().to(list_wan))
        .route("/api/router/wan",          web::post().to(create_wan))
        .route("/api/router/wan/{id}",     web::put().to(update_wan))
        .route("/api/router/wan/{id}",     web::delete().to(delete_wan))
        .route("/api/router/wan-status",   web::get().to(wan_status))
        .route("/api/router/interface-up", web::post().to(interface_up));
}
