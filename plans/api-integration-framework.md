# External API Integration Framework — Implementation Plan

## Executive Summary

An extensible framework for managing external services (NetBird, TrueNAS, Unraid, Unifi) through their REST APIs. Trait-based connector architecture — implement one trait per service, the framework handles auth, retry, rate limiting, health checks, credential storage, WolfFlow action registration, and frontend dashboards.

---

## 1. Module Structure

```
src/integrations/
    mod.rs              — Connector trait, IntegrationState, credential vault
    client.rs           — Generic REST client (auth strategies, retry, rate limiting)
    connectors/
        mod.rs          — Registry, built-in connector list
        netbird.rs      — NetBird VPN
        truenas.rs      — TrueNAS
        unifi.rs        — Unifi Controller
        unraid.rs       — Unraid (stub)
        custom.rs       — OpenAPI-spec-driven custom connector (Phase 2)
```

Config files:
- `/etc/wolfstack/integrations/instances.json` — configured connections
- `/etc/wolfstack/integrations/vault.json` — encrypted credentials

---

## 2. Connector Trait

```rust
#[async_trait]
pub trait Connector: Send + Sync {
    fn info(&self) -> ConnectorInfo;
    fn capabilities(&self) -> Vec<ConnectorCapability>;
    async fn health_check(&self, client: &IntegrationClient, instance: &IntegrationInstance) -> HealthStatus;
    async fn execute(&self, client: &IntegrationClient, instance: &IntegrationInstance,
                     operation: &str, params: &Value) -> Result<Value, String>;
    async fn dashboard_data(&self, client: &IntegrationClient, instance: &IntegrationInstance,
                            capability_id: &str) -> Result<Value, String>;
}
```

Each connector declares:
- **ConnectorInfo**: id, name, icon, auth methods, config fields
- **Capabilities**: feature groups (e.g., "vpn_users", "storage_pools"), each with WolfFlow ActionDefs
- **Health check**: async probe returning Online/Degraded/Offline
- **Execute**: run a named operation with params (used by WolfFlow + dashboard)
- **Dashboard data**: return structured JSON for a capability tab

---

## 3. Credential Vault

AES-256-GCM encryption at rest, key derived from cluster secret via HKDF-SHA256.

```rust
pub struct StoredCredential {
    pub instance_id: String,
    pub auth_method: AuthMethod,      // Bearer, ApiKey, BasicAuth, OAuth2, Cookie
    pub encrypted_data: String,       // base64(nonce || ciphertext || tag)
}
```

- Uses `ring` crate (already in Cargo.toml)
- Key derived from cluster secret — no separate master password
- Re-encrypt on cluster secret rotation
- Credentials never returned in plaintext via API

---

## 4. Generic REST Client

```rust
pub struct IntegrationClient {
    inner: reqwest::Client,
    rate_limiters: RwLock<HashMap<String, RateLimiter>>,  // per-instance token bucket
}
```

Features:
- **Auth strategies**: Bearer, API Key (custom header), Basic, OAuth2 (auto-refresh), Cookie (session login)
- **Retry**: Exponential backoff (1s/2s/4s) for 5xx + timeouts, no retry on 4xx
- **Rate limiting**: Token bucket per instance (default 10 req/s, connector-overridable)
- **Timeout**: 30s default, configurable
- **TLS**: `danger_accept_invalid_certs` option (matching existing pattern)
- **User-Agent**: `WolfStack/{version}`

---

## 5. Integration Instance Model

```rust
pub struct IntegrationInstance {
    pub id: String,
    pub connector_id: String,        // "netbird", "truenas", "unifi"
    pub name: String,                // user display name
    pub base_url: String,
    pub auth_method: AuthMethod,
    pub config: HashMap<String, String>,  // connector-specific
    pub enabled: bool,
    pub allowed_roles: Vec<String>,  // ["admin"] or ["admin", "viewer"]
}

pub struct IntegrationState {
    instances: RwLock<Vec<IntegrationInstance>>,
    health_cache: RwLock<HashMap<String, HealthStatus>>,
    vault: RwLock<Vec<StoredCredential>>,
    client: IntegrationClient,
    connectors: HashMap<String, Box<dyn Connector>>,
    encryption_key: Vec<u8>,
}
```

Added to `AppState` as `pub integrations: Arc<IntegrationState>`.

---

## 6. Health Check Background Loop

In `main.rs`, following existing tokio::spawn pattern:

```rust
tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        int_state.check_all_health().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
});
```

- Iterates enabled instances, calls each connector's `health_check()`
- Updates `health_cache`
- Fires alert via `alerting::send_alert()` on Online→Offline transitions

---

## 7. First Three Connectors

### 7.1 NetBird

- **API**: `https://<host>/api` — Bearer token auth
- **Capabilities**: peers, groups, users, routes, acl, dns
- **WolfFlow actions**: `netbird_list_peers`, `netbird_disable_peer`, `netbird_create_group`, `netbird_add_route`, `netbird_create_acl`
- **Dashboard**: peers table (status dots), groups tree, routes table, ACL rules

### 7.2 TrueNAS

- **API**: `https://<host>/api/v2.0` — Bearer token (API key)
- **Capabilities**: pools, datasets, snapshots, shares, system
- **WolfFlow actions**: `truenas_pool_status`, `truenas_create_snapshot`, `truenas_list_alerts`, `truenas_create_share`, `truenas_system_info`
- **Dashboard**: pool cards (usage bars, health), dataset tree, snapshot table (rollback buttons), shares tabs, alerts

### 7.3 Unifi

- **API**: `https://<host>:8443/api` — Cookie auth (login with username/password)
- **Capabilities**: devices, clients, networks, firewall, stats
- **WolfFlow actions**: `unifi_list_clients`, `unifi_block_client`, `unifi_restart_device`, `unifi_adopt_device`, `unifi_create_firewall_rule`
- **Dashboard**: device table, client table (signal/bandwidth), VLAN table, firewall rules, stats charts
- **Note**: Requires session cookie management — login endpoint → store cookie → use for subsequent requests

---

## 8. WolfFlow Integration

### New ActionType Variants

```rust
IntegrationAction {
    instance_id: String,
    operation: String,
    params: serde_json::Value,
},
IntegrationHealthCheck {
    instance_id: String,
    require_online: bool,
},
```

### Toolbox Extension

`toolbox_actions()` dynamically includes integration actions from each enabled connector's capabilities. Each action appears in an "Integrations" category with an instance selector dropdown.

---

## 9. REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/integrations/connectors` | List available connector types |
| GET | `/api/integrations` | List configured instances + health |
| POST | `/api/integrations` | Create instance |
| GET | `/api/integrations/{id}` | Instance details |
| PUT | `/api/integrations/{id}` | Update config |
| DELETE | `/api/integrations/{id}` | Remove |
| POST | `/api/integrations/{id}/test` | Test connectivity |
| POST | `/api/integrations/{id}/toggle` | Enable/disable |
| POST | `/api/integrations/{id}/credentials` | Store credentials (encrypted) |
| DELETE | `/api/integrations/{id}/credentials` | Remove credentials |
| GET | `/api/integrations/{id}/data/{capability}` | Dashboard data |
| POST | `/api/integrations/{id}/action` | Execute ad-hoc action |

---

## 10. Frontend

### Navigation
New "Integrations" icon in datacenter sidebar → `selectView('integrations')` → loads integration list page.

### Integration List Page
Card grid of configured integrations: icon, name, status dot, base URL, latency. "Add Integration" button opens wizard (select connector → enter URL → credentials → test → confirm).

### Per-Service Dashboard
Tabbed view per instance. Tabs from connector capabilities. Data fetched from `/api/integrations/{id}/data/{capability}`. Connector-specific JS renderers with a generic table fallback:

```javascript
const integrationRenderers = {
    'netbird': { 'peers': renderNetBirdPeers, ... },
    'truenas': { 'pools': renderTrueNasPools, ... },
    'unifi':   { 'devices': renderUnifiDevices, ... },
};
```

### WolfFlow Editor
Integration actions auto-appear in toolbox via backend. Add `integration_select` field type (dropdown of instances for the connector). Add "Integrations" category filter.

---

## 11. Custom Integrations (Phase 2)

Import OpenAPI 3.x spec → auto-generate capabilities from path groups → dynamic API calls from spec. Endpoint: `POST /api/integrations/import-openapi`.

For Phase 1: framework supports it architecturally, but OpenAPI parser not built. Users can use WolfFlow's `RunCommand` or generic `HttpRequest` nodes.

---

## 12. Security Model

- **RBAC**: `allowed_roles` per instance, checked against user role from `require_auth()`
- **Credentials**: never returned in plaintext, vault file 0600 perms, decryption only in-memory before API calls
- **SSRF mitigation**: validate `base_url` not private/loopback (admin override available)
- **Rate limiting**: prevents runaway calls to external services
- **Re-encryption**: vault re-encrypted on cluster secret rotation

---

## 13. Implementation Sequence

### Phase 1: Foundation
1. Path entries in `src/paths.rs`
2. Core module: `src/integrations/mod.rs` — types, trait, state, vault
3. Client: `src/integrations/client.rs` — auth, retry, rate limiting
4. Connector registry: `src/integrations/connectors/mod.rs`
5. Wire into `main.rs` — AppState, background health loop
6. REST endpoints in `src/api/mod.rs`

### Phase 2: Connectors
7. NetBird connector
8. TrueNAS connector
9. Unifi connector

### Phase 3: WolfFlow
10. `IntegrationAction` / `IntegrationHealthCheck` in ActionType enum
11. Execution logic + dynamic toolbox

### Phase 4: Frontend
12. Navigation + integration list page
13. Add Integration wizard
14. Per-service dashboards (NetBird, TrueNAS, Unifi renderers)
15. WolfFlow editor instance selector

### Phase 5: Polish
16. Unraid connector stub
17. OpenAPI import
18. Alerting integration (health transitions)
19. Settings tab (global defaults, SSRF toggle)

---

## Dependencies

```toml
ring = "0.17"           # already present — AEAD encryption
async-trait = "0.1"     # for async trait methods
# reqwest, serde, tokio, chrono, uuid, base64, tracing — already present
```

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `src/integrations/mod.rs` | Create — trait, state, vault |
| `src/integrations/client.rs` | Create — REST client |
| `src/integrations/connectors/mod.rs` | Create — registry |
| `src/integrations/connectors/netbird.rs` | Create |
| `src/integrations/connectors/truenas.rs` | Create |
| `src/integrations/connectors/unifi.rs` | Create |
| `src/paths.rs` | Modify — add integration paths |
| `src/api/mod.rs` | Modify — AppState field, 12 endpoints, routes |
| `src/main.rs` | Modify — module decl, state init, health loop |
| `src/wolfflow/mod.rs` | Modify — ActionType variants, toolbox |
| `web/js/app.js` | Modify — integration pages, dashboards |
| `web/index.html` | Modify — navigation icon |
