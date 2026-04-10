# Docker Image Update Watcher - Implementation Plan

## Executive Summary

Adds a Docker image update watcher that periodically checks whether a container's upstream image has a newer digest available in its source registry. Covers Docker Hub, GHCR, and private registries. Key differentiator over Watchtower: automatically creates a full backup (volumes + config) before any update, enabling one-click rollback.

---

## 1. Registry API Integration (Docker Registry HTTP API v2)

### 1.1 Image Reference Parsing

New module `src/containers/image_watcher.rs`. Parse Docker image references:

- **Input**: `nginx:latest`, `ghcr.io/org/app:v2`, `registry.example.com:5000/myimage:stable`
- **Output struct** `ImageRef`:
  - `registry`: `registry-1.docker.io` / `ghcr.io` / custom
  - `repository`: `library/nginx` / `org/app`
  - `tag`: `latest` / `v2` / `stable`

Rules:
- No slash, no prefix → Docker Hub official: `nginx` → `registry-1.docker.io/library/nginx:latest`
- Single slash, no dots → Docker Hub user: `user/repo` → `registry-1.docker.io/user/repo:latest`
- Domain with dots/colons → custom registry
- Missing tag defaults to `latest`

### 1.2 Digest Comparison

1. **Local digest**: `docker inspect --format='{{index .RepoDigests 0}}'`
2. **Remote digest**: HEAD `/v2/<repository>/manifests/<tag>` with Accept headers for manifest v2 + OCI. Response header `Docker-Content-Digest` contains the remote digest.
3. **Multi-arch**: If manifest list returned, extract platform-specific digest for current arch.

Use `reqwest` (already a dependency) for async HTTP calls.

### 1.3 Authentication

- **Docker Hub**: Token from `https://auth.docker.io/token?service=registry.docker.io&scope=repository:<repo>:pull`
- **GHCR**: Token from `https://ghcr.io/token?service=ghcr.io&scope=repository:<repo>:pull`
- **Private**: Parse `/root/.docker/config.json` → `auths` map or `credStore`/`credHelpers`

---

## 2. Configuration Schema

### File: `/etc/wolfstack/image-watcher.json`

```rust
pub struct ImageWatcherConfig {
    pub enabled: bool,                                          // opt-in
    pub check_interval_secs: u64,                               // default: 3600
    pub default_policy: UpdatePolicy,                           // NotifyOnly | AutoUpdate | Ignore
    pub container_policies: HashMap<String, ContainerUpdatePolicy>,
    pub update_history: Vec<ImageUpdateEvent>,
}

pub struct ContainerUpdatePolicy {
    pub policy: UpdatePolicy,
    pub backup_before_update: bool,        // default: true
    pub backup_storage: Option<BackupStorage>,
    pub health_check: bool,                // default: true
    pub health_check_timeout_secs: u64,    // default: 60
    pub auto_rollback: bool,               // default: true
}

pub struct ImageUpdateEvent {
    pub id: String,                        // UUID
    pub container_name: String,
    pub image: String,
    pub old_digest: String,
    pub new_digest: String,
    pub backup_id: Option<String>,         // links to backup entry
    pub status: ImageUpdateStatus,         // UpdateAvailable | BackingUp | Pulling | Recreating | HealthChecking | Completed | RolledBack | Failed
    pub timestamp: String,
    pub error: Option<String>,
}
```

---

## 3. Background Check Loop

Spawn in `main.rs` following existing pattern (near line 332):

```rust
tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(120)).await; // settle
    loop {
        let config = image_watcher::load_config();
        if config.enabled {
            image_watcher::check_all_images(&config, &cluster, &alert_log).await;
        }
        tokio::time::sleep(Duration::from_secs(config.check_interval_secs.max(300))).await;
    }
});
```

Batching:
- Group containers by registry hostname for token reuse
- Max 10 concurrent registry API calls via `tokio::sync::Semaphore`
- Track rate limit headers and back off when approaching limits
- Cache results in `Arc<RwLock<HashMap<String, ImageCheckResult>>>` on AppState

---

## 4. Update Execution Flow

### Full Pipeline

1. **Pre-flight**: Verify container exists, has trackable image (has RepoDigests)
2. **Backup**: `backup_docker_volumes()` + `backup_docker()` (existing)
3. **Pull**: `docker pull <image>`
4. **Recreate**: Rename-based safe approach (modeled on `docker_recreate_with_env()`):
   - `docker inspect` → capture full config
   - `docker stop` + `docker rename` to `{name}_wolfstack_pre_update`
   - `docker create` with same config + new image
   - `docker start`
5. **Health check**: Wait N seconds, verify `State.Running`, optionally check HTTP endpoint
6. **Verify/Rollback**:
   - Healthy → remove old container, record success
   - Unhealthy + auto_rollback → stop new, rename old back, start, record rollback
   - Unhealthy + no rollback → keep both, alert user

### New: Volume Backup

```rust
pub fn backup_docker_volumes(container: &str) -> Result<Vec<(String, PathBuf, u64)>, String>
```

Tars each volume/bind mount to staging directory before update.

---

## 5. Rollback Mechanism

**Fast rollback** (within 24h): Old container was only renamed, not deleted:
1. Stop + remove new container
2. Rename `{name}_wolfstack_pre_update` back to `{name}`
3. Start it

**Full restore** (after cleanup): From backup archive:
1. `docker load` to restore image
2. Recreate container with original config
3. Restore volumes from tar backups
4. Start

---

## 6. REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/image-watcher/config` | Get watcher config |
| PUT | `/api/image-watcher/config` | Update global config |
| PUT | `/api/image-watcher/config/{container}` | Set per-container policy |
| GET | `/api/image-watcher/status` | Cached check results |
| POST | `/api/image-watcher/check` | Force check all |
| POST | `/api/image-watcher/check/{container}` | Force check one |
| POST | `/api/image-watcher/update/{container}` | Trigger update |
| POST | `/api/image-watcher/update-all` | Update all available |
| POST | `/api/image-watcher/rollback/{container}` | Rollback |
| GET | `/api/image-watcher/history` | Update history |
| DELETE | `/api/image-watcher/history/{id}` | Delete history entry |

---

## 7. Alerting Integration

Trigger alerts via existing `alerting::send_alert()`:
- Update available / started / completed / failed / rolled back
- Use cooldown with key `"image_update:{container_name}"`
- Push to `alert_log` for Tasks panel visibility

---

## 8. Frontend UI

### 8.1 Image Update Badge on Container Cards
Add `data-image-badge="docker:{name}"` spans alongside existing package update badges.

### 8.2 Update Dialog (Modal)
- Current vs available digest
- Backup checkbox (default: checked)
- Auto-rollback checkbox
- "Update Now" / "Cancel"

### 8.3 Container Detail Enhancement
- Image name + digest, last checked
- Policy dropdown (Notify / Auto / Ignore)
- "Check Now" / "Update Now" / "Rollback" buttons
- Per-container update history

### 8.4 Settings Page
- Global enable/disable
- Check interval (15m / 30m / 1h / 6h / 12h / 24h)
- Default policy + backup toggle
- Container policy overrides table

---

## 9. Edge Cases

| Case | Handling |
|------|----------|
| **Multi-arch images** | Compare manifest list digest first, fall back to platform-specific |
| **Docker Compose** | Detect via `com.docker.compose.project` label, warn about desync |
| **Anonymous volumes** | Warn — these won't survive recreation |
| **Locally built images** | Mark "not trackable", skip checks |
| **Self-signed certs** | `danger_accept_invalid_certs(true)` option per registry |
| **Rate limits** | Track `RateLimit-Remaining` header, back off |
| **Concurrent updates** | In-memory `HashSet<String>` of updating containers, one at a time |
| **WolfNet IPs** | Re-applied after recreation via existing `docker_effective_wolfnet_ip()` |

---

## 10. Implementation Sequence

### Phase 1: Core Infrastructure
1. Image reference parser + `ImageRef` struct
2. Registry auth (Docker config reader, token exchange)
3. Digest comparison (local inspect + remote HEAD)
4. Config load/save

### Phase 2: Background Loop
5. `image_watcher_cache` on AppState
6. `tokio::spawn` loop in main.rs
7. Alerting integration

### Phase 3: Update Pipeline
8. `backup_docker_volumes()` in backup module
9. `docker_recreate_with_image()` in containers module
10. Full pipeline (backup → pull → recreate → health check → rollback)

### Phase 4: REST API
11. 11 endpoint handlers + route registration

### Phase 5: Frontend
12. Badges, dialog, detail panel, settings UI, history view

### Phase 6: Polish
13. Compose handling, multi-arch, rate limiting, history pruning (keep 100)

---

## Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `src/containers/mod.rs` | Modify | Add image_watcher module, `docker_recreate_with_image()` |
| `src/backup/mod.rs` | Modify | Add `backup_docker_volumes()` |
| `src/api/mod.rs` | Modify | Add `image_watcher_cache` to AppState, 11 endpoints |
| `src/main.rs` | Modify | Background loop, AppState init |
| `web/js/app.js` | Modify | Badges, dialogs, settings, history |
