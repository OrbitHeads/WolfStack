# WolfFlow Extended Action Nodes — Implementation Plan

## Executive Summary

Extend WolfFlow with new action nodes for Docker update checks, generic HTTP requests, conditional branching, webhook triggers, and service-specific API integrations (NetBird, TrueNAS, Unifi). Also adds structured data passing between steps and a credential store.

---

## 1. Current Architecture

WolfFlow (`src/wolfflow/mod.rs`):
- **ActionType**: serde-tagged enum with 8 variants (RunCommand, DockerExec, etc.)
- **Toolbox**: `toolbox_actions()` returns JSON array of action metadata for the frontend
- **Execution**: `execute_action_local()` dispatches by ActionType, returns `Result<String, String>`
- **Workflow model**: linear sequential pipeline, each step has one ActionType + OnFailure policy
- **Scheduler**: 60-second tick loop, cron-based triggers
- **Frontend**: 3-panel editor (toolbox palette, step canvas, properties panel)

**Key limitation**: no data passing between steps, no branching. This plan adds both.

---

## 2. Core Data Model Extensions

### 2.1 Structured Step Output

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StepOutput {
    pub text: String,                                        // human-readable
    pub data: serde_json::Map<String, serde_json::Value>,   // structured key-value
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkflowContext {
    pub step_outputs: HashMap<String, StepOutput>,           // step_name → output
}
```

**Migration**: `execute_action_local()` changes from `Result<String, String>` to `Result<StepOutput, String>`. All existing handlers wrap their string output: `StepOutput { text: output, data: Default::default() }`. Fully backward-compatible.

### 2.2 New ActionType Variants (7 new)

```rust
pub enum ActionType {
    // ... existing 8 variants unchanged ...

    DockerCheckUpdate { container_or_image: String },

    DockerUpdate { container_name: String, #[serde(default)] backup_first: bool },

    HttpRequest {
        method: String,
        url: String,
        #[serde(default)] headers: Vec<HttpHeader>,
        #[serde(default)] body: Option<String>,
        #[serde(default)] auth: Option<HttpAuth>,
        #[serde(default = "default_timeout")] timeout_secs: u64,
        #[serde(default = "default_true")] fail_on_error: bool,
    },

    Condition {
        expression: String,     // e.g. "{{Docker Check.update_available}}"
        compare_to: String,     // e.g. "true"
        #[serde(default = "default_eq")] operator: String,  // eq, neq, gt, lt, contains, matches, truthy
    },

    NetBirdAction { endpoint: String, method: String, body: Option<String>, api_url: String, api_token: String },
    TrueNasAction { endpoint: String, method: String, body: Option<String>, api_url: String, api_key: String },
    UnifiAction { endpoint: String, method: String, body: Option<String>, api_url: String, username: String, password: String },
}
```

### 2.3 Branching Support in WorkflowStep

```rust
pub struct WorkflowStep {
    // ... existing fields ...
    #[serde(default)] pub on_true_step: Option<usize>,    // Condition → jump on true
    #[serde(default)] pub on_false_step: Option<usize>,   // Condition → jump on false
    #[serde(default)] pub retry_count: u32,
    #[serde(default)] pub retry_delay_secs: u64,
}
```

---

## 3. Execution Handlers

### 3.1 DockerCheckUpdate

1. Resolve container → image via `docker inspect`
2. Get local digest from `docker image inspect --format='{{.RepoDigests}}'`
3. Parse image reference → registry/namespace/name:tag
4. Acquire registry token (Docker Hub: `auth.docker.io/token`, GHCR: `ghcr.io/token`)
5. HEAD `/v2/<repo>/manifests/<tag>` → `Docker-Content-Digest` header
6. Compare. Output: `{ update_available: bool, current_digest, remote_digest, image }`

### 3.2 DockerUpdate

1. If `backup_first`: call `backup::backup_docker()` → store `rollback_id` in output
2. `docker pull <image>`
3. Rename-based safe recreate (same pattern as `docker_recreate_with_env()`)
4. Health check (wait, verify State.Running)
5. On failure: rollback (rename old back, restart)
6. Output: `{ success, rollback_id, old_image, new_image }`

### 3.3 HttpRequest

1. Build `reqwest::Client` with timeout
2. Apply auth (Bearer/Basic/ApiKey)
3. Set headers, body
4. Execute + return `{ status_code, response_body, response_headers }`
5. If `fail_on_error` and status >= 400 → `Err`

### 3.4 Condition

1. Resolve `{{step_name.key}}` templates from `WorkflowContext`
2. Apply operator (eq, neq, gt, lt, gte, lte, contains, matches, truthy)
3. Output: `{ result: true/false }`
4. Execution engine reads `on_true_step`/`on_false_step` to branch

### 3.5 Service-Specific Nodes

Thin wrappers around HTTP handler with pre-configured base URLs and auth:
- **NetBird**: Bearer token, endpoints like `/api/peers`, `/api/routes`
- **TrueNAS**: Bearer token (API key), endpoints like `/api/v2.0/pool`, `/api/v2.0/sharing/smb`
- **Unifi**: Cookie auth (login → session → subsequent requests), endpoints like `/api/s/default/stat/device`

---

## 4. Execution Engine Changes

### 4.1 Index-Based Loop with Jumps

```rust
let mut step_idx: usize = 0;
let mut context = WorkflowContext::default();

while step_idx < workflow.steps.len() {
    let step = &workflow.steps[step_idx];
    let result = execute_with_retry(step, &context).await;

    // Store output in context
    context.step_outputs.insert(step.name.clone(), result.clone());

    // Branching
    if matches!(step.action, ActionType::Condition { .. }) {
        let cond = result.data.get("result").and_then(|v| v.as_bool()).unwrap_or(false);
        step_idx = if cond { step.on_true_step } else { step.on_false_step }
            .unwrap_or(step_idx + 1);
    } else {
        step_idx += 1;
    }
}
```

### 4.2 Template Variable Resolution

```rust
fn resolve_templates(input: &str, context: &WorkflowContext) -> String {
    // Replace {{step_name.key}} with context.step_outputs[step_name].data[key]
    regex::Regex::new(r"\{\{(\w+)\.(\w+)\}\}")
}
```

### 4.3 Retry Logic

```rust
for attempt in 0..=step.retry_count {
    let result = execute_step(step, &context).await;
    if result.is_ok() || attempt == step.retry_count { break; }
    tokio::time::sleep(Duration::from_secs(step.retry_delay_secs)).await;
}
```

### 4.4 Context Passing

`execute_action_local()` signature becomes:
```rust
pub async fn execute_action_local(action: &ActionType, context: &WorkflowContext) -> Result<StepOutput, String>
```

---

## 5. Webhook Trigger

### Config

```rust
pub struct WebhookConfig {
    pub token: String,           // auto-generated UUID
    pub secret: Option<String>,  // optional HMAC-SHA256 verification
    pub enabled: bool,
}
```

Added as `#[serde(default)] pub webhook: Option<WebhookConfig>` on `Workflow`.

### Endpoint

`POST /api/wolfflow/webhook/{token}` — no auth required (secured by token):
1. Look up workflow by matching `webhook.token`
2. Validate optional HMAC signature (`X-Webhook-Signature` header)
3. Inject request body as `context.step_outputs["webhook"]`
4. Trigger `execute_workflow()` with trigger type `"webhook"`
5. Rate limited: 60 calls/minute per token

---

## 6. Credential Store

### File: `/etc/wolfstack/wolfflow/credentials.json`

```json
{
  "netbird-prod": { "type": "bearer", "token": "encrypted...", "label": "NetBird Prod" },
  "truenas-main": { "type": "api_key", "key": "encrypted...", "label": "TrueNAS Main" }
}
```

Referenced in actions as `"cred:netbird-prod"`. Resolved at runtime by execution engine.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/wolfflow/credentials` | List (names only, no secrets) |
| POST | `/api/wolfflow/credentials` | Create |
| PUT | `/api/wolfflow/credentials/{id}` | Update |
| DELETE | `/api/wolfflow/credentials/{id}` | Delete |

---

## 7. Enhanced Error Handling

### Extended OnFailure

```rust
pub enum OnFailure {
    Continue,
    Abort,
    Alert,
    NotifyAndAbort,      // alert + abort
    NotifyAndContinue,   // alert + continue
}
```

### Workflow Timeout

```rust
#[serde(default)] pub max_runtime_secs: u64,  // 0 = unlimited
```

---

## 8. Toolbox Entries

New entries in `toolbox_actions()` (existing 8 → 15 total):

| Action | Category | Icon | Key Fields |
|--------|----------|------|------------|
| `docker_check_update` | docker | magnifying-glass | container_or_image |
| `docker_update` | docker | arrow-rotate-right | container_name, backup_first (checkbox) |
| `http_request` | integration | globe | method, url, headers, body, auth, timeout, fail_on_error |
| `condition` | logic | code-branch | expression, operator, compare_to |
| `netbird_action` | services | network-wired | api_url, api_token, endpoint, method, body |
| `truenas_action` | services | database | api_url, api_key, endpoint, method, body |
| `unifi_action` | services | wifi | api_url, username, password, endpoint, method, body |

Each declares `outputs` array for the properties panel to show reference syntax.

---

## 9. Frontend Changes

### New Field Types in `renderActionFields()`

| Type | Renders |
|------|---------|
| `checkbox` | Boolean toggle |
| `key_value` | Add/remove rows with name/value pairs (headers) |
| `auth_selector` | Auth type dropdown with conditional sub-fields |
| `credential` | Dropdown of saved credentials |

### Toolbox Categories

Collapsible sections: System, Docker, Integration, Logic, Services.

### Color/Icon Map Extensions

```javascript
const wfActionColors = {
    docker_check_update: '#0ea5e9',
    docker_update:       '#0284c7',
    http_request:        '#8b5cf6',
    condition:           '#f97316',
    netbird_action:      '#06b6d4',
    truenas_action:      '#14b8a6',
    unifi_action:        '#6366f1',
};
```

### Condition Node Rendering

Initial: condition cards show "True → Step N, False → Step M" as text annotations. Linear canvas layout with branch labels. Full visual fork rendering is Phase 2.

### Output Preview

Properties panel shows available output fields and template syntax:
```
Outputs: update_available, current_digest, remote_digest
Reference: {{Docker Check.update_available}}
```

---

## 10. Cross-Feature Integration

### Docker Update Watcher → WolfFlow

When the watcher detects a new image, it can trigger WolfFlow workflows that have a `DockerCheckUpdate` first step. Add trigger type `"docker_update_detected"` alongside manual/scheduled/webhook.

### API Framework → WolfFlow

Service nodes use credentials from the shared credential store. Connection health from the integration framework can skip unavailable services.

---

## 11. Testing Strategy

### Unit Tests (extend existing test module)

1. Serde round-trip for all 7 new ActionType variants
2. Template variable resolution (`{{step.key}}` substitution)
3. Condition evaluation (all operators with various inputs)
4. StepOutput construction from Docker/HTTP results
5. Extend `toolbox_returns_all_actions` test (8 → 15)

### Integration Tests

1. Docker update check (pinned old image, verify detection)
2. HTTP request node (local mock server, various auth types)
3. Webhook trigger (POST to endpoint, verify execution starts)
4. End-to-end: "Check Update → Condition → Update or Skip" flow

---

## 12. Implementation Sequence

### Sprint 1: Core (data model + generic nodes)
1. `StepOutput`, `WorkflowContext`, supporting types
2. 7 new ActionType variants
3. Change `execute_action_local()` return type
4. `HttpRequest` handler
5. `Condition` handler + expression evaluator
6. Execution engine: branching, context passing, retry
7. Toolbox updates
8. Frontend: new field types, categories, colors
9. Unit tests

### Sprint 2: Docker nodes
1. `DockerCheckUpdate` handler (registry API)
2. `DockerUpdate` handler (backup integration)
3. Credential store (backend + frontend)
4. Docker integration tests

### Sprint 3: Service nodes + webhook
1. `NetBirdAction` handler
2. `TrueNasAction` handler
3. `UnifiAction` handler
4. Webhook trigger endpoint + frontend config

### Sprint 4: Polish
1. Condition node visual rendering
2. Enhanced error handling + notifications
3. Output preview in properties panel
4. Documentation

---

## Key Architectural Decisions

1. **Linear-with-jumps over DAG**: Index-based jumps for if/else. Full DAG (parallel branches, merge) later if needed.
2. **Service nodes as HTTP wrappers**: NetBird/TrueNAS/Unifi wrap generic HTTP handler. Bug fixes benefit all.
3. **Credential references**: `"cred:name"` syntax, never plaintext in workflow JSON.
4. **Simple templates over expression language**: `{{step.key}}` — secure, deterministic. Complex logic via chained conditions.
5. **Backward compatibility**: All new fields `#[serde(default)]`. Existing workflows deserialize unchanged.

---

## Files to Modify/Create

| File | Action |
|------|--------|
| `src/wolfflow/mod.rs` | Modify — ActionType (7 new), StepOutput, Context, execution engine, toolbox |
| `src/api/mod.rs` | Modify — webhook endpoint, credential endpoints, route registration |
| `web/js/app.js` | Modify — field types, categories, colors, condition rendering, output preview |
| `web/index.html` | Modify — editor elements |
| `src/containers/mod.rs` | Read — Docker functions used by update handlers |
