# App Store — Opt-in Docker Compose deployment

## Why

The app store today installs every app as a single `docker run` / `docker create` container (via `install_docker` → `docker_create_with_cmd`). For multi-container apps the sponsor community flagged real limitations: no standardised lifecycle, unclear volume/network layout, poor backup alignment, no easy override path.

Docker Compose already exists elsewhere in WolfStack (`/api/compose/stacks/{name}/...`, stored under `~/wolfstack/compose/stacks/{name}/docker-compose.yml`). This plan opts apps *into* Compose without changing anything about the existing run path.

## Guiding rule

**Nothing that works today may break.** Existing apps in the catalog, every app already installed, and every existing handler keep behaving identically. Compose is added as a **new branch** of the install/uninstall paths, reached only when (a) the manifest exposes a Compose template and (b) the user picks Compose at install time.

## Data model changes (all additive, all `#[serde(default)]`)

### `AppManifest.DockerTarget`

New optional field:

- `compose_yaml: Option<String>` — Handlebars-style template. When present, the UI offers a "Deploy with Docker Compose" option. When absent, there's no behaviour change at all.

### `InstalledApp`

Two new fields with defaults, so every existing `installed.json` record keeps deserialising cleanly as a docker-run install:

- `deployment_type: String` — `"docker-run"` (default) or `"docker-compose"`.
- `compose_stack_name: Option<String>` — set only for compose installs. Format: `appstore-{install_id}`.

## Install flow

`appstore::install_app()` branches on the `deployment_type` in the request:

- `"docker-run"` (default) — existing `install_docker()` path, untouched.
- `"docker-compose"` — new `install_compose()`:
  1. Render `compose_yaml` with the user's inputs (reuse the same substitution helper as the run path).
  2. Write to `~/wolfstack/compose/stacks/appstore-{install_id}/docker-compose.yml`.
  3. Shell `docker compose -p appstore-{install_id} up -d`.
  4. Record `deployment_type`, `compose_stack_name` on the new `InstalledApp`.

## Uninstall flow

Branch likewise:

- `"docker-run"` — existing unchanged.
- `"docker-compose"` — `docker compose -p {stack} down -v` (volume wipe is behind a frontend typed-YES confirmation), then remove the stack dir.

## View / edit the compose file

Two new endpoints:

- `GET /api/appstore/installed/{install_id}/compose.yaml` — returns the current rendered YAML.
- `PUT /api/appstore/installed/{install_id}/compose.yaml` — writes + `docker compose up -d`. Same validation/error path as the existing compose stacks API.

Frontend adds two buttons to compose-backed installed apps: **View compose** (read-only), **Edit compose** (writable, runs `up -d` on Save).

## Side effect: discoverability

Compose installs are **real compose stacks** named `appstore-*`, so they automatically appear on the existing Compose Stacks page. No new UI needed there — the naming convention makes them identifiable.

## Confirmation modal (generic, reusable)

New JS helper `confirmTypedYes(title, body, requiredWord = 'YES'): Promise<boolean>`, lifted from `mysqlConfirmDestructive` and hoisted to a shared utility. Used by:

- Uninstall of a compose app (because `down -v` wipes named volumes).
- Future destructive paths in Control Panel, Docker Raw Config, etc.

## What is explicitly OUT of scope

- **Auto-migrating existing run-based apps to compose.** Round-tripping is lossy (networks, healthchecks, restart policies). If added later, it belongs behind a "Migrate to Compose" button that generates a YAML for user review, not an automatic conversion.
- **Changing the default.** `docker-run` stays the default for catalog apps that don't ship a compose template.
- **Compose as the only supported deployment mode.** Never forced; always opt-in per app, per install.

## File/handler change list

| File | Change |
|---|---|
| `src/appstore/mod.rs` | Add `compose_yaml`, `deployment_type`, `compose_stack_name` fields; add `install_compose()` and compose uninstall branch; helpers for compose view/edit. |
| `src/api/mod.rs` | Accept `deployment_type` on install; add `GET` and `PUT /api/appstore/installed/{id}/compose.yaml`; register routes. |
| `web/index.html` | (None expected — existing modals reused.) |
| `web/js/app.js` | `confirmTypedYes()` helper; deployment-type radio in install modal; compose badge + View/Edit buttons on installed-app rows; compose-aware uninstall. |
| `plans/app-store-compose.md` | This file. |

## Risk register

- **Project-name collisions**: two instances of the same app would clash if named by app id. Solved by using `appstore-{install_id}` (install_id is already unique).
- **Compose v1 vs v2**: detect `docker compose` first, fall back to `docker-compose`. If neither is installed, refuse with a clear error — same behaviour as the existing compose stacks UI.
- **Destructive uninstall**: `down -v` only runs after the typed-YES confirmation in the frontend. Backend still accepts the request unconditionally if called via API — the UI is the safety gate (matches the project's existing destructive-action pattern).
- **Orphaned stack dirs**: ~~if uninstall fails partway, the stack dir may remain~~ → on install failure the path is rolled back automatically (`down -v` + `remove_dir_all`). Uninstall-down failures still remove the stack dir (intentional — the record is gone from `installed.json` so the directory would be dead anyway).

## Shipped additions (v19.0.6)

- **Cluster-wide installed list**: `loadInstalledApps` fans out across every online WolfStack node, annotates each install with `__node_id` + `__node_hostname`, and routes View / Edit / Uninstall through the cluster proxy when the install is remote. Compose files on any node are viewable and editable from any admin UI.
- **Robust YAML escaping**: `yaml_double_quoted()` replaces the naive `.replace('"', "\\\"")` — handles backslashes, newlines, carriage returns, tabs and any control character (`\xNN`). User-input values containing quotes, newlines, or binary no longer break the synthesised compose file.
- **Install rollback**: if `docker compose up -d` fails, `install_compose` runs `down -v --remove-orphans` and `remove_dir_all` before returning the error. No orphan directories accumulate under `/etc/wolfstack/compose/` from failed installs.
