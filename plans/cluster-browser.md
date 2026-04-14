# Cluster Browser — implementation plan

## Goal

Run a real web browser inside the cluster (in a Docker container on a
WolfStack node) and stream its display to the user via WebSocket VNC.
The browser has direct WolfNet access, so it can hit any cluster web
service without any client-side VPN. The browser's homepage is a
WolfStack-served page listing all discovered web services as clickable
cards. URL bar still works for anything not in the list.

## Why a browser, not a proxy

Web apps assume their own root URL — proxying through path prefixes
breaks links/cookies/CSRF for any non-trivial app. A real browser
inside the cluster sees PBS / Plex / Sonarr / Grafana / etc. exactly
as they were designed.

## Architecture

```
[user's browser]
       │  HTTPS to WolfStack
       ▼
[WolfStack node:8553] ──── /api/cluster-browser/start
       │
       │ docker run lscr.io/linuxserver/firefox
       ▼
[firefox container]  ──── KasmVNC on container:3000
       │
       │ HTTP/HTTPS direct to WolfNet IPs (host network)
       ▼
[PBS @ 10.100.10.5:8007]   [Plex @ 10.100.10.12:32400]   ...
```

Container is on the host network namespace so the in-container browser
can reach WolfNet IPs the same way the WolfStack daemon does. WolfStack
proxies the container's KasmVNC web UI back to the user.

## Phases

### Phase 1 — minimal browser session (foundation)

- New module `src/cluster_browser/mod.rs`
- POST `/api/cluster-browser/sessions` — creates container, returns `{ session_id, ws_port, web_url }`
- DELETE `/api/cluster-browser/sessions/{id}` — stops + removes container
- GET `/api/cluster-browser/sessions` — list active per node
- Sidebar entry "Cluster Browser" → page with "Start Browser" button → opens a new tab/iframe pointing at the container's KasmVNC web URL
- Container image: `lscr.io/linuxserver/firefox:latest` (multi-arch, KasmVNC bundled)
- Per-session container name: `wolfstack-browser-<8char-id>`
- Per-session web port: allocated from 33000-33999 range
- Session metadata persisted in `/etc/wolfstack/cluster-browser-sessions.json`
- Cleanup: hourly background task removes sessions with stopped containers
- Resource defaults: 2 GB RAM, 2 cores (configurable in start request)

### Phase 2 — service discovery

- New module `src/services_discovery/mod.rs`
- Background task (every 5 minutes) walks `routes.json` (every WolfNet IP in the cluster)
- For each IP, probes a curated port list with a 2-second timeout each
- For responding ports, sniff `<title>`, `Server:` header, common path probes (`/api/version`, etc.)
- Identify well-known apps: PBS, Plex, Sonarr/Radarr/Prowlarr/Lidarr/Bazarr, Grafana, Prometheus, Portainer, Jellyfin, Home Assistant, Vaultwarden, Nextcloud, Gitea/Forgejo, Wolfstack itself, etc.
- Output to `/etc/wolfstack/cluster-services.json`
- Manual add/remove via API for non-standard ports we missed
- GET `/api/cluster-services` — list with filter/category

Curated port probe list:

| Port  | Protocol | Common app                    |
|------:|----------|-------------------------------|
|    80 | http     | Generic                       |
|   443 | https    | Generic                       |
|  3000 | http     | Grafana, Outline              |
|  3001 | http     | Uptime Kuma                   |
|  5000 | http     | dev / Synology Web Station    |
|  5601 | http     | Kibana                        |
|  7474 | http     | Neo4j                         |
|  7878 | http     | Radarr                        |
|  8000 | http     | dev                           |
|  8006 | https    | Proxmox VE                    |
|  8007 | https    | Proxmox Backup Server         |
|  8080 | http     | Many                          |
|  8081 | http     | Sonarr alt / Nexus            |
|  8090 | http     | Confluence                    |
|  8096 | http     | Jellyfin                      |
|  8112 | http     | Deluge                        |
|  8123 | http     | Home Assistant                |
|  8200 | http     | Vault                         |
|  8443 | https    | Many                          |
|  8553 | https    | WolfStack itself              |
|  8888 | http     | Jupyter                       |
|  8989 | http     | Sonarr                        |
|  9000 | http     | Portainer                     |
|  9090 | http     | Prometheus, Cockpit           |
|  9443 | https    | Portainer HTTPS               |
|  9696 | http     | Prowlarr                      |
| 32400 | http     | Plex                          |

### Phase 3 — homepage page

- Static-ish endpoint `GET /cluster-home` — returns HTML
- Auth: cluster secret in URL OR no auth (it just lists URLs that any
  WolfNet-attached host could list anyway)
- HTML: dark, big icon cards per service, click → open in same tab
- Default homepage for the in-container browser:
  `http://<wolfstack-host-wolfnet-ip>:8553/cluster-home`
- Set via the linuxserver/firefox image's `HOMEPAGE` env, or via a
  custom Firefox profile mounted into the container at startup

### Phase 4 — UX polish

- Persistent per-user browser profiles (Docker named volume `wolfstack-browser-<username>`)
- Bookmark file pre-seeded with discovered services
- Idle session timeout (close after N minutes of no client connection)
- Multi-session support per user
- Container resource limits surfaced in the UI
- "Open in Cluster Browser" button on the discovered services list AND
  next to every running container/VM in WolfStack that has a known web
  port

## Open questions

1. **Per-user vs shared sessions.** Probably per-user with persistent
   profile. Easier multi-tenancy, bookmarks survive across sessions.
2. **Session limits.** One per user? Multiple? GC after N minutes idle?
3. **Discovery scope.** Just WolfNet IPs, or also LAN-discovered
   services? Start with WolfNet only.
4. **Homepage auth.** No auth (URL-list only) or share-of-cluster-secret
   to view? Start with no auth — it leaks hostnames/ports but those are
   already discoverable on WolfNet anyway.
5. **Image trust.** linuxserver/firefox is well-maintained but a third
   party. Alternative: build our own minimal image. Start with theirs.

## File layout

- `src/cluster_browser/mod.rs` — new
- `src/services_discovery/mod.rs` — new
- `src/main.rs` — `mod cluster_browser; mod services_discovery;` + spawn discovery task
- `src/api/mod.rs` — new endpoints
- `web/js/app.js` — sidebar entry, view, session controls
- `web/cluster-home.html` — homepage template (or generated from API)
- `web/index.php` (website) — feature card

## Build order

1. Service discovery module (works standalone, no UI needed yet)
2. Discovery API endpoint + frontend Services page
3. Cluster browser session module
4. Cluster browser API + frontend page
5. Homepage HTML page
6. Wire homepage into the container's Firefox profile

Let's start at #1 and iterate.
