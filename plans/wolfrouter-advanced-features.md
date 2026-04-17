# WolfRouter Advanced Features — Parked Plan

Parked 2026-04-16. Four features queued; user has client work; pick this up later.

## Phase 1 — Multi-WAN Failover (~2 days, standalone)
- Extend `WanConnection` in `src/networking/router/wan.rs`: add `priority: u32`, `is_backup: bool`, `health_check: Option<HealthCheck>` (`target_ip`, `interval_secs`, `timeout_secs`, `fail_threshold`, `recover_threshold`).
- New `WanState` enum: `Active | Standby | Failed | Disabled`.
- Background task (~30s tick) in `main.rs`: ping `health_check.target_ip` via the WAN's iface (`ping -I <iface>`); swap default route on failover via `ip route replace default via <gw> dev <iface> metric <priority>`. Respect fail/recover thresholds.
- New `apply_routing_table()` — weighted ECMP (if multiple non-backup) or active/standby.
- New endpoints: `GET /api/router/wan-health`, `POST /api/router/wan/{id}/failover-test`.
- Frontend: extend existing WAN tab — health-check toggle, target IP, interval, priority slider, "backup" checkbox per card; live status badge; "Force failover" button.

## Phase 2 — IDS/IPS via Suricata (~4 days, depends on Phase 1)
- New module `src/networking/router/ids.rs`. `IdsConfig`: `enabled`, `mode: IdsMode` (IDS tap or IPS inline), `rule_sources`, `home_net`, `alert_threshold`, `excluded_sids`.
- `install_suricata()` + `suricata-update`; systemd lifecycle; `read_eve_log()` tails `/var/log/suricata/eve.json`.
- Firewall hook (`firewall.rs`):
  - IPS mode: `-A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass` (fail-open; toggleable).
  - IDS mode: reuse existing NFLOG at group 2.
- Endpoints: `GET|POST /api/router/ids/config`, `GET /api/router/ids/alerts`, `POST /api/router/ids/update-rules`, `POST /api/router/ids/exclude-sid`, `GET /api/router/ids/status`.
- New frontend tab `ids`: alert table with severity colour, top-10 sigs sparkline, IDS↔IPS toggle with warning, rule-sources checklist, "Ask AI" wired to `analyze_issue()` for alert triage.

## Phase 3 — Captive Portal (~3 days, depends on Phase 1)
- New module `src/networking/router/captive.rs`. `CaptivePortalConfig`: per-LAN, `auth_mode` (click-through/password/voucher/RADIUS), `session_timeout_mins`, optional `bandwidth_limit_kbps`, `splash_html`.
- `AuthSession { mac, ip, authenticated_at, expires_at }`. Persisted.
- DNS interception in `dhcp.rs`: inject `address=/#/<portal_ip>` into the LAN's dnsmasq config when captive is on.
- Firewall (`firewall.rs`): new `WOLFROUTER_CAPTIVE` chain. Authed MACs `-j RETURN`; unauthed HTTP/HTTPS DNATed to portal; everything else DROP.
- Splash page served at `GET /captive` (no auth). Auto-detects client IP/MAC from request. POST to `/api/router/captive/auth` then 302 back to original URL.
- Endpoints: `GET|POST /api/router/captive/config`, `GET /api/router/captive/sessions`, `DELETE /api/router/captive/sessions/{mac}`, `POST /api/router/captive/auth`, `POST /api/router/captive/vouchers/generate`.
- New frontend tab `captive`: enable-per-LAN, splash HTML editor with preview, active sessions table with kick button, voucher generator.

## Phase 4 — BGP/OSPF via FRRouting (~5 days, depends on Phase 1)
- Use FRR — don't reinvent a routing daemon.
- New module `src/networking/router/routing.rs`. `RoutingConfig.protocols: Vec<RoutingProtocol>`.
  - `Bgp { asn, router_id, neighbors, networks, route_maps }`
  - `Ospf { router_id, areas, passive_interfaces, redistribute }`
  - `Static { routes }`
- `install_frr()`; generate `/etc/frr/frr.conf` from config; `systemctl reload frr` or atomic `vtysh -f`.
- Query live state via `vtysh -c "show ... json"` for routes, BGP summary, OSPF neighbors.
- Endpoints: `GET|POST /api/router/routing/config`, `GET /api/router/routing/status`, `GET /api/router/routing/table`, `POST /api/router/routing/neighbor`, `POST /api/router/routing/area`.
- New frontend tab `routing`: BGP panel (neighbor table with state/prefixes/uptime), OSPF panel (areas + redistribute toggles), live RIB with search, topology mini-map of adjacencies.

## Notes
- Suricata NFQUEUE integration is the riskiest bit — fail-open via `--queue-bypass` is the safe default; document clearly.
- BGP/OSPF via FRR is safer than rolling our own; FRR is battle-tested and has good JSON output for the live state queries.
- Captive portal's DNS-redirect approach breaks DoH clients — document limitation; consider MAC-based iptables redirect as alternative.
