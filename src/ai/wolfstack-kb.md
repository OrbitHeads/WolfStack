# WolfStack Expert Knowledge Base

## Architecture
- Single Rust binary (actix-web 4), no database, no containers needed
- Config persisted as JSON files in /etc/wolfstack/
- Default ports: 8553 (HTTPS / dashboard), 8554 (HTTP inter-node, TLS-only installs), 8550 (public status pages)
- Requires root (reads /etc/shadow for auth)
- Background tasks: self-monitoring (2s), node polling (10s), status page checks (30s), session cleanup (300s), backup scheduling (60s)

## Ports Configuration
- Per-node ports persisted to /etc/wolfstack/ports.json as `{ api, inter_node, status }`
- UI: sidebar → gear icon on a node → Node Ports panel (local node only)
- CLI `--port N` still overrides the API port and pulls inter_node = N+1 with it
- Status port auto-fallback: if the configured status port is taken on boot, WolfStack scans 8550-8599 for a free one, binds there, persists the new port to ports.json, warns in logs
- API and inter_node ports hard-fail if taken (silent move would break peer polling)
- Common status-port collision: WolfDisk also defaults to 8550; auto-fallback moves WolfStack's status page aside

## VM Management (Native QEMU, Proxmox, Libvirt)
- Three backends: native QEMU (builds command line directly), Proxmox (qm commands), libvirt (virsh)
- Auto-detected: `is_proxmox()` checks for `pct`, `is_libvirt()` checks `virsh uri`
- VM configs stored in /var/lib/wolfstack/vms/{name}.json
- Disk images in /var/lib/wolfstack/vms/{name}.qcow2
- VmConfig carries `host_id: Option<String>` — the node that owns the VM. Stamped on create, rewritten by import_vm on migration target. Lets the cluster view render VMs as first-class members without a manual Scan.

### Serial Terminal
- Click the 💻 Terminal button on any running VM to open a WebSocket serial console
- Backend dispatches per platform: PVE runs `qm terminal <vmid>`, libvirt runs `virsh console <name> --force`, standalone QEMU uses socat to /var/lib/wolfstack/vms/{name}.serial.sock
- Standalone QEMU spawn wires `-chardev socket,id=serial0,path=<sock>,server=on,wait=off -serial chardev:serial0` automatically so the socket exists for socat to attach to
- Frontend pre-flights via GET /api/vms/{name}/serial-status — three outcomes:
  1. Not running → toast "start it first"
  2. Running but no serial device → Add-serial modal pops, POSTs /add-serial to wire one up
  3. Running + configured → opens terminal
- POST /api/vms/{name}/add-serial handles the fix:
  - PVE: `qm set <vmid> --serial0 socket` (reboot needed if running)
  - libvirt: dumpxml, attach only missing `<serial>` / `<console>` fragments via `virsh attach-device --config`, treats "already exists" as success
  - standalone: error message — restart the VM to pick up the new -chardev args
- Guest-side requirement (cannot be fixed from host): `console=ttyS0` on kernel cmdline + a getty on ttyS0. Terminal prints this hint at the top on every open.

### Stop vs Force Stop
- Running VMs have two stop buttons with distinct semantics
- Stop (`action: "stop"`, `force=false`): graceful ACPI — `qm shutdown --timeout 30`, `virsh shutdown`, or SIGTERM
- Force Stop (`action: "force-stop"`, `force=true`): immediate — `qm stop`, `virsh destroy`, or SIGKILL. Confirm dialog warns about unsaved data loss.
- Internal callers that need a guaranteed halt (migration export, VM delete) still pass force=true

### Import Disk Image
- When creating a VM, the "Import Disk Image" field accepts a path to an existing QCOW2, IMG, VMDK, VDI, or VHD file
- The image is converted to QCOW2 via qemu-img convert and used as the OS disk
- Supports importing from Proxmox, VMware, VirtualBox, and raw images like Home Assistant OS

### USB/PCI Passthrough
- Passthrough tab in VM settings shows host USB and PCI devices
- USB: matched by vendor:product ID (e.g. 046d:c52b)
- PCI: matched by BDF address (e.g. 0000:01:00.0), requires IOMMU/VFIO
- IOMMU group awareness — devices in the same group shown together
- Conflict guard: prevents two running VMs from claiming the same device
- Works across all three backends (native QEMU args, Proxmox qm set, libvirt hostdev XML)

### OVMF/UEFI Boot Issue
- When network config changes on a UEFI VM (WolfNet IP added, NIC added/removed, NIC model changed), OVMF boot entries reference old device paths
- WolfStack automatically resets EFI vars when network topology changes (v16.16.9+)
- Manual fix: delete /var/lib/wolfstack/vms/{name}_VARS.fd and restart VM
- Or switch to SeaBIOS temporarily — it doesn't have this issue

### Networking
- User-mode (default): VM gets NAT internet access, no incoming connections
- WolfNet IP: creates TAP interface with DHCP (requires dnsmasq installed on host)
- Bridge/Physical NIC: creates dedicated bridge for the physical interface, VM gets LAN IP via DHCP from router
- Extra NICs: add additional NICs for multi-homed VMs (e.g. OPNsense WAN+LAN)
- If VM has WolfNet IP but no DHCP response: check `ps aux | grep dnsmasq | grep tap` and install dnsmasq if missing

## Docker Container Management
- Lists containers via Docker socket API
- Start, stop, restart, remove, create
- Log viewing, exec into container
- WolfNet IP assignment for containers
- Auto-restart policy management

## LXC Container Management
- Full lifecycle: create from templates, start, stop, destroy
- File manager: browse, read, write, delete files inside LXC containers
- Exec commands inside containers
- Resource limits (CPU, memory)

## WolfNet (Encrypted Mesh VPN)
- Userspace VPN: X25519 key exchange + ChaCha20-Poly1305 encryption
- Does NOT use WireGuard kernel modules — only needs /dev/net/tun
- LAN auto-discovery on port 9601, tunnel traffic on port 9600
- Join flow: `wolfnet invite` on existing node → token → `wolfnet join <token>` on new node
- Docker image published to `ghcr.io/wolfsoftwaresystemsltd/wolfnet:latest` (multi-arch: linux/amd64 + linux/arm64)
- For NAS platforms (Unraid, Synology, TrueNAS), use the satellite compose file at docker/docker-compose.satellite.yml in the WolfStack repo — bundles WolfNet + WolfDisk
- Gateway mode: NAT traffic through a WolfNet peer

## WolfDisk (Distributed Filesystem)
- Rust FUSE-based replicated/shared storage across nodes
- Docker image published to `ghcr.io/wolfsoftwaresystemsltd/wolfdisk:latest` (multi-arch)
- Runs as native systemd service on Linux hosts (compile-from-source via setup.sh) or as a Docker container on NAS boxes
- Default bind port 8550 — conflicts with WolfStack's status page when both are on the same host; WolfStack's status-port auto-fallback resolves this
- Satellite compose pairs WolfDisk with WolfNet for NAS deployments

## WolfFlow (Workflow Automation)
- Visual drag-and-drop editor with 16 action types
- Actions sorted alphabetically: Check Disk Space, Clean Journal Logs, Condition (If/Else), Docker Container Update, Docker Prune, Docker Update Check, HTTP Request, Integration Action, NetBird API, Restart Container, Restart Systemd Service, Run Shell Command, TrueNAS API, Unifi Controller, Update System Packages, Update WolfStack
- Structured outputs: each action returns key-value data that downstream steps can reference via {{step_name.key}}
- Conditional branching: If/Else nodes evaluate expressions and jump to different steps
- Output reference picker: when editing a Condition, click to insert {{step.key}} references
- Retry logic: per-step retry count and delay
- Workflow timeout: max_runtime_secs
- 5 failure policies: Abort, Continue, Alert, Notify & Abort, Notify & Continue
- Cron scheduling with quick presets (Daily 3am, Hourly, Weekly, etc.)
- Parallel execution across cluster nodes
- Email results with HTML reports

### Check Disk Space Outputs
- available_gb, total_gb, usage_pct, mount_point, over_threshold
- Example: if {{Check Disk.available_gb}} lt 500 then run cleanup

### HTTP Request Outputs
- status_code, response_body, json (parsed response)

## Status Pages
- Public uptime monitoring at /status/{slug}
- HTTP/HTTPS/TCP/ICMP/DNS monitors
- Incident tracking with updates
- Cluster-scoped: monitors, pages, incidents all have a cluster field

## Backups
- Scheduled backups with multiple destination types
- Docker: commit + save + volume backup
- LXC: full container backup
- VM: disk image backup
- Seven destination types: Local, S3, Remote (WolfStack node), WolfDisk, PBS (Proxmox Backup Server), NFS, SMB/CIFS
- NFS/SMB backups mount the share idempotently at /mnt/wolfstack-backup/<kind>-<sanitised-source>/ and write through like Local
- SMB fields on BackupStorage: smb_source (//server/share or \\server\share — normalised), smb_subpath, smb_username, smb_password, smb_domain, smb_options. Defaults to SMB 3.0.
- NFS fields: nfs_source (server:/export), nfs_options (defaults to rw,soft,timeo=50)
- Pre-flight at save time: `POST /api/backups/test-storage` exercises the mount path without doing a real backup, so missing-package errors surface at schedule save instead of silently failing later
- The backup runs hidden in a background task, so the UI wouldn't otherwise see MISSING_PACKAGE errors until the first run

## Storage
- Mount types: S3, NFS, SMB/CIFS, SSHFS, Directory (bind mount), WolfDisk
- SMB/CIFS: guest or username/password/domain auth. Defaults to SMB 3.0 (matches Synology/QNAP defaults). `smb_options` can override e.g. `vers=2.1` for older NAS firmware.
- Source normalisation: `\\server\share` gets converted to `//server/share` automatically
- Auto-mount on boot
- Global mounts replicate across cluster nodes

## Auto-install for Mount Helpers
- When a mount needs `mount.cifs` (cifs-utils) or `mount.nfs` (nfs-common/nfs-utils/nfs-client) and it's missing, WolfStack does NOT silently apt-get
- Mount helpers return a structured error `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>` that the frontend parses
- UI pops a confirm modal: "Install cifs-utils? Run the install in a terminal window." Nothing installs without confirmation.
- On confirm: POST /api/system/prepare-install-package returns a session_id, frontend opens /console.html?type=pkg-install&name=<id> showing the install live
- Per-distro package names + package managers: Debian apt-get nfs-common/cifs-utils, RedHat dnf nfs-utils/cifs-utils, SUSE zypper nfs-client/cifs-utils, Arch pacman nfs-utils/cifs-utils, Unknown falls back to Debian
- Detected via `/etc/arch-release`, `/etc/debian_version`, `/etc/redhat-release`, `/etc/SuSE-release`, plus `/etc/os-release` fallback

## Alerting
- Threshold alerting with email notifications
- Discord, Slack, Telegram webhook support
- Alert cooldown to prevent spam

## App Store
- 510+ one-click applications
- Four install targets: Docker, LXC, bare-metal, VM
- User input fields for configuration (passwords, domains, etc.)
- Install modal detects which targets the manifest supports and shows matching pills
- Ports/env/memory sections auto-hide for non-Docker targets

### VM Target (ISO-Based Apps)
- For apps that want a whole OS (PBS, pfSense, OPNsense, Home Assistant OS, etc.)
- VmTarget fields: iso_url, memory_mb, cores, disk_gb, optional data_disk_gb + data_disk_label, vga
- install_vm: downloads ISO to /var/lib/wolfstack/iso/<app_id>.iso (cached, reused across installs), auto-allocates a WolfNet IP, creates the VM via VmManager::create_vm, starts it
- User overrides via user_inputs: disk_gb, data_disk_gb, memory_mb, cores. Manifest defaults kick in if missing/zero/unparseable.
- Data disk: when manifest's data_disk_gb is Some, install_vm pushes a StorageVolume onto extra_disks. Works on all three backends: qm_create adds `--scsi{N} <storage>:<size>`, virsh_create appends `--disk path=...,size=N,format=qcow2,bus=virtio`, standalone QEMU creates the volume file and attaches via -drive.
- ISO fetch: tries the manifest URL first; if wget fails (404), calls resolve_latest_iso which scrapes the parent directory's HTML index and picks the newest file matching the same stem. Handles Proxmox's no-`_latest.iso`-alias quirk.

### Proxmox Backup Server (PBS) entry
- First VM-target app in the catalogue
- Defaults: 16 GB OS disk, 200 GB data disk, 4 GB RAM, 2 cores
- User picks storage in the install modal; everything else auto
- Points user to open VNC for the PBS installer, then add PBS as a backup destination cluster-wide via its WolfNet IP

## Authentication
- Linux crypt() against /etc/shadow (default)
- WolfStack native user accounts with Argon2 password hashing
- TOTP two-factor authentication
- OIDC/SSO (Enterprise): Authentik, Azure AD, Okta, Keycloak, any OIDC provider
- Cookie-based sessions (wolfstack_session cookie)
- Inter-node auth: X-WolfStack-Secret header

## AI Agent
- Three providers: Claude (Anthropic), Gemini (Google), Local AI (self-hosted)
- Local AI supports any OpenAI-compatible server: Ollama, LM Studio, LocalAI, vLLM, text-generation-webui, llama.cpp
- Common local URLs: Ollama http://localhost:11434, LM Studio http://localhost:1234/v1, LocalAI http://localhost:8080/v1
- Auto-detects available models from the local server's /v1/models endpoint
- API key optional for most local servers
- Expert knowledge base shipped with WolfStack — AI gives deep answers about the platform
- AI can execute read-only commands on the server via [EXEC] tags
- Health monitoring: periodic scans with AI-generated recommendations

## Enterprise Features
- REST API keys (wsk_* tokens) with scoped permissions
- Plugin system
- OIDC/SSO
- WolfHost (web hosting platform)
- WolfCustom (white-label branding)
- License: £79/$99 per server per month
- License propagation: install on one node, all cluster nodes pick it up automatically

## Plugin System
- Plugins installed to /etc/wolfstack/plugins/{id}/
- manifest.json + web/plugin.js + optional bin/handler backend
- Plugin Store: fetches index from GitHub, one-click install
- Reinstall kills old handler process and starts new one automatically

## Clustering
- Nodes discover each other via HTTP polling every 10 seconds
- Cluster secret for inter-node authentication
- Default secret used if no custom-cluster-secret file exists
- Node proxy: /api/nodes/{id}/proxy/{path} forwards API calls to remote nodes

## Common Issues

### VM won't boot after NIC change (UEFI)
OVMF boot entries reference device paths. Network config changes alter the topology. Fix: WolfStack v16.16.9+ auto-resets EFI vars. Manual: delete {name}_VARS.fd file.

### VM has no IP (WolfNet)
Check dnsmasq is installed and running: `ps aux | grep dnsmasq | grep tap`. WolfStack starts a per-VM dnsmasq on the TAP interface to offer DHCP.

### VM has no IP (Bridge/Physical NIC)
Check bridge exists: `ip link show type bridge`. Check physical NIC is a member: `bridge link show`. Router DHCP must reach through the bridge.

### systemd-networkd-wait-online.service failed
Harmless — systemd timed out waiting for all interfaces. Common with bridges/TAPs/VPNs. Does not affect networking.

### Plugin backend not starting
Check if the handler binary is compatible: `file /etc/wolfstack/plugins/{id}/bin/handler`. Must be statically linked (musl) for cross-distro compatibility.

### WolfHost "could not reach WolfStack API"
WolfHost tries HTTPS:8553 then HTTP:8554. Also tries both custom and default cluster secrets. Restart WolfHost handler after WolfStack upgrade.

### VM terminal opens but is blank
Guest OS doesn't have a serial console enabled. Fix on the guest: add `console=ttyS0` (or `console=ttyS0,115200`) to the kernel command line, enable `systemd-getty@ttyS0.service` on systemd distros. The host side is wired automatically on all three backends.

### "VM not found in qm list" when opening terminal
PVE-only. The VM exists in the WolfStack UI but not in `qm list`. Usually means the VM was created outside Proxmox or the PVE DB is out of sync. Check `qm list` from the host shell — if the name's not there, WolfStack can't resolve a vmid for `qm terminal`.

### "Add serial console?" prompt on a PVE VM created in the Proxmox web UI
PVE VMs created outside WolfStack often lack `serial0: socket`. The prompt offers `qm set <vmid> --serial0 socket` — requires a reboot to take effect if the VM is currently running. Proxmox web UI doesn't expose the flag, so this is the fastest way to enable it.

### "Standalone VM was started before serial-console support was added"
A VM running from before the v16.40 QEMU spawn change doesn't have the -chardev socket wired. Stop + start the VM (not restart — the socket is created at spawn time).

### SMB backup to Synology/QNAP hangs or fails
Most consumer NAS defaults to SMB 3.0 (WolfStack's default). Older firmware may need `vers=2.1` in the smb_options field. Guest share permissions must allow the user you configured, or mark the share as guest-accessible and leave username blank.

### "MISSING_PACKAGE|mount.cifs|..." error
cifs-utils (or nfs-common/nfs-utils/nfs-client) not installed on the host. WolfStack never auto-installs — accept the confirm prompt to run the install in a live terminal. If you dismissed the prompt, just retry the mount or save the backup destination again and click through.

### Home Assistant VM setup
1. Import the HAOS QCOW2 image via "Import Disk Image" when creating VM
2. Set BIOS to OVMF (UEFI)
3. Add a bridge NIC for LAN access (Physical NIC passthrough)
4. Pass through Zigbee/Z-Wave USB dongle via Passthrough tab
5. If no IP: set static IP from HA CLI: `ha network update enp0s3 --ipv4-method static --ipv4-address 192.168.1.x/24 --ipv4-gateway 192.168.1.1`

## WireGuard Bridge (VPN access INTO the cluster from outside)

This is the answer to "how do I connect from my office / phone / laptop to my WolfStack cluster or WolfNet?". WireGuard bridges bolt a standard WireGuard VPN on the side of WolfNet so external clients can join the mesh from any network.

- Each cluster gets a unique /24 in 10.20.0.0/16 (e.g. 10.20.5.0/24) for its WireGuard bridge
- Config is stored in /etc/wolfstack/wireguard-bridge.json (per-cluster entries)
- UI: Settings → WireGuard Bridge → Create bridge for cluster → add clients
- Each client gets a download button for their .conf file (import into WireGuard app on phone/laptop)
- Endpoint = cluster node's public IP + listen port (default 51820, configurable)
- Client traffic enters the bridge, is routed into WolfNet, reaches every node + container/VM on the mesh
- Requires `wireguard-tools` on the host (install via the distro-aware deps page)
- Supports multiple bridges per host (different clusters = different subnets)
- **Wolfnet is NOT WireGuard**: WolfNet is the internal mesh overlay between cluster nodes; WireGuard bridge is the external-client door into that mesh
- WireGuard private keys are written to /tmp/wg-<iface>-key with mode 0600 (locked down since v18.7.27), consumed by `wg set`, then removed

## WolfRouter (native firewall / DHCP / DNS / WAN router on any node)

Turn any WolfStack node into a full router — no pfSense/OPNsense box needed.

- **Zones**: WAN / LAN / DMZ / WolfNet / Trusted / custom, assigned per interface
- **LAN segments**: each LAN = subnet + DHCP range + DNS. dnsmasq runs per-LAN, one process per bridge, pidfiles in /run/wolfstack-router/
- **DNS modes per LAN**: "WolfRouter" (dnsmasq serves :53) or "External" (dnsmasq DHCP-only, DHCP option 6 points clients at their chosen resolver — AdGuard/Pi-hole)
- **Firewall**: iptables filter table via iptables-restore, atomic swap, pre-flight refuses rules that would lock the admin out of :8553 / :8554 (handles --dport, port ranges `8000:9000`, `-m multiport --dports`)
- **Safe-mode rollback**: firewall apply registers a deadman-switch (default 120s) — if operator doesn't click Keep in the banner, the previous ruleset is restored automatically
- **WAN types**: DHCP, static, PPPoE (writes /etc/ppp/chap-secrets with mode 0600)
- **Host DNS panel**: when a container wants :53 on a node, use the Host DNS panel to release systemd-resolved's stub listener AND/OR move WolfRouter's own dnsmasq to a different port (e.g. 5353). Both actions are deadman-switched.
- UI: WolfRouter module in the datacenter view — Topology, Zones, Rules, LANs, WANs, DNS Tools
- Replicates config across cluster nodes automatically
- /etc/wolfstack/router.json is the source of truth

## WolfRun (container orchestration across the cluster)

n8n-like service manager that spreads Docker/LXC instances across nodes.

- Services = (image, replicas, placement, restart policy). Reconciler loop every 15s makes the live state match declared state
- Placement options: any node, specific node, all nodes (DaemonSet-like), per-zone
- Restart policy: `Always` means WolfRun auto-restarts exited containers on the next tick
- Failover events logged to /etc/wolfstack/wolfrun/failover-events.json
- Only the cluster LEADER runs the reconciler (Raft-free leader election via lowest node_id heuristic)
- Config: /etc/wolfstack/wolfrun/services.json
- UI: Datacenter → WolfRun

## WolfUSB (network USB device passthrough)

Expose host-plugged USB devices to containers/VMs on any node via USB/IP.

- Each node runs a wolfusb server on :3240 (key in /etc/wolfusb/wolfusb.env, same cluster secret)
- Requires kernel modules vhci-hcd (client) + usbip-host (server) — auto-modprobed on install, auto-installed for distros that ship them in kernel-modules-extra
- Assign a USB device to a container/VM via the WolfUSB panel; WolfStack auto-attaches on container start
- Cross-node: a USB device plugged into node A can be attached to a VM on node B. Re-attach on container restart is automatic (wolfusb::on_container_started hook).
- Common use: Zigbee/Z-Wave dongles for Home Assistant VMs, license dongles, webcams

## WolfKube (Kubernetes lifecycle + management on the cluster)

- Cluster modes: self-hosted (k3s/kubeadm installed by WolfStack), or attach to an existing kubeconfig
- Kubeconfig uploaded via UI is stored at /etc/wolfstack/kubernetes/<id>.yaml with mode 0600 (since v18.7.27)
- Pod terminal: WebSocket console to any container in any pod (`kubectl exec` under the hood)
- Scale/delete workloads from the UI; see resource usage per pod
- Stores JOIN tokens for node expansion — token endpoint is cluster-secret-auth'd

## Cluster Browser (unified web UI for every cluster-internal service)

- Scans all nodes for running web services (by common ports 80/443/3000/8080/...)
- Presents them as one pane: "Jellyfin on node-A", "AdGuard on node-B", "Grafana on node-C"
- Click through to the service's UI — WolfStack reverse-proxies it so browser credentials aren't needed per-service
- Discovery runs every 60 seconds via a reconciliation loop (main.rs background task)
- Config: /etc/wolfstack/cluster-services-discovered.json

## Ceph integration

- Attach an existing Ceph cluster (MON + keys) via Settings → Ceph → Add cluster
- WolfStack renders Ceph health, OSD status, pool usage; can create/delete pools and RBD volumes
- RBD volumes become a first-class storage target (alongside local, S3, NFS, SSHFS, WolfDisk)

## Discord / Telegram / WhatsApp bots (AI access from chat)

- Each bot runs as a supervised background task; credentials in /etc/wolfstack/ai-config.json (mode 0600)
- Bots relay user messages to the AI agent (same [EXEC]/[EXEC_ALL]/[WEBSEARCH]/[FETCH]/[READ]/[SECURITY_AUDIT] tool loop as the dashboard chat)
- Discord: set DISCORD_BOT_TOKEN in the AI settings; bot joins the configured channel, replies in-thread
- Telegram: paste bot token; /start to begin; long replies get chunked into 4096-char messages
- WhatsApp: relays via the Baileys gateway (Node.js subprocess) — requires pairing a phone once

## MCP server (Model Context Protocol)

- Exposes the WolfStack AI toolbox as an MCP server so Claude Desktop / Cursor / other MCP clients can reach it
- Endpoint: /api/mcp (WebSocket, session-auth)
- Same tool set as the built-in agent: run cluster commands, propose ACTIONs, read files
- Config: /etc/wolfstack/ai-config.json → mcp_enabled

## MySQL / MariaDB editor

- Attach credentials via the Database Manager panel — stored encrypted in /etc/wolfstack/
- Browse schemas/tables, run ad-hoc queries, edit rows
- Supports both MariaDB and MySQL protocol

## Deadman-switch framework (Level 2 safety)

Any operation that can brick the node's UI registers a rollback closure with a TTL. If the operator doesn't hit "Keep" in the banner before the TTL expires, the rollback fires automatically.

- Host DNS release: 120s TTL → restore systemd-resolved stub
- WolfRouter firewall apply: 120s TTL → revert to previous ruleset
- Interface down: 90s TTL → bring interface back up
- Endpoint: GET /api/danger/pending, POST /api/danger/confirm/{id}, POST /api/danger/rollback/{id}
- Frontend banner polls every 2s, survives session expiry and network blips
- See src/danger.rs for the registry internals

## Plugin system

- Plugins live in /etc/wolfstack/plugins/<plugin>/
- Each plugin has a manifest.json declaring name, icon, backend command (if any), frontend HTML
- Backend plugins run as child processes of WolfStack, expose HTTP endpoints under /api/plugins/<plugin>/...
- Frontend plugins inject their HTML + JS into a dedicated tab
- Install: drop the directory, reload WolfStack; or use the plugin install UI (fetches from a URL)
- Plugins are sandboxed only by Unix permissions — they run as root, so trust matters

## System Check (distro-aware diagnostics)

- UI: Settings → System Check
- Runs a battery of tests: kernel modules present, iptables/nftables choice, services enabled, ports open, disk space, memory, package manager health
- Each failing check is paired with a one-click "Fix" that knows the distro (apt/dnf/pacman/apk/zypper)
- Used by the installer too — `setup.sh` runs a subset on fresh install

## Services Discovery

- Background reconciler scans each node for well-known services (Docker registries, media servers, dashboards)
- Populates the Cluster Browser + drives the app-update-summary badge
- Service definitions at /etc/wolfstack/cluster-services.json
- Tombstoning prevents re-discovering deleted services

## Security posture summary (v18.7.27+)

- All sensitive files under /etc/wolfstack/ are mode 0600 (custom-cluster-secret, nodes.json with PVE tokens, join-token, license.key, users.json, oidc.json, auth-config.json, ai-config.json, s3/*.passwd, chap-secrets)
- /etc/wolfstack/ directory itself is mode 0700
- `paths::harden_existing` runs on startup to migrate pre-v18.7.27 installs
- `paths::write_secure(path, content)` is the canonical secure writer
- Cluster secret validation is constant-time including length
- Pre-flight firewall analyser refuses rules that would lock the admin out
- AI's [READ] tool has a hard-coded deny-list covering every credential file
- AI's [EXEC] pipe allowlist applies to EVERY pipe segment (no more exfil via `ls | wget`)
- AI's approved-action [ACTION] path blocks `;`, `&&`, `||`, newlines (no shell-chain injection)

## AI tool tags reference (for the agent itself)

- `[EXEC]cmd[/EXEC]` — local read-only shell, allowlist of safe commands only
- `[EXEC_ALL]cmd[/EXEC_ALL]` — same command on every cluster node, results labelled by hostname
- `[ACTION id=".." title=".." risk="low|medium|high" explain=".." target="local|all"]cmd[/ACTION]` — proposes a fix the operator approves with one click
- `[WOLFNOTE title="..."]body[/WOLFNOTE]` — save a note for the user
- `[WEBSEARCH query="..."][/WEBSEARCH]` — DuckDuckGo top 5 results
- `[FETCH url="..."][/FETCH]` — fetch a URL, strip HTML, 8 KB cap, SSRF-guarded
- `[READ path="..."][/READ]` — read a WolfStack runtime file from a sandboxed allow-list
- `[SECURITY_AUDIT][/SECURITY_AUDIT]` — run the built-in security audit (file perms, default secret, docker restart policies)

## Common user questions → where to point them

- **"Connect from outside to my cluster/containers"** → WireGuard Bridge (Settings → WireGuard Bridge → create bridge + add client → download .conf)
- **"How do I get two nodes to talk securely?"** → WolfNet (wolfnet invite on existing node → token → wolfnet join on new node)
- **"Make this node a router / firewall / DHCP server"** → WolfRouter module
- **"Plug a USB device into my Home Assistant VM on another node"** → WolfUSB panel
- **"Run a container on whichever node is free"** → WolfRun service
- **"Public status page for my apps"** → Status Pages (cluster-scoped, served on :8550)
- **"Manage Kubernetes from WolfStack"** → WolfKube (attach kubeconfig or let WolfStack install k3s)
- **"See all my web services in one place"** → Cluster Browser
- **"Use WolfStack from Claude Desktop / Cursor"** → MCP server (Settings → AI → Enable MCP)
- **"Chat with my cluster from my phone"** → Discord / Telegram / WhatsApp bots (Settings → AI → Bots)
- **"Back up my containers / VMs"** → Backups (scheduled, destinations: local / NFS / SMB / S3 / Proxmox Backup Server / SSHFS / WolfDisk)
