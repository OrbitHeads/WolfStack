// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd

//! Cluster Browser — a real Firefox running in a Docker container on a
//! WolfStack node, accessed via the in-image KasmVNC web UI.
//!
//! The container runs on the host's network namespace so the in-browser
//! Firefox can reach every WolfNet IP exactly the same way the WolfStack
//! daemon can — no client-side VPN, no per-app reverse proxy. From the
//! user's POV: log into WolfStack from anywhere, click "Cluster Browser",
//! get a Firefox tab in their own browser, type any cluster URL or click
//! a card from the auto-discovered services list.
//!
//! Sessions are 1:1 with Docker containers. The container image is
//! `lscr.io/linuxserver/firefox:latest` (multi-arch, KasmVNC bundled).
//!
//! Per-session port: allocated from 33000-33999 so we don't collide
//! with anything else on the host.

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const SESSIONS_FILE: &str = "/etc/wolfstack/cluster-browser-sessions.json";
const IMAGE: &str = "lscr.io/linuxserver/firefox:latest";
const PORT_RANGE: std::ops::Range<u16> = 33000..34000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    /// 8-char random id, used in the container name and as session handle.
    pub id: String,
    /// Docker container name: wolfstack-browser-<id>.
    pub container_name: String,
    /// Host port mapped to the container's KasmVNC web port (3000).
    pub web_port: u16,
    /// User who started the session, used to namespace the persistent
    /// profile volume so bookmarks/cookies survive across sessions.
    pub user: String,
    /// Unix epoch seconds.
    pub started_at: u64,
}

static SESSIONS: Mutex<Vec<BrowserSession>> = Mutex::new(Vec::new());

pub fn list_sessions() -> Vec<BrowserSession> {
    SESSIONS.lock().unwrap().clone()
}

fn save() {
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    let sessions = SESSIONS.lock().unwrap().clone();
    if let Ok(json) = serde_json::to_string_pretty(&sessions) {
        let _ = std::fs::write(SESSIONS_FILE, json);
    }
}

/// Restore the in-memory session list from disk on daemon startup.
/// Stale entries (container no longer exists) get pruned in the same
/// pass so we don't leak handles across restarts.
pub fn load_persisted() {
    let on_disk: Vec<BrowserSession> = std::fs::read_to_string(SESSIONS_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut alive = Vec::new();
    for s in on_disk {
        if container_exists(&s.container_name) {
            alive.push(s);
        }
    }
    *SESSIONS.lock().unwrap() = alive;
    save();
}

fn container_exists(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn random_id() -> String {
    use std::time::SystemTime;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // 8 chars of base36 from the nanosecond timestamp — collision-
    // resistant enough for this scope without a uuid alloc.
    let s = format!("{:x}", n);
    let len = s.len();
    if len <= 8 { s } else { s[len - 8..].to_string() }
}

/// Find a free port in PORT_RANGE not already used by an active
/// session. Bind-test each candidate so we don't collide with anything
/// else listening on the host either.
fn allocate_port() -> Option<u16> {
    let used: std::collections::HashSet<u16> = SESSIONS
        .lock().unwrap()
        .iter()
        .map(|s| s.web_port)
        .collect();
    for p in PORT_RANGE {
        if used.contains(&p) { continue; }
        if std::net::TcpListener::bind(("0.0.0.0", p)).is_ok() {
            return Some(p);
        }
    }
    None
}

/// Whether the image is already cached locally. Cheap pre-flight so
/// callers can decide whether to surface a "downloading, please wait"
/// state vs. a quick start.
pub fn image_present() -> bool {
    Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pull the image if not already present. The first session start
/// otherwise blocks for several minutes silently — pre-pulling lets
/// the API caller see "pulling image" log lines via docker pull's
/// stdout (we just block on it).
fn ensure_image() -> Result<(), String> {
    if image_present() {
        return Ok(());
    }
    info!("cluster_browser: pulling image {}", IMAGE);
    let pull = Command::new("docker")
        .args(["pull", IMAGE])
        .output()
        .map_err(|e| format!("docker pull failed: {}", e))?;
    if !pull.status.success() {
        return Err(format!(
            "docker pull {} failed: {}",
            IMAGE,
            String::from_utf8_lossy(&pull.stderr).trim()
        ));
    }
    Ok(())
}

/// Pull the image with progress events streamed to `tx`. Used by the
/// SSE start endpoint so the user sees "Downloading layer 4/7…" rather
/// than a silent multi-minute spinner. Parses docker pull's line-based
/// layer status (one event per layer state change), plus emits a
/// 5-second heartbeat with elapsed time so the UI never looks frozen.
fn pull_image_with_progress(tx: &std::sync::mpsc::Sender<String>) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    if image_present() {
        let _ = tx.send("Browser image already cached — starting straight away.".into());
        return Ok(());
    }
    let _ = tx.send(format!(
        "Downloading browser image {} (one-time, around 700 MB) — please wait...",
        IMAGE
    ));

    // Spawn docker pull with stdout piped so we can read line by line.
    // Each layer prints its own status line as it makes progress, and
    // docker emits a final "Status: Downloaded newer image" at the end.
    let mut child = std::process::Command::new("docker")
        .args(["pull", IMAGE])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run docker pull: {}", e))?;

    let stdout = child.stdout.take().ok_or("docker pull stdout missing")?;

    // Heartbeat thread — emits "still downloading (Xs elapsed)" every 5 s
    // so an in-progress layer download (which only logs at completion) doesn't
    // make the UI look frozen.
    let started = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let done_hb = done.clone();
    let tx_hb = tx.clone();
    let heartbeat = std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            if done_hb.load(Ordering::Relaxed) { break; }
            let elapsed = started.elapsed().as_secs();
            if tx_hb.send(format!("Still downloading... ({}s elapsed)", elapsed)).is_err() { break; }
        }
    });

    // Stream stdout line-by-line. docker pull emits short status lines
    // ("Pulling fs layer", "Downloading", "Verifying Checksum",
    // "Download complete", "Extracting", "Pull complete").
    let reader = BufReader::new(stdout);
    let mut layers_pulled: u32 = 0;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // Only forward state-change lines, not the verbose progress-bar
        // updates docker writes with carriage returns. The line-based
        // reader already strips most of those.
        if trimmed.contains("Pull complete") {
            layers_pulled += 1;
            let _ = tx.send(format!("Layer {} downloaded ({})", layers_pulled, &trimmed[..12.min(trimmed.len())]));
        } else if trimmed.starts_with("Status:") || trimmed.starts_with("Digest:") {
            let _ = tx.send(trimmed.to_string());
        } else if trimmed.contains("Pulling from") {
            let _ = tx.send(trimmed.to_string());
        }
        // Other lines (per-layer "Downloading [...]" with byte counts)
        // are skipped to avoid flooding the SSE stream.
    }

    let status = child.wait().map_err(|e| format!("docker pull wait: {}", e))?;
    done.store(true, Ordering::Relaxed);
    let _ = heartbeat.join();

    if !status.success() {
        return Err(format!("docker pull {} failed (exit {:?})", IMAGE, status.code()));
    }
    let _ = tx.send(format!(
        "Browser image ready ({} layers pulled in {}s).",
        layers_pulled,
        started.elapsed().as_secs()
    ));
    Ok(())
}

/// Streaming variant of start_session — emits docker pull progress
/// (layers downloaded, heartbeat) plus container start status into the
/// supplied channel. The non-streaming `start_session` below calls this
/// with a discard channel so both paths share one implementation.
pub fn start_session_streamed(
    user: &str,
    homepage: &str,
    tx: std::sync::mpsc::Sender<String>,
) -> Result<BrowserSession, String> {
    pull_image_with_progress(&tx)?;
    let _ = tx.send("Starting browser container...".into());
    let session = spawn_container(user, homepage)?;
    let _ = tx.send(format!("Container running on port {}", session.web_port));
    Ok(session)
}

/// Spin up a new browser session for `user`. Returns the session
/// metadata; the caller is responsible for telling the user where to
/// connect (the KasmVNC web UI is served from
/// `http://<wolfstack-host>:<web_port>`).
pub fn start_session(user: &str, homepage: &str) -> Result<BrowserSession, String> {
    ensure_image()?;
    spawn_container(user, homepage)
}

/// Internal helper — does the actual `docker run`. Assumes the image
/// has already been pulled. Used by both the streaming and non-
/// streaming start paths.
fn spawn_container(user: &str, homepage: &str) -> Result<BrowserSession, String> {
    let id = random_id();
    let container_name = format!("wolfstack-browser-{}", id);
    let web_port = allocate_port().ok_or("No free port in 33000-33999 range")?;

    // Per-user persistent profile volume so bookmarks/history/cookies
    // survive across sessions. Sanitise the username for Docker volume
    // naming (alphanumeric + dash/underscore only).
    let user_safe: String = user.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let volume_name = format!("wolfstack-browser-config-{}", user_safe);

    // The linuxserver/firefox image looks at $FIREFOX_CLI for extra
    // command-line flags passed to Firefox at startup. Setting the
    // homepage URL there means the user lands on the WolfStack
    // services grid the moment Firefox finishes booting.
    let firefox_cli = format!("--new-window {}", homepage);

    // linuxserver/baseimage-kasmvnc serves HTTPS on container port 3000
    // (with a self-signed cert) and plain HTTP on 3001. We map the HTTP
    // side so the browser doesn't refuse to load the KasmVNC JS over an
    // untrusted cert and so the popup tab works on first click without
    // the user clicking through a cert warning.
    let port_mapping = format!("{}:3001", web_port);
    let env_homepage = format!("FIREFOX_CLI={}", firefox_cli);
    let volume_mount = format!("{}:/config", volume_name);

    // 2 GB RAM cap, 2 cores — enough for browsing without running away
    // with host resources if a tab goes wild.
    let mem_limit = "2g";
    let cpu_limit = "2";

    let args: Vec<&str> = vec![
        "run", "-d",
        "--name", &container_name,
        "--restart", "unless-stopped",
        "-p", &port_mapping,
        "-v", &volume_mount,
        "-e", "PUID=0", "-e", "PGID=0",
        "-e", "TZ=UTC",
        "-e", &env_homepage,
        "--memory", mem_limit,
        "--cpus", cpu_limit,
        // SHM size — Firefox/Chromium often crash with the Docker
        // default 64MB. Bump to 1GB.
        "--shm-size", "1gb",
        "--label", "wolfstack-browser=true",
        "--label", "wolfstack-browser-user=", // filled below
        IMAGE,
    ];

    // Replace the placeholder user label with the real one. Doing it
    // here keeps the &str lifetimes straight in the args vec.
    let user_label = format!("wolfstack-browser-user={}", user_safe);
    let args: Vec<&str> = args.into_iter()
        .map(|a| if a == "wolfstack-browser-user=" { user_label.as_str() } else { a })
        .collect();

    info!("cluster_browser: starting session {} for {} (port {})", id, user_safe, web_port);
    let out = Command::new("docker")
        .args(&args)
        .output()
        .map_err(|e| format!("docker run failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let session = BrowserSession {
        id,
        container_name,
        web_port,
        user: user_safe,
        started_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
    };
    SESSIONS.lock().unwrap().push(session.clone());
    save();
    Ok(session)
}

pub fn stop_session(id: &str) -> Result<(), String> {
    let session = {
        let s = SESSIONS.lock().unwrap();
        s.iter().find(|x| x.id == id).cloned()
    };
    let session = session.ok_or_else(|| format!("Session '{}' not found", id))?;

    // Stop with a 5 s grace then force-remove. The browser session
    // doesn't need to flush anything to disk that the container can't
    // checkpoint between requests.
    let _ = Command::new("docker")
        .args(["stop", "-t", "5", &session.container_name])
        .output();
    let _ = Command::new("docker")
        .args(["rm", "-f", &session.container_name])
        .output();

    SESSIONS.lock().unwrap().retain(|s| s.id != id);
    save();
    info!("cluster_browser: stopped session {}", id);
    Ok(())
}

/// Sweep for sessions whose container has died or vanished. Called by
/// a periodic background task so the UI doesn't show ghost sessions
/// after a docker daemon restart or crash.
pub fn reconcile() {
    let snapshot = SESSIONS.lock().unwrap().clone();
    let mut alive = Vec::new();
    for s in snapshot {
        if container_exists(&s.container_name) {
            alive.push(s);
        } else {
            warn!("cluster_browser: pruning dead session {}", s.id);
        }
    }
    *SESSIONS.lock().unwrap() = alive;
    save();
}

/// Render the homepage HTML — a grid of the discovered services with
/// click-to-open links. Loaded by the in-container Firefox at startup
/// via the FIREFOX_CLI env var. Self-contained — no JS framework, no
/// external fonts, no auth so it just renders inside a fresh browser
/// profile. Pass `user` to also include that user's pinned manual
/// entries; pass `""` to render auto-discovered only.
pub fn render_homepage(user: &str) -> String {
    let groups = crate::services_discovery::grouped_for(user);
    let mut body = String::with_capacity(4096);
    body.push_str(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>WolfStack — Cluster Services</title>
<style>
:root { color-scheme: dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  background: #0d0f14; color: #e8eaf0; margin: 0; padding: 32px; }
h1 { font-size: 28px; margin: 0 0 4px; color: #fff; }
.lead { color: #9ba0ad; margin: 0 0 28px; font-size: 14px; }
h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em;
  color: #9ba0ad; margin: 28px 0 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
.card { background: #161922; border: 1px solid #232634; border-radius: 10px;
  padding: 14px; text-decoration: none; color: inherit; transition: all .12s ease; }
.card:hover { background: #1d2130; border-color: #3b4256; transform: translateY(-1px); }
.card .icon { font-size: 28px; margin-bottom: 8px; }
.card .name { font-weight: 600; font-size: 14px; margin-bottom: 2px; color: #fff; }
.card .url { font-size: 11px; color: #9ba0ad; font-family: ui-monospace, "JetBrains Mono", monospace;
  word-break: break-all; }
.empty { background: #161922; border: 1px dashed #2a2e3c; border-radius: 10px;
  padding: 32px; text-align: center; color: #9ba0ad; }
form { margin: 24px 0 32px; display: flex; gap: 8px; }
input { flex: 1; padding: 10px 14px; border-radius: 8px; border: 1px solid #2a2e3c;
  background: #0a0c12; color: #fff; font-size: 14px; font-family: inherit; }
button { padding: 10px 16px; border-radius: 8px; border: 0; background: #6366f1;
  color: #fff; font-weight: 600; font-size: 14px; cursor: pointer; }
button:hover { background: #818cf8; }
</style></head><body>
<h1>🐺 WolfStack — Cluster Services</h1>
<p class="lead">Click a card to open. Type any cluster URL in the address bar (top of this Firefox window) for anything not listed here.</p>
<form onsubmit="event.preventDefault(); var u = document.getElementById('q').value.trim(); if (u) { if (!/^https?:\/\//.test(u)) u = 'http://' + u; location.href = u; }">
  <input id="q" type="text" placeholder="Open URL — e.g. 10.100.10.5:8007 or sonarr:8989" autofocus>
  <button type="submit">Open</button>
</form>
"#);

    if groups.is_empty() {
        body.push_str(r#"<div class="empty">No services discovered yet. The discovery sweep runs every 5 minutes; check back shortly, or add services manually from the WolfStack UI.</div>"#);
    } else {
        for (cat, services) in groups {
            body.push_str(&format!("<h2>{}</h2><div class=\"grid\">", html_escape(&cat)));
            for s in services {
                body.push_str(&format!(
                    r#"<a class="card" href="{url}"><div class="icon">{icon}</div><div class="name">{name}</div><div class="url">{url}</div></a>"#,
                    url = html_escape(&s.url),
                    icon = html_escape(&s.icon),
                    name = html_escape(&s.name),
                ));
            }
            body.push_str("</div>");
        }
    }
    body.push_str("</body></html>");
    body
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Background reconciliation loop — every 60 s, prune sessions whose
/// container vanished. Called from main.rs as a tokio task.
pub async fn run_reconcile_loop() {
    load_persisted();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let _ = tokio::task::spawn_blocking(reconcile).await;
    }
}
