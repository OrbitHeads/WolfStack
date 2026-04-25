// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! VNC desktop access into LXC / Proxmox-LXC / Docker containers.
//!
//! Users may not have a VNC server inside their containers — we offer to
//! install TigerVNC + XFCE4 on detected OSes (Debian/Ubuntu, Alpine,
//! RHEL/Rocky/Fedora). Once installed, a WebSocket bridge spawns
//! `<runtime exec> -- socat STDIO TCP:127.0.0.1:5901` and shuttles the
//! stdio bytes ↔ noVNC binary frames in the browser. No port publishing,
//! no per-container firewall rules — works the same in any network mode.
//!
//! Cross-node access reuses the existing
//! /ws/remote-console/{node_id}/{ctype}/{name} bridge with ctype values
//! `lxc-vnc` / `docker-vnc` / `pct-vnc` (see console.rs).

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};

use super::AppState;

const VNC_CONFIG_PATH: &str = "/etc/wolfstack/container-vnc.json";

/// One entry per container that has been set up for VNC.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VncEntry {
    runtime: String,       // "lxc" | "docker" | "pct"
    name: String,          // container name (or numeric VMID for pct)
    password: String,      // 8-char alphanum (TigerVNC VncAuth truncates >8)
    installed_at: String,  // RFC3339
}

fn config_key(runtime: &str, name: &str) -> String {
    format!("{}:{}", runtime, name)
}

fn load_config() -> HashMap<String, VncEntry> {
    std::fs::read_to_string(VNC_CONFIG_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(map: &HashMap<String, VncEntry>) -> Result<(), String> {
    std::fs::create_dir_all("/etc/wolfstack")
        .map_err(|e| format!("create_dir /etc/wolfstack: {}", e))?;
    let s = serde_json::to_string_pretty(map)
        .map_err(|e| format!("serialise vnc config: {}", e))?;
    crate::paths::write_secure(VNC_CONFIG_PATH, &s)
        .map_err(|e| format!("write {}: {}", VNC_CONFIG_PATH, e))
}


/// 8-char alphanumeric password (avoiding visually-ambiguous chars).
/// TigerVNC VncAuth truncates passwords to 8 bytes anyway.
fn generate_password() -> String {
    use std::io::Read;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    let mut out = String::with_capacity(8);
    for b in &buf {
        out.push(CHARSET[(*b as usize) % CHARSET.len()] as char);
    }
    out
}

/// Validate the (runtime, name) pair to avoid command-injection through
/// the container name. Returns Err(HttpResponse) if invalid.
fn validate_target(runtime: &str, name: &str) -> Result<(), HttpResponse> {
    match runtime {
        "docker" | "lxc" => {
            if !crate::auth::is_safe_name(name) {
                return Err(HttpResponse::BadRequest()
                    .json(serde_json::json!({ "error": "Invalid container name" })));
            }
        }
        "pct" => {
            // Proxmox LXC — name is the numeric VMID
            if name.parse::<u64>().is_err() {
                return Err(HttpResponse::BadRequest()
                    .json(serde_json::json!({ "error": "Invalid VMID" })));
            }
        }
        _ => {
            return Err(HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Unknown runtime" })));
        }
    }
    Ok(())
}

/// Build argv for `<runtime exec> sh -c '<shell_cmd>'`.
/// Caller must have already passed validate_target — we re-check anyway
/// (defence in depth).
fn build_exec_argv(runtime: &str, name: &str, shell_cmd: &str) -> Result<Vec<String>, String> {
    match runtime {
        "docker" => {
            if !crate::auth::is_safe_name(name) {
                return Err("invalid container name".into());
            }
            Ok(vec![
                "docker".into(), "exec".into(), "-i".into(),
                name.into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ])
        }
        "lxc" => {
            if !crate::auth::is_safe_name(name) {
                return Err("invalid container name".into());
            }
            let base = crate::containers::lxc_base_dir(name);
            let mut a: Vec<String> = vec!["lxc-attach".into()];
            if base != crate::containers::LXC_DEFAULT_PATH {
                a.push("-P".into());
                a.push(base);
            }
            a.extend([
                "-n".into(), name.into(),
                "--".into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ]);
            Ok(a)
        }
        "pct" => {
            if name.parse::<u64>().is_err() {
                return Err("invalid VMID".into());
            }
            Ok(vec![
                "pct".into(), "exec".into(), name.into(),
                "--".into(),
                "sh".into(), "-c".into(), shell_cmd.into(),
            ])
        }
        _ => Err(format!("Unknown runtime: {}", runtime)),
    }
}

/// Run a one-shot command inside the container and capture
/// (exit_code, stdout, stderr). Used for OS detection + state probes.
fn container_exec(runtime: &str, name: &str, shell_cmd: &str) -> Result<(i32, String, String), String> {
    let argv = build_exec_argv(runtime, name, shell_cmd)?;
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn {}: {}", argv[0], e))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Detected OS family and the package manager / install commands we'll use.
#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub id: String,            // e.g. "debian", "ubuntu", "alpine", "rocky"
    pub id_like: String,       // /etc/os-release ID_LIKE
    pub version_id: String,    // /etc/os-release VERSION_ID
    pub family: String,        // "debian" | "alpine" | "rhel" | "unknown"
    pub supported: bool,
    pub packages: Vec<String>, // packages we'd install
    pub size_estimate_mb: u32, // rough on-disk size
}

fn classify_os(id: &str, id_like: &str) -> (String, bool, Vec<String>, u32) {
    let id_l = id.to_lowercase();
    let like_l = id_like.to_lowercase();
    let in_like = |needle: &str| like_l.split_whitespace().any(|w| w == needle);

    if id_l == "debian" || id_l == "ubuntu" || in_like("debian") || in_like("ubuntu") {
        (
            "debian".into(),
            true,
            vec![
                "tigervnc-standalone-server".into(),
                "tigervnc-common".into(),
                "xfce4".into(),
                "xfce4-terminal".into(),
                "dbus-x11".into(),
                "socat".into(),
                "fonts-dejavu".into(),
            ],
            450,
        )
    } else if id_l == "alpine" || in_like("alpine") {
        (
            "alpine".into(),
            true,
            vec![
                "tigervnc".into(),
                "xfce4".into(),
                "xfce4-terminal".into(),
                "dbus-x11".into(),
                "socat".into(),
                "ttf-dejavu".into(),
                // Alpine ships pgrep via busybox — no separate procps package needed.
            ],
            250,
        )
    } else if id_l == "rocky" || id_l == "almalinux" || id_l == "rhel"
        || id_l == "centos" || id_l == "fedora"
        || in_like("rhel") || in_like("fedora") || in_like("centos")
    {
        (
            "rhel".into(),
            true,
            vec![
                "tigervnc-server".into(),
                "xfce4-session".into(),
                "xfwm4".into(),
                "xfce4-panel".into(),
                "xfce4-terminal".into(),
                "thunar".into(),
                "dbus-x11".into(),
                "socat".into(),
                "dejavu-sans-fonts".into(),
            ],
            500,
        )
    } else {
        ("unknown".into(), false, Vec::new(), 0)
    }
}

fn detect_os(runtime: &str, name: &str) -> Result<OsInfo, String> {
    // Use printf+separators rather than `echo` so newlines in values can't fake out parsing.
    // Variables come from /etc/os-release; if missing we fall back to /usr/lib/os-release.
    let cmd = ". /etc/os-release 2>/dev/null || . /usr/lib/os-release 2>/dev/null; \
               printf '%s\\n%s\\n%s\\n' \"${ID:-unknown}\" \"${ID_LIKE:-}\" \"${VERSION_ID:-}\"";
    let (code, stdout, stderr) = container_exec(runtime, name, cmd)?;
    if code != 0 {
        return Err(format!("OS detection failed (exit {}): {}", code, stderr.trim()));
    }
    let mut lines = stdout.lines();
    let id = lines.next().unwrap_or("unknown").trim().to_string();
    let id_like = lines.next().unwrap_or("").trim().to_string();
    let version_id = lines.next().unwrap_or("").trim().to_string();
    let (family, supported, packages, size_estimate_mb) = classify_os(&id, &id_like);
    Ok(OsInfo { id, id_like, version_id, family, supported, packages, size_estimate_mb })
}

/// Build the install script. The VNC password is baked into the script
/// via `vncpasswd -f`. Idempotent: re-running re-installs cleanly.
fn build_install_script(family: &str, password: &str) -> String {
    // Common tail — set up xstartup, write vnc password, install start wrapper.
    // Note: xstartup runs as the VNC user (root here). dbus-launch is best-effort.
    let common_tail = format!(r#"
set -e
export DEBIAN_FRONTEND=noninteractive
mkdir -p /root/.vnc
chmod 700 /root/.vnc

# Encrypt password — TigerVNC's vncpasswd reads stdin, writes encrypted to stdout
printf '%s\n' '{password}' | vncpasswd -f > /root/.vnc/passwd
chmod 600 /root/.vnc/passwd

cat > /root/.vnc/xstartup <<'XSTART_EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
[ -r /etc/profile ] && . /etc/profile
if command -v dbus-launch >/dev/null 2>&1; then
    eval "$(dbus-launch --sh-syntax)"
fi
exec startxfce4
XSTART_EOF
chmod 700 /root/.vnc/xstartup

# wolfstack-vnc-start: idempotent VNC :1 starter, used by the bridge
cat > /usr/local/bin/wolfstack-vnc-start <<'STARTER_EOF'
#!/bin/sh
# Already running?
if pgrep -f 'Xvnc.*:1|Xtigervnc.*:1' >/dev/null 2>&1; then
    exit 0
fi
export USER=root HOME=/root
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
# Prefer /var/log when writable, otherwise /tmp.
if mkdir -p /var/log 2>/dev/null && [ -w /var/log ]; then
    LOG=/var/log/wolfstack-vnc.log
else
    LOG=/tmp/wolfstack-vnc.log
fi
if command -v tigervncserver >/dev/null 2>&1; then
    tigervncserver :1 -geometry 1280x800 -depth 24 -localhost yes \
        -SecurityTypes VncAuth -PasswordFile /root/.vnc/passwd >>"$LOG" 2>&1
elif command -v vncserver >/dev/null 2>&1; then
    vncserver :1 -geometry 1280x800 -depth 24 -localhost yes \
        -SecurityTypes VncAuth -PasswordFile /root/.vnc/passwd >>"$LOG" 2>&1
else
    echo "wolfstack-vnc-start: no VNC server binary found" >&2
    exit 1
fi
# Wait up to ~3s for port 5901 to accept connections
i=0
while [ $i -lt 10 ]; do
    if socat -T 1 /dev/null TCP:127.0.0.1:5901 >/dev/null 2>&1; then
        exit 0
    fi
    i=$((i + 1))
    sleep 0.3
done
echo "wolfstack-vnc-start: 127.0.0.1:5901 did not come up" >&2
exit 1
STARTER_EOF
chmod 755 /usr/local/bin/wolfstack-vnc-start

echo
echo "=== VNC desktop installed. ==="
echo "Starting VNC server now to verify..."
/usr/local/bin/wolfstack-vnc-start
echo "VNC server is running on display :1 (port 5901, localhost-only)."
echo "Click the VNC icon on the container card to connect."
"#);

    let head = match family {
        "debian" => r#"
echo "[wolfstack] Installing TigerVNC + XFCE4 on Debian/Ubuntu container..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    tigervnc-standalone-server tigervnc-common \
    xfce4 xfce4-terminal \
    dbus-x11 socat fonts-dejavu \
    procps
"#.to_string(),
        "alpine" => r#"
echo "[wolfstack] Installing TigerVNC + XFCE4 on Alpine container..."
apk update
# Alpine: busybox already provides pgrep, so no procps needed.
# 'xfce4' is the metapackage on community repo; xfce4-terminal is separate.
apk add --no-cache \
    tigervnc \
    xfce4 xfce4-terminal \
    dbus-x11 socat ttf-dejavu
"#.to_string(),
        "rhel" => r#"
echo "[wolfstack] Installing TigerVNC + XFCE4 on RHEL-family container..."
if command -v dnf >/dev/null 2>&1; then
    PKG="dnf -y install"
    dnf -y install epel-release 2>/dev/null || true
elif command -v yum >/dev/null 2>&1; then
    PKG="yum -y install"
    yum -y install epel-release 2>/dev/null || true
else
    echo "No dnf or yum found"; exit 1
fi
$PKG tigervnc-server xfce4-session xfwm4 xfce4-panel xfce4-terminal thunar \
     dbus-x11 socat dejavu-sans-fonts procps-ng
"#.to_string(),
        _ => return String::new(),
    };

    format!("{}{}", head, common_tail)
}

/// Ensure /etc/wolfstack/container-vnc.json has an entry with a password
/// for this container, returning the (possibly-existing) password.
fn ensure_password(runtime: &str, name: &str) -> Result<String, String> {
    let key = config_key(runtime, name);
    let mut map = load_config();
    if let Some(e) = map.get(&key) {
        return Ok(e.password.clone());
    }
    let password = generate_password();
    map.insert(key, VncEntry {
        runtime: runtime.to_string(),
        name: name.to_string(),
        password: password.clone(),
        installed_at: chrono::Utc::now().to_rfc3339(),
    });
    save_config(&map)?;
    Ok(password)
}

// ---- prepared install scripts (looked up by session_id from console.rs) ----

#[derive(Clone)]
pub struct PreparedInstall {
    pub runtime: String,
    pub name: String,
    pub host_script_path: String,
}

static PREPARED_INSTALLS: std::sync::LazyLock<Mutex<HashMap<String, PreparedInstall>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Look up a prepared install by session_id (called from console.rs).
pub fn take_prepared_install(session_id: &str) -> Option<PreparedInstall> {
    PREPARED_INSTALLS.lock().ok()?.remove(session_id)
}

fn random_session_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    let mut s = String::with_capacity(16);
    for b in &buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ===========================================================================
// REST endpoints
// ===========================================================================

/// GET /api/container-vnc/{runtime}/{name}/status
///
/// Returns the OS info (so the frontend modal can show the user what
/// will be installed), and whether VNC is already installed / running
/// inside the container.
pub async fn vnc_status(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    // OS detection — also tells us if the container is running (exec fails otherwise).
    let os = match detect_os(&runtime, &name) {
        Ok(o) => Some(o),
        Err(e) => {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "installed": false,
                "running": false,
                "container_running": false,
                "os": null,
                "error": format!("Cannot inspect container: {}", e),
            })));
        }
    };

    // Probe inside the container for VNC presence + state.
    // /root/.vnc/passwd → password file written by our installer
    // pgrep Xvnc → whether display :1 is currently running
    let probe = "if [ -f /root/.vnc/passwd ] && [ -x /usr/local/bin/wolfstack-vnc-start ]; \
                 then echo INSTALLED; else echo NOT_INSTALLED; fi; \
                 if pgrep -f 'Xvnc.*:1|Xtigervnc.*:1' >/dev/null 2>&1; \
                 then echo RUNNING; else echo NOT_RUNNING; fi";
    let (installed, running) = match container_exec(&runtime, &name, probe) {
        Ok((_, stdout, _)) => {
            let installed = stdout.contains("INSTALLED") && !stdout.contains("NOT_INSTALLED");
            let running = stdout.contains("RUNNING") && !stdout.contains("NOT_RUNNING");
            (installed, running)
        }
        Err(_) => (false, false),
    };

    // We treat "installed" as: marker files exist AND we have a stored password.
    let stored = load_config().get(&config_key(&runtime, &name)).cloned();
    let installed_final = installed && stored.is_some();
    let password = if installed_final { stored.map(|e| e.password) } else { None };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "installed": installed_final,
        "running": running,
        "container_running": true,
        "os": os,
        "password": password,
    })))
}

/// POST /api/container-vnc/{runtime}/{name}/prepare-install
///
/// Generates+stores a VNC password, writes the install script to /tmp,
/// and returns a session_id. The frontend then opens a console session
/// at /ws/console/vnc-install/{session_id} which streams the install live.
pub async fn vnc_prepare_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    let os = match detect_os(&runtime, &name) {
        Ok(o) => o,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Cannot detect OS: {}", e),
            })));
        }
    };
    if !os.supported {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unsupported OS: {} ({}). Supported: Debian/Ubuntu, Alpine, RHEL/Rocky/Fedora.", os.id, os.id_like),
        })));
    }

    let password = match ensure_password(&runtime, &name) {
        Ok(p) => p,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Cannot persist VNC password: {}", e),
            })));
        }
    };

    let script = build_install_script(&os.family, &password);
    if script.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Internal: empty install script for supported OS",
        })));
    }

    let session_id = random_session_id();
    let host_script_path = format!("/tmp/wolfstack-vnc-install-{}.sh", session_id);
    if let Err(e) = crate::paths::write_secure(&host_script_path, &script) {
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Cannot write install script: {}", e),
        })));
    }

    if let Ok(mut map) = PREPARED_INSTALLS.lock() {
        map.insert(session_id.clone(), PreparedInstall {
            runtime: runtime.clone(),
            name: name.clone(),
            host_script_path: host_script_path.clone(),
        });
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "ws_path": format!("/ws/console/vnc-install/{}", session_id),
        "os": os,
    })))
}

/// POST /api/container-vnc/{runtime}/{name}/uninstall
///
/// Just forgets the stored password and removes our marker files inside
/// the container. Doesn't uninstall packages — those are useful and the
/// user installed them deliberately.
pub async fn vnc_uninstall(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    let key = config_key(&runtime, &name);
    let mut map = load_config();
    map.remove(&key);
    if let Err(e) = save_config(&map) {
        warn!("Failed to save VNC config after uninstall: {}", e);
    }

    // Best-effort: stop the VNC server and delete the marker files.
    let cleanup = "if command -v tigervncserver >/dev/null 2>&1; then \
                       tigervncserver -kill :1 >/dev/null 2>&1 || true; \
                   elif command -v vncserver >/dev/null 2>&1; then \
                       vncserver -kill :1 >/dev/null 2>&1 || true; fi; \
                   pkill -f 'Xvnc.*:1' 2>/dev/null || true; \
                   pkill -f 'Xtigervnc.*:1' 2>/dev/null || true; \
                   rm -f /root/.vnc/passwd /usr/local/bin/wolfstack-vnc-start";
    let _ = container_exec(&runtime, &name, cleanup);

    Ok(HttpResponse::Ok().json(serde_json::json!({ "ok": true })))
}

// ===========================================================================
// WebSocket bridge
// ===========================================================================

/// GET /ws/container-vnc/{runtime}/{name}
///
/// Spawns `<runtime exec> -- sh -c 'wolfstack-vnc-start; exec socat STDIO TCP:127.0.0.1:5901'`
/// and shuttles the child's stdio ↔ noVNC binary frames.
pub async fn container_vnc_ws(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let (runtime, name) = path.into_inner();
    if let Err(resp) = validate_target(&runtime, &name) { return Ok(resp); }

    if !load_config().contains_key(&config_key(&runtime, &name)) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "VNC is not installed for this container — run install first",
        })));
    }

    // Bridge command: ensure server is up, then socat stdio ↔ TCP 127.0.0.1:5901
    // exec so socat replaces the shell — clean process tree, signals propagate.
    const BRIDGE_CMD: &str = "/usr/local/bin/wolfstack-vnc-start >/dev/null 2>&1 || \
                              { echo 'wolfstack-vnc-start failed' >&2; exit 1; }; \
                              exec socat STDIO TCP:127.0.0.1:5901";

    let argv = match build_exec_argv(&runtime, &name, BRIDGE_CMD) {
        Ok(a) => a,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": e })));
        }
    };

    let mut command = tokio::process::Command::new(&argv[0]);
    command.args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn VNC bridge for {}/{}: {}", runtime, name, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to spawn VNC bridge: {}", e),
            })));
        }
    };

    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to capture child stdin",
        }))),
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to capture child stdout",
        }))),
    };

    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    actix_rt::spawn(bridge_stdio_to_ws(session, msg_stream, child, stdin, stdout));
    Ok(response)
}

/// Bidirectional bridge: child stdio ↔ noVNC binary WebSocket frames.
/// Child stdout is RFB protocol bytes from socat; we forward as binary frames.
/// Browser sends RFB binary frames; we write to child stdin.
async fn bridge_stdio_to_ws(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    mut child: tokio::process::Child,
    mut stdin: tokio::process::ChildStdin,
    mut stdout: tokio::process::ChildStdout,
) {
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            // child stdout (VNC server bytes) → browser
            result = stdout.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if session.binary(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }

            // browser → child stdin
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if stdin.write_all(&data).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if stdin.write_all(text.as_bytes()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // kill_on_drop will reap the child when `child` is dropped at function exit.
    let _ = child.start_kill();
    let _ = session.close(None).await;
}

/// GET /api/container-vnc/list
///
/// Returns the keys of every container that has been set up for VNC,
/// so the frontend can show the VNC icon on the right rows without
/// having to probe each container individually.
pub async fn vnc_list(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_auth(&req, &state) { return Ok(resp); }
    let map = load_config();
    let keys: Vec<&String> = map.keys().collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "keys": keys })))
}
