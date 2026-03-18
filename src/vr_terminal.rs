// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! HTTP polling terminal for VR — avoids WebSocket port restrictions.
//! Creates PTY sessions accessible via REST API instead of WebSocket.

use actix_web::{web, HttpRequest, HttpResponse};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::{Instant, Duration};

/// A VR terminal session
struct VrTermSession {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    _child: Box<dyn portable_pty::Child + Send>,
    output_buf: Vec<u8>,
    last_poll: Instant,
}

static VR_SESSIONS: std::sync::LazyLock<Mutex<HashMap<String, VrTermSession>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// POST /api/vr-terminal/create — create a new PTY session
/// Body: { "type": "host|docker|lxc", "name": "container_name" }
pub async fn vr_term_create(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }

    let ctype = body.get("type").and_then(|v| v.as_str()).unwrap_or("host");
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("shell");

    // Validate name
    if ctype != "host" && !crate::auth::is_safe_name(name) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid name" }));
    }

    // Build command
    let mut cmd = CommandBuilder::new("sh");
    cmd.arg("-c");
    cmd.env("TERM", "xterm-256color");
    match ctype {
        "docker" => {
            cmd.arg(format!(
                "docker exec -e TERM=xterm-256color -it {} /bin/bash --login 2>/dev/null || \
                 docker exec -e TERM=xterm-256color -it {} /bin/sh -l 2>/dev/null || \
                 docker exec -e TERM=xterm-256color -it {} /bin/ash 2>/dev/null || \
                 echo 'No shell available'",
                name, name, name,
            ));
        }
        "lxc" => {
            let base = crate::containers::lxc_base_dir(name);
            let p_flag = if base != crate::containers::LXC_DEFAULT_PATH {
                format!("-P {} ", base)
            } else {
                String::new()
            };
            cmd.arg(format!(
                "lxc-attach {}-n {} --set-var TERM=xterm-256color -- /bin/sh -c \
                 'if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi'",
                p_flag, name
            ));
        }
        _ => {
            // host shell
            cmd.arg("if [ -x /bin/bash ]; then exec /bin/bash --login; else exec /bin/sh -l; fi");
        }
    }

    // Create PTY
    let pty_system = native_pty_system();
    let pty_pair = match pty_system.openpty(PtySize {
        rows: 30, cols: 100,
        pixel_width: 0, pixel_height: 0,
    }) {
        Ok(pair) => pair,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("PTY error: {}", e) })),
    };

    let child = match pty_pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Spawn error: {}", e) })),
    };

    let reader = match pty_pair.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Reader error: {}", e) })),
    };
    let writer = match pty_pair.master.take_writer() {
        Ok(w) => w,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Writer error: {}", e) })),
    };

    let session_id = format!("vrt-{}", uuid_simple());
    let mut sessions = VR_SESSIONS.lock().unwrap();
    // Clean up stale sessions (> 30 minutes idle)
    sessions.retain(|_, s| s.last_poll.elapsed() < Duration::from_secs(1800));

    sessions.insert(session_id.clone(), VrTermSession {
        reader,
        writer,
        _child: child,
        output_buf: Vec::new(),
        last_poll: Instant::now(),
    });

    HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "cols": 100,
        "rows": 30,
    }))
}

/// GET /api/vr-terminal/{id}/output — get new terminal output
pub async fn vr_term_output(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let mut sessions = VR_SESSIONS.lock().unwrap();
    let session = match sessions.get_mut(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Session not found" })),
    };

    session.last_poll = Instant::now();

    // Read available data from PTY (non-blocking)
    let mut buf = [0u8; 8192];
    let mut output = Vec::new();

    // Drain any buffered output first
    output.append(&mut session.output_buf);

    // Try to read more (non-blocking via timeout)
    loop {
        match session.reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                output.extend_from_slice(&buf[..n]);
                if output.len() > 32768 { break; } // cap at 32KB per poll
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&output).to_string();
    HttpResponse::Ok().json(serde_json::json!({
        "output": text,
        "alive": true,
    }))
}

/// POST /api/vr-terminal/{id}/input — send keystrokes
pub async fn vr_term_input(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let data = body.get("data").and_then(|v| v.as_str()).unwrap_or("");
    if data.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({ "ok": true }));
    }

    let mut sessions = VR_SESSIONS.lock().unwrap();
    let session = match sessions.get_mut(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Session not found" })),
    };

    session.last_poll = Instant::now();
    match session.writer.write_all(data.as_bytes()) {
        Ok(_) => { let _ = session.writer.flush(); }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Write error: {}", e) })),
    }

    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}

/// DELETE /api/vr-terminal/{id} — close session
pub async fn vr_term_close(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let mut sessions = VR_SESSIONS.lock().unwrap();
    if sessions.remove(&id).is_some() {
        HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": "Session closed" }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Session not found" }))
    }
}

/// Simple UUID-like ID generator
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let r: u32 = (t & 0xFFFFFFFF) as u32 ^ ((t >> 32) as u32);
    format!("{:x}{:08x}", t / 1_000_000_000, r)
}
