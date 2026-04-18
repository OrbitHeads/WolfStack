// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! REST API for WolfStack dashboard and agent communication

use actix_web::{web, HttpResponse, HttpRequest, cookie::Cookie};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::process::Command;
use tracing::{warn, error};

use crate::monitoring::{SystemMonitor, MetricsHistory};
use crate::installer;
use crate::containers;
use crate::storage;
use crate::networking;
use crate::backup;
use crate::agent::{ClusterState, AgentMessage};
use crate::auth::SessionManager;
use crate::appstore;


mod pve_console;
mod cluster_browser_proxy;

/// Build ordered URLs to try for inter-node communication.
/// Tries: HTTPS on main port, HTTP on internal port (port+1), HTTP on main port.
/// This ensures both TLS-enabled and HTTP-only nodes are reachable.
pub fn build_node_urls(address: &str, port: u16, path: &str) -> Vec<String> {
    vec![
        format!("https://{}:{}{}", address, port, path),
        format!("http://{}:{}{}", address, port + 1, path),
        format!("http://{}:{}{}", address, port, path),
    ]
}

/// Build ordered URLs to try for external (cross-cluster) communication.
/// All destination nodes run WolfStack (HTTPS 8553, HTTP 8554), so we try those ports
/// automatically — the user only needs to provide the hostname.
pub fn build_external_urls(target_url: &str, path: &str) -> Vec<String> {
    let trimmed = target_url.trim_end_matches('/');

    // Ensure we have a scheme — prepend https:// if missing
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    // Extract host from URL (scheme://host:port/path → host)
    let after_scheme = &with_scheme[with_scheme.find("://").unwrap() + 3..];
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let (host, user_port) = match host_port.rfind(':') {
        Some(pos) => {
            let port_str = &host_port[pos + 1..];
            match port_str.parse::<u16>() {
                Ok(port) => (&host_port[..pos], Some(port)),
                Err(_) => (host_port, None),
            }
        }
        None => (host_port, None),
    };

    let mut urls = Vec::new();

    // If user specified a port, try their exact URL first
    if user_port.is_some() {
        urls.push(format!("{}{}", with_scheme, path));
    }

    // Always try WolfStack ports
    if user_port != Some(8553) {
        urls.push(format!("https://{}:8553{}", host, path));
    }
    if user_port != Some(8554) {
        urls.push(format!("http://{}:8554{}", host, path));
    }

    urls
}

/// Progress state for PBS restore operations
#[derive(Clone, Serialize, Default)]
pub struct PbsRestoreProgress {
    pub active: bool,
    pub snapshot: String,
    pub progress_text: String,
    pub percentage: Option<f64>,
    pub finished: bool,
    pub success: Option<bool>,
    pub message: String,
    #[serde(skip)]
    pub started_at: Option<std::time::Instant>,
}

/// Shared application state
pub struct AppState {
    pub monitor: std::sync::Mutex<SystemMonitor>,
    pub metrics_history: std::sync::Mutex<MetricsHistory>,
    pub cluster: Arc<ClusterState>,
    pub sessions: Arc<SessionManager>,
    pub vms: std::sync::Mutex<crate::vms::manager::VmManager>,
    pub cluster_secret: String,
    pub join_token: String,
    pub pbs_restore_progress: std::sync::Mutex<PbsRestoreProgress>,
    pub ai_agent: Arc<crate::ai::AiAgent>,
    /// Pre-built agent status response, updated every 2s by background task
    pub cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>>,
    /// WolfRun orchestration state
    pub wolfrun: Arc<crate::wolfrun::WolfRunState>,
    pub wolfflow: Arc<crate::wolfflow::WolfFlowState>,
    /// Status page monitoring state
    pub statuspage: Arc<crate::statuspage::StatusPageState>,
    /// Whether this server has TLS enabled (HTTPS on main port)
    pub tls_enabled: bool,
    /// Login rate limiter (brute-force protection)
    pub login_limiter: Arc<crate::auth::LoginRateLimiter>,
    /// WireGuard bridge configs (cluster → bridge)
    pub wireguard_bridges: Arc<std::sync::RwLock<std::collections::HashMap<String, crate::networking::WireGuardBridge>>>,
    /// Patreon integration state
    pub patreon: Arc<crate::patreon::PatreonState>,
    /// Migration task progress tracker
    pub migration_tasks: Arc<std::sync::RwLock<std::collections::HashMap<String, MigrationTask>>>,
    /// Alert log — recent alerts surfaced to the frontend task log
    pub alert_log: Arc<std::sync::RwLock<Vec<AlertLogEntry>>>,
    /// Password reset tokens (in-memory, 30-minute expiry)
    pub password_reset_tokens: Arc<crate::auth::PasswordResetTokens>,
    /// OIDC pending authentication flows (state token → flow data, 5-minute TTL)
    pub oidc_pending_flows: Arc<std::sync::RwLock<std::collections::HashMap<String, crate::auth::oidc::OidcPendingFlow>>>,
    /// Image update watcher cache (container name → last check result)
    pub image_watcher_cache: Arc<std::sync::RwLock<std::collections::HashMap<String, crate::containers::image_watcher::ImageCheckResult>>>,
    /// Integration framework state
    pub integrations: Arc<crate::integrations::IntegrationState>,
    /// WolfRouter (native firewall/DHCP/DNS) state
    pub router: Arc<crate::networking::router::RouterState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AlertLogEntry {
    pub id: u64,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub hostname: String,
    pub cluster: String,
}

#[derive(Clone, Serialize)]
pub struct MigrationTask {
    pub id: String,
    pub stage: String,       // "preflight", "export", "upload", "import", "done", "failed"
    pub message: String,
    pub completed: bool,
    pub error: Option<String>,
    pub started_at: u64,
}

/// Load or generate the join token from /etc/wolfstack/join-token
pub fn load_join_token() -> String {
    let path = std::path::Path::new("/etc/wolfstack/join-token");
    if let Ok(token) = std::fs::read_to_string(path) {
        let token = token.trim().to_string();
        if !token.is_empty() {

            return token;
        }
    }
    // Generate a new token
    use std::fmt::Write;
    let mut token = String::with_capacity(64);
    let random_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        // Use /dev/urandom for cryptographic randomness
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = f.read_exact(&mut buf);
        } else {
            // Fallback: use system time + pid
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let seed = t.as_nanos() ^ (std::process::id() as u128);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((seed >> (i % 16 * 8)) & 0xFF) as u8 ^ (i as u8).wrapping_mul(37);
            }
        }
        buf
    };
    for b in &random_bytes {
        let _ = write!(token, "{:02x}", b);
    }
    // Save it
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    if let Err(e) = std::fs::write(path, &token) {
        warn!("Could not save join token to {}: {}", path.display(), e);
    } else {

    }
    token
}

// ─── Auth helpers ───

/// Extract session token from cookie
fn get_session_token(req: &HttpRequest) -> Option<String> {
    req.cookie("wolfstack_session")
        .map(|c| c.value().to_string())
}

/// Check if request is authenticated; returns username or error response
pub fn require_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    // Accept internal requests from other WolfStack nodes if they provide the cluster secret
    if let Some(val) = req.headers().get("X-WolfStack-Secret") {
        let provided = val.to_str().unwrap_or("");
        // Accept: the in-memory secret, the hardcoded default, OR the on-disk secret
        // (covers the window between secret propagation and node restart)
        if crate::auth::validate_cluster_secret(provided, &state.cluster_secret)
            || crate::auth::validate_cluster_secret(provided, crate::auth::default_cluster_secret())
            || crate::auth::validate_cluster_secret(provided, &crate::auth::load_cluster_secret())
        {
            return Ok("cluster-node".to_string());
        }
        // Invalid secret — do NOT fall through to session auth
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid cluster secret"
        })));
    }
    // Accept API key authentication (X-API-Key header or Authorization: Bearer wsk_...)
    // Check platform calibration state for token-based auth
    if crate::compat::platform_ready() {
        let api_key_value = req.headers().get("X-API-Key")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
            .or_else(|| {
                req.headers().get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .filter(|v| v.starts_with("wsk_"))
                    .map(|v| v.to_string())
            });

        if let Some(raw_key) = api_key_value {
            let ip = req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            match crate::compat::validate_key(&raw_key, Some(&ip)) {
                Some(key) => {
                    let method = req.method().as_str();
                    let path = req.path();
                    if !crate::compat::scope_allows(&key, method, path) {
                        return Err(HttpResponse::Forbidden().json(serde_json::json!({
                            "error": crate::compat::rt_msg(3),
                        })));
                    }
                    crate::compat::audit_log(&crate::compat::AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        key_name: key.name.clone(),
                        key_id: key.id.clone(),
                        method: method.to_string(),
                        path: path.to_string(),
                        ip,
                        status: 200,
                    });
                    return Ok(format!("apikey:{}", key.name));
                }
                None => {
                    return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": crate::compat::rt_msg(2)
                    })));
                }
            }
        }
    }

    match get_session_token(req) {
        Some(token) => {
            match state.sessions.validate(&token) {
                Some(username) => Ok(username),
                None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Session expired"
                }))),
            }
        }
        None => Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Not authenticated"
        }))),
    }
}

/// Require cluster secret authentication for inter-node endpoints
pub fn require_cluster_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<(), HttpResponse> {
    match req.headers().get("X-WolfStack-Secret") {
        Some(val) => {
            let provided = val.to_str().unwrap_or("");
            if crate::auth::validate_cluster_secret(provided, &state.cluster_secret)
                || crate::auth::validate_cluster_secret(provided, crate::auth::default_cluster_secret())
                || crate::auth::validate_cluster_secret(provided, &crate::auth::load_cluster_secret())
            {
                Ok(())
            } else {
                Err(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Invalid cluster secret"
                })))
            }
        }
        None => Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Cluster authentication required"
        }))),
    }
}

// ─── Auth API ───

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
}

/// POST /api/auth/login — authenticate with Linux or WolfStack credentials + optional 2FA
pub async fn login(req: HttpRequest, state: web::Data<AppState>, body: web::Json<LoginRequest>) -> HttpResponse {
    // Rate limiting — extract client IP
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    if state.login_limiter.is_locked_out(&client_ip) {
        return HttpResponse::TooManyRequests().json(serde_json::json!({
            "success": false,
            "error": "Too many failed login attempts. Please try again later."
        }));
    }

    // Check if direct login is disabled on this node
    {
        let nodes = state.cluster.nodes.read().unwrap();
        if let Some(self_node) = nodes.get(&state.cluster.self_id) {
            if self_node.login_disabled {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "success": false,
                    "error": "Direct login is disabled on this server. Access it via the primary dashboard."
                }));
            }
        }
    }

    let auth_config = crate::auth::users::AuthConfig::load();
    let mode = auth_config.auth_mode.as_str();

    // Try WolfStack users first (if mode is "wolfstack" or "both")
    if mode == "wolfstack" || mode == "both" {
        if let Some(user) = crate::auth::users::authenticate_wolfstack_user(&body.username, &body.password) {
            // Check 2FA if enabled
            if user.totp_enabled {
                if body.totp_code.is_empty() {
                    // Password correct, but 2FA required — tell frontend to prompt
                    return HttpResponse::Ok().json(serde_json::json!({
                        "success": false,
                        "requires_2fa": true,
                        "message": "Two-factor authentication required"
                    }));
                }
                if !crate::auth::users::verify_totp(&user.totp_secret, &body.totp_code) {
                    state.login_limiter.record_failure(&client_ip);
                    return HttpResponse::Unauthorized().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid two-factor authentication code"
                    }));
                }
            }

            state.login_limiter.clear(&client_ip);
            let token = state.sessions.create_session(&body.username);
            let mut cookie = Cookie::build("wolfstack_session", &token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::hours(8))
                .finish();
            if state.tls_enabled {
                cookie.set_secure(true);
            }
            return HttpResponse::Ok()
                .cookie(cookie)
                .json(serde_json::json!({
                    "success": true,
                    "username": body.username
                }));
        }
    }

    // Try Linux system auth (if mode is "linux" or "both")
    if mode == "linux" || mode == "both" {
        if crate::auth::authenticate_user(&body.username, &body.password) {
            state.login_limiter.clear(&client_ip);
            let token = state.sessions.create_session(&body.username);
            let mut cookie = Cookie::build("wolfstack_session", &token)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::hours(8))
                .finish();
            if state.tls_enabled {
                cookie.set_secure(true);
            }
            return HttpResponse::Ok()
                .cookie(cookie)
                .json(serde_json::json!({
                    "success": true,
                    "username": body.username
                }));
        }
    }

    state.login_limiter.record_failure(&client_ip);
    HttpResponse::Unauthorized().json(serde_json::json!({
        "success": false,
        "error": "Invalid username or password"
    }))
}

/// GET /api/settings/login-disabled — check if direct login is disabled (no auth needed)
pub async fn login_disabled_status(state: web::Data<AppState>) -> HttpResponse {
    let disabled = {
        let nodes = state.cluster.nodes.read().unwrap();
        nodes.get(&state.cluster.self_id).map(|n| n.login_disabled).unwrap_or(false)
    };
    HttpResponse::Ok().json(serde_json::json!({ "login_disabled": disabled }))
}

/// POST /api/settings/login-disabled — set login_disabled on this node (cluster-auth required)
pub async fn set_login_disabled(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    // Accept both cluster auth (from remote dashboard) and session auth (local admin)
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let disabled = body.get("login_disabled").and_then(|v| v.as_bool()).unwrap_or(false);
    {
        let mut nodes = state.cluster.nodes.write().unwrap();
        if let Some(node) = nodes.get_mut(&state.cluster.self_id) {
            node.login_disabled = disabled;
        }
    }
    // Persist to disk
    crate::agent::ClusterState::save_login_disabled_file(disabled);

    HttpResponse::Ok().json(serde_json::json!({ "login_disabled": disabled }))
}

/// POST /api/auth/logout — destroy session
pub async fn logout(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Some(token) = get_session_token(&req) {
        state.sessions.destroy(&token);
    }
    let mut cookie = Cookie::build("wolfstack_session", "")
        .path("/")
        .finish();
    cookie.make_removal();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "success": true }))
}

/// GET /api/auth/check — check if session is valid
pub async fn auth_check(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    match require_auth(&req, &state) {
        Ok(username) => HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "username": username
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "authenticated": false
        })),
    }
}

// ─── Password Reset API (no auth required) ───

/// GET /api/auth/smtp-configured — check if SMTP is configured (controls "Lost Password" visibility)
pub async fn smtp_configured() -> HttpResponse {
    let config = crate::ai::AiConfig::load();
    let configured = !config.smtp_host.is_empty() && !config.smtp_user.is_empty() && !config.smtp_pass.is_empty();
    HttpResponse::Ok().json(serde_json::json!({ "smtp_configured": configured, "version": env!("CARGO_PKG_VERSION") }))
}

/// POST /api/auth/forgot-password — send a password reset email
pub async fn forgot_password(state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let username = body["username"].as_str().unwrap_or("").trim();
    if username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Username is required"}));
    }

    // Rate limit by IP is already handled at the login level, but let's not leak user existence.
    // Always return success to prevent user enumeration.
    let generic_ok = HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "If an account with that username exists and has an email address, a reset link has been sent."
    }));

    // Look up the WolfStack user
    let store = crate::auth::users::UserStore::load();
    let user = match store.find(username) {
        Some(u) => u.clone(),
        None => return generic_ok,
    };

    if user.email.is_empty() {
        return generic_ok;
    }

    // Check SMTP is configured
    let config = crate::ai::AiConfig::load();
    if config.smtp_host.is_empty() || config.smtp_user.is_empty() || config.smtp_pass.is_empty() {
        return generic_ok;
    }

    // Create reset token
    let token = state.password_reset_tokens.create(username);

    // Send the email
    let subject = "WolfStack — Password Reset";
    let body_text = format!(
        "A password reset was requested for your WolfStack account '{}'.\n\n\
         Your reset code is:\n\n    {}\n\n\
         Enter this code on the login page to set a new password.\n\
         This code expires in 30 minutes.\n\n\
         If you did not request this, you can safely ignore this email.",
        username, token
    );

    match crate::ai::send_alert_email(&config, subject, &body_text) {
        Ok(()) => generic_ok,
        Err(e) => {
            tracing::warn!("Failed to send password reset email: {}", e);
            generic_ok // Don't leak SMTP errors
        }
    }
}

/// POST /api/auth/reset-password — validate reset token and set new password
pub async fn reset_password(state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let token = body["token"].as_str().unwrap_or("").trim();
    let new_password = body["password"].as_str().unwrap_or("");

    if token.is_empty() || new_password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Token and new password are required"}));
    }

    if new_password.len() < 6 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Password must be at least 6 characters"}));
    }

    // Validate and consume the token
    let username = match state.password_reset_tokens.validate_and_consume(token) {
        Some(u) => u,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid or expired reset code"})),
    };

    // Hash the new password and update the user
    let password_hash = match crate::auth::users::hash_password(new_password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let mut store = crate::auth::users::UserStore::load();
    if let Some(user) = store.find_mut(&username) {
        user.password_hash = password_hash;
        if let Err(e) = store.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
        HttpResponse::Ok().json(serde_json::json!({"success": true, "message": "Password has been reset. You can now log in."}))
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({"error": "User no longer exists"}))
    }
}

// ─── User Management API ───

/// GET /api/auth/config — get auth configuration
pub async fn get_auth_config(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::auth::users::AuthConfig::load())
}

/// POST /api/auth/config — update auth configuration
pub async fn save_auth_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::auth::users::AuthConfig>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match body.into_inner().save() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/auth/users — list all WolfStack users (hides password hashes and TOTP secrets)
pub async fn list_users(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let store = crate::auth::users::UserStore::load();
    let users: Vec<serde_json::Value> = store.users.iter().map(|u| {
        serde_json::json!({
            "username": u.username,
            "role": u.role,
            "display_name": u.display_name,
            "email": u.email,
            "totp_enabled": u.totp_enabled,
            "created_at": u.created_at,
        })
    }).collect();
    HttpResponse::Ok().json(users)
}

/// POST /api/auth/users — create a new WolfStack user
pub async fn create_user(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let username = body["username"].as_str().unwrap_or("").trim().to_string();
    let password = body["password"].as_str().unwrap_or("");
    let role = body["role"].as_str().unwrap_or("admin").to_string();
    let display_name = body["display_name"].as_str().unwrap_or("").to_string();

    if username.is_empty() || password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Username and password required"}));
    }
    if !crate::auth::is_safe_name(&username) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid username — use alphanumeric, dash, underscore only"}));
    }

    let password_hash = match crate::auth::users::hash_password(password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let email = body["email"].as_str().unwrap_or("").trim().to_string();

    // Allowed clusters — comma-free list from the create form. Empty =
    // see-everything (matches the existing default for legacy users);
    // for restricted team members the operator fills this in.
    let allowed_clusters: Vec<String> = body.get("allowed_clusters")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let user = crate::auth::users::WolfUser {
        username: username.clone(),
        password_hash,
        totp_secret: String::new(),
        totp_enabled: false,
        role,
        display_name,
        email,
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        allowed_clusters,
    };

    let mut store = crate::auth::users::UserStore::load();
    match store.add(user) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true, "username": username})),
        Err(e) => HttpResponse::Conflict().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /api/auth/users/{username} — delete a WolfStack user
pub async fn delete_user(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let username = path.into_inner();
    let mut store = crate::auth::users::UserStore::load();
    match store.remove(&username) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": e})),
    }
}

/// POST /api/auth/users/{username}/password — change password
pub async fn change_user_password(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let username = path.into_inner();
    let new_password = body["password"].as_str().unwrap_or("");
    if new_password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Password required"}));
    }

    let password_hash = match crate::auth::users::hash_password(new_password) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    };

    let mut store = crate::auth::users::UserStore::load();
    match store.find_mut(&username) {
        Some(user) => {
            user.password_hash = password_hash;
            match store.save() {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

/// POST /api/auth/users/{username}/2fa/setup — generate a new TOTP secret (not yet confirmed)
pub async fn setup_2fa(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let username = path.into_inner();
    let store = crate::auth::users::UserStore::load();
    if store.find(&username).is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
    }

    let secret = crate::auth::users::generate_totp_secret();
    let uri = crate::auth::users::totp_uri(&secret, &username);

    HttpResponse::Ok().json(serde_json::json!({
        "secret": secret,
        "uri": uri,
    }))
}

/// POST /api/auth/users/{username}/2fa/confirm — verify a TOTP code and enable 2FA
pub async fn confirm_2fa(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let username = path.into_inner();
    let code = body["code"].as_str().unwrap_or("");
    let secret = body["secret"].as_str().unwrap_or("");

    if code.is_empty() || secret.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Code and secret required"}));
    }

    // Verify the code matches the secret before enabling
    if !crate::auth::users::verify_totp(secret, code) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid code — check your authenticator app and try again"}));
    }

    let mut store = crate::auth::users::UserStore::load();
    match store.find_mut(&username) {
        Some(user) => {
            user.totp_secret = secret.to_string();
            user.totp_enabled = true;
            match store.save() {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

/// PUT /api/auth/users/{username}/clusters — update which clusters
/// this user is allowed to see. Empty list = all clusters (legacy
/// behaviour, admins always pass regardless). Non-empty list = only
/// the named clusters show up in /api/nodes responses and related
/// per-cluster views. Requires admin auth — we don't let a restricted
/// user re-widen their own scope.
pub async fn update_user_clusters(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let caller = match require_auth(&req, &state) { Ok(u) => u, Err(resp) => return resp };
    let store = crate::auth::users::UserStore::load();
    let caller_is_admin = store.find(&caller)
        .map(|u| u.role == "admin").unwrap_or(false);
    if !caller_is_admin {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Only admin users can change cluster access"
        }));
    }
    let username = path.into_inner();
    let new_clusters: Vec<String> = body.get("allowed_clusters")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let mut store = crate::auth::users::UserStore::load();
    match store.find_mut(&username) {
        Some(user) => {
            user.allowed_clusters = new_clusters.clone();
            match store.save() {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "username": username,
                    "allowed_clusters": new_clusters,
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

/// POST /api/auth/users/{username}/2fa/disable — disable 2FA for a user
pub async fn disable_2fa(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let username = path.into_inner();
    let mut store = crate::auth::users::UserStore::load();
    match store.find_mut(&username) {
        Some(user) => {
            user.totp_secret.clear();
            user.totp_enabled = false;
            match store.save() {
                Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

// ─── Dashboard API ───

/// GET /api/metrics — current system metrics
pub async fn get_metrics(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let st = state.into_inner();
    let metrics = tokio::task::spawn_blocking(move || {
        st.monitor.lock().unwrap().collect()
    }).await.unwrap();
    HttpResponse::Ok().json(metrics)
}

/// GET /api/metrics/history — historical CPU, RAM, disk metrics
pub async fn get_metrics_history(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let history = state.metrics_history.lock().unwrap();
    HttpResponse::Ok().json(history.get_all())
}

/// GET /api/metrics/processes — top CPU and memory consuming processes
pub async fn get_top_processes(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let st = state.into_inner();
    let (top_cpu, top_mem) = tokio::task::spawn_blocking(move || {
        st.monitor.lock().unwrap().top_processes(10)
    }).await.unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({
        "top_cpu": top_cpu,
        "top_mem": top_mem,
    }))
}

/// POST /api/metrics/processes/{pid}/kill — kill a process by PID
pub async fn kill_process(req: HttpRequest, state: web::Data<AppState>, path: web::Path<u32>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let pid = path.into_inner();
    // Safety: refuse to kill PID 1 (init) or PID 0
    if pid <= 1 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot kill system process"}));
    }
    let result = std::process::Command::new("kill")
        .arg(pid.to_string())
        .output();
    match result {
        Ok(o) if o.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({"ok": true, "pid": pid}))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({"ok": false, "error": stderr.trim()}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

// ─── Systemd Services ───

#[derive(Serialize)]
struct SystemdService {
    name: String,
    description: String,
    active: String,    // "active", "inactive", "failed", etc.
    sub_state: String, // "running", "dead", "exited", "failed", etc.
    enabled: String,   // "enabled", "disabled", "static", "masked", etc.
}

/// GET /api/systemd — list systemd services
pub async fn list_services(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let services = tokio::task::spawn_blocking(|| {
        // Use JSON output for reliable parsing (supported by systemd 240+)
        let output = std::process::Command::new("systemctl")
            .args(["list-units", "--type=service", "--all", "--no-pager", "--output=json"])
            .output();
        let mut result = Vec::new();
        if let Ok(out) = output {
            if let Ok(units) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
                for u in &units {
                    let name = u["unit"].as_str().unwrap_or("").trim_end_matches(".service").to_string();
                    if name.is_empty() { continue; }
                    // Skip internal systemd units
                    if name.starts_with("systemd-") { continue; }
                    let active = u["active"].as_str().unwrap_or("").to_string();
                    let sub = u["sub"].as_str().unwrap_or("").to_string();
                    let desc = u["description"].as_str().unwrap_or("").to_string();
                    result.push(SystemdService {
                        name,
                        description: desc,
                        active,
                        sub_state: sub,
                        enabled: String::new(),
                    });
                }
            }
        }
        // Get enabled/disabled status
        let enabled_output = std::process::Command::new("systemctl")
            .args(["list-unit-files", "--type=service", "--no-pager", "--no-legend"])
            .output();
        if let Ok(out) = enabled_output {
            let enabled_map: std::collections::HashMap<String, String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        Some((parts[0].trim_end_matches(".service").to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            for svc in &mut result {
                if let Some(state) = enabled_map.get(&svc.name) {
                    svc.enabled = state.clone();
                }
            }
        }
        result
    }).await.unwrap_or_default();
    HttpResponse::Ok().json(services)
}

#[derive(Deserialize)]
pub struct SystemdActionRequest {
    pub action: String,
}

/// POST /api/services/{name}/action — start/stop/restart/enable/disable a systemd service
pub async fn systemd_service_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<SystemdActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let action = body.action.clone();

    // Validate action
    if !["start", "stop", "restart", "enable", "disable"].contains(&action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Unknown action: {}", action)}));
    }
    // Validate service name (prevent injection)
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '@' || c == '.') {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid service name"}));
    }

    let svc_name = format!("{}.service", name);
    let act = action.clone();
    let result = tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new("systemctl")
            .args([&act, &svc_name])
            .output();
        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                (o.status.success(), stdout, stderr)
            }
            Err(e) => (false, String::new(), format!("Failed to execute: {}", e)),
        }
    }).await.unwrap_or((false, String::new(), "Task failed".to_string()));

    if result.0 {
        HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": format!("{} {}", action, name)}))
    } else {
        // On failure, also grab the service status/journal for diagnostics
        let svc_name2 = format!("{}.service", name);
        let diagnostics = tokio::task::spawn_blocking(move || {
            let status = std::process::Command::new("systemctl")
                .args(["status", &svc_name2, "--no-pager", "-l"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            let journal = std::process::Command::new("journalctl")
                .args(["-u", &svc_name2, "--no-pager", "-n", "30", "--no-hostname"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            (status, journal)
        }).await.unwrap_or_default();

        HttpResponse::Ok().json(serde_json::json!({
            "ok": false,
            "error": result.2.trim(),
            "status": diagnostics.0,
            "journal": diagnostics.1,
        }))
    }
}

/// GET /api/nodes — all cluster nodes
pub async fn get_nodes(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let caller = match require_auth(&req, &state) { Ok(u) => u, Err(resp) => return resp };
    let nodes = state.cluster.get_all_nodes();
    // Per-user cluster filter. Cluster-node callers (inter-node
    // traffic via X-WolfStack-Secret) always see everything; the
    // helper returns "cluster-node" for those and find() below misses,
    // so the unfiltered path kicks in. Admin users also pass through
    // — the helper handles that.
    let filtered = filter_nodes_for_caller(&caller, nodes);
    HttpResponse::Ok().json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "nodes": filtered,
        "tls_enabled": state.tls_enabled,
    }))
}

/// Filter a nodes list down to what the caller (by username) is
/// allowed to see. The "cluster-node" pseudo-caller (inter-node
/// auth) and any user not found in the store pass everything through
/// — this is the safe default for service-to-service and for cases
/// where a session exists without a matching user record.
fn filter_nodes_for_caller(caller: &str, nodes: Vec<crate::agent::Node>) -> Vec<crate::agent::Node> {
    if caller == "cluster-node" { return nodes; }
    let store = crate::auth::users::UserStore::load();
    let Some(user) = store.find(caller) else { return nodes; };
    if user.role == "admin" || user.allowed_clusters.is_empty() {
        return nodes;
    }
    nodes.into_iter()
        .filter(|n| user.can_access_cluster(n.cluster_name.as_deref()))
        .collect()
}

/// GET /api/nodes/{id} — single node details
pub async fn get_node(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let caller = match require_auth(&req, &state) { Ok(u) => u, Err(resp) => return resp };
    let id = path.into_inner();
    match state.cluster.get_node(&id) {
        Some(node) => {
            // Refuse if the caller can't see this cluster — same rule
            // as /api/nodes, applied to the single-node view.
            let store = crate::auth::users::UserStore::load();
            if caller != "cluster-node" {
                if let Some(user) = store.find(&caller) {
                    if !user.can_access_cluster(node.cluster_name.as_deref()) {
                        return HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "You don't have access to this cluster"
                        }));
                    }
                }
            }
            HttpResponse::Ok().json(node)
        },
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Node not found"
        })),
    }
}

/// GET /api/auth/join-token — display this server's join token (session-auth required)
pub async fn get_join_token(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(serde_json::json!({
        "join_token": state.join_token,
    }))
}

/// GET /api/cluster/verify-token?token=xxx — verify a join token (unauthenticated, called by remote servers)
pub async fn verify_join_token(state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    let provided = query.get("token").map(|s| s.as_str()).unwrap_or("");
    if provided.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing token parameter" }));
    }
    if crate::auth::validate_cluster_secret(provided, &state.join_token) {
        HttpResponse::Ok().json(serde_json::json!({
            "valid": true,
            "hostname": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        }))
    } else {
        HttpResponse::Forbidden().json(serde_json::json!({
            "valid": false,
            "error": "Invalid join token",
        }))
    }
}

// ─── Cluster Secret Management ───

/// GET /api/cluster/secret-status — check whether a custom cluster secret is active
pub async fn cluster_secret_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    // Check the on-disk secret (not just in-memory) so status is correct even before restart
    let active = crate::auth::load_cluster_secret();
    let has_custom = active != crate::auth::default_cluster_secret();
    HttpResponse::Ok().json(serde_json::json!({
        "has_custom_secret": has_custom,
    }))
}

/// POST /api/cluster/secret/generate — generate a new cluster secret and propagate to all nodes
pub async fn cluster_secret_generate(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let new_secret = crate::auth::generate_cluster_secret();
    if let Err(e) = crate::auth::save_cluster_secret(&new_secret) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }

    // Propagate to all online nodes across all clusters
    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut results = Vec::new();
    for node in &nodes {
        if node.is_self || !node.online || node.node_type == "proxmox" {
            continue;
        }
        let urls = build_node_urls(&node.address, node.port, "/api/cluster/secret/receive");
        let mut pushed = false;
        let mut err = String::new();
        for url in &urls {
            match client.post(url)
                .header("X-WolfStack-Secret", crate::auth::default_cluster_secret())
                .json(&serde_json::json!({ "secret": new_secret }))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => { pushed = true; break; }
                Ok(resp) => { err = format!("HTTP {}", resp.status()); }
                Err(e) => { err = format!("{}", e); }
            }
        }
        results.push(serde_json::json!({
            "node": if node.hostname.is_empty() { &node.address } else { &node.hostname },
            "address": node.address,
            "success": pushed,
            "error": if pushed { "" } else { &err },
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "generated": true,
        "nodes": results,
    }))
}

/// POST /api/cluster/secret/repush — re-push the existing custom secret to all nodes
pub async fn cluster_secret_repush(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let active = crate::auth::load_cluster_secret();
    if active == crate::auth::default_cluster_secret() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No custom secret to push — generate one first"
        }));
    }

    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut results = Vec::new();
    for node in &nodes {
        if node.is_self || !node.online || node.node_type == "proxmox" {
            continue;
        }
        let urls = build_node_urls(&node.address, node.port, "/api/cluster/secret/receive");
        let mut pushed = false;
        let mut err = String::new();
        for url in &urls {
            match client.post(url)
                .header("X-WolfStack-Secret", crate::auth::default_cluster_secret())
                .json(&serde_json::json!({ "secret": active }))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => { pushed = true; break; }
                Ok(resp) => { err = format!("HTTP {}", resp.status()); }
                Err(e) => { err = format!("{}", e); }
            }
        }
        results.push(serde_json::json!({
            "node": if node.hostname.is_empty() { &node.address } else { &node.hostname },
            "address": node.address,
            "success": pushed,
            "error": if pushed { "" } else { &err },
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "pushed": true,
        "nodes": results,
    }))
}

/// POST /api/cluster/secret/receive — receive a new cluster secret from admin node
pub async fn cluster_secret_receive(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_cluster_auth(&req, &state) { return resp; }
    let secret = match body.get("secret").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing secret" })),
    };
    if let Err(e) = crate::auth::save_cluster_secret(secret) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    HttpResponse::Ok().json(serde_json::json!({ "saved": true }))
}

/// POST /api/nodes — add a server to the cluster
#[derive(Deserialize)]
pub struct AddServerRequest {
    pub address: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub node_type: Option<String>,       // "wolfstack" (default) or "proxmox"
    #[serde(default)]
    pub join_token: Option<String>,      // Required for WolfStack nodes — validates against remote
    #[serde(default)]
    pub pve_token: Option<String>,       // PVEAPIToken=user@realm!tokenid=uuid
    #[serde(default)]
    pub pve_fingerprint: Option<String>,
    #[serde(default)]
    pub pve_node_name: Option<String>,
    #[serde(default)]
    pub pve_cluster_name: Option<String>, // User-friendly cluster name for sidebar
    #[serde(default)]
    pub cluster_name: Option<String>,     // Generic cluster name for WolfStack nodes
}

pub async fn add_node(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AddServerRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_type = body.node_type.as_deref().unwrap_or("wolfstack");

    if node_type == "proxmox" {
        let port = body.port.unwrap_or(8006);
        let token = body.pve_token.clone().unwrap_or_default();
        let fingerprint = body.pve_fingerprint.clone();
        let pve_node_name = body.pve_node_name.clone().unwrap_or_default();
        let cluster_name = body.pve_cluster_name.clone();

        if token.is_empty() || pve_node_name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Proxmox nodes require pve_token and pve_node_name"
            }));
        }

        // Block duplicate Proxmox nodes — check if this address+port+node_name already exists
        let existing_nodes = state.cluster.get_all_nodes();
        for existing in &existing_nodes {
            if existing.address == body.address && existing.port == port
                && existing.pve_node_name.as_deref() == Some(&pve_node_name)
            {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": format!(
                        "Proxmox node '{}' at {}:{} already exists in the cluster (id: '{}'). \
                         Remove the existing node first if you want to re-add it.",
                        pve_node_name, body.address, port, existing.id
                    )
                }));
            }
        }

        // Try to discover all nodes in the cluster
        let client = crate::proxmox::PveClient::new(&body.address, port, &token, fingerprint.as_deref(), &pve_node_name);
        let discovered = client.discover_nodes().await.unwrap_or_default();

        let mut added_ids = Vec::new();
        let mut added_nodes = Vec::new();
        let mut skipped_nodes = Vec::new();

        if discovered.len() > 1 {
            // Multi-node cluster — add each discovered node (skip duplicates)
            for node_name in &discovered {
                // Skip if this node already exists
                let already_exists = existing_nodes.iter().any(|n|
                    n.address == body.address && n.port == port
                    && n.pve_node_name.as_deref() == Some(node_name)
                );
                if already_exists {
                    skipped_nodes.push(node_name.clone());
                    continue;
                }
                let id = state.cluster.add_proxmox_server(
                    body.address.clone(), port, token.clone(),
                    fingerprint.clone(), node_name.clone(), cluster_name.clone(),
                );

                added_ids.push(id);
                added_nodes.push(node_name.clone());
            }
        } else {
            // Single node or discovery failed — add just the specified node
            let id = state.cluster.add_proxmox_server(
                body.address.clone(), port, token, fingerprint,
                pve_node_name.clone(), cluster_name.clone(),
            );

            added_ids.push(id);
            added_nodes.push(pve_node_name.clone());
        }

        HttpResponse::Ok().json(serde_json::json!({
            "ids": added_ids,
            "address": body.address,
            "port": port,
            "node_type": "proxmox",
            "nodes_discovered": added_nodes,
            "nodes_skipped": skipped_nodes,
            "cluster_name": cluster_name,
        }))
    } else {
        let port = body.port.unwrap_or(8553);
        let cluster_name = body.cluster_name.clone();

        // Validate join token against the remote server
        let join_token = body.join_token.clone().unwrap_or_default();
        if join_token.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Join token is required. Get it from the remote server's dashboard."
            }));
        }

        // Call the remote server to verify the token
        // Try HTTPS on the given port first (accept self-signed certs), then HTTP on port+1 (inter-node port)
        let verify_path = format!("/api/cluster/verify-token?token={}", join_token);
        let urls = vec![
            format!("https://{}:{}{}", body.address, port, verify_path),
            format!("http://{}:{}{}", body.address, port + 1, verify_path),
            format!("http://{}:{}{}", body.address, port, verify_path),
        ];

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build() {
            Ok(c) => c,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("HTTP client error: {}", e)
                }));
            }
        };

        let mut last_error = String::new();
        let mut verified = false;
        for url in &urls {
            match client.get(url).send().await {
                Ok(resp) => {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if data.get("valid").and_then(|v| v.as_bool()) == Some(true) {

                            verified = true;
                            break;
                        } else {
                            let err_msg = data.get("error").and_then(|v| v.as_str()).unwrap_or("Invalid join token");
                            return HttpResponse::Forbidden().json(serde_json::json!({
                                "error": err_msg
                            }));
                        }
                    }
                    // Got a response but couldn't parse — try next URL
                    last_error = format!("Unparseable response from {}", url);
                }
                Err(e) => {
                    last_error = format!("{}", e);
                    // Connection failed — try next URL
                }
            }
        }

        if !verified {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("Cannot reach remote server at {}:{} — {}", body.address, port, last_error)
            }));
        }

        // Check for WolfNet IP conflicts before adding the node.
        // Fetch the remote node's status to get its wolfnet_ips, then compare
        // against all IPs known in this cluster (local + remote via route cache).
        let status_urls = build_node_urls(&body.address, port, "/api/agent/status");
        let cluster_secret = crate::auth::load_cluster_secret();
        let default_secret = crate::auth::default_cluster_secret();
        let mut remote_wolfnet_ips: Vec<String> = Vec::new();
        for url in &status_urls {
            // Try the active cluster secret first, then the default (new node may not have received custom secret yet)
            for secret in [&cluster_secret, &default_secret.to_string()] {
                if let Ok(resp) = client.get(url)
                    .header("X-WolfStack-Secret", secret)
                    .send().await
                {
                    if resp.status().is_success() {
                        if let Ok(data) = resp.json::<serde_json::Value>().await {
                            if let Some(ips) = data.get("wolfnet_ips").and_then(|v| v.as_array()) {
                                remote_wolfnet_ips = ips.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                            }
                        }
                        break;
                    }
                }
            }
            if !remote_wolfnet_ips.is_empty() { break; }
        }

        if !remote_wolfnet_ips.is_empty() {
            // Collect all WolfNet IPs known in this cluster
            let local_ips = containers::wolfnet_used_ips();
            let route_ips: Vec<String> = containers::WOLFNET_ROUTES.lock().unwrap()
                .keys().cloned().collect();

            let mut conflicts = Vec::new();
            for ip in &remote_wolfnet_ips {
                if local_ips.contains(ip) || route_ips.contains(ip) {
                    conflicts.push(ip.clone());
                }
            }
            if !conflicts.is_empty() {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": format!(
                        "Cannot join node: WolfNet IP conflict — {} is already in use in this cluster. \
                         Change the node's IP in /etc/wolfnet/config.toml and restart wolfnet before joining.",
                        conflicts.join(", ")
                    )
                }));
            }
        }

        // Block duplicate nodes — check if a node with this address:port already exists
        let existing_nodes = state.cluster.get_all_nodes();
        for existing in &existing_nodes {
            if existing.address == body.address && existing.port == port {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": format!(
                        "A node at {}:{} already exists in the cluster (hostname: '{}', id: '{}'). \
                         Remove the existing node first if you want to re-add it.",
                        body.address, port, existing.hostname, existing.id
                    )
                }));
            }
        }

        let id = state.cluster.add_server(body.address.clone(), port, cluster_name.clone());

        // If we have a custom cluster secret (on disk), push it to the new node
        let active_secret = crate::auth::load_cluster_secret();
        if active_secret != crate::auth::default_cluster_secret() {
            let addr = body.address.clone();
            let secret = active_secret;
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap_or_default();
                let urls = build_node_urls(&addr, port, "/api/cluster/secret/receive");
                for url in &urls {
                    if let Ok(resp) = client.post(url)
                        .header("X-WolfStack-Secret", crate::auth::default_cluster_secret())
                        .json(&serde_json::json!({ "secret": secret }))
                        .send()
                        .await
                    {
                        if resp.status().is_success() { break; }
                    }
                }
            });
        }

        HttpResponse::Ok().json(serde_json::json!({
            "id": id,
            "address": body.address,
            "port": port,
            "node_type": "wolfstack",
            "cluster_name": cluster_name,
        }))
    }
}

/// DELETE /api/nodes/{id} — remove a server
pub async fn remove_node(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.cluster.remove_server(&id) {
        // Broadcast deletion to all other online nodes so they don't gossip it back
        let nodes = state.cluster.get_all_nodes();
        let secret = state.cluster_secret.clone();
        let delete_id = id.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            for node in &nodes {
                if node.is_self || !node.online { continue; }
                // Try HTTPS first, then HTTP on port+1, then HTTP on main port
                let urls = build_node_urls(&node.address, node.port, &format!("/api/nodes/{}", delete_id));
                for url in &urls {
                    if let Ok(_) = client.delete(url)
                        .header("X-WolfStack-Secret", &secret)
                        .send()
                        .await
                    {
                        break; // Success, no need to try next URL
                    }
                }
            }
        });
        HttpResponse::Ok().json(serde_json::json!({ "removed": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

/// PATCH /api/nodes/{id}/settings — update node settings
#[derive(Deserialize)]
pub struct UpdateNodeSettings {
    pub hostname: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub pve_token: Option<String>,
    pub pve_fingerprint: Option<String>,
    pub pve_cluster_name: Option<String>,
    pub cluster_name: Option<String>,
    pub login_disabled: Option<bool>,
    pub update_script: Option<String>,
}

pub async fn update_node_settings(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateNodeSettings>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let fp = if body.pve_fingerprint.is_some() {
        Some(body.pve_fingerprint.clone())
    } else {
        None
    };

    // Support updating both pve_cluster_name (for compat) and generic cluster_name
    let cluster_name = body.cluster_name.clone().or(body.pve_cluster_name.clone());

    // Capture old cluster name before update so we can migrate data if it changes
    let old_cluster_name = state.cluster.get_node(&id)
        .and_then(|n| n.cluster_name.clone());

    if state.cluster.update_node_settings(
        &id,
        body.hostname.clone(),
        body.address.clone(),
        body.port,
        body.pve_token.clone(),
        fp,
        cluster_name.clone(),
        body.login_disabled,
        body.update_script.clone(),
    ) {
        // If cluster name changed, rename all cluster-scoped data to match.
        // All nodes in the cluster share the same name, so wolfrun services,
        // status pages, monitors, and incidents must all follow the rename.
        if let (Some(old_name), Some(new_name)) = (&old_cluster_name, &cluster_name) {
            if old_name != new_name {
                // Rename status page monitors, pages, and incidents
                let mut config = state.statuspage.config.write().unwrap();
                let sp_count = config.rename_cluster(old_name, new_name);
                if sp_count > 0 {
                    let _ = config.save();
                    tracing::info!("Cluster rename: updated {} status page items '{}' -> '{}'", sp_count, old_name, new_name);
                }
                drop(config);

                // Rename wolfrun services
                let wr_count = state.wolfrun.rename_cluster(old_name, new_name);
                if wr_count > 0 {
                    tracing::info!("Cluster rename: updated {} WolfRun services '{}' -> '{}'", wr_count, old_name, new_name);
                }

                // Rename other nodes in the same cluster so the whole cluster stays together
                for node in state.cluster.get_all_nodes() {
                    if node.cluster_name.as_deref() == Some(old_name.as_str()) {
                        state.cluster.update_node_settings(
                            &node.id, None, None, None, None, None,
                            Some(new_name.clone()), None, None,
                        );
                    }
                }
            }
        }
        // Propagate login_disabled to remote node so it takes effect on their login page
        if let Some(disabled) = body.login_disabled {
            let node = state.cluster.get_node(&id);
            if let Some(node) = node {
                if !node.is_self && node.node_type == "wolfstack" {
                    let secret = state.cluster_secret.clone();
                    let address = node.address.clone();
                    let port = node.port;
                    tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(5))
                            .danger_accept_invalid_certs(true)
                            .build()
                            .unwrap_or_default();
                        let urls = build_node_urls(&address, port, "/api/settings/login-disabled");
                        let payload = serde_json::json!({ "login_disabled": disabled });
                        for url in &urls {
                            if let Ok(_) = client.post(url)
                                .header("X-WolfStack-Secret", &secret)
                                .header("Content-Type", "application/json")
                                .body(payload.to_string())
                                .send()
                                .await
                            {

                                break;
                            }
                        }
                    });
                }
            }
        }
        // Propagate cluster_name to remote WolfStack node so its own reconcile works correctly
        let cluster_name = body.cluster_name.clone().or(body.pve_cluster_name.clone());
        if let Some(ref name) = cluster_name {
            let node = state.cluster.get_node(&id);
            if let Some(node) = node {
                if !node.is_self && node.node_type == "wolfstack" {
                    let secret = state.cluster_secret.clone();
                    let address = node.address.clone();
                    let port = node.port;
                    let cluster_name_val = name.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(5))
                            .danger_accept_invalid_certs(true)
                            .build()
                            .unwrap_or_default();
                        let urls = build_node_urls(&address, port, "/api/agent/cluster-name");
                        let payload = serde_json::json!({ "cluster_name": cluster_name_val });
                        for url in &urls {
                            if client.post(url)
                                .header("X-WolfStack-Secret", &secret)
                                .json(&payload)
                                .send()
                                .await
                                .is_ok()
                            {

                                break;
                            }
                        }
                    });
                }
            }
        }
        HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))
    }
}

/// POST /api/agent/cluster-name — accept cluster name update from admin node
pub async fn agent_set_cluster_name(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    if let Some(name) = body.get("cluster_name").and_then(|v| v.as_str()) {

        let mut nodes = state.cluster.nodes.write().unwrap();
        if let Some(n) = nodes.get_mut(&state.cluster.self_id) {
            n.cluster_name = Some(name.to_string());
        }
        drop(nodes);
        crate::agent::ClusterState::save_self_cluster_name(name);
        HttpResponse::Ok().json(serde_json::json!({ "updated": true, "cluster_name": name }))
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({ "error": "cluster_name required" }))
    }
}

/// POST /api/agent/wolfnet-routes — accept WolfNet route updates from orchestrator
/// Used to push VIP routes to all nodes so they can reach service VIPs via the orchestrator
pub async fn agent_set_wolfnet_routes(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    if let Some(routes) = body.get("routes").and_then(|v| v.as_object()) {
        let mut route_map = std::collections::HashMap::new();
        for (k, v) in routes {
            if let Some(ip) = v.as_str() {
                route_map.insert(k.clone(), ip.to_string());
            }
        }
        let changed = crate::containers::update_wolfnet_routes(&route_map);
        // Also add kernel routes so traffic for VIPs enters the wolfnet tunnel
        for vip in route_map.keys() {
            let _ = std::process::Command::new("ip")
                .args(["route", "replace", &format!("{}/32", vip), "dev", "wolfnet0"])
                .output();
        }

        HttpResponse::Ok().json(serde_json::json!({ "updated": changed, "routes": route_map.len() }))
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({ "error": "routes object required" }))
    }
}

/// POST /api/cluster/wolfnet-sync — ensure all WolfStack nodes in a cluster know about each other's WolfNet peers
#[derive(Deserialize)]
pub struct WolfNetSyncRequest {
    pub node_ids: Vec<String>,
}

pub async fn wolfnet_sync_cluster(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetSyncRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_ids = &body.node_ids;
    if node_ids.len() < 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Need at least 2 nodes to sync"}));
    }

    // Collect WolfNet info from each node
    #[derive(Clone)]
    struct NodeWnInfo {
        hostname: String,
        wolfnet_ip: String,
        public_key: String,
        /// The reachable endpoint (node.address:listen_port) for WolfNet
        endpoint: String,
        is_self: bool,
        address: String,
        port: u16,
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut infos: Vec<NodeWnInfo> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for nid in node_ids {
        let node = match state.cluster.get_node(nid) {
            Some(n) => n,
            None => { errors.push(format!("Node {} not found", nid)); continue; }
        };
        if node.node_type != "wolfstack" {
            errors.push(format!("{} is not a WolfStack node", node.hostname));
            continue;
        }

        if node.is_self {
            // Get local info directly
            match networking::get_wolfnet_local_info() {
                Some(info) => {
                    let hostname = info["hostname"].as_str().unwrap_or("").to_string();
                    let address = info["address"].as_str().unwrap_or("").to_string();
                    let public_key = info["public_key"].as_str().unwrap_or("").to_string();
                    let listen_port = info["listen_port"].as_u64().unwrap_or(9600) as u16;
                    if address.is_empty() || public_key.is_empty() {
                        errors.push(format!("{}: WolfNet not configured", node.hostname));
                        continue;
                    }
                    // Use the node's real address as the endpoint.
                    // If bound to 0.0.0.0 or 127.0.0.1, those aren't routable — use the
                    // public IP (for internet-reachable nodes) or fall back to LAN IP
                    // (for local-only networks).
                    let effective_addr = if node.address == "0.0.0.0" || node.address == "127.0.0.1" {
                        node.public_ip.clone()
                            .or_else(|| networking::detect_lan_ip())
                            .unwrap_or_else(|| node.address.clone())
                    } else {
                        node.address.clone()
                    };
                    let endpoint = format!("{}:{}", effective_addr, listen_port);
                    infos.push(NodeWnInfo {
                        hostname,
                        wolfnet_ip: address,
                        public_key,
                        endpoint,
                        is_self: true,
                        address: effective_addr,
                        port: node.port,
                    });
                }
                None => {
                    errors.push(format!("{}: WolfNet not running", node.hostname));
                }
            }
        } else {
            // Fetch from remote node — try HTTPS first, then HTTP fallback
            let urls = build_node_urls(&node.address, node.port, "/api/networking/wolfnet/local-info");
            let mut fetched = false;
            for url in &urls {
                match client.get(url)
                    .header("X-WolfStack-Secret", &state.cluster_secret)
                    .send().await
                {
                    Ok(resp) => {
                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                            if info.get("error").is_some() {
                                errors.push(format!("{}: {}", node.hostname, info["error"]));
                                fetched = true;
                                break;
                            }
                            let hostname = info["hostname"].as_str().unwrap_or("").to_string();
                            let address = info["address"].as_str().unwrap_or("").to_string();
                            let public_key = info["public_key"].as_str().unwrap_or("").to_string();
                            let listen_port = info["listen_port"].as_u64().unwrap_or(9600) as u16;
                            if address.is_empty() || public_key.is_empty() {
                                errors.push(format!("{}: WolfNet not configured", node.hostname));
                                fetched = true;
                                break;
                            }
                            let endpoint = format!("{}:{}", node.address, listen_port);
                            infos.push(NodeWnInfo {
                                hostname,
                                wolfnet_ip: address,
                                public_key,
                                endpoint,
                                is_self: false,
                                address: node.address.clone(),
                                port: node.port,
                            });
                            fetched = true;
                            break;
                        }
                    }
                    Err(_) => continue, // Try next URL
                }
            }
            if !fetched {
                errors.push(format!("{}: unreachable on all ports/protocols", node.hostname));
            }
        }
    }

    if infos.len() < 2 {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "error",
            "message": "Could not reach enough nodes to sync",
            "errors": errors,
        }));
    }

    // Now tell each node about every other node
    let mut synced = 0u32;
    let mut skipped = 0u32;

    for i in 0..infos.len() {
        let target = &infos[i];
        for j in 0..infos.len() {
            if i == j { continue; }
            let peer = &infos[j];

            if target.is_self {
                // Add peer locally
                match networking::add_wolfnet_peer(
                    &peer.hostname,
                    &peer.endpoint,
                    &peer.wolfnet_ip,
                    Some(&peer.public_key),
                ) {
                    Ok(_) => { synced += 1; }
                    Err(e) => {
                        if e.contains("already exists") {
                            skipped += 1;
                        } else {
                            errors.push(format!("local add {}: {}", peer.hostname, e));
                        }
                    }
                }
            } else {
                // Add peer on remote node — try HTTPS first, then HTTP fallback
                let urls = build_node_urls(&target.address, target.port, "/api/networking/wolfnet/peers");
                let payload = serde_json::json!({
                    "name": peer.hostname,
                    "endpoint": peer.endpoint,
                    "ip": peer.wolfnet_ip,
                    "public_key": peer.public_key,
                });
                let mut posted = false;
                for url in &urls {
                    match client.post(url)
                        .header("X-WolfStack-Secret", &state.cluster_secret)
                        .header("Content-Type", "application/json")
                        .body(payload.to_string())
                        .send().await
                    {
                        Ok(resp) => {
                            if let Ok(data) = resp.json::<serde_json::Value>().await {
                                if data.get("error").is_some() {
                                    let err = data["error"].as_str().unwrap_or("unknown");
                                    if err.contains("already exists") {
                                        skipped += 1;
                                    } else {
                                        errors.push(format!("{} → {}: {}", target.hostname, peer.hostname, err));
                                    }
                                } else {
                                    synced += 1;
                                }
                            }
                            posted = true;
                            break;
                        }
                        Err(_) => continue, // Try next URL
                    }
                }
                if !posted {
                    errors.push(format!("{} → {}: unreachable on all ports/protocols", target.hostname, peer.hostname));
                }
            }
        }
    }



    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "synced": synced,
        "skipped": skipped,
        "nodes_reached": infos.len(),
        "errors": errors,
    }))
}

/// POST /api/cluster/diagnose — manually poll each node and report detailed connectivity info
pub async fn cluster_diagnose(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetSyncRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let node_ids = &body.node_ids;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut results = Vec::new();

    for nid in node_ids {
        let node = match state.cluster.get_node(nid) {
            Some(n) => n,
            None => {
                results.push(serde_json::json!({
                    "node_id": nid,
                    "hostname": "unknown",
                    "address": "",
                    "port": 0,
                    "is_self": false,
                    "wolfstack_api": { "reachable": false, "error": "Node not found in cluster" },
                    "wolfnet": { "reachable": false },
                    "last_seen_ago_secs": null,
                }));
                continue;
            }
        };

        let last_seen_ago = if node.last_seen > 0 { Some(now.saturating_sub(node.last_seen)) } else { None };

        if node.is_self {
            results.push(serde_json::json!({
                "node_id": node.id,
                "hostname": node.hostname,
                "address": node.address,
                "port": node.port,
                "is_self": true,
                "wolfstack_api": {
                    "reachable": true,
                    "url_used": "localhost (self)",
                    "status_code": 200,
                    "latency_ms": 0,
                    "error": null,
                },
                "wolfnet": {
                    "ip": "self",
                    "reachable": true,
                    "latency_ms": 0,
                },
                "last_seen_ago_secs": 0,
            }));
            continue;
        }

        // Try HTTP on port+1 first (inter-node), then HTTPS on main port, then HTTP on main port
        let urls = vec![
            format!("http://{}:{}/api/agent/status", node.address, node.port + 1),
            format!("https://{}:{}/api/agent/status", node.address, node.port),
            format!("http://{}:{}/api/agent/status", node.address, node.port),
        ];

        let mut api_result = serde_json::json!({
            "reachable": false,
            "url_used": null,
            "status_code": null,
            "latency_ms": null,
            "error": "Could not reach node on any port/protocol",
        });

        for url in &urls {
            let start = std::time::Instant::now();
            match client.get(url)
                .header("X-WolfStack-Secret", &state.cluster_secret)
                .send().await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let latency = start.elapsed().as_millis() as u64;
                    let body_text = resp.text().await.unwrap_or_default();

                    // Try to parse as AgentMessage
                    let is_valid = serde_json::from_str::<serde_json::Value>(&body_text)
                        .map(|v| v.get("StatusReport").is_some() || v.get("hostname").is_some())
                        .unwrap_or(false);

                    if status == 200 && (is_valid || body_text.contains("hostname")) {
                        api_result = serde_json::json!({
                            "reachable": true,
                            "url_used": url,
                            "status_code": status,
                            "latency_ms": latency,
                            "error": null,
                        });
                        break;
                    } else {
                        // Got a response but not the expected one
                        let snippet = if body_text.len() > 100 { &body_text[..100] } else { &body_text };
                        api_result = serde_json::json!({
                            "reachable": false,
                            "url_used": url,
                            "status_code": status,
                            "latency_ms": latency,
                            "error": format!("HTTP {}: {}", status, snippet.trim()),
                        });
                        // Don't break — try the other port
                    }
                }
                Err(e) => {
                    let latency = start.elapsed().as_millis() as u64;
                    let err_str = format!("{}", e);
                    // Only update if we haven't gotten a better result
                    if api_result.get("status_code").and_then(|v| v.as_u64()).is_none() {
                        api_result = serde_json::json!({
                            "reachable": false,
                            "url_used": url,
                            "status_code": null,
                            "latency_ms": latency,
                            "error": err_str,
                        });
                    }
                }
            }
        }

        // Check WolfNet connectivity by pinging the node's WolfNet IP
        let wolfnet_result = {
            // Get WolfNet peers to find this node's WolfNet IP
            let peers = networking::get_wolfnet_peers_list();
            let wolfnet_ip = peers.iter()
                .find(|p| p.name.contains(&node.hostname) || node.hostname.contains(&p.name))
                .map(|p| p.ip.clone());

            if let Some(ref ip) = wolfnet_ip {
                // Quick ping test (1 packet, 2s timeout)
                let start = std::time::Instant::now();
                let ping_ok = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "2", ip])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                let latency = start.elapsed().as_millis() as u64;
                let ping_latency: Option<u64> = if ping_ok { Some(latency) } else { None };

                serde_json::json!({
                    "ip": ip,
                    "reachable": ping_ok,
                    "latency_ms": ping_latency,
                })
            } else {
                serde_json::json!({
                    "ip": serde_json::Value::Null,
                    "reachable": false,
                    "latency_ms": serde_json::Value::Null,
                })
            }
        };

        results.push(serde_json::json!({
            "node_id": node.id,
            "hostname": node.hostname,
            "address": node.address,
            "port": node.port,
            "is_self": false,
            "wolfstack_api": api_result,
            "wolfnet": wolfnet_result,
            "last_seen_ago_secs": last_seen_ago,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "results": results }))
}

/// GET /api/nodes/{id}/pve/resources — list VMs and containers on a Proxmox node
pub async fn get_pve_resources(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);
    match client.list_all_guests().await {
        Ok(guests) => HttpResponse::Ok().json(guests),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/nodes/{id}/pve/{vmid}/{action} — start/stop/restart a Proxmox guest
pub async fn pve_guest_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, vmid_str, action) = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" })),
    };

    // Validate action
    if !["start", "stop", "shutdown", "reboot", "suspend", "resume"].contains(&action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid action. Use: start, stop, shutdown, reboot, suspend, resume" }));
    }

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);

    // Determine guest type by listing all and finding the VMID
    let guests = client.list_all_guests().await.unwrap_or_default();
    let guest_type = guests.iter()
        .find(|g| g.vmid == vmid)
        .map(|g| g.guest_type.clone())
        .unwrap_or_else(|| "qemu".to_string()); // default to qemu

    match client.guest_action(vmid, &guest_type, &action).await {
        Ok(upid) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "upid": upid,
            "vmid": vmid,
            "action": action
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/nodes/{id}/pve/test — test Proxmox API connection
pub async fn pve_test_connection(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let node = match state.cluster.get_node(&id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" })),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" })),
    };

    let token = node.pve_token.unwrap_or_default();
    let pve_name = node.pve_node_name.unwrap_or_default();
    let fp = node.pve_fingerprint.as_deref();

    let client = crate::proxmox::PveClient::new(&node.address, node.port, &token, fp, &pve_name);
    match client.test_connection().await {
        Ok(version) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "version": version,
            "node_name": pve_name
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Components API ───

/// GET /api/components — status of all components on this node
pub async fn get_components(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let status = installer::get_all_status();
    HttpResponse::Ok().json(status)
}

/// GET /api/components/{name}/detail — detailed component info with config and logs
pub async fn get_component_detail(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    let component = match name.to_lowercase().as_str() {
        "wolfnet" => installer::Component::WolfNet,
        "wolfproxy" => installer::Component::WolfProxy,
        "wolfserve" => installer::Component::WolfServe,
        "wolfdisk" => installer::Component::WolfDisk,
        "wolfscale" => installer::Component::WolfScale,
        "mariadb" => installer::Component::MariaDB,
        "postgresql" => installer::Component::PostgreSQL,
        "certbot" => installer::Component::Certbot,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unknown component: {}", name)
        })),
    };

    // Get service status
    let (installed, running, enabled) = installer::check_service(component.service_name());

    // Get config file contents
    let config_path = component.config_path();
    let config_content = if let Some(path) = config_path {
        std::fs::read_to_string(path).ok()
    } else {
        None
    };

    // Get recent journal logs
    let logs = get_service_logs(component.service_name(), 50);

    // Get systemd unit info
    let unit_info = get_unit_info(component.service_name());

    HttpResponse::Ok().json(serde_json::json!({
        "name": component.name(),
        "service": component.service_name(),
        "description": component.description(),
        "installed": installed,
        "running": running,
        "enabled": enabled,
        "config_path": config_path,
        "config": config_content,
        "logs": logs,
        "unit_info": unit_info,
    }))
}

/// PUT /api/components/{name}/config — save component config
#[derive(Deserialize)]
pub struct SaveConfigRequest {
    pub content: String,
}

pub async fn save_component_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SaveConfigRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    let component = match name.to_lowercase().as_str() {
        "wolfnet" => installer::Component::WolfNet,
        "wolfproxy" => installer::Component::WolfProxy,
        "wolfserve" => installer::Component::WolfServe,
        "wolfdisk" => installer::Component::WolfDisk,
        "wolfscale" => installer::Component::WolfScale,
        "mariadb" => installer::Component::MariaDB,
        "postgresql" => installer::Component::PostgreSQL,
        "certbot" => installer::Component::Certbot,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unknown component: {}", name)
        })),
    };

    let config_path = match component.config_path() {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This component has no config file"
        })),
    };

    match std::fs::write(config_path, &body.content) {
        Ok(_) => {

            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Config saved. Restart {} to apply changes.", component.service_name())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save config: {}", e)
        })),
    }
}

/// POST /api/components/{name}/install — install a component
pub async fn install_component(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let component = match name.to_lowercase().as_str() {
        "wolfnet" => installer::Component::WolfNet,
        "wolfproxy" => installer::Component::WolfProxy,
        "wolfserve" => installer::Component::WolfServe,
        "wolfdisk" => installer::Component::WolfDisk,
        "wolfscale" => installer::Component::WolfScale,
        "mariadb" => installer::Component::MariaDB,
        "postgresql" => installer::Component::PostgreSQL,
        "certbot" => installer::Component::Certbot,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unknown component: {}", name)
        })),
    };

    match installer::install_component(component) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Service Control API ───

#[derive(Deserialize)]
pub struct ServiceActionRequest {
    pub action: String,  // start, stop, restart
}

/// POST /api/services/{name}/action — start/stop/restart a service
pub async fn service_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ServiceActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let service = path.into_inner();
    let result = match body.action.as_str() {
        "start" => installer::start_service(&service),
        "stop" => installer::stop_service(&service),
        "restart" => installer::restart_service(&service),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Cron Job Management API ───

#[derive(Deserialize)]
pub struct CronJobRequest {
    pub schedule: String,
    pub command: String,
    #[serde(default)]
    pub comment: String,
    pub index: Option<usize>,
    #[serde(default = "cron_enabled_default")]
    pub enabled: bool,
}

fn cron_enabled_default() -> bool { true }

#[derive(serde::Serialize)]
struct CronEntry {
    index: usize,
    schedule: String,
    command: String,
    comment: String,
    human: String,
    enabled: bool,
    raw: String,
}

fn humanize_schedule(schedule: &str) -> String {
    match schedule.trim() {
        "@reboot" => "On reboot".to_string(),
        "@hourly" => "Every hour".to_string(),
        "@daily" | "@midnight" => "Every day (midnight)".to_string(),
        "@weekly" => "Every week".to_string(),
        "@monthly" => "Every month".to_string(),
        "@yearly" | "@annually" => "Every year".to_string(),
        s => {
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.len() != 5 { return s.to_string(); }
            let (min, hour, dom, mon, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
            // Common patterns
            if s == "* * * * *" { return "Every minute".to_string(); }
            if min.starts_with("*/") && hour == "*" && dom == "*" && mon == "*" && dow == "*" {
                let n = &min[2..];
                return format!("Every {} minutes", n);
            }
            if min != "*" && hour == "*" && dom == "*" && mon == "*" && dow == "*" {
                return format!("Hourly at :{}", min);
            }
            if min != "*" && hour != "*" && dom == "*" && mon == "*" && dow == "*" {
                return format!("Daily at {}:{}", hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            if min != "*" && hour != "*" && dom == "*" && mon == "*" && dow != "*" {
                let day = match dow {
                    "0" | "7" => "Sunday", "1" => "Monday", "2" => "Tuesday",
                    "3" => "Wednesday", "4" => "Thursday", "5" => "Friday", "6" => "Saturday",
                    _ => dow,
                };
                return format!("Every {} at {}:{}", day, hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            if min != "*" && hour != "*" && dom != "*" && mon == "*" && dow == "*" {
                return format!("Monthly on day {} at {}:{}", dom, hour, if min.len() == 1 { format!("0{}", min) } else { min.to_string() });
            }
            s.to_string()
        }
    }
}

fn parse_crontab_line(line: &str, index: usize) -> Option<CronEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() { return None; }

    // Check for disabled entries
    if trimmed.starts_with("# DISABLED: ") {
        let rest = &trimmed["# DISABLED: ".len()..];
        if let Some(entry) = parse_cron_expression(rest, index) {
            return Some(CronEntry { enabled: false, ..entry });
        }
        return None;
    }

    // Skip pure comments
    if trimmed.starts_with('#') { return None; }

    parse_cron_expression(trimmed, index)
}

fn parse_cron_expression(line: &str, index: usize) -> Option<CronEntry> {
    let trimmed = line.trim();
    // Handle @reboot, @hourly, etc.
    if trimmed.starts_with('@') {
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 { return None; }
        let schedule = parts[0].to_string();
        let rest = parts[1].trim();
        let (command, comment) = extract_inline_comment(rest);
        return Some(CronEntry {
            human: humanize_schedule(&schedule),
            index, schedule, command, comment, enabled: true, raw: line.to_string(),
        });
    }

    // Standard 5-field cron
    let parts: Vec<&str> = trimmed.splitn(6, char::is_whitespace).collect();
    if parts.len() < 6 { return None; }
    let schedule = parts[..5].join(" ");
    let rest = parts[5].trim();
    let (command, comment) = extract_inline_comment(rest);
    Some(CronEntry {
        human: humanize_schedule(&schedule),
        index, schedule, command, comment, enabled: true, raw: line.to_string(),
    })
}

fn extract_inline_comment(s: &str) -> (String, String) {
    // Look for # comment at end (not inside quotes)
    if let Some(pos) = s.rfind(" # ") {
        (s[..pos].trim().to_string(), s[pos+3..].trim().to_string())
    } else {
        (s.trim().to_string(), String::new())
    }
}

fn read_crontab() -> (Vec<String>, String) {
    let output = std::process::Command::new("crontab")
        .arg("-l")
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout).to_string();
            let lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
            (lines, raw)
        }
        _ => (vec![], String::new()),
    }
}

fn write_crontab(lines: &[String]) -> Result<(), String> {
    let content = lines.join("\n") + "\n";
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn crontab: {}", e))?;
    use std::io::Write;
    child.stdin.as_mut().unwrap()
        .write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write crontab: {}", e))?;
    let status = child.wait().map_err(|e| format!("crontab error: {}", e))?;
    if status.success() { Ok(()) } else { Err("crontab exited with error".to_string()) }
}

/// GET /api/cron — list cron entries
pub async fn cron_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (lines, raw) = read_crontab();
    let entries: Vec<CronEntry> = lines.iter().enumerate()
        .filter_map(|(i, line)| parse_crontab_line(line, i))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "entries": entries, "raw": raw }))
}

/// POST /api/cron — add or edit a cron entry
pub async fn cron_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CronJobRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (mut lines, _) = read_crontab();
    let comment_suffix = if body.comment.is_empty() { String::new() } else { format!(" # {}", body.comment) };
    let new_line = if body.enabled {
        format!("{} {}{}", body.schedule, body.command, comment_suffix)
    } else {
        format!("# DISABLED: {} {}{}", body.schedule, body.command, comment_suffix)
    };

    if let Some(idx) = body.index {
        if idx < lines.len() {
            lines[idx] = new_line;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
        }
    } else {
        lines.push(new_line);
    }

    match write_crontab(&lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/cron/{index} — remove a cron entry by line index
pub async fn cron_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<usize>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let idx = path.into_inner();
    let (mut lines, _) = read_crontab();
    if idx >= lines.len() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
    }
    lines.remove(idx);
    match write_crontab(&lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Container Cron Job Management ───

/// Build a Command to exec inside a container (docker or lxc).
fn container_exec_cmd(runtime: &str, container: &str, cmd_args: &[&str]) -> std::process::Command {
    if runtime == "docker" {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("exec").arg(container);
        for a in cmd_args { cmd.arg(a); }
        cmd
    } else {
        lxc_exec_cmd(container, cmd_args)
    }
}

/// Build a Command with stdin piped for writing into a container.
fn container_exec_cmd_stdin(runtime: &str, container: &str, cmd_args: &[&str]) -> std::process::Command {
    if runtime == "docker" {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("exec").arg("-i").arg(container);
        for a in cmd_args { cmd.arg(a); }
        cmd.stdin(std::process::Stdio::piped());
        cmd
    } else {
        let mut cmd = lxc_exec_cmd(container, cmd_args);
        cmd.stdin(std::process::Stdio::piped());
        cmd
    }
}

fn read_container_crontab(runtime: &str, container: &str) -> (Vec<String>, String) {
    let output = container_exec_cmd(runtime, container, &["crontab", "-l"]).output();
    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout).to_string();
            let lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
            (lines, raw)
        }
        _ => (vec![], String::new()),
    }
}

fn write_container_crontab(runtime: &str, container: &str, lines: &[String]) -> Result<(), String> {
    let content = lines.join("\n") + "\n";
    let mut child = container_exec_cmd_stdin(runtime, container, &["crontab", "-"])
        .spawn()
        .map_err(|e| format!("Failed to spawn crontab in container: {}", e))?;
    use std::io::Write;
    child.stdin.as_mut().unwrap()
        .write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write crontab: {}", e))?;
    let status = child.wait().map_err(|e| format!("crontab error: {}", e))?;
    if status.success() { Ok(()) } else { Err("crontab in container exited with error".to_string()) }
}

/// GET /api/containers/{runtime}/{id}/cron — list cron entries inside a container
pub async fn container_cron_list(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container) = path.into_inner();
    let (lines, raw) = read_container_crontab(&runtime, &container);
    let entries: Vec<CronEntry> = lines.iter().enumerate()
        .filter_map(|(i, line)| parse_crontab_line(line, i))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "entries": entries, "raw": raw }))
}

/// POST /api/containers/{runtime}/{id}/cron — add or edit a cron entry inside a container
pub async fn container_cron_save(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<CronJobRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container) = path.into_inner();
    let (mut lines, _) = read_container_crontab(&runtime, &container);
    let comment_suffix = if body.comment.is_empty() { String::new() } else { format!(" # {}", body.comment) };
    let new_line = if body.enabled {
        format!("{} {}{}", body.schedule, body.command, comment_suffix)
    } else {
        format!("# DISABLED: {} {}{}", body.schedule, body.command, comment_suffix)
    };

    if let Some(idx) = body.index {
        if idx < lines.len() {
            lines[idx] = new_line;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
        }
    } else {
        lines.push(new_line);
    }

    match write_container_crontab(&runtime, &container, &lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/containers/{runtime}/{id}/cron/{index} — remove a cron entry from a container
pub async fn container_cron_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String, usize)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container, idx) = path.into_inner();
    let (mut lines, _) = read_container_crontab(&runtime, &container);
    if idx >= lines.len() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Index out of range" }));
    }
    lines.remove(idx);
    match write_container_crontab(&runtime, &container, &lines) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "status": "deleted" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Container Update Checking ───

/// Detect which package manager is available inside a container.
/// Uses `command -v` (POSIX shell built-in) instead of `which` for compatibility
/// with minimal containers (e.g. AlmaLinux) that don't ship `which`.
fn detect_container_pkg_manager(runtime: &str, container: &str) -> &'static str {
    for pm in &["apt", "dnf", "yum", "pacman", "apk"] {
        let check = format!("command -v {} >/dev/null 2>&1 && echo found", pm);
        let out = container_exec_cmd(runtime, container, &["sh", "-c", &check]).output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if o.status.success() && stdout.trim() == "found" { return pm; }
        }
    }
    "unknown"
}

/// Quick update count check for a container (uses cached package data, no refresh).
fn quick_container_update_count(runtime: &str, container: &str) -> (String, usize) {
    let pm = detect_container_pkg_manager(runtime, container);
    let cmd = match pm {
        "apt"    => "apt list --upgradable 2>/dev/null | grep -v '^Listing' | grep -c .",
        "dnf"    => "dnf check-update --quiet 2>/dev/null | grep -c '^\\S'",
        "yum"    => "yum check-update --quiet 2>/dev/null | grep -c '^\\S'",
        "pacman" => "pacman -Qu 2>/dev/null | grep -c .",
        "apk"    => "apk version -l '<' 2>/dev/null | grep -c .",
        _ => return (pm.to_string(), 0),
    };
    let out = container_exec_cmd(runtime, container, &["sh", "-c", cmd]).output();
    let count = out.ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<usize>().unwrap_or(0))
        .unwrap_or(0);
    (pm.to_string(), count)
}

/// POST /api/containers/updates/summary — quick update count for all running containers
pub async fn container_updates_summary(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let docker = containers::docker_list_all();
    let lxc = containers::lxc_list_all();

    // Collect running containers to check
    let running: Vec<(String, String)> = docker.iter().chain(lxc.iter())
        .filter(|c| c.state == "running")
        .map(|c| (c.runtime.clone(), c.name.clone()))
        .collect();

    // Check all containers in parallel using thread::scope
    let results_vec: Vec<(String, String, usize)> = std::thread::scope(|s| {
        let handles: Vec<_> = running.iter().map(|(runtime, name)| {
            let runtime = runtime.clone();
            let name = name.clone();
            s.spawn(move || {
                let (pm, count) = quick_container_update_count(&runtime, &name);
                (format!("{}:{}", runtime, name), pm, count)
            })
        }).collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut results = serde_json::Map::new();
    for (key, pm, count) in results_vec {
        results.insert(key, serde_json::json!({ "package_manager": pm, "count": count }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "containers": results }))
}

/// POST /api/containers/{runtime}/{id}/updates/check — check for updates inside a container
pub async fn container_updates_check(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container) = path.into_inner();
    let pkg_manager = detect_container_pkg_manager(&runtime, &container);

    let output = match pkg_manager {
        "apt" => {
            let _ = container_exec_cmd(&runtime, &container, &["sh", "-c", "apt-get update -qq 2>/dev/null"]).output();
            container_exec_cmd(&runtime, &container, &["sh", "-c", "apt list --upgradable 2>/dev/null | grep -v '^Listing'"])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        }
        "dnf" => {
            container_exec_cmd(&runtime, &container, &["sh", "-c", "dnf check-update --quiet 2>/dev/null"])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        }
        "yum" => {
            container_exec_cmd(&runtime, &container, &["sh", "-c", "yum check-update --quiet 2>/dev/null"])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        }
        "pacman" => {
            let _ = container_exec_cmd(&runtime, &container, &["sh", "-c", "pacman -Sy 2>/dev/null"]).output();
            container_exec_cmd(&runtime, &container, &["sh", "-c", "pacman -Qu 2>/dev/null"])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        }
        "apk" => {
            let _ = container_exec_cmd(&runtime, &container, &["sh", "-c", "apk update 2>/dev/null"]).output();
            container_exec_cmd(&runtime, &container, &["sh", "-c", "apk version -l '<' 2>/dev/null"])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
        }
        _ => String::new(),
    };

    let count = output.lines().filter(|l| !l.trim().is_empty()).count();
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "package_manager": pkg_manager,
        "count": count,
        "list": output.trim(),
    }))
}

/// POST /api/containers/{runtime}/{id}/updates/apply — apply updates inside a container
pub async fn container_updates_apply(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container) = path.into_inner();
    let pkg_manager = detect_container_pkg_manager(&runtime, &container);

    let cmd = match pkg_manager {
        "apt" => "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1",
        "dnf" => "dnf upgrade -y 2>&1",
        "yum" => "yum update -y 2>&1",
        "pacman" => "pacman -Syu --noconfirm 2>&1",
        "apk" => "apk upgrade 2>&1",
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "No supported package manager found in container" })),
    };

    let output = container_exec_cmd(&runtime, &container, &["sh", "-c", cmd]).output();
    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            let combined = if err.is_empty() { out } else { format!("{}\n{}", out, err) };
            if o.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": combined.trim() }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({ "error": combined.trim() }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to execute: {}", e) })),
    }
}

/// POST /api/containers/{runtime}/{id}/exec — run a command inside a container
pub async fn container_exec(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (runtime, container) = path.into_inner();
    let cmd = body["command"].as_str().unwrap_or("");
    if cmd.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No command provided"}));
    }

    let output = container_exec_cmd(&runtime, &container, &["sh", "-c", cmd]).output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "ok": o.status.success(),
                "exit_code": o.status.code(),
                "stdout": stdout,
                "stderr": stderr,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed: {}", e)})),
    }
}

// ─── Certbot API ───

#[derive(Deserialize)]
pub struct CertRequest {
    pub domain: String,
    pub email: String,
}

/// POST /api/certificates — request a certificate
pub async fn request_certificate(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CertRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match installer::request_certificate(&body.domain, &body.email) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/certificates/list — list installed certificates
pub async fn list_certificates(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    // Use the exact same discovery as startup (find_tls_certificate)
    let certs = installer::list_certificates();
    HttpResponse::Ok().json(certs)
}

// ─── Agent API (server-to-server, no auth required) ───

/// GET /api/agent/status — return this node's status (for remote polling)
/// Uses pre-cached data from the 2-second background task for instant responses.
pub async fn agent_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }

    // Return cached status if available (sub-millisecond response)
    if let Ok(cache) = state.cached_status.read() {
        if let Some(ref json) = *cache {
            return HttpResponse::Ok().json(json);
        }
    }

    // Fallback: first request before cache is populated (only happens once at startup)
    let st = state.clone().into_inner();
    let (metrics, components, docker_count, lxc_count, vm_count, has_docker, has_lxc, has_kvm) =
        tokio::task::spawn_blocking(move || {
            let m = st.monitor.lock().unwrap().collect();
            let c = installer::get_all_status();
            let dc = containers::docker_list_all().len() as u32;
            let lc = containers::lxc_list_all().len() as u32;
            let vc = st.vms.lock().unwrap().list_vms().len() as u32;
            let hd = containers::docker_status().installed;
            let hl = containers::lxc_status().installed;
            let hk = containers::kvm_installed();
            (m, c, dc, lc, vc, hd, hl, hk)
        }).await.unwrap();
    let hostname = metrics.hostname.clone();
    let public_ip = state.cluster.get_node(&state.cluster.self_id).and_then(|n| n.public_ip);
    let msg = AgentMessage::StatusReport {
        node_id: state.cluster.self_id.clone(),
        hostname,
        metrics,
        components,
        docker_count,
        lxc_count,
        vm_count,
        public_ip,
        known_nodes: state.cluster.get_all_nodes(),
        deleted_ids: state.cluster.get_deleted_ids(),
        wolfnet_ips: containers::wolfnet_used_ips(),
        has_docker,
        has_lxc,
        has_kvm,
        license_key: if crate::compat::platform_ready() {
            std::fs::read_to_string(crate::compat::dm_path()).ok().map(|s| s.trim().to_string())
        } else { None },
    };
    HttpResponse::Ok().json(msg)
}

/// POST /api/install/{tech} — install Docker, LXC, or KVM on this node
pub async fn install_runtime(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let tech = path.into_inner().to_lowercase();

    // Detect distro for package manager
    let distro = installer::detect_distro();
    let (pm, install_flag) = installer::pkg_install_cmd(distro);

    let packages = match tech.as_str() {
        "docker" => {
            // Use Docker's install script for best compatibility
            let result = std::process::Command::new("bash")
                .args(["-c", "curl -fsSL https://get.docker.com | sh"])
                .output();
            match result {
                Ok(o) if o.status.success() => {
                    // Enable and start Docker
                    let _ = std::process::Command::new("systemctl").args(["enable", "--now", "docker"]).output();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "message": "Docker installed and started successfully"
                    }));
                }
                Ok(o) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Docker install failed: {}", String::from_utf8_lossy(&o.stderr))
                    }));
                }
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to run Docker installer: {}", e)
                    }));
                }
            }
        }
        "lxc" => match distro {
            installer::DistroFamily::Debian => "lxc lxc-templates",
            installer::DistroFamily::RedHat => "lxc lxc-templates lxc-extra",
            installer::DistroFamily::Suse => "lxc",
            installer::DistroFamily::Arch => "lxc",
            _ => "lxc",
        },
        "kvm" => match distro {
            installer::DistroFamily::Debian => "qemu-system-x86 qemu-utils libvirt-daemon-system virtinst ovmf",
            installer::DistroFamily::RedHat => "qemu-kvm libvirt virt-install",
            installer::DistroFamily::Suse => "qemu-kvm libvirt virt-install",
            installer::DistroFamily::Arch => "qemu-full libvirt virt-install edk2-ovmf",
            _ => "qemu-system-x86",
        },
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown technology: {}. Use docker, lxc, or kvm.", tech)
            }));
        }
    };

    // Run package install
    let cmd = format!("{} {} {}", pm, install_flag, packages);
    let result = std::process::Command::new("bash")
        .args(["-c", &cmd])
        .output();

    match result {
        Ok(o) if o.status.success() => {
            // Post-install actions
            if tech == "lxc" {
                containers::ensure_lxc_bridge();
            } else if tech == "kvm" {
                let _ = std::process::Command::new("systemctl").args(["enable", "--now", "libvirtd"]).output();
            }
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("{} installed successfully", tech)
            }))
        }
        Ok(o) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Install failed: {}", String::from_utf8_lossy(&o.stderr))
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to run installer: {}", e)
        })),
    }
}

/// GET /api/geolocate?ip={address} — server-side geolocation proxy
/// Proxies requests to ip-api.com because their free tier is HTTP-only,
/// and browsers block HTTP requests from HTTPS pages (mixed content).
/// Also resolves domain names to IPs before lookup.
pub async fn geolocate(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let ip_or_host = match query.get("ip") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing ip parameter" })),
    };

    // If it's a domain name (not an IP), resolve it to an IP first
    let ip = if ip_or_host.parse::<std::net::IpAddr>().is_ok() {
        ip_or_host
    } else {
        // DNS lookup
        match tokio::net::lookup_host(format!("{}:0", ip_or_host)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    addr.ip().to_string()
                } else {
                    return HttpResponse::Ok().json(serde_json::json!({
                        "status": "fail",
                        "message": "DNS resolution returned no addresses",
                        "query": ip_or_host
                    }));
                }
            }
            Err(e) => {
                return HttpResponse::Ok().json(serde_json::json!({
                    "status": "fail",
                    "message": format!("DNS resolution failed: {}", e),
                    "query": ip_or_host
                }));
            }
        }
    };

    // Call ip-api.com server-side (HTTP is fine from backend)
    let url = format!("http://ip-api.com/json/{}", ip);
    match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => {
            match client.get(&url).send().await {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => HttpResponse::Ok().json(data),
                        Err(e) => HttpResponse::Ok().json(serde_json::json!({
                            "status": "fail",
                            "message": format!("Failed to parse response: {}", e),
                            "query": ip
                        })),
                    }
                }
                Err(e) => HttpResponse::Ok().json(serde_json::json!({
                    "status": "fail",
                    "message": format!("Request failed: {}", e),
                    "query": ip
                })),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("HTTP client error: {}", e)
        })),
    }
}

/// GET/POST /api/nodes/{id}/proxy/{path:.*} — proxy API calls to a remote node
pub async fn node_proxy(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Bytes,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let (node_id, api_path) = path.into_inner();

    // Find the node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Node not found"})),
    };

    // If it's the local node, tell frontend to use local API
    if node.is_self {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Use local API for self node"}));
    }

    let method = req.method().clone();
    let content_type = req.headers().get("content-type").and_then(|ct| ct.to_str().ok()).unwrap_or("application/json").to_string();
    let body_vec = body.to_vec();

    // Build URLs to try in order (security-first):
    // 1. HTTPS on the main port — preferred, encrypted end-to-end
    // 2. HTTP on internal port (port + 1) — only exists when TLS is on main port,
    //    accessible only via WolfNet (encrypted tunnel) so still secure
    // 3. HTTP on the main port — last resort (dev/local only)
    let internal_port = node.port + 1;
    let qs = req.query_string();
    let query_suffix = if qs.is_empty() { String::new() } else { format!("?{}", qs) };
    let urls = vec![
        format!("https://{}:{}/api/{}{}", node.address, node.port, api_path, query_suffix),
        format!("http://{}:{}/api/{}{}", node.address, internal_port, api_path, query_suffix),
        format!("http://{}:{}/api/{}{}", node.address, node.port, api_path, query_suffix),
    ];

    let timeout_secs = if method == actix_web::http::Method::POST || method == actix_web::http::Method::PUT { 300 } else { 120 };

    // Build a client that accepts self-signed certificates (inter-node traffic)
    // Short connect_timeout so failed URL schemes fail fast without blocking
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("HTTP client error: {}", e)})),
    };

    let mut last_error = String::new();

    for url in &urls {
        let mut builder = match method {
            actix_web::http::Method::GET => client.get(url),
            actix_web::http::Method::POST => client.post(url),
            actix_web::http::Method::PUT => client.put(url),
            actix_web::http::Method::DELETE => client.delete(url),
            actix_web::http::Method::PATCH => client.patch(url),
            _ => client.get(url),
        };

        builder = builder.header("content-type", &content_type);
        builder = builder.header("X-WolfStack-Secret", state.cluster_secret.clone());
        if !body_vec.is_empty() {
            builder = builder.body(body_vec.clone());
        }

        match builder.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/json")
                    .to_string();

                // Stream SSE responses through without buffering
                if resp_ct.contains("text/event-stream") {
                    use futures::StreamExt;
                    let byte_stream = resp.bytes_stream().map(|chunk| -> Result<actix_web::web::Bytes, actix_web::Error> {
                        match chunk {
                            Ok(b) => Ok(actix_web::web::Bytes::copy_from_slice(&b)),
                            Err(e) => Err(actix_web::error::ErrorBadGateway(e.to_string())),
                        }
                    });
                    return HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK))
                        .insert_header(("Content-Type", "text/event-stream"))
                        .insert_header(("Cache-Control", "no-cache"))
                        .insert_header(("Connection", "keep-alive"))
                        .insert_header(("X-Accel-Buffering", "no"))
                        .streaming(byte_stream);
                }

                match resp.bytes().await {
                    Ok(bytes) => {
                        return HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK))
                            .content_type(resp_ct)
                            .body(bytes.to_vec());
                    }
                    Err(e) => {
                        last_error = format!("Read error from {}: {}", url, e);
                    }
                }
            }
            Err(e) => {
                last_error = format!("{}: {}", url, e);
                // Try next URL
                continue;
            }
        }
    }

    // All URLs failed
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Could not reach node {} ({}:{}). Tried HTTP/HTTPS on ports {}/{} — last error: {}",
            node.hostname, node.address, node.port, internal_port, node.port, last_error)
    }))
}

// ─── Helpers ───

/// Get recent journal logs for a service
fn get_service_logs(service: &str, lines: u32) -> Vec<String> {
    Command::new("journalctl")
        .args(["-u", service, "--no-pager", "-n", &lines.to_string(), "--output", "short-iso"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Get systemd unit info
fn get_unit_info(service: &str) -> serde_json::Value {
    let get_prop = |prop: &str| -> String {
        Command::new("systemctl")
            .args(["show", service, "-p", prop, "--value"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    serde_json::json!({
        "active_state": get_prop("ActiveState"),
        "sub_state": get_prop("SubState"),
        "load_state": get_prop("LoadState"),
        "main_pid": get_prop("MainPID"),
        "memory_current": get_prop("MemoryCurrent"),
        "cpu_usage": get_prop("CPUUsageNSec"),
        "restart_count": get_prop("NRestarts"),
        "active_enter": get_prop("ActiveEnterTimestamp"),
        "description": get_prop("Description"),
    })
}

// ─── Containers API ───

/// GET /api/containers/status — get Docker and LXC runtime status
pub async fn container_runtime_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let docker = containers::docker_status();
    let lxc = containers::lxc_status();
    HttpResponse::Ok().json(serde_json::json!({
        "docker": docker,
        "lxc": lxc,
    }))
}

/// GET /api/containers/docker — list all Docker containers
pub async fn docker_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::docker_list_all_cached();
    HttpResponse::Ok().json(containers)
}

/// GET /api/containers/docker/search?q=<query> — search Docker Hub
pub async fn docker_search(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let q = query.get("q").cloned().unwrap_or_default();
    if q.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing query parameter 'q'" }));
    }
    let results = containers::docker_search(&q);
    HttpResponse::Ok().json(results)
}

#[derive(Deserialize)]
pub struct DockerPullRequest {
    pub image: String,
}

/// POST /api/containers/docker/pull — pull a Docker image
pub async fn docker_pull(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DockerPullRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match containers::docker_pull(&body.image) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct DockerCreateRequest {
    pub name: String,
    pub image: String,
    pub ports: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub wolfnet_ip: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_cores: Option<String>,
    pub storage_limit: Option<String>,
    /// Volume mounts: ["host:container", "volume_name:/data", ...]
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// POST /api/containers/docker/create — create a Docker container
pub async fn docker_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DockerCreateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let ports = body.ports.as_deref().unwrap_or(&[]);
    let env = body.env.as_deref().unwrap_or(&[]);
    let wolfnet_ip = body.wolfnet_ip.as_deref();
    let memory = body.memory_limit.as_deref();
    let cpus = body.cpu_cores.as_deref();
    let storage = body.storage_limit.as_deref();
    match containers::docker_create(&body.name, &body.image, ports, env, wolfnet_ip, memory, cpus, storage, &body.volumes) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc/templates — list available LXC templates
pub async fn lxc_templates(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let templates = containers::lxc_list_templates();
    HttpResponse::Ok().json(templates)
}

#[derive(Deserialize)]
pub struct LxcCreateRequest {
    pub name: String,
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub wolfnet_ip: Option<String>,
    pub storage_path: Option<String>,
    /// Where the distro template tarball should live. On Proxmox this is
    /// the PVE storage id that holds `vztmpl` content (defaults to "local").
    /// On native LXC it's used as LXC_CACHE_PATH for lxc-create so the
    /// downloaded tarball goes there instead of /var/cache/lxc.
    #[serde(default)]
    pub template_storage: Option<String>,
    pub root_password: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_cores: Option<String>,
    /// Network mode: "wolfnet" (default), "bridge", or "host". When
    /// "bridge" is set, bridge_name / bridge_ip / bridge_gateway control
    /// the LXC veth network config. When "host" is set, the container
    /// shares the host's network namespace.
    #[serde(default)]
    pub network_mode: Option<String>,
    /// Bridge name for mode=bridge (e.g. "lxcbr0", "vmbr0"). Ignored for
    /// other modes.
    #[serde(default)]
    pub bridge_name: Option<String>,
    /// Static IP in CIDR form for mode=bridge+static (e.g. "192.168.10.50/24").
    /// If absent or empty, the container uses DHCP from the bridge.
    #[serde(default)]
    pub bridge_ip: Option<String>,
    /// Gateway for mode=bridge+static. Usually the router IP on that subnet.
    #[serde(default)]
    pub bridge_gateway: Option<String>,
}

/// POST /api/containers/lxc/create — create an LXC container from template
pub async fn lxc_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LxcCreateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Auto-assign WolfNet IP only when the user chose WolfNet mode (or
    // no mode = legacy/default). Bridge and Host modes explicitly don't
    // want a WolfNet IP — auto-assigning one from the pool was a bug
    // that burned addresses the user never intended to use and
    // confused the "simple WolfNet setup" path by attaching WolfNet
    // even on bridge-mode containers.
    let net_mode = body.network_mode.as_deref().unwrap_or("wolfnet");
    let wolfnet_ip = if net_mode == "wolfnet" || net_mode.is_empty() {
        match body.wolfnet_ip.as_deref() {
            Some(ip) if !ip.is_empty() => Some(ip.to_string()),
            _ => containers::next_available_wolfnet_ip(),
        }
    } else {
        None
    };

    // On Proxmox, pct_create handles password, memory, and CPU natively
    if containers::is_proxmox() {
        let storage = body.storage_path.as_deref();
        let template_storage = body.template_storage.as_deref();
        let password = body.root_password.as_deref();
        // Parse memory limit (e.g. "512m" -> 512, "2g" -> 2048)
        let memory_mb = body.memory_limit.as_deref().and_then(|m| {
            let m = m.trim().to_lowercase();
            if m.ends_with('g') { m.trim_end_matches('g').parse::<u32>().ok().map(|v| v * 1024) }
            else if m.ends_with('m') { m.trim_end_matches('m').parse::<u32>().ok() }
            else { m.parse::<u32>().ok() }
        });
        let cpu_cores = body.cpu_cores.as_deref().and_then(|c| c.parse::<u32>().ok());

        return match containers::pct_create_api(
            &body.name, &body.distribution, &body.release, &body.architecture,
            storage, template_storage, password, memory_mb, cpu_cores,
            wolfnet_ip.as_deref(),
        ) {
            Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        };
    }

    // Standalone LXC path
    let storage = body.storage_path.as_deref();
    let template_storage = body.template_storage.as_deref();
    match containers::lxc_create(&body.name, &body.distribution, &body.release, &body.architecture, storage, template_storage) {
        Ok(msg) => {
            let mut messages = vec![msg];

            // Set root password if provided
            if let Some(ref password) = body.root_password {
                if !password.is_empty() {
                    match containers::lxc_set_root_password(&body.name, password) {
                        Ok(pw_msg) => messages.push(pw_msg),
                        Err(e) => messages.push(format!("Password warning: {}", e)),
                    }
                }
            }

            // Set resource limits if provided
            let memory = body.memory_limit.as_deref();
            let cpus = body.cpu_cores.as_deref();
            match containers::lxc_set_resource_limits(&body.name, memory, cpus) {
                Ok(Some(rl_msg)) => messages.push(rl_msg),
                Err(e) => messages.push(format!("Resource limit warning: {}", e)),
                _ => {}
            }

            // Network — three modes:
            //   "wolfnet" (default): attach to WolfNet overlay with auto or manual IP
            //   "bridge":            configure LXC veth on the specified bridge (DHCP or static)
            //   "host":              no network namespace isolation
            let net_mode = body.network_mode.as_deref().unwrap_or("wolfnet");
            match net_mode {
                "wolfnet" | "" => {
                    if let Some(ref ip) = wolfnet_ip {
                        match containers::lxc_attach_wolfnet(&body.name, ip) {
                            Ok(wn_msg) => messages.push(wn_msg),
                            Err(e) => messages.push(format!("WolfNet warning: {}", e)),
                        }
                    }
                }
                "bridge" => {
                    let bridge = body.bridge_name.as_deref().unwrap_or("lxcbr0");
                    let config_path = format!("{}/{}/config",
                        containers::lxc_base_dir(&body.name), body.name);
                    // Replace the existing lxc.net.0.* block with our bridge config.
                    // Read → filter out old net lines → append fresh ones. This is
                    // safe because lxc-create already wrote a net block and we're
                    // just changing the bridge and IP assignment.
                    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
                    let mut lines: Vec<String> = existing.lines()
                        .filter(|l| !l.trim().starts_with("lxc.net.0."))
                        .map(|s| s.to_string())
                        .collect();
                    lines.push(format!("lxc.net.0.type = veth"));
                    lines.push(format!("lxc.net.0.link = {}", bridge));
                    lines.push(format!("lxc.net.0.flags = up"));
                    // Generate a random MAC so each container has a unique one.
                    let mac = format!("00:16:3e:{:02x}:{:02x}:{:02x}",
                        rand_byte(), rand_byte(), rand_byte());
                    lines.push(format!("lxc.net.0.hwaddr = {}", mac));
                    if let Some(ref ip) = body.bridge_ip {
                        let ip = ip.trim();
                        if !ip.is_empty() {
                            lines.push(format!("lxc.net.0.ipv4.address = {}", ip));
                            if let Some(ref gw) = body.bridge_gateway {
                                let gw = gw.trim();
                                if !gw.is_empty() {
                                    lines.push(format!("lxc.net.0.ipv4.gateway = {}", gw));
                                }
                            }
                        }
                    }
                    lines.push(String::new()); // trailing newline
                    if let Err(e) = std::fs::write(&config_path, lines.join("\n")) {
                        messages.push(format!("Bridge config warning: {}", e));
                    } else {
                        messages.push(format!("Network: veth on {} ({})", bridge,
                            if body.bridge_ip.as_deref().map(|s| s.trim()).unwrap_or("").is_empty() { "DHCP" } else { "static" }));
                    }
                }
                "host" => {
                    let config_path = format!("{}/{}/config",
                        containers::lxc_base_dir(&body.name), body.name);
                    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
                    let mut lines: Vec<String> = existing.lines()
                        .filter(|l| !l.trim().starts_with("lxc.net.0."))
                        .map(|s| s.to_string())
                        .collect();
                    lines.push("lxc.net.0.type = none".to_string());
                    lines.push(String::new());
                    if let Err(e) = std::fs::write(&config_path, lines.join("\n")) {
                        messages.push(format!("Host network config warning: {}", e));
                    } else {
                        messages.push("Network: host (no isolation)".to_string());
                    }
                }
                _ => {}
            }

            HttpResponse::Ok().json(serde_json::json!({ "message": messages.join(" — ") }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Quick pseudo-random byte for MAC addresses. NOT crypto-grade — just
/// needs to be unique-enough per container so bridges don't confuse them.
/// Reads 1 byte from /dev/urandom which is always non-blocking on Linux.
fn rand_byte() -> u8 {
    use std::io::Read;
    let mut buf = [0u8; 1];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    } else {
        // Fallback: nanos-derived (non-repeatable across fast calls but better than nothing).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos()).unwrap_or(0);
        buf[0] = (nanos & 0xFF) as u8;
    }
    buf[0]
}

/// GET /api/storage/remote-list?url=<target> — proxy storage list from a remote WolfStack node
pub async fn remote_storage_list(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let target = match query.get("url") {
        Some(u) if !u.is_empty() => u.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "url parameter required"})),
    };

    let urls = build_external_urls(&target, "/api/storage/list");
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut last_err = String::new();
    for url in &urls {
        match client.get(url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                return HttpResponse::Ok()
                    .content_type("application/json")
                    .body(body);
            }
            Ok(r) => {
                last_err = format!("{}: HTTP {}", url, r.status());
                continue;
            }
            Err(e) => {
                last_err = format!("{}: {}", url, e);
                continue;
            }
        }
    }

    tracing::warn!("remote_storage_list failed for '{}': {}", target, last_err);
    HttpResponse::BadGateway().json(serde_json::json!({"error": format!("Could not reach remote cluster: {}", last_err)}))
}

/// GET /api/storage/filesystems — list real host mountpoints. Unlike
/// /api/storage/list this never returns PVE storage IDs; it walks the
/// live metrics disk list so callers that need a filesystem *path*
/// (LXC rsync migrate, anything writing via bind mount) don't get
/// handed something like `wolfpool` or `local-zfs` they can't cd into.
pub async fn storage_filesystems(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Writable on-disk filesystems that actually host container data.
    // NFS / CIFS etc are intentionally excluded — rsync across them
    // works but loses perms/xattrs that -aHAX promises.
    const WRITABLE_FS_TYPES: &[&str] = &[
        "ext4", "ext3", "ext2", "xfs", "btrfs", "zfs", "f2fs", "reiserfs", "jfs",
    ];

    let node = state.cluster.get_node(&state.cluster.self_id);
    let disks = node.as_ref().and_then(|n| n.metrics.as_ref())
        .map(|m| m.disks.clone())
        .unwrap_or_default();

    let items: Vec<serde_json::Value> = disks.iter()
        .filter(|d| {
            let fs = d.fs_type.to_ascii_lowercase();
            WRITABLE_FS_TYPES.iter().any(|t| fs == *t || fs.starts_with(&format!("{}.", t)))
                && d.available_bytes > 1024 * 1024 * 1024  // > 1 GiB free
                && !d.mount_point.starts_with("/snap")
                && !d.mount_point.starts_with("/boot")
                && !d.mount_point.starts_with("/var/lib/docker/")
                && !d.mount_point.starts_with("/var/lib/containers/")
        })
        .map(|d| serde_json::json!({
            "mount_point": d.mount_point,
            "fs_type": d.fs_type,
            "total_bytes": d.total_bytes,
            "used_bytes": d.used_bytes,
            "available_bytes": d.available_bytes,
        }))
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "filesystems": items,
    }))
}

/// GET /api/storage/list — list available storage locations (Proxmox-aware)
pub async fn storage_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let is_pve = containers::is_proxmox();

    if is_pve {
        // Return Proxmox storage IDs
        let storages = containers::pvesm_list_storage();
        let items: Vec<serde_json::Value> = storages.iter().map(|s| {
            serde_json::json!({
                "id": s.id,
                "type": s.storage_type,
                "status": s.status,
                "total_bytes": s.total_bytes,
                "used_bytes": s.used_bytes,
                "available_bytes": s.available_bytes,
                "content": s.content,
                "path": s.path,
            })
        }).collect();
        HttpResponse::Ok().json(serde_json::json!({
            "proxmox": true,
            "storages": items,
        }))
    } else {
        // Return filesystem-based storage
        let node = state.cluster.get_node(&state.cluster.self_id);
        let disks = node.as_ref().and_then(|n| n.metrics.as_ref())
            .map(|m| &m.disks)
            .cloned()
            .unwrap_or_default();

        let items: Vec<serde_json::Value> = disks.iter()
            .filter(|d| d.available_bytes > 1073741824) // > 1GB free
            .map(|d| serde_json::json!({
                "id": d.mount_point,
                "type": "dir",
                "status": "active",
                "total_bytes": d.total_bytes,
                "used_bytes": d.used_bytes,
                "available_bytes": d.available_bytes,
                "content": ["rootdir", "images"],
            }))
            .collect();
        HttpResponse::Ok().json(serde_json::json!({
            "proxmox": false,
            "storages": items,
        }))
    }
}

/// GET /api/wolfnet/status — get WolfNet networking status for container creation
/// Queries all cluster nodes for used IPs to avoid collisions
pub async fn wolfnet_network_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Collect used IPs from all remote cluster nodes
    let mut remote_used: Vec<u8> = Vec::new();
    let nodes = state.cluster.get_all_nodes();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    for node in &nodes {
        if node.is_self || !node.online { continue; }
        let urls = build_node_urls(&node.address, node.port, "/api/wolfnet/used-ips");
        for url in &urls {
            if let Ok(resp) = client.get(url)
                .header("X-WolfStack-Secret", state.cluster_secret.clone())
                .send().await {
                if let Ok(ips) = resp.json::<Vec<String>>().await {
                    for ip_str in ips {
                        let parts: Vec<&str> = ip_str.split('.').collect();
                        if parts.len() == 4 {
                            if let Ok(last) = parts[3].parse::<u8>() {
                                remote_used.push(last);
                            }
                        }
                    }
                }
                break; // Success on this node
            }
        }
    }

    let status = containers::wolfnet_status(&remote_used);
    HttpResponse::Ok().json(status)
}

/// GET /api/ports — return this node's persistent port config (api/inter_node/status).
pub async fn get_ports(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::ports::PortConfig::load())
}

/// POST /api/ports — update this node's persistent port config.
/// Changes take effect on next restart; we don't try to rebind live listeners.
pub async fn set_ports(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::ports::PortConfig>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cfg = body.into_inner();
    // Sanity: reject anything outside the unprivileged range to avoid foot-guns.
    for (name, p) in [("api", cfg.api), ("inter_node", cfg.inter_node), ("status", cfg.status)] {
        if p < 1024 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("{} port {} is in the privileged range (<1024)", name, p)}));
        }
    }
    if cfg.api == cfg.inter_node || cfg.api == cfg.status || cfg.inter_node == cfg.status {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "api, inter_node and status ports must all differ"}));
    }
    if let Err(e) = cfg.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }
    HttpResponse::Ok().json(serde_json::json!({"saved": true, "restart_required": true}))
}

// ─── Cluster Services Discovery ─────────────────────────────────────────

/// GET /api/cluster-services — every web service this user can see:
/// the cluster-wide auto-discovered list + their own pinned manual URLs.
/// Other users' pinned URLs are not returned.
pub async fn cluster_services_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    HttpResponse::Ok().json(serde_json::json!({
        "services": crate::services_discovery::list_for_user(&user),
        "grouped":  crate::services_discovery::grouped_for(&user),
    }))
}

/// POST /api/cluster-services/sweep — run a fresh discovery scan now.
/// Discovery is on-demand (no periodic loop), so the page calls this
/// when it loads. Returns once the sweep has finished, with the new
/// merged list for the requesting user.
pub async fn cluster_services_sweep(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let _ = tokio::task::spawn_blocking(crate::services_discovery::run_sweep).await;
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "services": crate::services_discovery::list_for_user(&user),
        "grouped":  crate::services_discovery::grouped_for(&user),
    }))
}

#[derive(Deserialize)]
pub struct AddManualServiceRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default = "default_other_category")]
    pub category: String,
}

fn default_other_category() -> String { "Other".to_string() }

/// POST /api/cluster-services/manual — pin a service against the
/// requesting user. Other users won't see this entry.
pub async fn cluster_services_add_manual(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AddManualServiceRequest>,
) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    match crate::services_discovery::add_manual_for_user(
        &user, body.name.clone(), body.url.clone(), body.icon.clone(), body.category.clone(),
    ) {
        Ok(svc) => HttpResponse::Ok().json(svc),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

pub async fn cluster_services_delete(
    req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>,
) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    if crate::services_discovery::remove_manual_for_user(&user, &id) {
        HttpResponse::Ok().json(serde_json::json!({"removed": true}))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "not found in your pinned list"}))
    }
}

// ─── Cluster Browser Sessions ───────────────────────────────────────────

/// GET /api/cluster-browser/sessions — active browser sessions on this node.
pub async fn cluster_browser_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::cluster_browser::list_sessions())
}

#[derive(Deserialize)]
pub struct StartBrowserRequest {
    /// Optional override for the homepage URL the in-container Firefox
    /// loads at startup. Defaults to /cluster-home on this node.
    #[serde(default)]
    pub homepage: Option<String>,
}

/// POST /api/cluster-browser/sessions — start a new browser session,
/// returning the session metadata + the connect URL for the user.
pub async fn cluster_browser_start(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<StartBrowserRequest>,
) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    // Default homepage = our /cluster-home reachable from inside the
    // browser container. Docker bridge containers can't reach the
    // host's wolfnet0 IP or 127.0.0.1, so we use host.docker.internal
    // (wired up via --add-host in spawn_container) which resolves to
    // the bridge gateway — the host listens there for any 0.0.0.0
    // bound service. Use plain HTTP regardless of WolfStack's TLS
    // mode: a fresh Firefox profile rejects self-signed certs, and
    // the inter_node port is always plain HTTP on TLS installs.
    let port_cfg = crate::ports::PortConfig::load();
    let homepage_port = if state.tls_enabled { port_cfg.inter_node } else { port_cfg.api };
    // Embed the user as a query param so /cluster-home renders that
    // user's pinned URLs alongside the cluster-wide discovered list.
    let default_homepage = format!(
        "http://host.docker.internal:{}/cluster-home?user={}",
        homepage_port,
        urlencoding_simple(&user)
    );
    let homepage = body.homepage.clone().filter(|s| !s.trim().is_empty()).unwrap_or(default_homepage);
    let tls = state.tls_enabled;

    // Capture the host:port the client used to reach WolfStack BEFORE
    // spawn_blocking — connection_info() returns a borrow that can't
    // cross the await. This becomes the base of the proxy URL so the
    // browser's ws/wss goes back to WolfStack on the same port the
    // user is already connected to.
    let wolfstack_authority = req.connection_info().host().to_string();
    let wolfstack_scheme = if state.tls_enabled { "https" } else { "http" };

    let result = tokio::task::spawn_blocking(move || {
        crate::cluster_browser::start_session(&user, &homepage, tls)
    }).await;

    match result {
        Ok(Ok(session)) => HttpResponse::Ok().json(serde_json::json!({
            "session": session,
            "connect_url": format!(
                "{}://{}/api/cluster-browser/session/{}/",
                wolfstack_scheme, wolfstack_authority, session.id
            ),
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /api/cluster-browser/image-status — quick "is the browser image
/// pre-pulled on this node?" so the UI can show "First run will download
/// ~700 MB" if not.
pub async fn cluster_browser_image_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(serde_json::json!({
        "image_present": crate::cluster_browser::image_present(),
    }))
}

/// POST /api/cluster-browser/sessions/start-stream — same as /sessions
/// but streams `docker pull` progress (image download, layers, container
/// start) as Server-Sent Events so the user has visible feedback during
/// the multi-minute first-time pull instead of a silent spinner.
/// Final event: `[done] {json}` with the connect_url.
pub async fn cluster_browser_start_stream(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<StartBrowserRequest>,
) -> HttpResponse {
    let user = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    // Firefox runs inside a Docker container that can't reach the
    // host's wolfnet0 IP — see cluster_browser_start for full comment.
    let port_cfg = crate::ports::PortConfig::load();
    let homepage_port = if state.tls_enabled { port_cfg.inter_node } else { port_cfg.api };
    // Embed the user as a query param so /cluster-home renders that
    // user's pinned URLs alongside the cluster-wide discovered list.
    let default_homepage = format!(
        "http://host.docker.internal:{}/cluster-home?user={}",
        homepage_port,
        urlencoding_simple(&user)
    );
    let homepage = body.homepage.clone().filter(|s| !s.trim().is_empty()).unwrap_or(default_homepage);
    let tls = state.tls_enabled;

    // Capture the host:port and scheme the client used to reach
    // WolfStack BEFORE the blocking thread spawn — connection_info()
    // borrows from req which is !Send across the thread boundary.
    // Connect URL points to the in-process reverse proxy, not a
    // per-session port, so ws/wss rides whatever port WolfStack is on.
    let wolfstack_authority = req.connection_info().host().to_string();
    let wolfstack_scheme = if state.tls_enabled { "https" } else { "http" };

    let (std_tx, std_rx) = std::sync::mpsc::channel::<String>();
    let (tok_tx, mut tok_rx) = tokio::sync::mpsc::channel::<String>(256);

    std::thread::spawn(move || {
        let result = crate::cluster_browser::start_session_streamed(&user, &homepage, tls, std_tx.clone());
        match result {
            Ok(session) => {
                let payload = serde_json::json!({
                    "session": session,
                    "connect_url": format!(
                        "{}://{}/api/cluster-browser/session/{}/",
                        wolfstack_scheme, wolfstack_authority, session.id
                    ),
                });
                let _ = std_tx.send(format!("[done] {}", payload));
            }
            Err(e) => { let _ = std_tx.send(format!("[error] {}", e)); }
        }
    });

    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = std_rx.recv() {
            if tok_tx.blocking_send(msg).is_err() { break; }
        }
    });

    let stream = async_stream::stream! {
        while let Some(msg) = tok_rx.recv().await {
            let event = format!("data: {}\n\n", msg.replace('\n', "\ndata: "));
            yield Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(event));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

pub async fn cluster_browser_stop(
    req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let result = tokio::task::spawn_blocking(move || {
        crate::cluster_browser::stop_session(&id)
    }).await;
    match result {
        Ok(Ok(())) => HttpResponse::Ok().json(serde_json::json!({"stopped": true})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /cluster-home[?user=alice] — the homepage HTML that the
/// in-container Firefox loads at startup. Lists discovered services as
/// click-cards plus an open-URL bar at the top. Intentionally
/// unauthenticated: the Firefox inside the container has a fresh
/// profile and no cookies, and the page only exposes information
/// that's already visible to anything on the WolfNet routing fabric.
/// The optional `user` query param scopes the homepage to that user's
/// pinned manual URLs in addition to auto-discovered services — the
/// session-start endpoint embeds the user in the homepage URL when it
/// spawns the container so each user lands on their own grid.
pub async fn cluster_browser_homepage(
    req: HttpRequest, _state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let _ = req; // intentional — unauthenticated by design
    let user = query.get("user").map(|s| s.as_str()).unwrap_or("");
    let html = crate::cluster_browser::render_homepage(user);
    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Cache-Control", "no-cache"))
        .body(html)
}

/// Minimal percent-encoder for the `user` query param embedded in the
/// in-container browser's homepage URL. Avoids pulling in a full
/// urlencoding crate just for one call site. Encodes everything that
/// isn't alphanumeric or `-_.` (RFC 3986 unreserved-ish).
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        let c = *byte;
        if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' || c == b'~' {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

/// GET /api/wolfnet/used-ips — returns WolfNet IPs in use on this node
/// Requires cluster auth — used for inter-node route discovery
pub async fn wolfnet_used_ips_endpoint(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_cluster_auth(&req, &state) { return resp; }
    let ips = containers::wolfnet_used_ips();
    HttpResponse::Ok().json(ips)
}

/// GET /api/wolfnet/routes — returns the full WOLFNET_ROUTES cache + local used IPs for debugging
pub async fn wolfnet_routes_debug(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Get the WOLFNET_ROUTES cache (container_ip -> gateway_host_ip)
    let routes = containers::WOLFNET_ROUTES.lock().unwrap().clone();

    // Get local used IPs with labels
    let local_ips = containers::wolfnet_used_ips();
    let host_ip = local_ips.first().cloned().unwrap_or_default();

    // Build a combined view: each IP with its type and route info
    let mut entries: Vec<serde_json::Value> = Vec::new();

    // Local used IPs
    for (i, ip) in local_ips.iter().enumerate() {
        entries.push(serde_json::json!({
            "ip": ip,
            "type": if i == 0 { "host" } else { "local" },
            "gateway": if i == 0 { "self" } else { &host_ip },
            "source": "local"
        }));
    }

    // Remote routes from cache
    for (ip, gateway) in &routes {
        // Skip if already in local list
        if local_ips.contains(ip) { continue; }
        entries.push(serde_json::json!({
            "ip": ip,
            "type": "remote",
            "gateway": gateway,
            "source": "cache"
        }));
    }

    // Also read routes.json for comparison
    let routes_json = std::fs::read_to_string("/var/run/wolfnet/routes.json")
        .ok()
        .and_then(|c| serde_json::from_str::<std::collections::HashMap<String, String>>(&c).ok())
        .unwrap_or_default();

    HttpResponse::Ok().json(serde_json::json!({
        "entries": entries,
        "routes_cache_count": routes.len(),
        "routes_json_count": routes_json.len(),
        "host_ip": host_ip,
        "local_ips": local_ips,
    }))
}

/// GET /api/containers/docker/stats — Docker container stats
pub async fn docker_stats(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let stats = containers::docker_stats_cached();
    HttpResponse::Ok().json(stats)
}

/// GET /api/containers/docker/images — list Docker images
pub async fn docker_images(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let images = containers::docker_images_cached();
    HttpResponse::Ok().json(images)
}

/// DELETE /api/containers/docker/images/{id} — remove a Docker image
pub async fn docker_remove_image(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match containers::docker_remove_image(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/docker/{id}/logs — get Docker container logs
pub async fn docker_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let logs = containers::docker_logs(&id, 100);
    HttpResponse::Ok().json(serde_json::json!({ "logs": logs }))
}

#[derive(Deserialize)]
pub struct ContainerActionRequest {
    pub action: String,  // start, stop, restart, remove, pause, unpause
}

/// POST /api/containers/docker/{id}/action — control Docker container
pub async fn docker_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ContainerActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let result = match body.action.as_str() {
        "start" => containers::docker_start(&id),
        "stop" => containers::docker_stop(&id),
        "restart" => containers::docker_restart(&id),
        "remove" => containers::docker_remove(&id),
        "pause" => containers::docker_pause(&id),
        "unpause" => containers::docker_unpause(&id),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct CloneRequest {
    pub new_name: String,
    pub snapshot: Option<bool>,  // LXC only — use copy-on-write clone
    pub storage: Option<String>, // target storage (Proxmox ID or path)
    pub target_node: Option<String>, // clone to a different node in the cluster
    pub wolfnet_ip: Option<String>,  // pre-allocated wolfnet IP (avoids cross-node conflicts)
}

#[derive(Deserialize)]
pub struct MigrateRequest {
    pub target_node: String,
    pub storage: Option<String>,
    pub new_name: Option<String>,
    #[serde(default)]
    pub target_address: Option<String>,
    #[serde(default)]
    pub target_port: Option<u16>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MigrateExternalRequest {
    pub target_url: String,
    pub target_token: String,
    pub new_name: Option<String>,
    pub storage: Option<String>,
    pub delete_source: Option<bool>, // accepted but ignored — source is never deleted
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ImportRequest {
    pub new_name: String,
    pub storage: Option<String>,
}

/// POST /api/containers/docker/{id}/clone — clone a Docker container
pub async fn docker_clone(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CloneRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match containers::docker_clone(&id, &body.new_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/docker/{id}/migrate — migrate a Docker container to another node
#[derive(Deserialize)]
pub struct DockerMigrateRequest {
    pub target_url: String,
    pub remove_source: Option<bool>,
}
pub async fn docker_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<DockerMigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let remove = body.remove_source.unwrap_or(false);
    match containers::docker_migrate(&id, &body.target_url, remove, &state.cluster_secret) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc — list all LXC containers
pub async fn lxc_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::lxc_list_all_cached();
    HttpResponse::Ok().json(containers)
}

/// GET /api/containers/lxc/stats — LXC container stats
pub async fn lxc_stats(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let stats = containers::lxc_stats_cached();
    HttpResponse::Ok().json(stats)
}

/// GET /api/containers/lxc/{name}/logs — get LXC container logs
pub async fn lxc_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let logs = containers::lxc_logs(&name, 100);
    HttpResponse::Ok().json(serde_json::json!({ "logs": logs }))
}

/// GET /api/containers/lxc/{name}/config — get LXC container config
pub async fn lxc_config(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_config(&name) {
        Some(content) => HttpResponse::Ok().json(serde_json::json!({ "config": content })),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Config not found" })),
    }
}

/// PUT /api/containers/lxc/{name}/config — save LXC container config
pub async fn lxc_save_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SaveConfigRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_save_config(&name, &body.content) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/lxc/{name}/action — control LXC container
pub async fn lxc_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ContainerActionRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let result = match body.action.as_str() {
        "start" => containers::lxc_start(&name),
        "stop" => containers::lxc_stop(&name),
        "restart" => containers::lxc_restart(&name),
        "freeze" => containers::lxc_freeze(&name),
        "unfreeze" => containers::lxc_unfreeze(&name),
        "destroy" => containers::lxc_destroy(&name),
        _ => Err(format!("Unknown action: {}", body.action)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/lxc/{name}/clone — clone an LXC container
pub async fn lxc_clone(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CloneRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    // Remote clone: export → transfer → import on target node
    if let Some(ref target_node_id) = body.target_node {
        return lxc_remote_clone(&state, &name, &body.new_name, target_node_id, body.storage.as_deref(), body.wolfnet_ip.as_deref(), None, None).await;
    }

    // Local clone — lxc-copy requires container to be stopped
    let _ = containers::lxc_stop(&name);
    let storage = body.storage.as_deref();
    let result = if body.snapshot.unwrap_or(false) {
        containers::lxc_clone_snapshot(&name, &body.new_name)
    } else {
        containers::lxc_clone_local(&name, &body.new_name, storage)
    };
    let _ = containers::lxc_start(&name); // restart template
    match result {
        Ok(msg) => {
            // Remove duplicated wolfnet IP marker and allocate fresh one
            let _ = std::fs::remove_dir_all(format!("{}/{}/.wolfnet", containers::lxc_base_dir(&body.new_name), body.new_name));
            let _ = containers::lxc_start(&body.new_name);
            if let Some(ip) = containers::next_available_wolfnet_ip() {
                let _ = containers::lxc_attach_wolfnet(&body.new_name, &ip);
            }
            HttpResponse::Ok().json(serde_json::json!({ "message": msg }))
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Remote clone: export on this node, stream to target, import there
async fn lxc_remote_clone(
    state: &web::Data<AppState>,
    source: &str,
    new_name: &str,
    target_node_id: &str,
    storage: Option<&str>,
    wolfnet_ip: Option<&str>,
    fallback_address: Option<&str>,
    fallback_port: Option<u16>,
) -> HttpResponse {
    // 1. Find target node — fall back to address/port if node ID not in local cluster state
    //    (can happen when request is proxied to a remote node with different cluster state)
    let node = match state.cluster.get_node(target_node_id) {
        Some(n) => n,
        None => {
            if let Some(addr) = fallback_address {
                let port = fallback_port.unwrap_or(8553);
                tracing::info!("Node '{}' not in cluster state, using fallback address {}:{}", target_node_id, addr, port);
                crate::agent::Node {
                    id: target_node_id.to_string(),
                    address: addr.to_string(),
                    port,
                    hostname: addr.to_string(),
                    is_self: false,
                    online: true,
                    node_type: "wolfstack".to_string(),
                    last_seen: 0,
                    metrics: None,
                    components: vec![],
                    docker_count: 0,
                    lxc_count: 0,
                    vm_count: 0,
                    public_ip: None,
                    pve_token: None,
                    pve_fingerprint: None,
                    pve_node_name: None,
                    pve_cluster_name: None,
                    cluster_name: None,
                    join_verified: false,
                    has_docker: false,
                    has_lxc: false,
                    has_kvm: false,
                    login_disabled: false,
                    tls: false,
                    update_script: None,
                }
            } else {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Target node not found"}));
            }
        }
    };
    if node.is_self {
        // Local clone, not remote
        match containers::lxc_clone_local(source, new_name, storage) {
            Ok(msg) => return HttpResponse::Ok().json(serde_json::json!({"message": msg})),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        }
    }

    // 2. Stop container temporarily for consistent export, then restart immediately
    let _ = containers::lxc_stop(source);

    // 3. Export container
    let (archive_path, meta) = match containers::lxc_export(source) {
        Ok(v) => v,
        Err(e) => {
            let _ = containers::lxc_start(source);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Export failed: {}", e)}));
        }
    };

    // Restart source immediately after export — source stays running during transfer
    let _ = containers::lxc_start(source);

    // 4. Read archive
    let archive_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to read archive: {}", e)}));
        }
    };

    // 5. Transfer to target
    // For Proxmox-type nodes, WolfStack is also installed on the server but the
    // node is registered with the PVE API port (8006), not the WolfStack port (8553).
    // Build import URLs using the correct WolfStack port.
    let import_urls = if node.node_type == "proxmox" {
        // Proxmox nodes have WolfStack running on port 8553 — try that
        let mut urls = build_node_urls(&node.address, 8553, "/api/containers/lxc/import");
        // Also try 8552 as a fallback WolfStack port
        urls.extend(build_node_urls(&node.address, 8552, "/api/containers/lxc/import"));
        urls
    } else {
        build_node_urls(&node.address, node.port, "/api/containers/lxc/import")
    };

    let storage_val = storage.unwrap_or("").to_string();

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(600))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let meta_json = serde_json::to_string(&meta).unwrap_or_default();
    let mut last_err: Option<String> = None;

    for import_url in &import_urls {
        let mut form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .text("meta", meta_json.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));

        // Pass pre-allocated wolfnet IP to avoid cross-node conflicts
        if let Some(ip) = wolfnet_ip {
            form = form.text("wolfnet_ip", ip.to_string());
        }

        match client.post(import_url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .multipart(form)
            .send()
            .await
        {
            Ok(r) => {
                containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
                if r.status().is_success() {
                    return match r.json::<serde_json::Value>().await {
                        Ok(data) => HttpResponse::Ok().json(serde_json::json!({
                            "message": format!("Container '{}' cloned to '{}' on node '{}'", source, new_name, target_node_id),
                            "detail": data
                        })),
                        Err(_) => HttpResponse::Ok().json(serde_json::json!({
                            "message": format!("Container '{}' cloned to '{}' on node '{}'", source, new_name, target_node_id)
                        })),
                    };
                } else {
                    let err_text = r.text().await.unwrap_or_default();
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Import on target failed: {}", err_text)}));
                }
            }
            Err(e) => {
                last_err = Some(e.to_string());
                continue; // Try next URL
            }
        }
    }

    // All URLs failed — source is already running
    containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Transfer to {} failed on all ports/protocols: {}", node.address, last_err.unwrap_or_default())
    }))
}

/// POST /api/containers/lxc/{name}/export — export container as downloadable archive
pub async fn lxc_export_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    // Stop, export, restart
    let _ = containers::lxc_stop(&name);
    let (archive_path, meta) = match containers::lxc_export(&name) {
        Ok(v) => v,
        Err(e) => {
            let _ = containers::lxc_start(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }
    };
    let _ = containers::lxc_start(&name);

    // Read the file and return as binary download
    match std::fs::read(&archive_path) {
        Ok(bytes) => {
            let filename = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            HttpResponse::Ok()
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .insert_header(("X-Container-Meta", serde_json::to_string(&meta).unwrap_or_default()))
                .content_type("application/octet-stream")
                .body(bytes)
        }
        Err(e) => {
            containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
            HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read archive: {}", e)}))
        }
    }
}

/// POST /api/containers/lxc/import — import container from uploaded archive (multipart)
pub async fn lxc_import_endpoint(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    lxc_import_endpoint_inner(&mut payload).await
}

/// POST /api/containers/lxc/{name}/migrate — migrate to another node (clone + destroy source)
pub async fn lxc_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name);

    // Clone to target node — source stays running, destination is not started
    let clone_resp = lxc_remote_clone(&state, &name, new_name, &body.target_node, body.storage.as_deref(), None, body.target_address.as_deref(), body.target_port).await;

    clone_resp
}

// ─── Cross-cluster Transfer Tokens ───

static TRANSFER_TOKENS: std::sync::LazyLock<std::sync::Mutex<Vec<TransferToken>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[derive(Clone, Debug)]
struct TransferToken {
    token: String,
    expires: std::time::Instant,
}

/// POST /api/containers/transfer-token — generate a one-time import token
pub async fn generate_transfer_token(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let token = format!("wst_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let expires = std::time::Instant::now() + std::time::Duration::from_secs(1800); // 30 min

    if let Ok(mut tokens) = TRANSFER_TOKENS.lock() {
        // Purge expired
        tokens.retain(|t| t.expires > std::time::Instant::now());
        tokens.push(TransferToken { token: token.clone(), expires });
    }

    HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "expires_in_seconds": 1800,
        "instructions": "Provide this token to the source cluster to authorize a container transfer."
    }))
}

/// Validate and consume a transfer token
pub(crate) fn validate_transfer_token(token: &str) -> bool {
    if let Ok(mut tokens) = TRANSFER_TOKENS.lock() {
        tokens.retain(|t| t.expires > std::time::Instant::now()); // purge expired
        if let Some(pos) = tokens.iter().position(|t| t.token == token) {
            tokens.remove(pos); // consume
            return true;
        }
    }
    false
}

/// POST /api/containers/lxc/import-external — import from external cluster
/// Auth: X-WolfStack-Secret (same cluster) or X-Transfer-Token (cross-cluster) or session cookie
pub async fn lxc_import_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    // Accept cluster secret (same cluster), transfer token (cross-cluster), or session auth
    let has_secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == state.cluster_secret.as_str())
        .unwrap_or(false);

    let has_token = req.headers().get("X-Transfer-Token")
        .and_then(|v| v.to_str().ok())
        .map(|v| validate_transfer_token(v))
        .unwrap_or(false);

    if !has_secret && !has_token {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    // Delegate to the standard import logic
    lxc_import_endpoint_inner(&mut payload).await
}

/// Shared import logic for both internal and external imports
async fn lxc_import_endpoint_inner(
    payload: &mut actix_multipart::Multipart,
) -> HttpResponse {
    let import_dir = std::path::Path::new("/tmp/wolfstack-imports");
    let _ = std::fs::create_dir_all(import_dir);

    let mut new_name = String::new();
    let mut storage = None;
    let mut archive_path = None;
    let mut wolfnet_ip: Option<String> = None;
    let mut archive_format = String::new(); // "vzdump" or "tar.gz"

    use futures::StreamExt;
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Multipart error: {}", e)})),
        };

        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "new_name" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                new_name = String::from_utf8_lossy(&buf).trim().to_string();
            }
            "storage" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let s = String::from_utf8_lossy(&buf).trim().to_string();
                if !s.is_empty() { storage = Some(s); }
            }
            "wolfnet_ip" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let s = String::from_utf8_lossy(&buf).trim().to_string();
                if !s.is_empty() { wolfnet_ip = Some(s); }
            }
            "meta" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let s = String::from_utf8_lossy(&buf).trim().to_string();
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&s) {
                    archive_format = meta.get("archive_format").and_then(|v| v.as_str()).unwrap_or("").to_string();
                }
            }
            "archive" => {
                // Use UUID filename — pick extension based on source archive format
                let ext = if archive_format == "vzdump" { "tar.zst" } else { "tar.gz" };
                let filename = format!("lxc-import-{}.{}", uuid::Uuid::new_v4(), ext);
                let dest = import_dir.join(&filename);
                let mut file = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write error: {}", e)})),
                };
                use std::io::Write;
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk {
                        if let Err(e) = file.write_all(&data) {
                            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write error: {}", e)}));
                        }
                    }
                }
                archive_path = Some(dest);
            }
            _ => { while let Some(_) = field.next().await {} }
        }
    }

    if new_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "new_name is required"}));
    }
    if !crate::auth::is_safe_name(&new_name) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid container name"}));
    }
    let archive = match archive_path {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "archive file is required"})),
    };

    match containers::lxc_import(archive.to_str().unwrap(), &new_name, storage.as_deref()) {
        Ok(msg) => {
            let _ = std::fs::remove_file(&archive);

            // Remove duplicated wolfnet IP from the template (both standalone and Proxmox)
            let wolfnet_marker = format!("{}/{}/.wolfnet", containers::lxc_base_dir(&new_name), new_name);
            let _ = std::fs::remove_dir_all(&wolfnet_marker);

            // Also strip any wolfnet veth config from the imported container
            // so it doesn't conflict with the template's IP
            containers::lxc_clone_fixup_ip(&new_name);

            // Imported container is left stopped — user starts it manually when ready

            // Allocate a fresh wolfnet IP — use pre-allocated one from orchestrator if available
            let ip_to_use = wolfnet_ip.clone().or_else(|| containers::next_available_wolfnet_ip());
            if let Some(ip) = ip_to_use {
                let _ = containers::lxc_attach_wolfnet(&new_name, &ip);

            }

            HttpResponse::Ok().json(serde_json::json!({"message": msg}))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e}))
        }
    }
}

/// Helper: update a migration task's status
fn migration_update(tasks: &Arc<std::sync::RwLock<std::collections::HashMap<String, MigrationTask>>>, id: &str, stage: &str, message: &str) {
    if let Ok(mut map) = tasks.write() {
        if let Some(task) = map.get_mut(id) {
            task.stage = stage.to_string();
            task.message = message.to_string();
        }
    }
}

fn migration_fail(tasks: &Arc<std::sync::RwLock<std::collections::HashMap<String, MigrationTask>>>, id: &str, error: &str) {
    if let Ok(mut map) = tasks.write() {
        if let Some(task) = map.get_mut(id) {
            task.stage = "failed".to_string();
            task.message = error.to_string();
            task.error = Some(error.to_string());
            task.completed = true;
        }
    }
}

fn migration_done(tasks: &Arc<std::sync::RwLock<std::collections::HashMap<String, MigrationTask>>>, id: &str, message: &str) {
    if let Ok(mut map) = tasks.write() {
        if let Some(task) = map.get_mut(id) {
            task.stage = "done".to_string();
            task.message = message.to_string();
            task.completed = true;
        }
    }
}

/// GET /api/migration/{id}/status — poll migration task progress
pub async fn migration_status(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if let Ok(map) = state.migration_tasks.read() {
        if let Some(task) = map.get(&id) {
            return HttpResponse::Ok().json(task);
        }
    }
    HttpResponse::NotFound().json(serde_json::json!({"error": "Task not found"}))
}

/// POST /api/containers/lxc/{name}/migrate-external — migrate to external cluster (background task)
pub async fn lxc_migrate_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateExternalRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name).to_string();
    let target_url = body.target_url.clone();
    let target_token = body.target_token.clone();
    let storage_val = body.storage.as_deref().unwrap_or("").to_string();
    let cluster_secret = state.cluster_secret.clone();
    let tasks = state.migration_tasks.clone();

    // Create task entry
    let task_id = format!("mig_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    {
        let mut map = tasks.write().unwrap();
        map.insert(task_id.clone(), MigrationTask {
            id: task_id.clone(),
            stage: "preflight".to_string(),
            message: "Checking destination connectivity...".to_string(),
            completed: false,
            error: None,
            started_at: now,
        });
    }

    let tid = task_id.clone();
    // Spawn migration in background
    tokio::spawn(async move {
        // 1. Pre-flight
        let preflight_urls = build_external_urls(&target_url, "/api/storage/list");
        let preflight_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        let mut preflight_ok = false;
        let mut preflight_err = String::new();
        for url in &preflight_urls {
            // Just check connectivity — any HTTP response means the destination is running
            match preflight_client.get(url)
                .header("X-WolfStack-Secret", cluster_secret.clone())
                .send()
                .await
            {
                Ok(_) => { preflight_ok = true; break; } // any response = reachable
                Err(e) => { preflight_err = format!("{}: {}", url, e); }
            }
        }
        if !preflight_ok {
            migration_fail(&tasks, &tid, &format!("Cannot reach destination: {}", preflight_err));
            return;
        }

        // 2. Export
        migration_update(&tasks, &tid, "export", "Stopping container for export...");
        let _ = containers::lxc_stop(&name);
        let (archive_path, meta) = match containers::lxc_export(&name) {
            Ok(v) => v,
            Err(e) => {
                let _ = containers::lxc_start(&name);
                migration_fail(&tasks, &tid, &format!("Export failed: {}", e));
                return;
            }
        };
        let _ = containers::lxc_start(&name);
        migration_update(&tasks, &tid, "export", "Reading archive...");

        let archive_bytes = match std::fs::read(&archive_path) {
            Ok(b) => b,
            Err(e) => {
                containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
                migration_fail(&tasks, &tid, &format!("Read archive: {}", e));
                return;
            }
        };

        let size_mb = archive_bytes.len() / (1024 * 1024);
        migration_update(&tasks, &tid, "upload", &format!("Uploading {} MB to destination...", size_mb));

        // 3. Upload
        let import_urls = build_external_urls(&target_url, "/api/containers/lxc/import-external");
        let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(600))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        let mut last_err: Option<String> = None;

        for import_url in &import_urls {
            let form = reqwest::multipart::Form::new()
                .text("new_name", new_name.clone())
                .text("storage", storage_val.clone())
                .text("meta", serde_json::to_string(&meta).unwrap_or_default())
                .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                    .file_name(file_name.clone()));

            match client.post(import_url)
                .header("X-Transfer-Token", &target_token)
                .header("X-WolfStack-Secret", cluster_secret.clone())
                .multipart(form)
                .send()
                .await
            {
                Ok(r) => {
                    containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
                    if r.status().is_success() {
                        migration_update(&tasks, &tid, "import", "Importing on destination...");
                        migration_done(&tasks, &tid, &format!("Container '{}' transferred. Destination is stopped — start it manually.", name));
                    } else {
                        let err = r.text().await.unwrap_or_default();
                        migration_fail(&tasks, &tid, &format!("Import failed: {}", err));
                    }
                    return;
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            }
        }

        containers::lxc_export_cleanup(archive_path.to_str().unwrap_or(""));
        migration_fail(&tasks, &tid, &format!("Transfer failed on all ports: {}", last_err.unwrap_or_default()));
    });

    // Return task ID immediately
    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "message": "Migration started"
    }))
}

// ─── Mount / Volume Management Endpoints ───

/// GET /api/containers/docker/{id}/volumes — list Docker container volumes
pub async fn docker_volumes(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mounts = containers::docker_list_volumes(&id);
    HttpResponse::Ok().json(mounts)
}

#[derive(Deserialize)]
pub struct DockerUpdateConfigReq {
    pub autostart: Option<bool>,
    pub memory_mb: Option<u64>,
    pub cpus: Option<f32>,
    #[serde(default)]
    pub wolfnet_ip: Option<String>,
}

pub async fn docker_update_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<DockerUpdateConfigReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    match containers::docker_update_config(&id, body.autostart, body.memory_mb, body.cpus, body.wolfnet_ip.clone()) {
         Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
         Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/docker/{id}/env — update environment variables (recreates container)
pub async fn docker_update_env(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let env: Vec<String> = match body.get("env").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'env' array" })),
    };

    match containers::docker_recreate_with_env(&id, &env) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/docker/{id}/inspect — inspect raw docker config
pub async fn docker_inspect(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    
    match containers::docker_inspect(&id) {
        Ok(json) => HttpResponse::Ok().json(json),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── LXC disk: inspect / resize / migrate ───────────────────────

#[derive(serde::Deserialize)]
pub struct LxcResizeRequest {
    /// Target absolute size in GB. Backend converts to bytes / Proxmox
    /// short form. Must be ≥ current usage (refused otherwise).
    pub size_gb: u64,
    /// Volume id for Proxmox containers. Defaults to "rootfs" when
    /// unset. Native LXC always grows the rootfs.
    #[serde(default)]
    pub volume: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct LxcMigrateStorageRequest {
    /// Target storage path (native) or Proxmox storage id (PVE).
    pub target: String,
    /// Whether to remove the source after a successful copy. Defaults
    /// to false — we keep the source until the user confirms the new
    /// copy boots OK.
    #[serde(default)]
    pub remove_source: bool,
    /// Volume id for Proxmox containers. Defaults to "rootfs".
    #[serde(default)]
    pub volume: Option<String>,
}

/// GET /api/containers/lxc/{name}/disk — current backend, size, used.
pub async fn lxc_disk_info(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_storage::inspect(&name) {
        Ok(info) => HttpResponse::Ok().json(info),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/containers/lxc/{name}/disk/resize — grow the rootfs (or
/// a specific Proxmox volume) to a new absolute size in GB.
pub async fn lxc_disk_resize(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcResizeRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let r = body.into_inner();
    let info = match containers::lxc_storage::inspect(&name) {
        Ok(i) => i,
        Err(e) => return HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    };
    let new_bytes = r.size_gb.saturating_mul(1024 * 1024 * 1024);
    if info.proxmox {
        // Route via PVE API. Look up the matching PveClient by node name.
        let vol = r.volume.unwrap_or_else(|| "rootfs".into());
        let pve = match find_pve_client(&state, &info.pve_node).await {
            Some(c) => c,
            None => return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "no Proxmox node registered for this container"
            })),
        };
        let size_str = format!("{}G", r.size_gb);
        match pve.lxc_resize_disk(info.pve_vmid, &vol, &size_str).await {
            Ok(upid) => HttpResponse::Ok().json(serde_json::json!({
                "message": format!("PVE resize task started: {}", upid),
                "upid": upid,
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        }
    } else {
        match containers::lxc_storage::resize(&name, new_bytes) {
            Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        }
    }
}

/// POST /api/containers/lxc/{name}/disk/migrate — move the rootfs to
/// a different storage path / pool.
pub async fn lxc_disk_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcMigrateStorageRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let r = body.into_inner();
    let info = match containers::lxc_storage::inspect(&name) {
        Ok(i) => i,
        Err(e) => return HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    };
    if info.proxmox {
        let vol = r.volume.unwrap_or_else(|| "rootfs".into());
        let pve = match find_pve_client(&state, &info.pve_node).await {
            Some(c) => c,
            None => return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "no Proxmox node registered for this container"
            })),
        };
        match pve.lxc_move_volume(info.pve_vmid, &vol, &r.target, r.remove_source).await {
            Ok(upid) => HttpResponse::Ok().json(serde_json::json!({
                "message": format!("PVE move-volume task started: {}", upid),
                "upid": upid,
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        }
    } else {
        match containers::lxc_storage::migrate(&name, &r.target, r.remove_source) {
            Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        }
    }
}

/// Look up a connected PveClient by node id. Returns None if no
/// Proxmox node by that id is registered (or if pve_node is empty,
/// which means the container is on the local host running pct).
async fn find_pve_client(
    state: &web::Data<AppState>,
    pve_node: &str,
) -> Option<crate::proxmox::PveClient> {
    if pve_node.is_empty() { return None; }
    let nodes = state.cluster.get_all_nodes();
    let target = nodes.iter().find(|n| n.node_type == "proxmox" && n.id == pve_node)?;
    let token = target.pve_token.as_deref()?;
    let node_name = target.pve_node_name.as_deref().unwrap_or(&target.hostname);
    Some(crate::proxmox::PveClient::new(
        &target.address,
        target.port,
        token,
        target.pve_fingerprint.as_deref(),
        node_name,
    ))
}

/// GET /api/containers/lxc/{name}/mounts — list LXC container bind mounts
pub async fn lxc_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let mounts = containers::lxc_list_mounts(&name);
    HttpResponse::Ok().json(mounts)
}

#[derive(Deserialize)]
pub struct AddMountRequest {
    pub host_path: String,
    pub container_path: String,
    #[serde(default)]
    pub read_only: bool,
    // PVE-only flags; ignored on native LXC where `lxc.mount.entry`
    // has no equivalent.
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub quota: bool,
    #[serde(default)]
    pub size_gb: Option<u64>,
}

/// POST /api/containers/lxc/{name}/mounts — add bind mount to LXC container
pub async fn lxc_add_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AddMountRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let opts = containers::LxcMountOptions {
        host_path: body.host_path.clone(),
        container_path: body.container_path.clone(),
        read_only: body.read_only,
        shared: body.shared,
        backup: body.backup,
        quota: body.quota,
        size_gb: body.size_gb,
    };
    match containers::lxc_add_mount(&name, &opts) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct RemoveMountRequest {
    pub host_path: String,
}

/// DELETE /api/containers/lxc/{name}/mounts — remove bind mount from LXC container
pub async fn lxc_remove_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RemoveMountRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_remove_mount(&name, &body.host_path) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct LxcSetAutostartReq {
    pub enabled: bool,
}

pub async fn lxc_set_autostart(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcSetAutostartReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    
    match containers::lxc_set_autostart(&name, body.enabled) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct LxcSetNetworkLinkReq {
    pub link: String,
}

pub async fn lxc_set_network_link(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LxcSetNetworkLinkReq>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    
    match containers::lxc_set_network_link(&name, &body.link) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/containers/lxc/{name}/parsed-config — get structured config
pub async fn lxc_parsed_config(
    req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_parse_config(&name) {
        Some(cfg) => HttpResponse::Ok().json(cfg),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Config not found" })),
    }
}

/// POST /api/containers/lxc/{name}/settings — update structured settings
pub async fn lxc_update_settings(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<containers::LxcSettingsUpdate>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match containers::lxc_update_settings(&name, &body.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfnet/next-ip — find next available WolfNet IP (cluster-wide)
pub async fn wolfnet_next_ip(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Query ALL remote cluster nodes for their used WolfNet IPs
    // to prevent cross-node IP collisions
    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut remote_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    for node in &nodes {
        if node.is_self || !node.online { continue; }
        let urls = build_node_urls(&node.address, node.port, "/api/wolfnet/used-ips");
        for url in &urls {
            if let Ok(resp) = client.get(url)
                .header("X-WolfStack-Secret", state.cluster_secret.clone())
                .send().await
            {
                if let Ok(ips) = resp.json::<Vec<String>>().await {
                    for ip in ips {
                        remote_ips.insert(ip);
                    }
                }
                break; // Success on this node
            }
        }
    }

    // Build a combined set of used IPs (local + remote) for allocation
    // Do NOT inject into WOLFNET_ROUTES cache — that would corrupt routing
    // with invalid "remote" gateway values
    let mut all_used: std::collections::HashSet<String> = remote_ips;

    // Add local used IPs
    for ip in containers::wolfnet_used_ips() {
        all_used.insert(ip);
    }

    // Add IPs from WOLFNET_ROUTES cache (without modifying it)
    {
        let cache = containers::WOLFNET_ROUTES.lock().unwrap();
        for ip in cache.keys() {
            all_used.insert(ip.clone());
        }
    }

    // Add IPs from routes.json
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json") {
        if let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip in routes.keys() {
                all_used.insert(ip.clone());
            }
        }
    }

    // Find next available IP that isn't in the combined used set
    let prefix = containers::wolfnet_subnet_prefix().unwrap_or_default();
    if prefix.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({ "ip": null, "error": "WolfNet is not configured" }));
    }
    let next_ip = (2..=254u8)
        .map(|i| format!("{}.{}", prefix, i))
        .find(|ip| !all_used.contains(ip));

    match next_ip {
        Some(ip) => HttpResponse::Ok().json(serde_json::json!({ "ip": ip })),
        None => HttpResponse::Ok().json(serde_json::json!({ "ip": null, "error": "No available IPs in the WolfNet subnet" })),
    }
}

/// GET /api/network/conflicts — detect duplicate MACs/IPs across LXC containers
pub async fn network_conflicts(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let conflicts = containers::detect_network_conflicts();
    HttpResponse::Ok().json(conflicts)
}

/// POST /api/containers/docker/import — receive a migrated container image
/// Auth: X-WolfStack-Secret (same cluster) or X-Transfer-Token (cross-cluster) or session cookie
pub async fn docker_import(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let has_secret = require_cluster_auth(&req, &state).is_ok();

    let has_token = req.headers().get("X-Transfer-Token")
        .and_then(|v| v.to_str().ok())
        .map(|v| validate_transfer_token(v))
        .unwrap_or(false);

    if !has_secret && !has_token {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    let container_name = query.get("name")
        .cloned()
        .unwrap_or_else(|| format!("migrated-{}", chrono::Utc::now().timestamp()));

    // Sanitize container name to prevent path traversal
    if !crate::auth::is_safe_name(&container_name) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid container name"
        }));
    }

    // Save to temp file
    let tar_path = format!("/tmp/wolfstack-import-{}.tar", container_name);
    if let Err(e) = std::fs::write(&tar_path, &body) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save import file: {}", e)
        }));
    }

    match containers::docker_import_image(&tar_path, &container_name) {
        Ok(msg) => {
            // Imported container is left stopped — user starts it manually when ready
            HttpResponse::Ok().json(serde_json::json!({ "message": msg }))
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct InstallRuntimeRequest {
    pub runtime: String,  // docker or lxc
}

/// POST /api/containers/install — install Docker or LXC
pub async fn install_container_runtime(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InstallRuntimeRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let result = match body.runtime.as_str() {
        "docker" => containers::install_docker(),
        "lxc" => containers::install_lxc(),
        _ => Err(format!("Unknown runtime: {}", body.runtime)),
    };

    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct InstallComponentInContainerRequest {
    pub runtime: String,    // docker or lxc
    pub container: String,  // container name
    pub component: String,  // wolfnet, wolfproxy, etc.
}

/// POST /api/containers/install-component — install a Wolf component inside a container
async fn install_component_in_container(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InstallComponentInContainerRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = body.runtime.clone();
    let container = body.container.clone();
    let component = body.component.clone();

    // Run in blocking thread since it may take a while
    let result = web::block(move || {
        containers::install_component_in_container(&runtime, &container, &component)
    }).await;

    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// GET /api/containers/component-version?runtime=lxc&target=name&component=wolfdisk
async fn container_component_version(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let runtime = query.get("runtime").cloned().unwrap_or_default();
    let target = query.get("target").cloned().unwrap_or_default();
    let component = query.get("component").cloned().unwrap_or_default();
    if runtime.is_empty() || target.is_empty() || component.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "runtime, target, and component are required"}));
    }
    let exec_target = match runtime.as_str() {
        "docker" => crate::configurator::ExecTarget::Docker(target),
        "lxc" => crate::configurator::ExecTarget::Lxc(target),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "runtime must be docker or lxc"})),
    };
    let cmd = format!("{} --version 2>/dev/null | head -1", component);
    let result = web::block(move || exec_target.exec(&cmd)).await;
    match result {
        Ok(Ok(output)) => {
            let version = output.trim().split_whitespace()
                .find(|w| w.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                .unwrap_or("")
                .to_string();
            HttpResponse::Ok().json(serde_json::json!({"version": version}))
        }
        _ => HttpResponse::Ok().json(serde_json::json!({"version": serde_json::Value::Null})),
    }
}

/// GET /api/containers/running — list all running containers for component install UI
async fn list_running_containers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let containers = containers::list_running_containers();
    let list: Vec<serde_json::Value> = containers.into_iter().map(|(runtime, name, image)| {
        serde_json::json!({
            "runtime": runtime,
            "name": name,
            "image": image
        })
    }).collect();
    HttpResponse::Ok().json(list)
}

// ─── AI Agent API ───

/// GET /api/ai/config — get AI configuration (keys masked)
pub async fn ai_get_config(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap();
    HttpResponse::Ok().json(config.masked())
}

/// POST /api/ai/config — save AI configuration
pub async fn ai_save_config(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config_json;
    {
        let mut config = state.ai_agent.config.lock().unwrap();

        // Update fields — only update keys if not masked values
        if let Some(v) = body.get("provider").and_then(|v| v.as_str()) {
            config.provider = v.to_string();
        }
        if let Some(v) = body.get("claude_api_key").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.claude_api_key = v.to_string();
            }
        }
        if let Some(v) = body.get("gemini_api_key").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.gemini_api_key = v.to_string();
            }
        }
        if let Some(v) = body.get("openrouter_api_key").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.openrouter_api_key = v.to_string();
            }
        }
        if let Some(v) = body.get("model").and_then(|v| v.as_str()) {
            config.model = v.to_string();
        }
        if let Some(v) = body.get("email_enabled").and_then(|v| v.as_bool()) {
            config.email_enabled = v;
        }
        if let Some(v) = body.get("email_to").and_then(|v| v.as_str()) {
            config.email_to = v.to_string();
        }
        if let Some(v) = body.get("smtp_host").and_then(|v| v.as_str()) {
            config.smtp_host = v.to_string();
        }
        if let Some(v) = body.get("smtp_port").and_then(|v| v.as_u64()) {
            config.smtp_port = v as u16;
        }
        if let Some(v) = body.get("smtp_user").and_then(|v| v.as_str()) {
            config.smtp_user = v.to_string();
        }
        if let Some(v) = body.get("smtp_pass").and_then(|v| v.as_str()) {
            if !v.contains("••••") && !v.is_empty() {
                config.smtp_pass = v.to_string();
            }
        }
        if let Some(v) = body.get("smtp_tls").and_then(|v| v.as_str()) {
            config.smtp_tls = v.to_string();
        }
        if let Some(v) = body.get("check_interval_minutes").and_then(|v| v.as_u64()) {
            config.check_interval_minutes = v as u32;
        }
        if let Some(v) = body.get("scan_schedule").and_then(|v| v.as_str()) {
            config.scan_schedule = v.to_string();
        }

        if let Err(e) = config.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
        }

        // Serialize full config (with real keys) for cluster sync
        config_json = serde_json::to_value(&*config).unwrap_or_default();
    }

    // Broadcast to all online cluster nodes in the background
    let cluster_secret = state.cluster_secret.clone();
    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::new();
    for node in nodes.iter().filter(|n| !n.is_self && n.online) {
        let url = format!("http://{}:{}/api/ai/config/sync", node.address, node.port);
        let secret = cluster_secret.clone();
        let cfg = config_json.clone();
        let c = client.clone();
        tokio::spawn(async move {
            let _ = c.post(&url)
                .header("X-WolfStack-Secret", secret)
                .json(&cfg)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
        });
    }

    HttpResponse::Ok().json(serde_json::json!({"status": "saved"}))
}

/// POST /api/ai/config/sync — receive AI config from another cluster node
pub async fn ai_sync_config(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<crate::ai::AiConfig>,
) -> HttpResponse {
    if let Err(resp) = require_cluster_auth(&req, &state) { return resp; }

    let new_config = body.into_inner();
    if let Err(e) = new_config.save() {
        warn!("Failed to save synced AI config: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e}));
    }

    // Update in-memory config
    let mut config = state.ai_agent.config.lock().unwrap();
    *config = new_config;


    HttpResponse::Ok().json(serde_json::json!({"status": "synced"}))
}

/// POST /api/ai/test-email — send a test email to verify SMTP settings
pub async fn ai_test_email(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let config = state.ai_agent.config.lock().unwrap().clone();

    if !config.email_enabled || config.email_to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Email alerts not enabled or no recipient configured"
        }));
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let version = env!("CARGO_PKG_VERSION");

    let subject = format!("[WolfStack] Test Email from {}", hostname);
    let body = format!(
        "✅ WolfStack Test Email\n\n\
         This is a test email from your WolfStack AI Agent.\n\n\
         Hostname: {}\n\
         Version: {}\n\
         Time: {}\n\n\
         If you received this, your email alert settings are working correctly.",
        hostname, version,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    match crate::ai::send_alert_email(&config, &subject, &body) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "sent",
            "message": format!("Test email sent to {}", config.email_to)
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to send: {}", e)
        })),
    }
}

/// POST /api/ai/chat — send a message to the AI agent
#[derive(Deserialize)]
pub struct AiChatRequest {
    pub message: String,
    /// The node ID the user is currently viewing (null/empty = datacenter level)
    #[serde(default)]
    pub node_id: Option<String>,
    /// The page/view the user is currently on (e.g. "dashboard", "containers", "vms", "networking")
    #[serde(default)]
    pub view: Option<String>,
    /// Friendly name of what the user is looking at (e.g. node hostname, container name)
    #[serde(default)]
    pub context_name: Option<String>,
}

pub async fn ai_chat(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiChatRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Build server context for the AI
    let server_context = {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Get local container/VM lists once (reuse for counts and names)
        let local_docker_list = crate::containers::docker_list_all();
        let local_lxc_list = crate::containers::lxc_list_all();
        let local_vm_list = state.vms.lock().unwrap().list_vms();
        let docker_count = local_docker_list.len();
        let lxc_count = local_lxc_list.len();
        let vm_count = local_vm_list.len();
        let components = crate::installer::get_all_status();

        let local_docker: Vec<String> = local_docker_list.iter().map(|c| format!("{} [{}]", c.name, c.state)).collect();
        let local_lxc: Vec<String> = local_lxc_list.iter().map(|c| format!("{} [{}]", c.name, c.state)).collect();
        let local_vms: Vec<String> = local_vm_list.iter().map(|v| format!("{} [{}]", v.name, if v.running { "running" } else { "stopped" })).collect();

        let nodes = state.cluster.get_all_nodes();

        // All nodes (including Proxmox nodes that have WolfStack agents)
        let all_online: Vec<&crate::agent::Node> = nodes.iter().filter(|n| n.online).collect();
        // PVE nodes for separate cluster grouping display
        let pve_nodes: Vec<&crate::agent::Node> = nodes.iter().filter(|n| n.node_type == "proxmox").collect();

        let node_info = all_online.iter().map(|n| {
            let mut line = format!("  - {} ({}) [{}]", n.hostname, n.address,
                if n.online { "online" } else { "offline" });
            if n.docker_count > 0 { line.push_str(&format!(" — {} Docker", n.docker_count)); }
            if n.lxc_count > 0 { line.push_str(&format!(", {} LXC", n.lxc_count)); }
            if n.vm_count > 0 { line.push_str(&format!(", {} VMs", n.vm_count)); }
            // For the local node, include actual names
            if n.is_self {
                if !local_docker.is_empty() { line.push_str(&format!("\n      Docker: {}", local_docker.join(", "))); }
                if !local_lxc.is_empty() { line.push_str(&format!("\n      LXC: {}", local_lxc.join(", "))); }
                if !local_vms.is_empty() { line.push_str(&format!("\n      VMs: {}", local_vms.join(", "))); }
            }
            line
        }).collect::<Vec<_>>().join("\n");

        // Group PVE nodes by cluster
        let mut pve_clusters: std::collections::HashMap<String, Vec<&crate::agent::Node>> = std::collections::HashMap::new();
        for n in &pve_nodes {
            let key = n.pve_cluster_name.clone()
                .or_else(|| n.cluster_name.clone())
                .unwrap_or_else(|| n.address.clone());
            pve_clusters.entry(key).or_default().push(n);
        }

        let pve_info = if pve_clusters.is_empty() {
            "None".to_string()
        } else {
            pve_clusters.iter().map(|(cluster_name, cnodes)| {
                let node_details = cnodes.iter().map(|n| {
                    let metrics_str = if let Some(ref m) = n.metrics {
                        let mem_used_gb = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let mem_total_gb = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                        let disk_info = root_disk.map(|d| {
                            let used_gb = d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let total_gb = d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            format!(", disk {:.1}/{:.1}GB", used_gb, total_gb)
                        }).unwrap_or_default();
                        format!(" — CPU {:.0}%, RAM {:.1}/{:.1}GB{}",
                            m.cpu_usage_percent, mem_used_gb, mem_total_gb, disk_info)
                    } else {
                        String::new()
                    };
                    format!("    - {} (pve_node: {}, {}) [{}] — {} VMs, {} CTs{}",
                        n.hostname, n.pve_node_name.as_deref().unwrap_or("?"),
                        n.address,
                        if n.online { "online" } else { "offline" },
                        n.vm_count, n.lxc_count, metrics_str)
                }).collect::<Vec<_>>().join("\n");
                format!("  Cluster '{}' ({} nodes):\n{}", cluster_name, cnodes.len(), node_details)
            }).collect::<Vec<_>>().join("\n")
        };

        // Build user navigation context
        let user_context = {
            let mut ctx = String::new();
            if let Some(ref nid) = body.node_id {
                if !nid.is_empty() {
                    let target_node = nodes.iter().find(|n| n.id == *nid);
                    if let Some(tn) = target_node {
                        ctx.push_str(&format!("\n\nUSER IS CURRENTLY VIEWING: Node '{}' ({})", tn.hostname, tn.address));
                        if tn.node_type == "proxmox" {
                            ctx.push_str(" [Proxmox VE node]");
                        }
                    } else {
                        ctx.push_str(&format!("\n\nUSER IS CURRENTLY VIEWING: Node ID '{}'", nid));
                    }
                } else {
                    ctx.push_str("\n\nUSER IS CURRENTLY VIEWING: Datacenter overview (all nodes)");
                }
            } else {
                ctx.push_str("\n\nUSER IS CURRENTLY VIEWING: Datacenter overview (all nodes)");
            }
            if let Some(ref view) = body.view {
                if !view.is_empty() {
                    ctx.push_str(&format!(", Page: {}", view));
                }
            }
            if let Some(ref name) = body.context_name {
                if !name.is_empty() {
                    ctx.push_str(&format!(", Context: {}", name));
                }
            }
            // Enumerate containers/VMs on the viewed node (reuse already-fetched local data)
            if body.node_id.as_ref().map(|s| !s.is_empty()).unwrap_or(false) {
                let is_self_node = nodes.iter().any(|n| n.is_self && Some(&n.id) == body.node_id.as_ref());
                if is_self_node {
                    if !local_docker.is_empty() {
                        ctx.push_str("\n\nDocker containers on this node:");
                        for name in &local_docker { ctx.push_str(&format!("\n  - {}", name)); }
                    }
                    if !local_lxc.is_empty() {
                        ctx.push_str("\n\nLXC containers on this node:");
                        for name in &local_lxc { ctx.push_str(&format!("\n  - {}", name)); }
                    }
                    if !local_vms.is_empty() {
                        ctx.push_str("\n\nVMs on this node:");
                        for name in &local_vms { ctx.push_str(&format!("\n  - {}", name)); }
                    }
                } else {
                    ctx.push_str("\n\n(Container/VM list for remote nodes is provided by the frontend target picker)");
                }
            }

            ctx.push_str("\n\nWhen the user says 'this server', 'this node', 'here', etc. they mean the node/view shown above.");
            ctx.push_str("\nThe user may be asking about a specific container, VM, or the host itself. If it's ambiguous, ask which one they mean.");
            ctx.push_str("\nWhen proposing [ACTION] fixes, set target=\"local\" for commands on the host node. The user will choose the actual target (host, container, or VM) before approving.");
            ctx
        };

        format!(
            "Hostname: {}\nLocal Docker containers: {}\nLocal LXC containers: {}\nLocal VMs: {}\n\
             Components: {}\n\nAll Nodes ({}):\n{}\n\nProxmox Clusters:\n{}{}",
            hostname, docker_count, lxc_count, vm_count,
            components.iter().map(|c| format!("{:?}: {}", c.component, if c.running { "running" } else { "stopped" })).collect::<Vec<_>>().join(", "),
            all_online.len(), node_info,
            pve_info,
            user_context,
        )
    };

    // Build cluster node list for remote command execution
    // Include ALL online nodes (including Proxmox nodes that have WolfStack agents)
    let cluster_nodes: Vec<(String, String, String, String)> = {
        let nodes = state.cluster.get_all_nodes();
        nodes.iter()
            .filter(|n| !n.is_self && n.online)
            .map(|n| {
                let url1 = format!("http://{}:{}", n.address, n.port + 1);
                let url2 = format!("http://{}:{}", n.address, n.port);
                (n.id.clone(), n.hostname.clone(), url1, url2)
            })
            .collect()
    };

    match state.ai_agent.chat(&body.message, &server_context, &cluster_nodes, &state.cluster_secret).await {
        Ok((response, actions)) => {
            let actions_json: Vec<serde_json::Value> = actions.iter().map(|a| {
                serde_json::json!({
                    "id": a.id,
                    "title": a.title,
                    "command": a.command,
                    "risk": a.risk,
                    "explanation": a.explanation,
                    "target": a.node_target,
                })
            }).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "response": response,
                "actions": actions_json,
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "error": e,
        })),
    }
}

/// POST /api/ai/action — approve or reject a proposed action.
/// Approve only marks the action as "approved" — it does NOT execute it.
/// The terminal (console.html) fetches the command via GET /api/ai/action/command
/// and sends it to the PTY shell, so the user sees it run live.
#[derive(Deserialize)]
pub struct AiActionRequest {
    pub action_id: String,
    #[serde(default = "default_true")]
    pub approved: bool,
}

fn default_true() -> bool { true }

pub async fn ai_action(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiActionRequest>,
) -> HttpResponse {
    let username = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    if !body.approved {
        match state.ai_agent.reject_action(&body.action_id, &username) {
            Ok(()) => return HttpResponse::Ok().json(serde_json::json!({ "status": "rejected" })),
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
        }
    }

    // Mark as approved (terminal will fetch and execute the command)
    {
        let mut pa = state.ai_agent.pending_actions.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        if let Some(a) = pa.iter_mut().find(|a| a.id == body.action_id) {
            if a.status != "pending" {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Action already {}", a.status)
                }));
            }
            if now - a.created_at > 600 {
                a.status = "expired".to_string();
                return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Action expired" }));
            }
            a.status = "approved".to_string();
            a.approved_by = username.clone();
            crate::ai::log_action_audit(a, "approved", &username, "");
            return HttpResponse::Ok().json(serde_json::json!({
                "status": "approved",
                "command": a.command,
            }));
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({ "error": "Action not found" }))
}

/// GET /api/ai/action/command?id=xxx — retrieve the command for an approved action (one-time, for terminal auto-exec)
pub async fn ai_action_command(
    req: HttpRequest, state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let action_id = match query.get("id") {
        Some(id) => id.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing id parameter"})),
    };

    let pa = state.ai_agent.pending_actions.lock().unwrap();
    // Only return command for approved actions (approved by the POST /api/ai/action call)
    match pa.iter().find(|a| a.id == action_id && a.status == "approved") {
        Some(a) => HttpResponse::Ok().json(serde_json::json!({
            "command": a.command,
            "title": a.title,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Action not found, not approved, or expired"
        })),
    }
}

/// POST /api/ai/action/exec — execute an approved action command on a remote node (cluster proxy)
pub async fn ai_action_exec(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiExecRequest>,
) -> HttpResponse {
    // Only allow inter-node auth (X-WolfStack-Secret) — not browser sessions
    let secret_header = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::validate_cluster_secret(secret_header, &state.cluster_secret)
        && !crate::auth::validate_cluster_secret(secret_header, crate::auth::default_cluster_secret())
    {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Cluster auth required"}));
    }

    match crate::ai::execute_action_command(&body.command) {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "output": output })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/ai/exec — execute a safe read-only command (used by cluster proxy)
#[derive(Deserialize)]
pub struct AiExecRequest {
    pub command: String,
}

pub async fn ai_exec(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<AiExecRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    match crate::ai::execute_safe_command(&body.command) {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({
            "output": output,
            "exit_code": 0,
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "error": e,
        })),
    }
}

/// GET /api/ai/status — agent status and last health check
/// GET /api/system-check — runs the dependency audit on this node
/// and returns a structured report for the Settings UI.
pub async fn system_check_run(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let ai_enabled = state.ai_agent.config.lock().unwrap().is_configured();
    // Run both audits off the async executor — they shell out to lsmod,
    // systemctl, docker info, ss, journalctl, pgrep etc. and we don't
    // want actix's async runtime parked on them. Run them in parallel
    // so the user-visible latency matches the slower of the two, not
    // the sum.
    let deps_fut = web::block(crate::systemcheck::run_checks);
    let sec_fut  = web::block(crate::security::run_security_checks);
    let (deps_res, sec_res) = tokio::join!(deps_fut, sec_fut);
    let mut checks = match deps_res {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": format!("System check failed: {}", e) })),
    };
    // Cluster-scoped checks (cross-node WolfNet IP conflicts) need
    // AppState for the cached remote topologies. Runs synchronously
    // here — cheap because it just reads in-memory topology snapshots.
    let mut cluster_checks = crate::security::run_cluster_checks(&state);
    checks.append(&mut cluster_checks);

    match sec_res {
        Ok(mut v) => checks.append(&mut v),
        Err(e) => {
            // Security scan error doesn't fail the whole endpoint —
            // surface it as a single Warning entry so the user sees
            // why the Security category looks thin. Any other outcome
            // would hide a real issue.
            checks.push(crate::systemcheck::DependencyCheck {
                name: "Security scan errored".into(),
                category: "Security".into(),
                status: crate::systemcheck::DepStatus::Warning,
                version: None,
                detail: format!("Security scan task failed: {}. Non-fatal — dependency checks above are still accurate.", e),
                install_hint: None,
                ai_helpful: false,
                install_package: None,
            });
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "checks": checks,
        "ai_enabled": ai_enabled,
        "hostname": hostname::get().ok().and_then(|h| h.into_string().ok()),
    }))
}

/// POST /api/system-check/ask-ai — given a specific failing dependency,
/// ask the AI agent for tailored remediation advice. Body: `{ name, detail, install_hint }`.
#[derive(serde::Deserialize)]
pub struct SystemCheckAskAi {
    pub name: String,
    pub detail: String,
    pub install_hint: Option<String>,
}
pub async fn system_check_ask_ai(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<SystemCheckAskAi>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !state.ai_agent.config.lock().unwrap().is_configured() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "AI agent is not configured — enable it in Settings → AI Agent first"
        }));
    }
    // Include a few lines of host context so the AI gives distro-
    // specific advice. detect_distro() returns an enum with no Display
    // impl so format with {:?}.
    let distro = format!("{:?}", crate::installer::detect_distro());
    let os_release = std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("PRETTY_NAME=") || l.starts_with("ID="))
        .collect::<Vec<_>>()
        .join(" | ");
    let prompt = format!(
        "WolfStack system check found a problem with `{}`.\n\
         Detail: {}\n\
         Suggested fix already shown to admin: {}\n\
         Host: {} ({})\n\
         Architecture: {}\n\n\
         Give concrete remediation steps the admin can run *right now*. \
         If the dependency simply isn't supported on this OS/arch, say so clearly \
         and suggest the closest workaround. Keep it short and distro-aware.",
        body.name,
        body.detail,
        body.install_hint.clone().unwrap_or_else(|| "(none)".into()),
        os_release,
        distro,
        std::env::consts::ARCH,
    );
    match state.ai_agent.analyze_issue(&prompt).await {
        Some(advice) => HttpResponse::Ok().json(serde_json::json!({ "advice": advice })),
        None => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "AI agent did not respond — check provider API key and model in Settings"
        })),
    }
}

pub async fn ai_status(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap();
    let last_check = state.ai_agent.last_health_check.lock().unwrap().clone();
    let alert_count = state.ai_agent.alerts.lock().unwrap().len();
    let history_count = state.ai_agent.chat_history.lock().unwrap().len();
    let pending_actions: Vec<serde_json::Value> = {
        let pa = state.ai_agent.pending_actions.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        pa.iter()
            .filter(|a| a.status == "pending" && (now - a.created_at) < 600)
            .map(|a| serde_json::json!({
                "id": a.id, "title": a.title, "command": a.command,
                "risk": a.risk, "explanation": a.explanation,
                "target": a.node_target, "created_at": a.created_at,
            }))
            .collect()
    };

    HttpResponse::Ok().json(serde_json::json!({
        "configured": config.is_configured(),
        "provider": config.provider,
        "model": config.model,
        "last_health_check": last_check,
        "alert_count": alert_count,
        "chat_message_count": history_count,
        "knowledge_base_size": state.ai_agent.knowledge_base.len(),
        "pending_actions": pending_actions,
    }))
}

/// GET /api/ai/alerts — historical alerts
pub async fn ai_alerts(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let alerts = state.ai_agent.alerts.lock().unwrap().clone();
    HttpResponse::Ok().json(alerts)
}

/// GET /api/ai/models?provider=claude|gemini — list available models
pub async fn ai_models(
    req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.ai_agent.config.lock().unwrap().clone();
    let provider = query.get("provider").map(|s| s.as_str()).unwrap_or(&config.provider);

    // Local AI: fetch models from the local server's /v1/models endpoint
    if provider == "local" {
        if config.local_url.is_empty() {
            return HttpResponse::Ok().json(serde_json::json!({ "models": ["llama3", "mistral", "codellama", "phi3", "gemma2", "qwen2"], "note": "Enter your local AI URL and save to auto-detect models" }));
        }
        let base = config.local_url.trim_end_matches('/');
        let url = if base.ends_with("/v1") { format!("{}/models", base) } else { format!("{}/v1/models", base) };
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).danger_accept_invalid_certs(true).build().unwrap_or_default();
        let mut req_builder = client.get(&url);
        if !config.local_api_key.is_empty() {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", config.local_api_key));
        }
        match req_builder.send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let models: Vec<String> = data["data"].as_array()
                        .or_else(|| data["models"].as_array())
                        .map(|arr| arr.iter().filter_map(|m| m["id"].as_str().or_else(|| m["name"].as_str()).or_else(|| m.as_str()).map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    if !models.is_empty() {
                        return HttpResponse::Ok().json(serde_json::json!({ "models": models }));
                    }
                }
                HttpResponse::Ok().json(serde_json::json!({ "models": ["llama3", "mistral", "codellama"], "note": "Could not parse model list — showing defaults" }))
            }
            Ok(resp) => HttpResponse::Ok().json(serde_json::json!({ "models": ["llama3", "mistral"], "error": format!("Server returned {}", resp.status()) })),
            Err(e) => HttpResponse::Ok().json(serde_json::json!({ "models": ["llama3", "mistral"], "error": format!("Cannot reach {}: {}", url, e) })),
        }
    } else {
        let api_key = match provider {
            "gemini" => &config.gemini_api_key,
            "openrouter" => &config.openrouter_api_key,
            _ => &config.claude_api_key,
        };
        if api_key.is_empty() {
            return HttpResponse::Ok().json(serde_json::json!({ "models": [], "error": "No API key configured for this provider" }));
        }
        match state.ai_agent.list_models(provider, api_key).await {
            Ok(models) => HttpResponse::Ok().json(serde_json::json!({ "models": models })),
            Err(e) => HttpResponse::Ok().json(serde_json::json!({ "models": [], "error": e })),
        }
    }
}

// ─── Networking API ───

/// GET /api/networking/interfaces — list all network interfaces
pub async fn net_list_interfaces(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::list_interfaces())
}

/// GET /api/networking/dns — get DNS configuration
pub async fn net_get_dns(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_dns())
}

#[derive(Deserialize)]
pub struct DnsSetRequest {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
}

/// POST /api/networking/dns — set DNS configuration
pub async fn net_set_dns(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<DnsSetRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::set_dns(body.nameservers.clone(), body.search_domains.clone()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet — get WolfNet overlay status
pub async fn net_get_wolfnet(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_wolfnet_status())
}

/// GET /api/networking/wolfnet/config — get raw WolfNet config
pub async fn net_get_wolfnet_config(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::get_wolfnet_config() {
        Ok(config) => HttpResponse::Ok().json(serde_json::json!({"config": config})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetConfigSave {
    pub config: String,
}

/// PUT /api/networking/wolfnet/config — save raw WolfNet config
pub async fn net_save_wolfnet_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetConfigSave>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::save_wolfnet_config(&body.config) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetAddPeer {
    pub name: String,
    pub endpoint: Option<String>,
    pub ip: Option<String>,
    pub public_key: Option<String>,
}

/// POST /api/networking/wolfnet/peers — add a WolfNet peer
pub async fn net_add_wolfnet_peer(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetAddPeer>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let endpoint = body.endpoint.as_deref().unwrap_or("");
    let ip = body.ip.as_deref().unwrap_or("");
    let public_key = body.public_key.as_deref();
    match networking::add_wolfnet_peer(&body.name, endpoint, ip, public_key) {
        Ok(msg) => {
            let local_info = networking::get_wolfnet_local_info();
            HttpResponse::Ok().json(serde_json::json!({
                "message": msg,
                "local_info": local_info,
            }))
        },
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/local-info — get this node's WolfNet identity
pub async fn net_get_wolfnet_local_info(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::get_wolfnet_local_info() {
        Some(info) => HttpResponse::Ok().json(info),
        None => HttpResponse::Ok().json(serde_json::json!({"error": "WolfNet not running or status unavailable"})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetRemovePeer {
    pub name: String,
}

/// DELETE /api/networking/wolfnet/peers — remove a WolfNet peer
pub async fn net_remove_wolfnet_peer(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetRemovePeer>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::remove_wolfnet_peer(&body.name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WolfNetAction {
    pub action: String,
}

/// POST /api/networking/wolfnet/action — start/stop/restart WolfNet
pub async fn net_wolfnet_action(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfNetAction>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let allowed = ["start", "stop", "restart", "enable", "disable"];
    if !allowed.contains(&body.action.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid action"}));
    }
    match networking::wolfnet_service_action(&body.action) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/invite — generate a WolfNet invite token
pub async fn net_wolfnet_invite(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::generate_wolfnet_invite() {
        Ok(invite) => HttpResponse::Ok().json(invite),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wolfnet/status-full — get full status including live peers
pub async fn net_wolfnet_status_full(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::get_wolfnet_status_full())
}

#[derive(Deserialize)]
pub struct IpAction {
    pub address: String,
    pub prefix: u32,
}

/// POST /api/networking/interfaces/{name}/ip — add an IP address
pub async fn net_add_ip(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<IpAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::add_ip(&iface, &body.address, body.prefix) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/interfaces/{name}/ip — remove an IP address
pub async fn net_remove_ip(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<IpAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::remove_ip(&iface, &body.address, body.prefix) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct InterfaceStateAction {
    pub up: bool,
}

/// POST /api/networking/interfaces/{name}/state — bring interface up/down
pub async fn net_set_state(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<InterfaceStateAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::set_interface_state(&iface, body.up) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct MtuAction {
    pub mtu: u32,
}

/// POST /api/networking/interfaces/{name}/mtu — set interface MTU
pub async fn net_set_mtu(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<MtuAction>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let iface = path.into_inner();
    match networking::set_mtu(&iface, body.mtu) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct CreateVlanRequest {
    pub parent: String,
    pub vlan_id: u32,
    pub name: Option<String>,
}

/// POST /api/networking/vlans — create a VLAN
pub async fn net_create_vlan(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateVlanRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match networking::create_vlan(&body.parent, body.vlan_id, body.name.as_deref()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/vlans/{name} — delete a VLAN
pub async fn net_delete_vlan(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    match networking::delete_vlan(&name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── IP Mapping API ───

#[derive(Deserialize)]
pub struct CreateIpMappingRequest {
    pub public_ip: String,
    pub wolfnet_ip: String,
    pub ports: Option<String>,
    pub dest_ports: Option<String>,
    pub protocol: Option<String>,
    pub label: Option<String>,
}

/// GET /api/networking/ip-mappings — list all IP mappings
pub async fn net_list_ip_mappings(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(networking::list_ip_mappings())
}

/// POST /api/networking/ip-mappings — create an IP mapping
pub async fn net_add_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateIpMappingRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let protocol = body.protocol.as_deref().unwrap_or("all");
    let label = body.label.as_deref().unwrap_or("");
    match networking::add_ip_mapping(
        &body.public_ip,
        &body.wolfnet_ip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Mapped {} → {}", mapping.public_ip, mapping.wolfnet_ip),
            "mapping": mapping,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/networking/ip-mappings/{id} — remove an IP mapping
pub async fn net_remove_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match networking::remove_ip_mapping(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// PUT /api/networking/ip-mappings/{id} — update an existing mapping
pub async fn net_update_ip_mapping(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CreateIpMappingRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    let protocol = body.protocol.as_deref().unwrap_or("all");
    let label = body.label.as_deref().unwrap_or("");
    match networking::update_ip_mapping(
        &id,
        &body.public_ip,
        &body.wolfnet_ip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(mapping),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/networking/available-ips — detect public + wolfnet IPs for the UI
pub async fn net_available_ips(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(serde_json::json!({
        "public_ips": networking::detect_public_ips(),
        "wolfnet_ips": networking::detect_wolfnet_ips(),
    }))
}

/// GET /api/networking/listening-ports — ports currently in use on server
pub async fn net_listening_ports(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(serde_json::json!({
        "listening": networking::get_listening_ports(),
        "blocked": networking::get_blocked_ports(),
    }))
}

// ─── WireGuard Bridge API ───

/// GET /api/networking/wireguard — list all bridges
pub async fn net_wireguard_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let bridges = state.wireguard_bridges.read().unwrap();
    let installed = networking::wireguard_installed();
    let list: Vec<serde_json::Value> = bridges.values().map(|b| {
        serde_json::json!({
            "cluster": b.cluster,
            "enabled": b.enabled,
            "listen_port": b.listen_port,
            "public_key": b.public_key,
            "bridge_subnet": b.bridge_subnet(),
            "server_ip": b.server_ip,
            "wolfnet_subnet": b.wolfnet_subnet,
            "interface": b.interface_name(),
            "client_count": b.clients.len(),
        })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "installed": installed,
        "bridges": list,
    }))
}

/// GET /api/networking/wireguard/{cluster} — get bridge details + clients
pub async fn net_wireguard_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let cluster = path.into_inner();
    let bridges = state.wireguard_bridges.read().unwrap();
    match bridges.get(&cluster) {
        Some(bridge) => {
            let clients: Vec<serde_json::Value> = bridge.clients.iter().map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "name": c.name,
                    "public_key": c.public_key,
                    "assigned_ip": c.assigned_ip,
                    "created_at": c.created_at,
                    "enabled": c.enabled,
                })
            }).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "cluster": bridge.cluster,
                "enabled": bridge.enabled,
                "listen_port": bridge.listen_port,
                "public_key": bridge.public_key,
                "bridge_subnet": bridge.bridge_subnet(),
                "server_ip": bridge.server_ip,
                "wolfnet_subnet": bridge.wolfnet_subnet,
                "interface": bridge.interface_name(),
                "clients": clients,
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "No bridge for this cluster"})),
    }
}

#[derive(Deserialize)]
pub struct WgInitRequest {
    #[serde(default = "default_wg_port")]
    listen_port: u16,
}
fn default_wg_port() -> u16 { 51820 }

/// POST /api/networking/wireguard/{cluster}/init — initialize bridge
pub async fn net_wireguard_init(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WgInitRequest>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let cluster = path.into_inner();
    match networking::init_wireguard_bridge(&cluster, body.listen_port) {
        Ok(bridge) => {
            let mut bridges = state.wireguard_bridges.write().unwrap();
            bridges.insert(cluster, bridge.clone());
            HttpResponse::Ok().json(serde_json::json!({
                "status": "ok",
                "bridge_subnet": bridge.bridge_subnet(),
                "listen_port": bridge.listen_port,
                "public_key": bridge.public_key,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WgToggleRequest {
    enabled: bool,
}

/// POST /api/networking/wireguard/{cluster}/toggle — enable/disable bridge
pub async fn net_wireguard_toggle(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WgToggleRequest>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let cluster = path.into_inner();
    match networking::toggle_wireguard_bridge(&cluster, body.enabled) {
        Ok(msg) => {
            // Reload state
            let fresh = networking::load_wireguard_bridges();
            *state.wireguard_bridges.write().unwrap() = fresh;
            HttpResponse::Ok().json(serde_json::json!({"status": msg}))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /api/networking/wireguard/{cluster} — delete bridge entirely
pub async fn net_wireguard_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let cluster = path.into_inner();
    match networking::delete_wireguard_bridge(&cluster) {
        Ok(msg) => {
            state.wireguard_bridges.write().unwrap().remove(&cluster);
            HttpResponse::Ok().json(serde_json::json!({"status": msg}))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct WgAddClientRequest {
    name: String,
}

/// POST /api/networking/wireguard/{cluster}/clients — add client
pub async fn net_wireguard_add_client(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WgAddClientRequest>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let cluster = path.into_inner();
    match networking::add_wireguard_client(&cluster, &body.name) {
        Ok((client, conf)) => {
            // Reload state
            let fresh = networking::load_wireguard_bridges();
            *state.wireguard_bridges.write().unwrap() = fresh;
            HttpResponse::Ok().json(serde_json::json!({
                "client": {
                    "id": client.id,
                    "name": client.name,
                    "assigned_ip": client.assigned_ip,
                    "created_at": client.created_at,
                },
                "config": conf,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /api/networking/wireguard/{cluster}/clients/{id} — remove client
pub async fn net_wireguard_remove_client(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let (cluster, client_id) = path.into_inner();
    match networking::remove_wireguard_client(&cluster, &client_id) {
        Ok(msg) => {
            let fresh = networking::load_wireguard_bridges();
            *state.wireguard_bridges.write().unwrap() = fresh;
            HttpResponse::Ok().json(serde_json::json!({"status": msg}))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/networking/wireguard/{cluster}/clients/{id}/config — download client config
pub async fn net_wireguard_client_config(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let (cluster, client_id) = path.into_inner();
    match networking::get_client_config(&cluster, &client_id) {
        Ok(conf) => HttpResponse::Ok()
            .content_type("text/plain")
            .insert_header(("Content-Disposition", format!("attachment; filename=\"wg-{}-{}.conf\"", cluster, client_id)))
            .body(conf),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": e})),
    }
}

// ─── Backup API ───

#[derive(Deserialize)]
pub struct CreateBackupRequest {
    /// Optional specific target — if omitted, backup everything
    pub target: Option<backup::BackupTarget>,
    pub storage: backup::BackupStorage,
    /// Cluster name override — sent by frontend so remote nodes use the correct cluster
    #[serde(default)]
    pub cluster_name: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub frequency: backup::BackupFrequency,
    pub time: String,
    pub retention: u32,
    pub backup_all: bool,
    #[serde(default)]
    pub targets: Vec<backup::BackupTarget>,
    pub storage: backup::BackupStorage,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// GET /api/backups — list all backup entries
pub async fn backup_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_backups())
}

/// POST /api/backups — create a backup now
pub async fn backup_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateBackupRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    // If PBS storage selected, merge in saved secrets (frontend doesn't send them)
    let mut storage = body.storage.clone();
    if storage.storage_type == backup::StorageType::Pbs {
        let saved = backup::load_pbs_config();
        if storage.pbs_password.is_empty() && !saved.pbs_password.is_empty() {
            storage.pbs_password = saved.pbs_password;
        }
        if storage.pbs_token_secret.is_empty() && !saved.pbs_token_secret.is_empty() {
            storage.pbs_token_secret = saved.pbs_token_secret;
        }
        // Also fill in any missing connection details from saved config
        if storage.pbs_server.is_empty() { storage.pbs_server = saved.pbs_server; }
        if storage.pbs_datastore.is_empty() { storage.pbs_datastore = saved.pbs_datastore; }
        if storage.pbs_user.is_empty() { storage.pbs_user = saved.pbs_user; }
        if storage.pbs_token_name.is_empty() { storage.pbs_token_name = saved.pbs_token_name; }
        if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = saved.pbs_fingerprint; }
        if storage.pbs_namespace.is_empty() { storage.pbs_namespace = saved.pbs_namespace; }
    }
    let entries = backup::create_backup(body.target.clone(), storage);
    let success_count = entries.iter().filter(|e| e.status == backup::BackupStatus::Completed).count();
    let fail_count = entries.iter().filter(|e| e.status == backup::BackupStatus::Failed).count();
    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("{} backup(s) completed, {} failed", success_count, fail_count),
        "entries": entries,
    }))
}

/// POST /api/backups/stream — run backup with SSE log output
pub async fn backup_stream(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateBackupRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let mut storage = body.storage.clone();
    if storage.storage_type == backup::StorageType::Pbs {
        let saved = backup::load_pbs_config();
        if storage.pbs_password.is_empty() && !saved.pbs_password.is_empty() {
            storage.pbs_password = saved.pbs_password;
        }
        if storage.pbs_token_secret.is_empty() && !saved.pbs_token_secret.is_empty() {
            storage.pbs_token_secret = saved.pbs_token_secret;
        }
        if storage.pbs_server.is_empty() { storage.pbs_server = saved.pbs_server; }
        if storage.pbs_datastore.is_empty() { storage.pbs_datastore = saved.pbs_datastore; }
        if storage.pbs_user.is_empty() { storage.pbs_user = saved.pbs_user; }
        if storage.pbs_token_name.is_empty() { storage.pbs_token_name = saved.pbs_token_name; }
        if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = saved.pbs_fingerprint; }
        if storage.pbs_namespace.is_empty() { storage.pbs_namespace = saved.pbs_namespace; }
    }

    let target = body.target.clone();
    let cluster_name = Some(body.cluster_name.clone()
        .unwrap_or_else(|| state.cluster.get_self_cluster_name()));

    // Use tokio mpsc so we can await recv() without blocking the runtime
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);

    // Bridge: backup code uses std::sync::mpsc, so we bridge to tokio channel
    let (std_tx, std_rx) = std::sync::mpsc::channel::<String>();

    // Spawn the backup in a blocking thread using std channel
    std::thread::spawn(move || {
        backup::create_backup_with_log(target, storage, std_tx, cluster_name);
    });

    // Bridge thread: reads from std channel and forwards to tokio channel
    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = std_rx.recv() {
            if tx.blocking_send(msg).is_err() { break; }
        }
    });

    // Stream SSE events from the tokio channel
    let stream = async_stream::stream! {
        while let Some(msg) = rx.recv().await {
            let event = format!("data: {}\n\n", msg.replace('\n', "\ndata: "));
            yield Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(event));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

/// POST /api/backups/{id}/restore/stream — restore with SSE progress
pub async fn backup_restore_stream(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    let overwrite = query.get("overwrite").map(|v| v == "true").unwrap_or(false);

    // Check for container existence before streaming (to return 409 synchronously)
    {
        let config = backup::load_config();
        if let Some(entry) = config.entries.iter().find(|e| e.id == id) {
            if entry.target.target_type == backup::BackupTargetType::Docker && !overwrite {
                let check = std::process::Command::new("docker")
                    .args(["container", "inspect", &entry.target.name])
                    .output();
                if check.map(|o| o.status.success()).unwrap_or(false) {
                    return HttpResponse::Conflict().json(serde_json::json!({
                        "error": "container_exists",
                        "container": entry.target.name,
                        "message": format!("Container '{}' already exists. Overwrite?", entry.target.name)
                    }));
                }
            }
        }
    }

    let (std_tx, std_rx) = std::sync::mpsc::channel::<String>();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);

    std::thread::spawn(move || {
        let result = backup::restore_by_id_with_log(&id, overwrite, std_tx.clone());
        match result {
            Ok(msg) => { let _ = std_tx.send(format!("RESULT:OK:{}", msg)); }
            Err(e) => { let _ = std_tx.send(format!("RESULT:ERR:{}", e)); }
        }
    });

    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = std_rx.recv() {
            if tx.blocking_send(msg).is_err() { break; }
        }
    });

    let stream = async_stream::stream! {
        while let Some(msg) = rx.recv().await {
            let event = format!("data: {}\n\n", msg.replace('\n', "\ndata: "));
            yield Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(event));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

/// DELETE /api/backups/{id} — delete a backup entry + file
pub async fn backup_delete(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::delete_backup(&path.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/backups/{id}/restore — restore from a backup
pub async fn backup_restore(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let overwrite = query.get("overwrite").map(|v| v == "true").unwrap_or(false);
    match backup::restore_by_id(&path.into_inner(), overwrite) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) if e.starts_with("CONTAINER_EXISTS:") => {
            let name = e.strip_prefix("CONTAINER_EXISTS:").unwrap_or("");
            HttpResponse::Conflict().json(serde_json::json!({
                "error": "container_exists",
                "container": name,
                "message": format!("Container '{}' already exists. Overwrite?", name)
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/backups/targets — list available backup targets
pub async fn backup_targets(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_available_targets())
}

/// GET /api/backups/schedules — list schedules
pub async fn backup_schedules_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(backup::list_schedules())
}

/// POST /api/backups/test-storage — try to set up the destination (mount
/// NFS/SMB, create local dir, etc.) without actually backing anything up.
/// Lets the UI pre-validate a schedule before saving it and surface a
/// MISSING_PACKAGE marker at save time — otherwise the user only sees
/// failures hours later in the backup history.
#[derive(Deserialize)]
pub struct TestStorageRequest {
    pub storage: backup::BackupStorage,
}

pub async fn backup_test_storage(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<TestStorageRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::test_storage(&body.storage) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// POST /api/backups/schedules — create or update a schedule
pub async fn backup_schedule_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<CreateScheduleRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let schedule = backup::BackupSchedule {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        frequency: body.frequency.clone(),
        time: body.time.clone(),
        retention: body.retention,
        backup_all: body.backup_all,
        targets: body.targets.clone(),
        storage: body.storage.clone(),
        enabled: body.enabled,
        last_run: String::new(),
    };
    match backup::save_schedule(schedule) {
        Ok(s) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Schedule '{}' created", s.name),
            "schedule": s,
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/backups/schedules/{id} — delete a schedule
pub async fn backup_schedule_delete(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match backup::delete_schedule(&path.into_inner()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/backups/import — receive a backup from remote node
pub async fn backup_import(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Bytes,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let filename = query.get("filename")
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("import-{}.tar.gz", chrono::Utc::now().timestamp()));
    match backup::import_backup(&body, &filename) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── Proxmox Backup Server (PBS) API ───

/// GET /api/backups/pbs/status — check PBS connectivity
pub async fn pbs_status(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    HttpResponse::Ok().json(backup::check_pbs_status(&config))
}

/// GET /api/backups/pbs/snapshots — list all PBS snapshots, enriched with container details
pub async fn pbs_snapshots(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    match backup::list_pbs_snapshots(&config) {
        Ok(snapshots) => {
            // Enrich ct/vm snapshots with local container/VM details
            let enriched = backup::enrich_pbs_snapshots(snapshots);
            HttpResponse::Ok().json(enriched)
        },
        Err(e) => {
            eprintln!("PBS snapshot list failed: {}", e);
            HttpResponse::Ok().json(serde_json::json!([]))
        },
    }
}

#[derive(Deserialize)]
pub struct PbsRestoreRequest {
    pub snapshot: String,
    pub archive: String,
    #[serde(default = "default_pbs_target_dir")]
    pub target_dir: String,
    #[serde(default)]
    pub overwrite: bool,
}
fn default_pbs_target_dir() -> String { "/var/lib/wolfstack/restored".to_string() }

/// POST /api/backups/pbs/restore — restore a PBS snapshot (runs in background)
pub async fn pbs_restore(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<PbsRestoreRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    // Check if a restore is already running (auto-expire after 30 min)
    {
        let mut progress = state.pbs_restore_progress.lock().unwrap();
        let stale = progress.started_at
            .map(|t| t.elapsed().as_secs() > 1800)
            .unwrap_or(true);
        if progress.active && !progress.finished && !stale {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "A restore is already in progress",
                "snapshot": progress.snapshot,
            }));
        }
        // Clear stale or finished state
        if stale || progress.finished {
            *progress = PbsRestoreProgress::default();
        }
    }

    let config = backup::load_pbs_config();
    let snapshot = body.snapshot.clone();
    let archive = body.archive.clone();
    let target_dir = body.target_dir.clone();
    let overwrite = body.overwrite;

    // Reset progress state
    {
        let mut progress = state.pbs_restore_progress.lock().unwrap();
        *progress = PbsRestoreProgress {
            active: true,
            snapshot: snapshot.clone(),
            progress_text: "Starting restore...".to_string(),
            percentage: Some(0.0),
            finished: false,
            success: None,
            message: String::new(),
            started_at: Some(std::time::Instant::now()),
        };
    }

    // Spawn background thread
    let state_clone = state.clone();
    std::thread::spawn(move || {
        match backup::restore_from_pbs_with_progress(&config, &snapshot, &archive, &target_dir, |text, pct| {
            if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                progress.progress_text = text;
                progress.percentage = pct;
            }
        }, overwrite) {
            Ok(msg) => {
                if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                    progress.active = false;
                    progress.finished = true;
                    progress.success = Some(true);
                    progress.message = msg;
                    progress.percentage = Some(100.0);
                    progress.progress_text = "Restore complete!".to_string();
                }
            }
            Err(ref e) if e == "TARGET_EXISTS" => {
                if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                    progress.active = false;
                    progress.finished = true;
                    progress.success = Some(false);
                    progress.message = "TARGET_EXISTS".to_string();
                    progress.progress_text = "Target already has files from a previous restore".to_string();
                }
            }
            Err(e) => {
                if let Ok(mut progress) = state_clone.pbs_restore_progress.lock() {
                    progress.active = false;
                    progress.finished = true;
                    progress.success = Some(false);
                    progress.message = e;
                    progress.progress_text = "Restore failed".to_string();
                }
            }
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "status": "started",
        "message": "Restore started in background",
    }))
}

/// GET /api/backups/pbs/restore/progress — poll restore progress
pub async fn pbs_restore_progress(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let progress = state.pbs_restore_progress.lock().unwrap().clone();
    HttpResponse::Ok().json(progress)
}

/// GET /api/backups/pbs/config — get PBS configuration
pub async fn pbs_config_get(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    // Return config without the token secret for security
    HttpResponse::Ok().json(serde_json::json!({
        "pbs_server": config.pbs_server,
        "pbs_datastore": config.pbs_datastore,
        "pbs_user": config.pbs_user,
        "pbs_token_name": config.pbs_token_name,
        "pbs_fingerprint": config.pbs_fingerprint,
        "pbs_namespace": config.pbs_namespace,
        "has_token_secret": !config.pbs_token_secret.is_empty(),
        "has_password": !config.pbs_password.is_empty(),
    }))
}

#[derive(Deserialize)]
pub struct PbsConfigRequest {
    pub pbs_server: String,
    pub pbs_datastore: String,
    pub pbs_user: String,
    #[serde(default)]
    pub pbs_token_name: String,
    #[serde(default)]
    pub pbs_token_secret: String,
    #[serde(default)]
    pub pbs_password: String,
    #[serde(default)]
    pub pbs_fingerprint: String,
    #[serde(default)]
    pub pbs_namespace: String,
}

/// GET /api/backups/pbs/config/full — return PBS config INCLUDING secrets (for node-to-node copy)
pub async fn pbs_config_get_full(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let config = backup::load_pbs_config();
    HttpResponse::Ok().json(serde_json::json!({
        "pbs_server": config.pbs_server,
        "pbs_datastore": config.pbs_datastore,
        "pbs_user": config.pbs_user,
        "pbs_token_name": config.pbs_token_name,
        "pbs_token_secret": config.pbs_token_secret,
        "pbs_password": config.pbs_password,
        "pbs_fingerprint": config.pbs_fingerprint,
        "pbs_namespace": config.pbs_namespace,
    }))
}

/// POST /api/backups/pbs/config — save PBS configuration
pub async fn pbs_config_save(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<PbsConfigRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    // Preserve existing secrets if the user didn't re-enter them
    let existing = backup::load_pbs_config();
    let storage = backup::BackupStorage {
        storage_type: backup::StorageType::Pbs,
        pbs_server: body.pbs_server.clone(),
        pbs_datastore: body.pbs_datastore.clone(),
        pbs_user: body.pbs_user.clone(),
        pbs_token_name: body.pbs_token_name.clone(),
        pbs_token_secret: if body.pbs_token_secret.is_empty() {
            existing.pbs_token_secret
        } else {
            body.pbs_token_secret.clone()
        },
        pbs_password: if body.pbs_password.is_empty() {
            existing.pbs_password
        } else {
            body.pbs_password.clone()
        },
        pbs_fingerprint: body.pbs_fingerprint.clone(),
        pbs_namespace: body.pbs_namespace.clone(),
        ..backup::BackupStorage::default()
    };
    match backup::save_pbs_config(&storage) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "PBS configuration saved",
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

// ─── Wolfram Memory Compression ───

/// GET /api/wolfram/status — check if wolfram is installed and read stats
pub async fn wolfram_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let installed = std::path::Path::new("/usr/local/bin/wolfram").exists();
    let service_active = Command::new("systemctl")
        .args(["is-active", "wolfram"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);
    let service_enabled = Command::new("systemctl")
        .args(["is-enabled", "wolfram"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
        .unwrap_or(false);

    let version = if installed {
        Command::new("/usr/local/bin/wolfram")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // Output is typically "wolfram X.Y.Z" — extract version
                s.split_whitespace().last().map(|v| v.to_string())
            })
    } else {
        None
    };

    let stats: Option<serde_json::Value> = if service_active {
        std::fs::read_to_string("/var/lib/wolfram/stats.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    HttpResponse::Ok().json(serde_json::json!({
        "installed": installed,
        "active": service_active,
        "enabled": service_enabled,
        "version": version,
        "stats": stats,
    }))
}

/// POST /api/wolfram/install — install wolfram via the install script
pub async fn wolfram_install(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    match web::block(|| {
        let output = Command::new("sh")
            .args(["-c", "curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfram/master/install.sh | sh"])
            .output();
        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if o.status.success() {
                    Ok(format!("{}\n{}", stdout, stderr))
                } else {
                    Err(format!("Install failed (exit {}): {}\n{}", o.status.code().unwrap_or(-1), stdout, stderr))
                }
            }
            Err(e) => Err(format!("Failed to run installer: {}", e)),
        }
    }).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

/// POST /api/wolfram/uninstall — remove wolfram
pub async fn wolfram_uninstall(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    match web::block(|| {
        // Stop service, disable, remove binary and service file
        let _ = Command::new("systemctl").args(["stop", "wolfram"]).output();
        let _ = Command::new("systemctl").args(["disable", "wolfram"]).output();
        let _ = std::fs::remove_file("/usr/local/bin/wolfram");
        let _ = std::fs::remove_file("/etc/systemd/system/wolfram.service");
        let _ = Command::new("systemctl").arg("daemon-reload").output();
        Ok::<_, String>("Wolfram uninstalled".to_string())
    }).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct WolframActionRequest {
    pub action: String,
}

/// POST /api/wolfram/action — start/stop/restart wolfram service
pub async fn wolfram_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<WolframActionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let action = match body.action.as_str() {
        "start" | "stop" | "restart" | "enable" | "disable" => body.action.as_str(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid action"})),
    };

    match Command::new("systemctl").args([action, "wolfram"]).output() {
        Ok(o) if o.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({"ok": true}))
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": err}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

/// GET /api/wolfram/config — read /etc/wolfram/config.toml
pub async fn wolfram_config_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let content = std::fs::read_to_string("/etc/wolfram/config.toml").unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({"config": content}))
}

#[derive(Deserialize)]
pub struct WolframConfigSaveRequest {
    pub config: String,
}

/// POST /api/wolfram/config — write /etc/wolfram/config.toml
pub async fn wolfram_config_save(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<WolframConfigSaveRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let _ = std::fs::create_dir_all("/etc/wolfram");
    match std::fs::write("/etc/wolfram/config.toml", &body.config) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

// ─── Ceph Cluster API ───

/// GET /api/ceph/status — full cluster status
pub async fn ceph_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(crate::ceph::get_cluster_status())
}

/// GET /api/ceph/install-status — check what ceph components are installed
pub async fn ceph_install_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(crate::ceph::get_install_status())
}

/// GET /api/ceph/devices — list available devices for OSD creation
pub async fn ceph_devices(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::get_available_devices() {
        Ok(devices) => HttpResponse::Ok().json(devices),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// POST /api/ceph/install — install ceph packages
pub async fn ceph_install(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match web::block(|| crate::ceph::install_ceph()).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct CephBootstrapRequest {
    #[serde(default)]
    pub cluster_name: String,
    pub public_network: String,
    pub mon_ip: String,
}

/// POST /api/ceph/bootstrap — bootstrap a new cluster
pub async fn ceph_bootstrap(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CephBootstrapRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::bootstrap_cluster(&body.cluster_name, &body.public_network, &body.mon_ip) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephCreatePoolRequest {
    pub name: String,
    #[serde(default)]
    pub pg_num: u32,
    #[serde(default = "default_pool_type")]
    pub pool_type: String,
    #[serde(default)]
    pub size: Option<u32>,
    #[serde(default)]
    pub crush_rule: Option<String>,
    #[serde(default)]
    pub application: Option<String>,
}
fn default_pool_type() -> String { "replicated".to_string() }

/// POST /api/ceph/pools — create a pool
pub async fn ceph_create_pool(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CephCreatePoolRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::create_pool(&body.name, body.pg_num, &body.pool_type, body.size, body.crush_rule.as_deref(), body.application.as_deref()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// DELETE /api/ceph/pools/{name} — delete a pool
pub async fn ceph_delete_pool(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool_name = path.into_inner();
    match crate::ceph::delete_pool(&pool_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephSetPoolOptionRequest {
    pub key: String,
    pub value: String,
}

/// PUT /api/ceph/pools/{name} — set pool options
pub async fn ceph_set_pool_option(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CephSetPoolOptionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool_name = path.into_inner();
    match crate::ceph::set_pool_option(&pool_name, &body.key, &body.value) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephAddOsdRequest {
    pub device: String,
}

/// POST /api/ceph/osds — add an OSD
pub async fn ceph_add_osd(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CephAddOsdRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::add_osd(&body.device) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// DELETE /api/ceph/osds/{id} — remove an OSD
pub async fn ceph_remove_osd(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<u32>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let osd_id = path.into_inner();
    match crate::ceph::remove_osd(osd_id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephOsdActionRequest {
    pub action: String,
    #[serde(default)]
    pub weight: Option<f64>,
}

/// POST /api/ceph/osds/{id}/action — mark in/out, reweight
pub async fn ceph_osd_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<u32>,
    body: web::Json<CephOsdActionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let osd_id = path.into_inner();
    let result = match body.action.as_str() {
        "in" => crate::ceph::set_osd_in(osd_id, true),
        "out" => crate::ceph::set_osd_in(osd_id, false),
        "reweight" => {
            let w = body.weight.unwrap_or(1.0);
            crate::ceph::reweight_osd(osd_id, w)
        },
        _ => Err(format!("Unknown action: {}", body.action)),
    };
    match result {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephCreateFsRequest {
    pub name: String,
    pub metadata_pool: String,
    pub data_pool: String,
}

/// POST /api/ceph/fs — create a CephFS
pub async fn ceph_create_fs(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CephCreateFsRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::create_filesystem(&body.name, &body.metadata_pool, &body.data_pool) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// DELETE /api/ceph/fs/{name} — remove a CephFS
pub async fn ceph_delete_fs(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let fs_name = path.into_inner();
    match crate::ceph::remove_filesystem(&fs_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// GET /api/ceph/rbd/{pool} — list RBD images
pub async fn ceph_list_rbd(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = path.into_inner();
    match crate::ceph::list_rbd_images(&pool) {
        Ok(images) => HttpResponse::Ok().json(images),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct CephCreateRbdRequest {
    pub pool: String,
    pub name: String,
    pub size_mb: u64,
}

/// POST /api/ceph/rbd — create RBD image
pub async fn ceph_create_rbd(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CephCreateRbdRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    match crate::ceph::create_rbd_image(&body.pool, &body.name, body.size_mb) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// DELETE /api/ceph/rbd/{pool}/{image} — delete RBD image
pub async fn ceph_delete_rbd(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let (pool, image) = path.into_inner();
    match crate::ceph::delete_rbd_image(&pool, &image) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": e})),
    }
}

// ─── Storage Manager API ───

/// GET /api/storage/mounts — list all storage mounts with live status
pub async fn storage_list_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::list_mounts())
}

/// GET /api/storage/available — list mounted storage suitable for container attachment
pub async fn storage_available_mounts(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::available_mounts())
}

#[derive(Deserialize)]
pub struct CreateMountRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub mount_type: storage::MountType,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub mount_point: String,
    #[serde(default)]
    pub global: bool,
    #[serde(default)]
    pub auto_mount: bool,
    #[serde(default)]
    pub s3_config: Option<storage::S3Config>,
    #[serde(default)]
    pub nfs_options: Option<String>,
    #[serde(default)]
    pub smb_options: Option<String>,
    #[serde(default)]
    pub smb_config: Option<storage::SmbConfig>,
    #[serde(default = "default_do_mount")]
    pub do_mount: bool,
}

fn default_do_mount() -> bool { true }

/// POST /api/storage/mounts — create a new storage mount
pub async fn storage_create_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreateMountRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    
    let mount = storage::StorageMount {
        id: String::new(),
        name: body.name.clone(),
        mount_type: body.mount_type.clone(),
        source: body.source.clone(),
        mount_point: body.mount_point.clone(),
        enabled: true,
        global: body.global,
        auto_mount: body.auto_mount,
        s3_config: body.s3_config.clone(),
        nfs_options: body.nfs_options.clone(),
        smb_options: body.smb_options.clone(),
        smb_config: body.smb_config.clone(),
        status: "unmounted".to_string(),
        error_message: None,
        created_at: String::new(),
    };
    
    let do_mount = body.do_mount;
    // Run on blocking threadpool — mount_s3_via_rust_s3 creates a nested tokio runtime
    // which panics if called directly from an async context
    let result = web::block(move || storage::create_mount(mount, do_mount)).await;
    match result {
        Ok(Ok(created)) => {
            // If global, sync to cluster nodes
            if created.global {
                let _ = sync_mount_to_cluster(&state, &created).await;
            }
            HttpResponse::Ok().json(created)
        }
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// PUT /api/storage/mounts/{id} — update a mount
pub async fn storage_update_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::update_mount(&id, body.into_inner()) {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/storage/mounts/{id} — remove a mount
pub async fn storage_remove_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::remove_mount(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/duplicate — clone a mount entry
pub async fn storage_duplicate_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    match storage::duplicate_mount(&id) {
        Ok(dup) => HttpResponse::Ok().json(dup),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/mount — mount a storage entry
pub async fn storage_do_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    // Run on blocking threadpool — mount_s3_via_rust_s3 creates a nested tokio runtime
    // which panics if called directly from an async context
    let result = web::block(move || storage::mount_storage(&id)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// POST /api/storage/mounts/{id}/unmount — unmount a storage entry
pub async fn storage_do_unmount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    let result = web::block(move || storage::unmount_storage(&id)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

#[derive(Deserialize)]
pub struct ImportRcloneRequest {
    pub config: String,
}

/// POST /api/storage/import-rclone — import S3 remotes from rclone.conf content
pub async fn storage_import_rclone(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ImportRcloneRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    
    match storage::import_rclone_config(&body.config) {
        Ok(mounts) => {
            let mut created = Vec::new();
            for mount in mounts {
                match storage::create_mount(mount, false) {
                    Ok(m) => created.push(m),
                    Err(e) => {
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": e,
                            "created": created
                        }));
                    }
                }
            }
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Imported {} S3 remotes", created.len()),
                "mounts": created
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/storage/providers — list installed storage providers
pub async fn storage_list_providers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::list_providers())
}

/// POST /api/storage/providers/{name}/install — install a storage provider
pub async fn storage_install_provider(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    let result = web::block(move || storage::install_provider(&name)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/storage/providers/{name}/action — start/stop/restart a provider service
/// Supports ?runtime=docker|lxc&target=containerName to manage inside containers
pub async fn storage_provider_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
    query: web::Query<ConfiguratorTarget>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let result = web::block(move || storage::provider_action_targeted(&name, &action, &target)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/providers/{name}/config — read a provider's config file
pub async fn storage_provider_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    match storage::provider_config(&name) {
        Ok(content) => HttpResponse::Ok().json(serde_json::json!({ "content": content, "name": name })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "content": "", "error": e, "name": name })),
    }
}

/// POST /api/storage/providers/{name}/config — save a provider's config file
pub async fn storage_provider_config_save(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let name = path.into_inner();
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let result = web::block(move || storage::save_provider_config(&name, &content)).await;
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

#[derive(Deserialize)]
pub struct SystemLogsQuery {
    pub lines: Option<usize>,
    pub search: Option<String>,
    pub unit: Option<String>,
}

/// GET /api/system/logs — read system journal logs
pub async fn system_logs(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<SystemLogsQuery>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let lines = query.lines.unwrap_or(200).min(5000);
    let search = query.search.as_deref();
    let unit = query.unit.as_deref();
    let logs = storage::read_system_logs(lines, search, unit);
    HttpResponse::Ok().json(serde_json::json!({
        "lines": logs,
        "count": logs.len(),
    }))
}

/// POST /api/storage/mounts/{id}/sync — sync a global mount to all cluster nodes
pub async fn storage_sync_mount(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    
    let config = storage::load_config();
    let mount = match config.mounts.iter().find(|m| m.id == id) {
        Some(m) => m.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Mount not found" })),
    };
    
    match sync_mount_to_cluster(&state, &mount).await {
        Ok(results) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Sync complete",
            "results": results
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/storage/mounts/{id}/sync-s3 — sync local changes back to S3 bucket
pub async fn storage_sync_s3(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let id = path.into_inner();
    
    // Run in blocking thread since S3 upload may take a while
    let result = web::block(move || {
        storage::sync_to_s3(&id)
    }).await;
    
    match result {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

// ─── Disk Partition Info ───

/// GET /api/storage/disk-info — list all block devices, partitions, filesystems & free space
pub async fn storage_disk_info(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    // Run lsblk in JSON mode with useful columns
    let lsblk_out = std::process::Command::new("lsblk")
        .args([
            "-J",
            "-o", "NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS,TYPE,HOTPLUG,ROTA,MODEL,SERIAL,UUID,PTTYPE,TRAN",
            "--bytes",
        ])
        .output();

    let block_devices: serde_json::Value = match lsblk_out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "blockdevices": [] }))
        }
        _ => serde_json::json!({ "blockdevices": [] }),
    };

    // Run df to get free-space per mount point
    let df_out = std::process::Command::new("df")
        .args(["-B1", "--output=target,avail,size,pcent"])
        .output();

    let mut df_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    if let Ok(o) = df_out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mountpoint = parts[0].to_string();
                let avail_bytes: u64 = parts[1].parse().unwrap_or(0);
                let total_bytes: u64 = parts[2].parse().unwrap_or(0);
                let use_pct = parts[3].trim_end_matches('%');
                let use_pct: f64 = use_pct.parse().unwrap_or(0.0);
                let free_pct = (100.0 - use_pct).max(0.0);
                df_map.insert(mountpoint, serde_json::json!({
                    "avail_bytes": avail_bytes,
                    "total_bytes": total_bytes,
                    "use_pct": use_pct,
                    "free_pct": free_pct,
                }));
            }
        }
    }

    // Walk lsblk tree and flatten into a list of partitions/disks with free-space data
    fn fmt_bytes(b: u64) -> String {
        const TB: u64 = 1_099_511_627_776;
        const GB: u64 = 1_073_741_824;
        const MB: u64 = 1_048_576;
        if b >= TB      { format!("{:.1} TB", b as f64 / TB as f64) }
        else if b >= GB { format!("{:.1} GB", b as f64 / GB as f64) }
        else if b >= MB { format!("{:.1} MB", b as f64 / MB as f64) }
        else            { format!("{} B", b) }
    }

    fn walk_devices(
        devices: &[serde_json::Value],
        df_map: &std::collections::HashMap<String, serde_json::Value>,
        parent_disk: &str,
        parent_model: &str,
        out: &mut Vec<serde_json::Value>,
    ) {
        for dev in devices {
            let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let dev_path = format!("/dev/{}", name);
            let size_bytes: u64 = dev.get("size")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .or_else(|| dev.get("size").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            let size_str = fmt_bytes(size_bytes);
            let fstype = dev.get("fstype").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let label  = dev.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let kind   = dev.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let model  = dev.get("model").and_then(|v| v.as_str()).unwrap_or(parent_model).to_string();
            let hotplug = dev.get("hotplug").and_then(|v| v.as_bool()).unwrap_or(false);
            let rotational = dev.get("rota").and_then(|v| v.as_bool()).unwrap_or(true);
            let serial = dev.get("serial").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let uuid   = dev.get("uuid").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let pttype = dev.get("pttype").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tran   = dev.get("tran").and_then(|v| v.as_str()).unwrap_or("").to_string();

            // Collect mountpoints
            let mounts: Vec<String> = dev.get("mountpoints")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|m| m.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect())
                .unwrap_or_default();

            // Get df data for the first mount point
            let df = mounts.first()
                .and_then(|mp| df_map.get(mp.as_str()))
                .cloned()
                .unwrap_or(serde_json::json!(null));

            let disk_name = if kind == "disk" { name } else { parent_disk };
            let disk_model = if kind == "disk" { &model } else { parent_model };

            out.push(serde_json::json!({
                "device": dev_path,
                "disk": format!("/dev/{}", disk_name),
                "model": disk_model,
                "type": kind,
                "size": size_str,
                "size_bytes": size_bytes,
                "fstype": if fstype.is_empty() { serde_json::json!(null) } else { serde_json::json!(fstype) },
                "label": if label.is_empty() { serde_json::json!(null) } else { serde_json::json!(label) },
                "mountpoints": mounts,
                "hotplug": hotplug,
                "rotational": rotational,
                "serial": if serial.is_empty() { serde_json::json!(null) } else { serde_json::json!(serial) },
                "uuid": if uuid.is_empty() { serde_json::json!(null) } else { serde_json::json!(uuid) },
                "pttype": if pttype.is_empty() { serde_json::json!(null) } else { serde_json::json!(pttype) },
                "tran": if tran.is_empty() { serde_json::json!(null) } else { serde_json::json!(tran) },
                "df": df,
            }));

            // Recurse into children (partitions)
            if let Some(children) = dev.get("children").and_then(|v| v.as_array()) {
                walk_devices(children, df_map, disk_name, disk_model, out);
            }
        }
    }

    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Some(devs) = block_devices.get("blockdevices").and_then(|v| v.as_array()) {
        walk_devices(devs, &df_map, "", "", &mut entries);
    }

    // Collect SMART health for physical disks (best-effort, smartctl may not be installed)
    let has_smartctl = std::process::Command::new("which")
        .arg("smartctl")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_smartctl {
        let mut smart_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        for entry in &entries {
            if entry.get("type").and_then(|v| v.as_str()) == Some("disk") {
                if let Some(dev) = entry.get("device").and_then(|v| v.as_str()) {
                    if dev.starts_with("/dev/loop") { continue; }
                    if let Ok(out) = std::process::Command::new("smartctl")
                        .args(["--json=c", "-H", "-A", dev])
                        .output()
                    {
                        let text = String::from_utf8_lossy(&out.stdout);
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            let passed = json.pointer("/smart_status/passed");
                            let temp = json.pointer("/temperature/current")
                                .and_then(|v| v.as_i64());
                            let power_on = json.pointer("/power_on_time/hours")
                                .and_then(|v| v.as_u64());
                            let attrs_table = json.get("ata_smart_attributes")
                                .and_then(|a| a.get("table"))
                                .and_then(|t| t.as_array());
                            let find_attr = |id: u64| -> Option<u64> {
                                attrs_table?.iter()
                                    .find(|a| a.get("id").and_then(|v| v.as_u64()) == Some(id))
                                    .and_then(|a| a.get("raw").and_then(|r| r.get("value")).and_then(|v| v.as_u64()))
                            };
                            let reallocated = find_attr(5);     // Reallocated Sector Count
                            let pending = find_attr(197);       // Current Pending Sector Count
                            let uncorrectable = find_attr(198); // Offline Uncorrectable
                            let wear_level = find_attr(177)     // SSD Wear Leveling Count
                                .or_else(|| find_attr(233));    // Media Wearout Indicator
                            let total_written = json.pointer("/ata_device_statistics/pages")
                                .and_then(|p| p.as_array())
                                .and_then(|pages| pages.iter()
                                    .flat_map(|page| page.get("table").and_then(|t| t.as_array()).into_iter().flatten())
                                    .find(|e| e.get("name").and_then(|n| n.as_str()) == Some("Logical Sectors Written"))
                                )
                                .and_then(|e| e.get("value").and_then(|v| v.as_u64()));
                            // For NVMe, use different paths
                            let nvme_spare = json.pointer("/nvme_smart_health_information_log/available_spare")
                                .and_then(|v| v.as_u64());
                            let nvme_pct_used = json.pointer("/nvme_smart_health_information_log/percentage_used")
                                .and_then(|v| v.as_u64());
                            smart_map.insert(dev.to_string(), serde_json::json!({
                                "passed": passed,
                                "temperature_c": temp,
                                "power_on_hours": power_on,
                                "reallocated_sectors": reallocated,
                                "pending_sectors": pending,
                                "uncorrectable_sectors": uncorrectable,
                                "wear_level": wear_level,
                                "total_written_sectors": total_written,
                                "nvme_spare_pct": nvme_spare,
                                "nvme_pct_used": nvme_pct_used,
                            }));
                        }
                    }
                }
            }
        }
        // Attach SMART data to disk entries
        for entry in &mut entries {
            if let Some(dev) = entry.get("device").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                if let Some(smart) = smart_map.get(&dev) {
                    entry.as_object_mut().map(|m| m.insert("smart".to_string(), smart.clone()));
                }
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "devices": entries }))
}

// ─── Disk Partitioning & Formatting ───

#[derive(Deserialize)]
pub struct CreatePartitionTableRequest {
    pub disk: String,
    pub table_type: String, // "gpt" or "msdos"
}

/// POST /api/storage/disk/partition-table — create a partition table
pub async fn disk_create_partition_table(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreatePartitionTableRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let disk = body.disk.clone();
    let table_type = body.table_type.clone();
    match web::block(move || storage::create_partition_table(&disk, &table_type)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct CreatePartitionRequest {
    pub disk: String,
    #[serde(default)]
    pub size_mb: Option<u64>, // None = use all remaining space
    #[serde(default)]
    pub fs_type_hint: Option<String>,
}

/// POST /api/storage/disk/partition — create a partition
pub async fn disk_create_partition(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<CreatePartitionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let disk = body.disk.clone();
    let size_mb = body.size_mb;
    let hint = body.fs_type_hint.clone();
    match web::block(move || storage::create_partition(&disk, size_mb, hint.as_deref())).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct DeletePartitionRequest {
    pub device: String,
}

/// POST /api/storage/disk/partition/delete — delete a partition
pub async fn disk_delete_partition(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DeletePartitionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let device = body.device.clone();
    match web::block(move || storage::delete_partition(&device)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct FormatPartitionRequest {
    pub device: String,
    pub fstype: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// POST /api/storage/disk/format — format a partition
pub async fn disk_format_partition(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<FormatPartitionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let device = body.device.clone();
    let fstype = body.fstype.clone();
    let label = body.label.clone();
    match web::block(move || storage::format_partition(&device, &fstype, label.as_deref())).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

#[derive(Deserialize)]
pub struct ResizePartitionRequest {
    pub device: String,
}

/// POST /api/storage/disk/resize — grow a partition and its filesystem
pub async fn disk_resize_partition(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ResizePartitionRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let device = body.device.clone();
    match web::block(move || storage::resize_partition(&device)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({"ok": true, "message": msg})),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({"ok": false, "error": e})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"ok": false, "error": format!("{}", e)})),
    }
}

/// GET /api/storage/disk/filesystems — list supported filesystem types
pub async fn disk_supported_filesystems(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(storage::SUPPORTED_FILESYSTEMS)
}

// ─── ZFS Storage ───

/// GET /api/storage/zfs/status — check if ZFS is available and return overview
pub async fn zfs_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let available = std::process::Command::new("which").arg("zfs").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if !available {
        return HttpResponse::Ok().json(serde_json::json!({
            "available": false,
            "pools": []
        }));
    }

    // Get pool summary
    let pools = zfs_get_pools();
    HttpResponse::Ok().json(serde_json::json!({
        "available": true,
        "pools": pools
    }))
}

/// GET /api/storage/zfs/pools — list all ZFS pools with usage stats
pub async fn zfs_pools(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(zfs_get_pools())
}

/// GET /api/storage/zfs/datasets?pool=POOL — list datasets for a pool
pub async fn zfs_datasets(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    if pool.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'pool' parameter" }));
    }
    // Validate pool name (alphanumeric, dash, underscore, dot only)
    if !pool.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zfs")
        .args(["list", "-H", "-r", "-o", "name,used,avail,refer,mountpoint,compression,compressratio", &pool])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let datasets: Vec<serde_json::Value> = text.lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "used": parts.get(1).unwrap_or(&""),
                        "available": parts.get(2).unwrap_or(&""),
                        "refer": parts.get(3).unwrap_or(&""),
                        "mountpoint": parts.get(4).unwrap_or(&""),
                        "compression": parts.get(5).unwrap_or(&""),
                        "compressratio": parts.get(6).unwrap_or(&""),
                    })
                })
                .collect();
            HttpResponse::Ok().json(datasets)
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/snapshots?dataset=DATASET — list snapshots
pub async fn zfs_snapshots(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dataset = query.get("dataset").cloned().unwrap_or_default();

    let mut args = vec!["list", "-t", "snapshot", "-H", "-o", "name,creation,used,refer"];
    if !dataset.is_empty() {
        if !dataset.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == '@') {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid dataset name" }));
        }
        args.push("-r");
        args.push(&dataset);
    }

    let output = std::process::Command::new("zfs").args(&args).output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let snapshots: Vec<serde_json::Value> = text.lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "creation": parts.get(1).unwrap_or(&""),
                        "used": parts.get(2).unwrap_or(&""),
                        "refer": parts.get(3).unwrap_or(&""),
                    })
                })
                .collect();
            HttpResponse::Ok().json(snapshots)
        }
        Ok(out) => {
            let _err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(Vec::<serde_json::Value>::new()) // empty list if no snapshots
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/storage/zfs/snapshot — create a snapshot
pub async fn zfs_create_snapshot(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dataset = body.get("dataset").and_then(|v| v.as_str()).unwrap_or("");
    let snap_name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");

    if dataset.is_empty() || snap_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'dataset' or 'name'" }));
    }
    // Validate names
    let valid_chars = |s: &str| s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/');
    if !valid_chars(dataset) || !valid_chars(snap_name) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid characters in dataset or snapshot name" }));
    }

    let snapshot_full = format!("{}@{}", dataset, snap_name);
    let output = std::process::Command::new("zfs")
        .args(["snapshot", &snapshot_full])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "message": format!("Snapshot '{}' created", snapshot_full) }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /api/storage/zfs/snapshot — delete a snapshot
pub async fn zfs_delete_snapshot(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let snapshot = body.get("snapshot").and_then(|v| v.as_str()).unwrap_or("");

    if snapshot.is_empty() || !snapshot.contains('@') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid snapshot name (must contain @)" }));
    }
    if !snapshot.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == '@') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid characters in snapshot name" }));
    }

    let output = std::process::Command::new("zfs")
        .args(["destroy", snapshot])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "message": format!("Snapshot '{}' deleted", snapshot) }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// Helper: parse zpool list output into JSON
fn zfs_get_pools() -> Vec<serde_json::Value> {
    let output = std::process::Command::new("zpool")
        .args(["list", "-H", "-o", "name,size,alloc,free,health,fragmentation,capacity,dedup,altroot"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut pools: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout).lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    serde_json::json!({
                        "name": parts.get(0).unwrap_or(&""),
                        "size": parts.get(1).unwrap_or(&""),
                        "alloc": parts.get(2).unwrap_or(&""),
                        "free": parts.get(3).unwrap_or(&""),
                        "health": parts.get(4).unwrap_or(&""),
                        "fragmentation": parts.get(5).unwrap_or(&""),
                        "capacity": parts.get(6).unwrap_or(&""),
                        "dedup": parts.get(7).unwrap_or(&"1.00x"),
                        "altroot": parts.get(8).unwrap_or(&"-"),
                    })
                })
                .collect();

            // Enrich each pool with scan/scrub status from `zpool status`
            for pool in &mut pools {
                let pool_name = pool["name"].as_str().unwrap_or("").to_string();
                if let Ok(status_out) = std::process::Command::new("zpool")
                    .args(["status", &pool_name])
                    .output()
                {
                    if status_out.status.success() {
                        let status_text = String::from_utf8_lossy(&status_out.stdout).to_string();
                        // Extract scan line
                        let scan_line = status_text.lines()
                            .find(|l| l.trim_start().starts_with("scan:"))
                            .map(|l| l.trim_start().trim_start_matches("scan:").trim().to_string())
                            .unwrap_or_else(|| "none requested".to_string());
                        // Extract errors line
                        let errors_line = status_text.lines()
                            .find(|l| l.trim_start().starts_with("errors:"))
                            .map(|l| l.trim_start().trim_start_matches("errors:").trim().to_string())
                            .unwrap_or_else(|| "unknown".to_string());

                        pool["scan"] = serde_json::json!(scan_line);
                        pool["errors"] = serde_json::json!(errors_line);
                    }
                }
            }

            pools
        }
        _ => vec![],
    }
}

/// POST /api/storage/zfs/pool/scrub — start or stop a scrub
pub async fn zfs_pool_scrub(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = body.get("pool").and_then(|v| v.as_str()).unwrap_or("").trim();
    let stop = body.get("stop").and_then(|v| v.as_bool()).unwrap_or(false);
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let mut args = vec!["scrub"];
    if stop { args.push("-s"); }
    args.push(pool);

    let output = std::process::Command::new("zpool").args(&args).output();
    match output {
        Ok(out) if out.status.success() => {
            let msg = if stop { format!("Scrub stopped on pool '{}'", pool) }
                      else { format!("Scrub started on pool '{}'", pool) };
            HttpResponse::Ok().json(serde_json::json!({ "message": msg }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/pool/status?pool=POOL — detailed pool status (vdevs, errors, scan)
pub async fn zfs_pool_status(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    let pool = pool.trim().to_string();
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zpool").args(["status", "-v", &pool]).output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "pool": pool,
                "status_text": text,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/storage/zfs/pool/iostat?pool=POOL — pool IO statistics
pub async fn zfs_pool_iostat(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let pool = query.get("pool").cloned().unwrap_or_default();
    let pool = pool.trim().to_string();
    if pool.is_empty() || pool.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid pool name" }));
    }

    let output = std::process::Command::new("zpool").args(["iostat", "-v", &pool]).output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "pool": pool,
                "iostat_text": text,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": err.trim() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── File Manager ───

/// Validate and normalize a file path — prevent traversal attacks
fn sanitize_file_path(path: &str) -> Result<std::path::PathBuf, String> {
    let p = std::path::Path::new(path);
    // Must be absolute
    if !p.is_absolute() {
        return Err("Path must be absolute".into());
    }
    // Canonicalize to resolve .. and symlinks
    match p.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(_) => {
            // For paths that don't exist yet (e.g., mkdir), check the parent
            if let Some(parent) = p.parent() {
                if let Ok(canonical_parent) = parent.canonicalize() {
                    let file_name = p.file_name().ok_or("Invalid path")?;
                    Ok(canonical_parent.join(file_name))
                } else {
                    Err("Parent directory does not exist".into())
                }
            } else {
                Err("Invalid path".into())
            }
        }
    }
}

/// GET /api/files/browse?path=/some/path — list directory contents
pub async fn files_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a directory" }));
    }

    let mut entries = Vec::new();
    match std::fs::read_dir(&canonical) {
        Ok(dir) => {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let meta = entry.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let modified = meta.as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // Unix permissions
                #[cfg(unix)]
                let permissions = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.as_ref()
                        .map(|m| format!("{:o}", m.permissions().mode() & 0o7777))
                        .unwrap_or_default()
                };
                #[cfg(not(unix))]
                let permissions = String::new();

                let entry_path = canonical.join(&name);
                entries.push(serde_json::json!({
                    "name": name,
                    "path": entry_path.to_string_lossy(),
                    "is_dir": is_dir,
                    "size": if is_dir { 0 } else { size },
                    "modified": modified,
                    "permissions": permissions,
                }));
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Cannot read directory: {}", e)
            }));
        }
    }

    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        let a_dir = a["is_dir"].as_bool().unwrap_or(false);
        let b_dir = b["is_dir"].as_bool().unwrap_or(false);
        match (a_dir, b_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a["name"].as_str().unwrap_or("")
                .to_lowercase()
                .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "path": canonical.to_string_lossy(),
        "entries": entries,
    }))
}

/// POST /api/files/mkdir — create directory
pub async fn files_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    match std::fs::create_dir_all(&canonical) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Directory created: {}", canonical.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create directory: {}", e)
        })),
    }
}

/// POST /api/files/delete — delete file or directory
pub async fn files_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    // Prevent deleting critical system paths
    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/var", "/root"];
    if critical.contains(&canonical.to_string_lossy().as_ref()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let result = if canonical.is_dir() {
        std::fs::remove_dir_all(&canonical)
    } else {
        std::fs::remove_file(&canonical)
    };

    match result {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Deleted: {}", canonical.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete: {}", e)
        })),
    }
}

/// POST /api/files/rename — rename / move a file or directory
pub async fn files_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'from' or 'to'" }));
    }

    let from_path = match sanitize_file_path(from) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    let to_path = match sanitize_file_path(to) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    match std::fs::rename(&from_path, &to_path) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Renamed to {}", to_path.display())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to rename: {}", e)
        })),
    }
}

/// POST /api/files/upload?path=/some/dir — upload file(s) via multipart
pub async fn files_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let dir = query.get("path").cloned().unwrap_or_else(|| "/tmp".into());

    let canonical_dir = match sanitize_file_path(&dir) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical_dir.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Target is not a directory" }));
    }

    use futures::StreamExt;
    let mut uploaded = Vec::new();

    while let Some(Ok(mut field)) = payload.next().await {
        let filename = field.content_disposition()
            .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
            .unwrap_or_else(|| "upload".to_string());

        // Sanitize filename
        let safe_name = filename.replace("..", "").replace("/", "").replace("\\", "");
        if safe_name.is_empty() { continue; }

        let file_path = canonical_dir.join(&safe_name);
        let mut file = match std::fs::File::create(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Cannot create file {}: {}", safe_name, e)
                }));
            }
        };

        use std::io::Write;
        while let Some(Ok(chunk)) = field.next().await {
            if file.write_all(&chunk).is_err() {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to write file {}", safe_name)
                }));
            }
        }
        uploaded.push(safe_name);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Uploaded {} file(s)", uploaded.len()),
        "files": uploaded,
    }))
}

/// GET /api/files/download?path=/some/file — download a file
pub async fn files_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = query.get("path").cloned().unwrap_or_default();
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" }));
    }

    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    if !canonical.is_file() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a file" }));
    }

    let filename = canonical.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".into());

    match std::fs::read(&canonical) {
        Ok(data) => HttpResponse::Ok()
            .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
            .insert_header(("Content-Type", "application/octet-stream"))
            .body(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Cannot read file: {}", e)
        })),
    }
}

/// GET /api/files/search?path=/start&query=pattern — recursive search using find
pub async fn files_search(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let search_path = query.get("path").cloned().unwrap_or_else(|| "/".into());
    let search_query = query.get("query").cloned().unwrap_or_default();

    if search_query.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'query'" }));
    }

    let canonical = match sanitize_file_path(&search_path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    // Use find with -iname for case-insensitive matching, limit results
    let output = std::process::Command::new("find")
        .args([canonical.to_str().unwrap_or("/"), "-maxdepth", "8",
               "-iname", &format!("*{}*", search_query),
               "-printf", "%y\t%s\t%T@\t%m\t%p\n"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut entries: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .take(100) // cap results
                .map(|line| {
                    let parts: Vec<&str> = line.splitn(5, '\t').collect();
                    let file_type = parts.get(0).unwrap_or(&"f");
                    let size: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let modified: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    let permissions = parts.get(3).unwrap_or(&"").to_string();
                    let full_path = parts.get(4).unwrap_or(&"").to_string();
                    let name = std::path::Path::new(&full_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| full_path.clone());
                    let is_dir = *file_type == "d";

                    serde_json::json!({
                        "name": name,
                        "path": full_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": modified as u64,
                        "permissions": permissions,
                    })
                })
                .collect();

            entries.sort_by(|a, b| {
                let ad = a["is_dir"].as_bool().unwrap_or(false);
                let bd = b["is_dir"].as_bool().unwrap_or(false);
                match (ad, bd) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("").to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": search_path,
                "query": search_query,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "path": search_path,
                "query": search_query,
                "entries": [],
                "warning": err.trim(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/chmod — change permissions on a file or files
pub async fn files_chmod(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let paths: Vec<String> = body.get("paths")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if mode.is_empty() || paths.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'mode' or 'paths'" }));
    }

    // Validate mode (must be octal like 755 or symbolic like u+x)
    if mode.len() > 10 || mode.contains("..") {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid mode" }));
    }

    let mut results = Vec::new();
    for path in &paths {
        let canonical = match sanitize_file_path(path) {
            Ok(p) => p,
            Err(e) => { results.push(serde_json::json!({"path": path, "error": e})); continue; }
        };
        let output = std::process::Command::new("chmod")
            .args([mode, canonical.to_str().unwrap_or("")])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                results.push(serde_json::json!({"path": path, "ok": true}));
            }
            Ok(out) => {
                results.push(serde_json::json!({"path": path, "error": String::from_utf8_lossy(&out.stderr).trim().to_string()}));
            }
            Err(e) => {
                results.push(serde_json::json!({"path": path, "error": format!("{}", e)}));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "results": results }))
}

/// GET /api/files/read?path=/etc/hosts — read file contents as text
pub async fn files_read(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = match query.get("path") {
        Some(p) => p.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    if canonical.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot edit a directory" }));
    }
    let metadata = match std::fs::metadata(&canonical) {
        Ok(m) => m,
        Err(e) => return HttpResponse::NotFound().json(serde_json::json!({ "error": format!("File not found: {}", e) })),
    };
    if metadata.len() > 2 * 1024 * 1024 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "File too large to edit (max 2MB)" }));
    }
    match std::fs::read_to_string(&canonical) {
        Ok(content) => HttpResponse::Ok().json(serde_json::json!({
            "path": path,
            "content": content,
            "size": metadata.len(),
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Cannot read file (binary?): {}", e) })),
    }
}

/// POST /api/files/write — write text content to a file
pub async fn files_write(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let path = match body.get("path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'content'" })),
    };
    let canonical = match sanitize_file_path(&path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    if canonical.is_dir() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot write to a directory" }));
    }
    match std::fs::write(&canonical, content) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "message": "File saved", "path": path })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Write failed: {}", e) })),
    }
}

/// GET /api/files/docker/browse?container=ID&path=/ — browse files inside a Docker container
pub async fn files_docker_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    // Use docker exec to list directory contents with stat-like output
    let output = std::process::Command::new("docker")
        .args(["exec", &container, "find", &path, "-maxdepth", "1", "-mindepth", "1",
               "-printf", "%y\\t%s\\t%T@\\t%m\\t%f\\n"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let mut entries: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.splitn(5, '\t').collect();
                    let file_type = parts.get(0).unwrap_or(&"f");
                    let size: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let modified: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    let permissions = parts.get(3).unwrap_or(&"");
                    let name = parts.get(4).unwrap_or(&"");
                    let is_dir = *file_type == "d";
                    let entry_path = if path.ends_with('/') {
                        format!("{}{}", path, name)
                    } else {
                        format!("{}/{}", path, name)
                    };

                    serde_json::json!({
                        "name": name,
                        "path": entry_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": modified as u64,
                        "permissions": permissions,
                    })
                })
                .collect();

            // Sort: directories first, then alphabetically
            entries.sort_by(|a, b| {
                let a_dir = a["is_dir"].as_bool().unwrap_or(false);
                let b_dir = b["is_dir"].as_bool().unwrap_or(false);
                match (a_dir, b_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("")
                        .to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": path,
                "container": container,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list directory: {}", err.trim())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to exec into container: {}", e)
        })),
    }
}

/// POST /api/files/docker/mkdir — create directory inside Docker container
pub async fn files_docker_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "mkdir", "-p", path])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Directory created: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/delete — delete file/dir inside Docker container
pub async fn files_docker_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev", "/var"];
    if critical.contains(&path) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "rm", "-rf", path])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Deleted: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/rename — rename file/dir inside Docker container
pub async fn files_docker_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing fields" }));
    }

    let output = std::process::Command::new("docker")
        .args(["exec", container, "mv", from, to])
        .output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Renamed to {}", to) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/files/docker/download?container=ID&path=/file — download file from Docker container
pub async fn files_docker_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_default();
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    // Use docker cp to a temp file
    let tmp = format!("/tmp/wolfstack-docker-dl-{}", std::process::id());
    let src = format!("{}:{}", container, path);
    let output = std::process::Command::new("docker").args(["cp", &src, &tmp]).output();

    match output {
        Ok(out) if out.status.success() => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".into());

            match std::fs::read(&tmp) {
                Ok(data) => {
                    let _ = std::fs::remove_file(&tmp);
                    HttpResponse::Ok()
                        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                        .insert_header(("Content-Type", "application/octet-stream"))
                        .body(data)
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Read error: {}", e) }))
                }
            }
        }
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": String::from_utf8_lossy(&out.stderr).trim().to_string()
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/upload?container=NAME&path=/some/dir — upload file(s) into a Docker container
pub async fn files_docker_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let dir = query.get("path").cloned().unwrap_or_else(|| "/tmp".into());
    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    use futures::StreamExt;
    let mut uploaded = Vec::new();

    while let Some(Ok(mut field)) = payload.next().await {
        let filename = field.content_disposition()
            .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
            .unwrap_or_else(|| "upload".to_string());

        let safe_name = filename.replace("..", "").replace("/", "").replace("\\", "");
        if safe_name.is_empty() { continue; }

        // Write to a temp file, then docker cp into container
        let tmp = format!("/tmp/wolfstack-docker-ul-{}-{}", std::process::id(), safe_name);
        {
            let mut file = match std::fs::File::create(&tmp) {
                Ok(f) => f,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Cannot create temp file: {}", e)
                    }));
                }
            };
            use std::io::Write;
            while let Some(Ok(chunk)) = field.next().await {
                if file.write_all(&chunk).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to write temp file {}", safe_name)
                    }));
                }
            }
        }

        let dest = format!("{}:{}/{}", container, dir.trim_end_matches('/'), safe_name);
        let output = std::process::Command::new("docker").args(["cp", &tmp, &dest]).output();
        let _ = std::fs::remove_file(&tmp);

        match output {
            Ok(out) if out.status.success() => { uploaded.push(safe_name); }
            Ok(out) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("docker cp failed: {}", String::from_utf8_lossy(&out.stderr).trim())
                }));
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("docker cp error: {}", e)
                }));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Uploaded {} file(s)", uploaded.len()),
        "files": uploaded,
    }))
}

/// GET /api/files/docker/read?container=ID&path=/etc/hosts — read file from Docker container
pub async fn files_docker_read(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = match query.get("container") {
        Some(c) => c.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" })),
    };
    let path = match query.get("path") {
        Some(p) => p.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let output = std::process::Command::new("docker")
        .args(["exec", &container, "cat", &path])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let content = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({ "path": path, "content": content, "size": content.len() }))
        }
        Ok(out) => HttpResponse::BadRequest().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/docker/write — write file inside Docker container
pub async fn files_docker_write(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = match body.get("container").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" })),
    };
    let path = match body.get("path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'content'" })),
    };
    // Write to temp file then docker cp in
    let tmp = format!("/tmp/wolfstack-edit-{}", std::process::id());
    if let Err(e) = std::fs::write(&tmp, content) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Temp write failed: {}", e) }));
    }
    let output = std::process::Command::new("docker")
        .args(["cp", &tmp, &format!("{}:{}", container, path)])
        .output();
    let _ = std::fs::remove_file(&tmp);
    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": "File saved", "path": path })),
        Ok(out) => HttpResponse::BadRequest().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── LXC File Manager ───

/// Detect if Proxmox `pct` is available, and use `pct exec` if so; else `lxc-attach`.
fn lxc_exec_cmd(container: &str, cmd_args: &[&str]) -> std::process::Command {
    let is_proxmox = std::process::Command::new("which").arg("pct").output()
        .map(|o| o.status.success()).unwrap_or(false);
    let mut cmd;
    if is_proxmox {
        cmd = std::process::Command::new("pct");
        cmd.arg("exec").arg(container).arg("--");
    } else {
        cmd = std::process::Command::new("lxc-attach");
        let base = crate::containers::lxc_base_dir(container);
        if base != crate::containers::LXC_DEFAULT_PATH {
            cmd.arg("-P").arg(&base);
        }
        cmd.arg("-n").arg(container).arg("--");
    }
    for a in cmd_args { cmd.arg(a); }
    cmd
}

/// GET /api/files/lxc/browse?container=NAME&path=/ — browse files inside an LXC container
pub async fn files_lxc_browse(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_else(|| "/".into());

    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    // Use a POSIX shell one-liner that works everywhere (BusyBox, Alpine, Debian, etc.)
    // Output format per line: TYPE<tab>SIZE<tab>NAME
    // TYPE: d = directory, f = file, l = link
    let script = format!(
        "cd '{}' 2>/dev/null && for f in .* *; do [ \"$f\" = '.' ] || [ \"$f\" = '..' ] || [ \"$f\" = '.*' ] || [ \"$f\" = '*' ] && continue; if [ -L \"$f\" ]; then printf 'l\\t0\\t%s\\n' \"$f\"; elif [ -d \"$f\" ]; then printf 'd\\t0\\t%s\\n' \"$f\"; else s=$(stat -c%s \"$f\" 2>/dev/null || echo 0); printf 'f\\t'\"$s\"'\\t%s\\n' \"$f\"; fi; done",
        path.replace('\'', "'\\''")
    );

    let output = lxc_exec_cmd(&container, &["sh", "-c", &script]).output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut entries: Vec<serde_json::Value> = stdout
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(3, '\t').collect();
                    if parts.len() < 3 { return None; }

                    let file_type = parts[0];
                    let size: u64 = parts[1].parse().unwrap_or(0);
                    let name = parts[2].to_string();

                    if name.is_empty() { return None; }

                    let is_dir = file_type == "d" || file_type == "l";
                    let entry_path = if path.ends_with('/') {
                        format!("{}{}", path, name)
                    } else {
                        format!("{}/{}", path, name)
                    };

                    Some(serde_json::json!({
                        "name": name,
                        "path": entry_path,
                        "is_dir": is_dir,
                        "size": if is_dir { 0 } else { size },
                        "modified": 0,
                        "permissions": "",
                    }))
                })
                .collect();

            entries.sort_by(|a, b| {
                let a_dir = a["is_dir"].as_bool().unwrap_or(false);
                let b_dir = b["is_dir"].as_bool().unwrap_or(false);
                match (a_dir, b_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a["name"].as_str().unwrap_or("")
                        .to_lowercase()
                        .cmp(&b["name"].as_str().unwrap_or("").to_lowercase()),
                }
            });

            HttpResponse::Ok().json(serde_json::json!({
                "path": path,
                "container": container,
                "entries": entries,
            }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            let _stdout = String::from_utf8_lossy(&out.stdout).to_string();

            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list directory: {}", err.trim())
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to exec into container: {}", e)
        })),
    }
}

/// POST /api/files/lxc/mkdir — create directory inside LXC container
pub async fn files_lxc_mkdir(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let output = lxc_exec_cmd(container, &["mkdir", "-p", path]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Directory created: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/delete — delete file/dir inside LXC container
pub async fn files_lxc_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    let critical = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev", "/var"];
    if critical.contains(&path) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete system directory" }));
    }

    let output = lxc_exec_cmd(container, &["rm", "-rf", path]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Deleted: {}", path) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/rename — rename file/dir inside LXC container
pub async fn files_lxc_rename(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = body.get("container").and_then(|v| v.as_str()).unwrap_or("");
    let from = body.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let to = body.get("to").and_then(|v| v.as_str()).unwrap_or("");
    if container.is_empty() || from.is_empty() || to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing fields" }));
    }

    let output = lxc_exec_cmd(container, &["mv", from, to]).output();

    match output {
        Ok(out) if out.status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Renamed to {}", to) })),
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/files/lxc/download?container=NAME&path=/file — download file from LXC container
pub async fn files_lxc_download(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_default();
    if container.is_empty() || path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container' or 'path'" }));
    }

    // Use lxc-attach cat to stream the file content
    let output = lxc_exec_cmd(&container, &["cat", &path]).output();

    match output {
        Ok(out) if out.status.success() => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "download".into());

            HttpResponse::Ok()
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .insert_header(("Content-Type", "application/octet-stream"))
                .body(out.stdout)
        }
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to read file: {}", String::from_utf8_lossy(&out.stderr).trim())
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/upload?container=NAME&path=/some/dir — upload file(s) into an LXC/Proxmox container
pub async fn files_lxc_upload(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = query.get("container").cloned().unwrap_or_default();
    let dir = query.get("path").cloned().unwrap_or_else(|| "/tmp".into());
    if container.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" }));
    }

    use futures::StreamExt;
    let mut uploaded = Vec::new();

    while let Some(Ok(mut field)) = payload.next().await {
        let filename = field.content_disposition()
            .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
            .unwrap_or_else(|| "upload".to_string());

        let safe_name = filename.replace("..", "").replace("/", "").replace("\\", "");
        if safe_name.is_empty() { continue; }

        // Write to temp file first (avoids buffering large files in memory)
        let tmp = format!("/tmp/wolfstack-lxc-ul-{}-{}", std::process::id(), safe_name);
        {
            let mut file = match std::fs::File::create(&tmp) {
                Ok(f) => f,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Cannot create temp file: {}", e)
                    }));
                }
            };
            use std::io::Write;
            while let Some(Ok(chunk)) = field.next().await {
                if file.write_all(&chunk).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to write temp file {}", safe_name)
                    }));
                }
            }
        }

        // Pipe temp file into container via tee (works with both lxc-attach and pct exec)
        let dest_path = format!("{}/{}", dir.trim_end_matches('/'), safe_name);
        let data = match std::fs::read(&tmp) {
            Ok(d) => d,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to read temp file: {}", e)
                }));
            }
        };
        let _ = std::fs::remove_file(&tmp);

        let mut child = match lxc_exec_cmd(&container, &["tee", &dest_path])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to exec into container: {}", e)
                }));
            }
        };

        if let Some(ref mut stdin) = child.stdin {
            use std::io::Write;
            if stdin.write_all(&data).is_err() {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to write to container: {}", safe_name)
                }));
            }
        }
        drop(child.stdin.take()); // Close stdin so tee finishes

        match child.wait() {
            Ok(status) if status.success() => { uploaded.push(safe_name); }
            Ok(_) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to upload {} to container", safe_name)
                }));
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Container exec error: {}", e)
                }));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Uploaded {} file(s)", uploaded.len()),
        "files": uploaded,
    }))
}

/// GET /api/files/lxc/read?container=NAME&path=/etc/hosts — read file from LXC container
pub async fn files_lxc_read(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = match query.get("container") {
        Some(c) => c.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" })),
    };
    let path = match query.get("path") {
        Some(p) => p.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let output = std::process::Command::new("lxc-attach")
        .args(["-n", &container, "--", "cat", &path])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let content = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({ "path": path, "content": content, "size": content.len() }))
        }
        Ok(out) => HttpResponse::BadRequest().json(serde_json::json!({ "error": String::from_utf8_lossy(&out.stderr).trim().to_string() })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/files/lxc/write — write file inside LXC container
pub async fn files_lxc_write(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let container = match body.get("container").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'container'" })),
    };
    let path = match body.get("path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'path'" })),
    };
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'content'" })),
    };
    // Write via lxc-attach using tee
    let mut child = match std::process::Command::new("lxc-attach")
        .args(["-n", &container, "--", "tee", &path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(content.as_bytes());
    }
    match child.wait() {
        Ok(status) if status.success() => HttpResponse::Ok().json(serde_json::json!({ "message": "File saved", "path": path })),
        Ok(_) => HttpResponse::BadRequest().json(serde_json::json!({ "error": "lxc-attach write failed" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/agent/storage/apply — receive and apply a mount config from another node (cluster-auth)
pub async fn agent_storage_apply(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<storage::StorageMount>,
) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let mount = body.into_inner();
    match storage::create_mount(mount, true) {
        Ok(m) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Mount applied",
            "mount": m
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Helper: push a mount config to all remote cluster nodes
async fn sync_mount_to_cluster(
    state: &web::Data<AppState>,
    mount: &storage::StorageMount,
) -> Result<Vec<serde_json::Value>, String> {
    let nodes = state.cluster.get_all_nodes();
    let mut results = Vec::new();
    
    for node in &nodes {
        if node.is_self { continue; }
        let url = format!("http://{}:{}/api/agent/storage/apply", node.address, node.port);
        let client = reqwest::Client::new();
        match client.post(&url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .json(mount)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                results.push(serde_json::json!({
                    "node": node.hostname,
                    "status": status,
                    "response": body
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "node": node.hostname,
                    "status": "error",
                    "response": e.to_string()
                }));
            }
        }
    }
    
    Ok(results)
}

/// POST /api/upgrade — run the WolfStack upgrade script in the background
// ─── Config Export / Import ───

/// Export all WolfStack configuration as a JSON file
pub async fn config_export(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }


    let mut bundle = serde_json::Map::new();

    // Helper: read a JSON file and insert into bundle
    fn read_json_file(path: &str) -> Option<serde_json::Value> {
        std::fs::read_to_string(path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    // Nodes (cluster links)
    if let Some(v) = read_json_file("/etc/wolfstack/nodes.json") {
        bundle.insert("nodes".into(), v);
    }
    // AI config
    if let Some(v) = read_json_file("/etc/wolfstack/ai-config.json") {
        bundle.insert("ai_config".into(), v);
    }
    // Storage config
    if let Some(v) = read_json_file("/etc/wolfstack/storage.json") {
        bundle.insert("storage_config".into(), v);
    }
    // Backup config (schedules only — strip entries to keep it small)
    if let Some(v) = read_json_file("/etc/wolfstack/backups.json") {
        if let Some(obj) = v.as_object() {
            let mut cleaned = serde_json::Map::new();
            if let Some(schedules) = obj.get("schedules") {
                cleaned.insert("schedules".into(), schedules.clone());
            }
            bundle.insert("backup_config".into(), serde_json::Value::Object(cleaned));
        }
    }
    // IP mappings
    if let Some(v) = read_json_file(&crate::paths::get().ip_mappings) {
        bundle.insert("ip_mappings".into(), v);
    }
    // PBS config
    if let Some(v) = read_json_file("/etc/wolfstack/pbs/config.json") {
        bundle.insert("pbs_config".into(), v);
    }

    // Add metadata
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    bundle.insert("exported_from".into(), serde_json::Value::String(hostname));
    bundle.insert("exported_at".into(), serde_json::Value::String(
        chrono::Utc::now().to_rfc3339()
    ));
    bundle.insert("version".into(), serde_json::Value::String(
        env!("CARGO_PKG_VERSION").to_string()
    ));

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Content-Disposition", "attachment; filename=\"wolfstack-config.json\""))
        .json(serde_json::Value::Object(bundle))
}

/// Import WolfStack configuration from a JSON bundle
pub async fn config_import(
    req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }


    let bundle = body.into_inner();
    let obj = match bundle.as_object() {
        Some(o) => o,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid config bundle — expected JSON object"
        })),
    };

    let mut imported = Vec::new();
    let mut errors = Vec::new();

    // Ensure config dir exists
    let _ = std::fs::create_dir_all("/etc/wolfstack");

    // Import nodes — merge with existing, skip self
    if let Some(nodes_val) = obj.get("nodes") {
        match import_nodes(nodes_val, &state) {
            Ok(count) => imported.push(format!("{} nodes", count)),
            Err(e) => errors.push(format!("nodes: {}", e)),
        }
    }

    // Simple file imports
    let file_imports = [
        ("ai_config", "/etc/wolfstack/ai-config.json", "AI config"),
        ("storage_config", "/etc/wolfstack/storage.json", "storage config"),
        ("ip_mappings", "/etc/wolfstack/ip-mappings.json", "IP mappings"),
    ];

    for (key, path, label) in &file_imports {
        if let Some(val) = obj.get(*key) {
            match write_json_file(path, val) {
                Ok(_) => imported.push(label.to_string()),
                Err(e) => errors.push(format!("{}: {}", label, e)),
            }
        }
    }

    // Reload AI config into the running agent so changes take effect immediately
    if obj.contains_key("ai_config") {
        let reloaded = crate::ai::AiConfig::load();
        let mut cfg = state.ai_agent.config.lock().unwrap();
        *cfg = reloaded;

    }

    // Backup config (schedules only)
    if let Some(val) = obj.get("backup_config") {
        // Merge schedules into existing config, keeping existing entries
        let mut config = backup::load_config();
        if let Some(schedules) = val.get("schedules").and_then(|v| v.as_array()) {
            if let Ok(imported_schedules) = serde_json::from_value::<Vec<backup::BackupSchedule>>(
                serde_json::Value::Array(schedules.clone())
            ) {
                let existing_ids: std::collections::HashSet<String> =
                    config.schedules.iter().map(|s| s.id.clone()).collect();
                let mut added = 0;
                for schedule in imported_schedules {
                    if !existing_ids.contains(&schedule.id) {
                        config.schedules.push(schedule);
                        added += 1;
                    }
                }
                if let Err(e) = backup::save_config(&config) {
                    errors.push(format!("backup schedules: {}", e));
                } else {
                    imported.push(format!("{} backup schedules", added));
                }
            }
        }
    }

    // PBS config
    if let Some(val) = obj.get("pbs_config") {
        let _ = std::fs::create_dir_all("/etc/wolfstack/pbs");
        match write_json_file("/etc/wolfstack/pbs/config.json", val) {
            Ok(_) => imported.push("PBS config".into()),
            Err(e) => errors.push(format!("PBS config: {}", e)),
        }
    }

    let summary = if errors.is_empty() {
        format!("Successfully imported: {}", imported.join(", "))
    } else {
        format!("Imported: {}. Errors: {}", imported.join(", "), errors.join(", "))
    };


    HttpResponse::Ok().json(serde_json::json!({
        "message": summary,
        "imported": imported,
        "errors": errors,
    }))
}

/// Write a serde_json::Value to a file as pretty JSON
fn write_json_file(path: &str, val: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create dir: {}", e))?;
    }
    let json = serde_json::to_string_pretty(val)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    std::fs::write(path, json)
        .map_err(|e| format!("Failed to write {}: {}", path, e))
}

/// Import nodes into the cluster, merging with existing. Returns count of added nodes.
fn import_nodes(nodes_val: &serde_json::Value, state: &web::Data<AppState>) -> Result<usize, String> {
    // Parse as HashMap<String, Node> (same format as nodes.json)
    let import_nodes: std::collections::HashMap<String, crate::agent::Node> =
        serde_json::from_value(nodes_val.clone())
            .map_err(|e| format!("Invalid nodes format: {}", e))?;

    let self_id = &state.cluster.self_id;
    let mut added = 0;

    {
        let mut nodes = state.cluster.nodes.write()
            .map_err(|_| "Failed to acquire lock".to_string())?;
        for (id, mut node) in import_nodes {
            // Skip self
            if id == *self_id {
                continue;
            }
            // Only add if not already present
            if !nodes.contains_key(&id) {
                node.is_self = false;
                node.online = false; // Will be updated on next poll
                nodes.insert(id, node);
                added += 1;
            }
        }
    }

    // Persist
    state.cluster.save_nodes();

    Ok(added)
}

/// POST /api/upgrade — run the WolfStack upgrade script in the background
/// Optional query param: ?channel=beta (defaults to master)
pub async fn system_upgrade(
    req: HttpRequest, state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let channel = query.get("channel").map(|s| s.as_str()).unwrap_or("master");
    let (branch, flag) = if channel == "beta" { ("beta", " --beta") } else { ("master", "") };


    let cmd = format!(
        "curl -sSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/{}/setup.sh | sudo bash -s --{}",
        branch, flag
    );

    // Spawn the upgrade script as a detached background process
    match std::process::Command::new("bash")
        .args(["-c", &cmd])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Upgrade started ({} channel) — WolfStack will restart automatically when complete.", branch)
        })),
        Err(e) => {
            error!("Failed to start upgrade: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to start upgrade: {}", e)
            }))
        }
    }
}

// ─── WolfFlow Workflow Automation API ───

/// GET /api/wolfflow/workflows — list workflows
pub async fn wolfflow_list(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = query.get("cluster").map(|s| s.as_str());
    HttpResponse::Ok().json(state.wolfflow.list_workflows(cluster))
}

/// POST /api/wolfflow/workflows — create workflow
pub async fn wolfflow_create(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match serde_json::from_value::<crate::wolfflow::Workflow>(body.into_inner()) {
        Ok(mut wf) => {
            if wf.id.is_empty() { wf.id = format!("wf-{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()); }
            if wf.created_at.is_empty() { wf.created_at = chrono::Utc::now().to_rfc3339(); }
            wf.updated_at = chrono::Utc::now().to_rfc3339();
            let created = state.wolfflow.create_workflow(wf);
            HttpResponse::Ok().json(created)
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid workflow: {}", e) })),
    }
}

/// GET /api/wolfflow/workflows/{id}
pub async fn wolfflow_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match state.wolfflow.get_workflow(&path.into_inner()) {
        Some(wf) => HttpResponse::Ok().json(wf),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Workflow not found" })),
    }
}

/// PUT /api/wolfflow/workflows/{id}
pub async fn wolfflow_update(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match serde_json::from_value::<crate::wolfflow::Workflow>(body.into_inner()) {
        Ok(mut wf) => {
            wf.updated_at = chrono::Utc::now().to_rfc3339();
            match state.wolfflow.update_workflow(&path.into_inner(), wf) {
                Some(updated) => HttpResponse::Ok().json(updated),
                None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Workflow not found" })),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid workflow: {}", e) })),
    }
}

/// DELETE /api/wolfflow/workflows/{id}
pub async fn wolfflow_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match state.wolfflow.delete_workflow(&path.into_inner()) {
        Some(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Workflow not found" })),
    }
}

/// POST /api/wolfflow/workflows/{id}/run — manually trigger a workflow
pub async fn wolfflow_trigger(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let workflow = match state.wolfflow.get_workflow(&id) {
        Some(wf) => wf,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Workflow not found" })),
    };
    let wf_state = state.wolfflow.clone();
    let cluster = state.cluster.clone();
    let secret = state.cluster_secret.clone();
    let ai_config = state.ai_agent.config.lock().unwrap().clone();
    tokio::spawn(async move {
        crate::wolfflow::execute_workflow(&wf_state, &cluster, &secret, &workflow, "manual", Some(ai_config)).await;
    });
    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": "Workflow triggered" }))
}

/// GET /api/wolfflow/runs — list execution history
pub async fn wolfflow_runs_list(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let wf_id = query.get("workflow_id").map(|s| s.as_str());
    let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let mut runs = state.wolfflow.list_runs(wf_id);
    runs.reverse(); // newest first
    runs.truncate(limit);
    HttpResponse::Ok().json(runs)
}

/// GET /api/wolfflow/runs/{id}
pub async fn wolfflow_run_detail(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let runs = state.wolfflow.list_runs(None);
    match runs.into_iter().find(|r| r.id == id) {
        Some(run) => HttpResponse::Ok().json(run),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Run not found" })),
    }
}

/// GET /api/wolfflow/toolbox — list available actions
pub async fn wolfflow_toolbox(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::wolfflow::toolbox_actions())
}

/// GET /api/wolfflow/infrastructure — returns the full infrastructure tree for target selection
/// Clusters → Nodes → Docker containers, LXC containers, VMs
pub async fn wolfflow_infrastructure(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let nodes = state.cluster.get_all_nodes();
    let cluster_secret = state.cluster_secret.clone();
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut clusters: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();

    for node in &nodes {
        let cluster_name = node.cluster_name.clone()
            .or(node.pve_cluster_name.clone())
            .unwrap_or_else(|| "Default".to_string());

        let mut node_data = serde_json::json!({
            "id": node.id,
            "hostname": node.hostname,
            "address": node.address,
            "port": node.port,
            "online": node.online,
            "node_type": node.node_type,
            "is_self": node.is_self,
            "docker": [],
            "lxc": [],
            "vms": [],
        });

        // Fetch containers for online nodes
        if node.online && node.node_type == "wolfstack" {
            let urls = build_node_urls(&node.address, node.port, "/api/containers/docker");
            for url in &urls {
                if let Ok(resp) = http_client.get(url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await
                {
                    if let Ok(containers) = resp.json::<Vec<serde_json::Value>>().await {
                        node_data["docker"] = serde_json::json!(containers.iter().map(|c| {
                            serde_json::json!({
                                "name": c.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                                "state": c.get("state").and_then(|v| v.as_str()).unwrap_or("?"),
                            })
                        }).collect::<Vec<_>>());
                        break;
                    }
                }
            }
            let urls = build_node_urls(&node.address, node.port, "/api/containers/lxc");
            for url in &urls {
                if let Ok(resp) = http_client.get(url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await
                {
                    if let Ok(containers) = resp.json::<Vec<serde_json::Value>>().await {
                        node_data["lxc"] = serde_json::json!(containers.iter().map(|c| {
                            serde_json::json!({
                                "name": c.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                                "state": c.get("state").and_then(|v| v.as_str()).unwrap_or("?"),
                            })
                        }).collect::<Vec<_>>());
                        break;
                    }
                }
            }
            let urls = build_node_urls(&node.address, node.port, "/api/vms");
            for url in &urls {
                if let Ok(resp) = http_client.get(url)
                    .header("X-WolfStack-Secret", &cluster_secret)
                    .send().await
                {
                    if let Ok(vms) = resp.json::<Vec<serde_json::Value>>().await {
                        node_data["vms"] = serde_json::json!(vms.iter().map(|v| {
                            serde_json::json!({
                                "name": v.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                                "state": if v.get("running").and_then(|v| v.as_bool()).unwrap_or(false) { "running" } else { "stopped" },
                            })
                        }).collect::<Vec<_>>());
                        break;
                    }
                }
            }
        } else if node.online && node.node_type == "proxmox" {
            // PVE nodes — fetch guests
            // PVE guests fetched via the local /pve/resources endpoint below
            let pve_url = format!("/api/nodes/{}/pve/resources", node.id);
            if let Ok(resp) = http_client.get(&format!("https://{}:{}{}", "127.0.0.1", 8553, pve_url))
                .header("X-WolfStack-Secret", &cluster_secret)
                .send().await
            {
                if let Ok(guests) = resp.json::<Vec<serde_json::Value>>().await {
                    let lxc: Vec<_> = guests.iter()
                        .filter(|g| g.get("guest_type").and_then(|v| v.as_str()) == Some("lxc"))
                        .map(|g| serde_json::json!({
                            "name": g.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                            "state": g.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                        }))
                        .collect();
                    let vms: Vec<_> = guests.iter()
                        .filter(|g| g.get("guest_type").and_then(|v| v.as_str()) == Some("qemu"))
                        .map(|g| serde_json::json!({
                            "name": g.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                            "state": g.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                        }))
                        .collect();
                    node_data["lxc"] = serde_json::json!(lxc);
                    node_data["vms"] = serde_json::json!(vms);
                }
            }
        }

        clusters.entry(cluster_name).or_default().push(node_data);
    }

    HttpResponse::Ok().json(clusters)
}

/// POST /api/wolfflow/exec — execute a single action (used by remote execution)
pub async fn wolfflow_exec(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match serde_json::from_value::<crate::wolfflow::ActionType>(body.into_inner()) {
        Ok(action) => {
            match crate::wolfflow::execute_action_local(&action).await {
                Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": output })),
                Err(err) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "output": err })),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid action: {}", e) })),
    }
}

/// POST /api/wolfflow/container-exec — execute an action inside a specific container (cluster proxy)
pub async fn wolfflow_container_exec(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let data = body.into_inner();
    let action_val = data.get("action").cloned().unwrap_or(serde_json::Value::Null);
    let ct_val = data.get("container").cloned().unwrap_or(serde_json::Value::Null);

    let action: crate::wolfflow::ActionType = match serde_json::from_value(action_val) {
        Ok(a) => a,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid action: {}", e) })),
    };
    let ct: crate::wolfflow::ContainerTarget = match serde_json::from_value(ct_val) {
        Ok(c) => c,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid container target: {}", e) })),
    };

    match crate::wolfflow::execute_action_in_container(&action, &ct).await {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": output.text })),
        Err(err) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": err })),
    }
}

/// POST /api/wolfflow/all-containers-exec — execute an action inside all containers on this node (cluster proxy)
pub async fn wolfflow_all_containers_exec(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match serde_json::from_value::<crate::wolfflow::ActionType>(body.into_inner()) {
        Ok(action) => {
            match crate::wolfflow::execute_in_all_local_containers(&action).await {
                Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": output.text })),
                Err(err) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": err })),
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Invalid action: {}", e) })),
    }
}

// ─── User Preferences API ───

fn user_prefs_path(username: &str) -> Option<String> {
    // Sanitize username — no dots (prevents ../ traversal), no slashes
    let safe: String = username.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if safe.is_empty() || safe == "cluster-node" { return None; }
    let path = format!("{}/user-prefs/{}.json", crate::paths::get().config_dir, safe);
    // Verify the path is under the expected directory
    let expected_dir = format!("{}/user-prefs/", crate::paths::get().config_dir);
    if !path.starts_with(&expected_dir) { return None; }
    Some(path)
}

/// GET /api/user/preferences — load the current user's preferences
pub async fn user_prefs_get(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let username = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let path = match user_prefs_path(&username) {
        Some(p) => p,
        None => return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Not a user account" })),
    };
    match std::fs::read_to_string(&path) {
        Ok(data) => {
            match serde_json::from_str::<serde_json::Value>(&data) {
                Ok(prefs) => HttpResponse::Ok().json(prefs),
                Err(_) => HttpResponse::Ok().json(serde_json::json!({})),
            }
        }
        Err(_) => HttpResponse::Ok().json(serde_json::json!({})),
    }
}

/// POST /api/user/preferences — save the current user's preferences (full replace)
pub async fn user_prefs_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let username = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let path = match user_prefs_path(&username) {
        Some(p) => p,
        None => return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Not a user account" })),
    };
    let dir = std::path::Path::new(&path).parent().unwrap_or(std::path::Path::new("/tmp"));
    if let Err(e) = std::fs::create_dir_all(dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to create dir: {}", e) }));
    }

    // Limit size to prevent abuse (64 KB should be plenty for preferences)
    let json = serde_json::to_string_pretty(&body.into_inner()).unwrap_or_default();
    if json.len() > 65536 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Preferences too large (max 64 KB)" }));
    }

    match std::fs::write(&path, &json) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to save: {}", e) })),
    }
}

/// PATCH /api/user/preferences — merge specific keys into existing preferences
pub async fn user_prefs_patch(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let username = match require_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let path = match user_prefs_path(&username) {
        Some(p) => p,
        None => return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Not a user account" })),
    };
    let dir = std::path::Path::new(&path).parent().unwrap_or(std::path::Path::new("/tmp"));
    let _ = std::fs::create_dir_all(dir);

    // Load existing
    let mut prefs: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default();

    // Merge incoming keys
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if v.is_null() {
                prefs.remove(k);
            } else {
                prefs.insert(k.clone(), v.clone());
            }
        }
    }

    let json = serde_json::to_string_pretty(&prefs).unwrap_or_default();
    if json.len() > 65536 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Preferences too large" }));
    }

    match std::fs::write(&path, &json) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to save: {}", e) })),
    }
}

// ─── WolfUSB API ───

/// GET /api/wolfusb/status — wolfusb availability, config, assignments
pub async fn wolfusb_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfusb::WolfUsbConfig::load();
    let available = crate::wolfusb::is_wolfusb_available();
    let version = if available { crate::wolfusb::get_wolfusb_version() } else { None };
    let kmod = crate::wolfusb::kernel_module_status();
    HttpResponse::Ok().json(serde_json::json!({
        "wolfusb_available": available,
        "enabled": config.enabled,
        "assignment_count": config.assignments.len(),
        "version": version,
        "kernel_modules": {
            "vhci_hcd_loaded": kmod.vhci_hcd_loaded,
            "usbip_host_loaded": kmod.usbip_host_loaded,
            "fully_ready": kmod.is_fully_ready(),
            "install_hint": kmod.install_hint,
        },
    }))
}

/// POST /api/wolfusb/install — install wolfusb tools
pub async fn wolfusb_install(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match crate::wolfusb::install_wolfusb().await {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": output })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// GET /api/wolfusb/config — get config
pub async fn wolfusb_get_config(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfusb::WolfUsbConfig::load();
    HttpResponse::Ok().json(&config)
}

/// POST /api/wolfusb/config — save config and sync to cluster
pub async fn wolfusb_save_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::wolfusb::WolfUsbConfig::load();
    if let Some(v) = body.get("enabled").and_then(|v| v.as_bool()) { config.enabled = v; }
    match config.save() {
        Ok(_) => {
            wolfusb_broadcast_sync(&state);
            HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// Broadcast WolfUSB assignments to all cluster nodes
fn wolfusb_broadcast_sync(state: &web::Data<AppState>) {
    let config = crate::wolfusb::WolfUsbConfig::load();
    let cluster_secret = state.cluster_secret.clone();
    let nodes = state.cluster.get_all_nodes();
    let client = reqwest::Client::new();
    let payload = serde_json::json!({ "assignments": config.assignments });

    for node in nodes.iter().filter(|n| !n.is_self && n.online) {
        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/wolfusb/sync");
        let secret = cluster_secret.clone();
        let body = payload.clone();
        let c = client.clone();
        tokio::spawn(async move {
            for url in &urls {
                if c.post(url)
                    .header("X-WolfStack-Secret", &secret)
                    .json(&body)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        });
    }
}

/// GET /api/wolfusb/devices — list USB devices on this node
pub async fn wolfusb_devices(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfusb::WolfUsbConfig::load();
    let (devices, wolfusb_working) = crate::wolfusb::list_local_devices_with_status(&config);
    HttpResponse::Ok().json(serde_json::json!({
        "devices": devices,
        "assignments": config.assignments,
        "wolfusb_working": wolfusb_working,
    }))
}

/// Pick the first non-loopback, non-wildcard IPv4 address on this host.
/// Used to fill in the self-node's connectable address when nodes.json has
/// it stored as a bind wildcard (0.0.0.0), which isn't routable from peers.
fn pick_routable_address() -> Option<String> {
    // Try tailscale first since wolfstack clusters usually use it.
    if let Ok(out) = std::process::Command::new("tailscale").arg("ip").arg("-4").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() && !s.starts_with("127.") {
                return Some(s.lines().next().unwrap_or("").to_string());
            }
        }
    }
    // Fall back to `ip -4 route get 1.1.1.1` to find the egress interface's IP.
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "route", "get", "1.1.1.1"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(src) = s.split("src ").nth(1) {
                let addr = src.split_whitespace().next().unwrap_or("");
                if !addr.is_empty() && !addr.starts_with("127.") {
                    return Some(addr.to_string());
                }
            }
        }
    }
    None
}

/// GET /api/wolfusb/cluster_devices — aggregate USB devices from every node.
/// Users pick the device they want and the target they want in one view; the
/// backend records the real source node automatically, no matter which node's
/// dashboard they're looking at.
pub async fn wolfusb_cluster_devices(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) {
        return resp;
    }
    // Skip nodes that are known-offline (last heartbeat > 5 min). The
    // cluster state can retain stale entries for nodes that were removed,
    // renamed, or permanently taken offline; querying them produces
    // spurious "Unreachable" warnings for nodes that aren't part of the
    // cluster anymore. We don't trust Node.online alone because it can
    // be stuck on True if the polling loop never managed to contact the
    // node to mark it false.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nodes: Vec<_> = state
        .cluster
        .get_all_nodes()
        .into_iter()
        .filter(|n| n.is_self || (n.online && now.saturating_sub(n.last_seen) < 300))
        .collect();
    let config = crate::wolfusb::WolfUsbConfig::load();
    let secret = state.cluster_secret.clone();
    let client = reqwest::Client::new();

    // Collect the local node's devices first.
    let (local_devices, local_ok) =
        crate::wolfusb::list_local_devices_with_status(&config);
    let mut out: Vec<serde_json::Value> = Vec::new();

    for node in &nodes {
        let entry = if node.is_self {
            // If the self node's stored address is a bind wildcard (0.0.0.0
            // or ::) it's not connectable from other nodes — pick the first
            // routable IP we can find so the assignment's source_address
            // is usable when a remote node tries to mount from us.
            let advertised_address = if node.address == "0.0.0.0"
                || node.address == "::"
                || node.address.is_empty()
            {
                pick_routable_address().unwrap_or_else(|| node.address.clone())
            } else {
                node.address.clone()
            };
            serde_json::json!({
                "node_id": node.id,
                "hostname": node.hostname,
                "address": advertised_address,
                "is_self": true,
                "reachable": true,
                "wolfusb_working": local_ok,
                "devices": local_devices,
            })
        } else {
            // Remote node — fetch via inter-node endpoint using cluster secret.
            let urls = build_node_urls(&node.address, node.port, "/api/wolfusb/devices");
            let mut remote_devices: Vec<serde_json::Value> = Vec::new();
            let mut reachable = false;
            let mut wolfusb_working = false;
            for url in &urls {
                match client
                    .get(url)
                    .header("X-WolfStack-Secret", &secret)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(j) = resp.json::<serde_json::Value>().await {
                            remote_devices = j
                                .get("devices")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default();
                            wolfusb_working = j
                                .get("wolfusb_working")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            reachable = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            serde_json::json!({
                "node_id": node.id,
                "hostname": node.hostname,
                "address": node.address,
                "is_self": false,
                "reachable": reachable,
                "wolfusb_working": wolfusb_working,
                "devices": remote_devices,
            })
        };
        out.push(entry);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "nodes": out,
        "assignments": config.assignments,
    }))
}

/// POST /api/wolfusb/assign — assign a USB device to a container/VM (cluster-wide)
pub async fn wolfusb_assign(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::wolfusb::WolfUsbConfig::load();

    let busid = body.get("busid").and_then(|v| v.as_str()).unwrap_or("");
    let label = body.get("label").and_then(|v| v.as_str()).unwrap_or("");
    let usb_id = body.get("usb_id").and_then(|v| v.as_str()).unwrap_or("");
    let source_node_id = body.get("source_node_id").and_then(|v| v.as_str()).unwrap_or("");
    let source_hostname = body.get("source_hostname").and_then(|v| v.as_str()).unwrap_or("");
    let source_address = body.get("source_address").and_then(|v| v.as_str()).unwrap_or("");
    let target_type = body.get("target_type").and_then(|v| v.as_str()).unwrap_or("");
    let target_name = body.get("target_name").and_then(|v| v.as_str()).unwrap_or("");
    let target_node_id = body.get("target_node_id").and_then(|v| v.as_str()).unwrap_or("");
    let target_hostname = body.get("target_hostname").and_then(|v| v.as_str()).unwrap_or("");

    if busid.is_empty() || target_type.is_empty() || target_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "busid, target_type, and target_name are required" }));
    }

    // Determine if this node is the source
    let self_node = state.cluster.get_all_nodes().into_iter().find(|n| n.is_self);
    let self_id = self_node.as_ref().map(|n| n.id.as_str()).unwrap_or("");
    let is_local_source = source_node_id == self_id || source_node_id.is_empty();

    // Use WolfNet IP if available, otherwise the regular address
    let effective_address = if !source_address.is_empty() {
        source_address.to_string()
    } else {
        self_node.as_ref().map(|n| n.address.clone()).unwrap_or_default()
    };

    let effective_source_id = if source_node_id.is_empty() { self_id } else { source_node_id };

    match crate::wolfusb::assign_device(
        &mut config, busid, label, usb_id,
        effective_source_id,
        source_hostname, &effective_address,
        target_type, target_name,
        target_node_id, target_hostname,
        is_local_source,
    ) {
        Ok(msg) => {
            wolfusb_broadcast_sync(&state);

            // Trigger the actual mount+passthrough. Four cases:
            //   1. source=self, target=self  → assign_device already did local_passthrough
            //   2. source=self, target=remote → nothing to mount here; target pulls from us
            //   3. source=remote, target=self → WE need to mount the remote device here
            //   4. source=remote, target=remote → forward to target to do case 3
            let is_local_target = target_node_id == self_id || target_node_id.is_empty();
            let is_cross_node_source = !is_local_source && !effective_address.is_empty();

            if is_local_target && is_cross_node_source {
                // Case 3: we're the target and the source is elsewhere. Run
                // attach_and_passthrough locally so the wolfusb-mount@ unit
                // gets installed, enabled, started, and the device gets
                // passed into the LXC/Docker/VM target.
                let src_addr = effective_address.clone();
                let busid_s = busid.to_string();
                let target_type_s = target_type.to_string();
                let target_name_s = target_name.to_string();
                tokio::task::spawn_blocking(move || {
                    match crate::wolfusb::attach_and_passthrough(
                        &src_addr, &busid_s, &target_type_s, &target_name_s,
                    ) {
                        Ok(m) => tracing::info!("WolfUSB: local attach done — {}", m),
                        Err(e) => tracing::warn!("WolfUSB: local attach failed — {}", e),
                    }
                });
            } else if !is_local_target && !target_node_id.is_empty() {
                // Case 4: target is a different node — forward the attach call.
                let nodes = state.cluster.get_all_nodes();
                if let Some(target_node) = nodes.iter().find(|n| n.id == target_node_id) {
                    let urls = crate::api::build_node_urls(&target_node.address, target_node.port, "/api/wolfusb/attach");
                    let secret = state.cluster_secret.clone();
                    let client = reqwest::Client::new();
                    let body = serde_json::json!({
                        "source_address": effective_address,
                        "busid": busid,
                        "target_type": target_type,
                        "target_name": target_name,
                    });
                    tokio::spawn(async move {
                        for url in &urls {
                            match client.post(url)
                                .header("X-WolfStack-Secret", &secret)
                                .json(&body)
                                .timeout(std::time::Duration::from_secs(30))
                                .send()
                                .await
                            {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::info!("WolfUSB: remote attach triggered on target node");
                                    break;
                                }
                                Ok(resp) => {
                                    tracing::warn!("WolfUSB: remote attach returned {}", resp.status());
                                }
                                Err(e) => {
                                    tracing::warn!("WolfUSB: remote attach failed ({}): {}", url, e);
                                }
                            }
                        }
                    });
                }
            }

            HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": msg }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// POST /api/wolfusb/unassign — remove a USB device assignment
pub async fn wolfusb_unassign(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::wolfusb::WolfUsbConfig::load();

    let busid = body.get("busid").and_then(|v| v.as_str()).unwrap_or("");
    let source_node_id = body.get("source_node_id").and_then(|v| v.as_str()).unwrap_or("");

    match crate::wolfusb::unassign_device(&mut config, busid, source_node_id) {
        Ok(msg) => {
            wolfusb_broadcast_sync(&state);
            HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": msg }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// POST /api/wolfusb/sync — receive assignment list from a cluster node (merge into local config)
pub async fn wolfusb_sync(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let assignments: Vec<crate::wolfusb::UsbAssignment> = body.get("assignments")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    crate::wolfusb::merge_remote_assignments(&assignments);
    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}

/// POST /api/wolfusb/attach — attach a remote USB device and pass into container (called on target node)
pub async fn wolfusb_attach(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let source_address = body.get("source_address").and_then(|v| v.as_str()).unwrap_or("");
    let busid = body.get("busid").and_then(|v| v.as_str()).unwrap_or("");
    let target_type = body.get("target_type").and_then(|v| v.as_str()).unwrap_or("");
    let target_name = body.get("target_name").and_then(|v| v.as_str()).unwrap_or("");

    if source_address.is_empty() || busid.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "source_address and busid required" }));
    }

    match crate::wolfusb::attach_and_passthrough(source_address, busid, target_type, target_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": msg })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// GET /api/wolfusb/diagnose/{busid} — read-only walk of the
/// passthrough chain for one assignment. Returns an ordered list of
/// {step, ok, detail} so the UI can render a top-to-bottom checklist.
/// No side effects — safe to call on a cron or from an on-page refresh.
pub async fn wolfusb_diagnose(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let busid = path.into_inner();
    let steps = crate::wolfusb::diagnose(&busid);
    let overall_ok = steps.iter().all(|s| s.ok);
    HttpResponse::Ok().json(serde_json::json!({
        "busid": busid,
        "ok": overall_ok,
        "steps": steps,
    }))
}

/// POST /api/wolfusb/prepare-for-export — called on the SOURCE node
/// (the one with the physical USB device) by a TARGET node that's
/// about to attach. Idempotent; ensures wolfusb-server is running,
/// confirms the device is on the host bus, confirms usbip-host kernel
/// module is loaded. Returns the checklist so the caller can surface
/// failures to the user before attempting attach.
pub async fn wolfusb_prepare_for_export(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let busid = body.get("busid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if busid.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "busid required" }));
    }
    let steps = tokio::task::spawn_blocking(move || {
        crate::wolfusb::prepare_for_export(&busid)
    }).await.unwrap_or_else(|e| vec![crate::wolfusb::ReattachStep {
        step: "prepare-for-export task".into(),
        ok: false,
        detail: format!("task panicked: {}", e),
    }]);
    let overall_ok = steps.iter().all(|s| s.ok);
    HttpResponse::Ok().json(serde_json::json!({
        "ok": overall_ok,
        "steps": steps,
    }))
}

/// POST /api/wolfusb/reattach/{busid} — full recovery flow.
///
/// Call from any node the operator is logged into. We look up the
/// assignment's target node and proxy to it if we're not that node.
/// On the target we:
///   1. (if cross-node) Call source's /api/wolfusb/prepare-for-export
///      so the device is unbound locally and ready for usbip-host
///      to claim it.
///   2. Run wolfusb::reattach_local which wipes any stale mount unit
///      and re-runs the attach chain.
/// Returns the combined step list so the UI shows everything that
/// happened — this is the UI for fixing Papa's "migration orphaned
/// my USB" scenario without SSHing into nodes.
pub async fn wolfusb_reattach(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let busid = path.into_inner();

    // Look up the assignment to find source + target.
    let config = crate::wolfusb::WolfUsbConfig::load();
    let assignment = config.assignments.iter().find(|a| a.busid == busid).cloned();
    let Some(a) = assignment else {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("no assignment for busid {}", busid),
        }));
    };

    let self_id = crate::agent::self_node_id();

    // Step A: if target is not us, proxy to target and let THEY run
    // the recovery. Keeps all the node-local kernel/systemd work on
    // the node that actually needs it.
    //
    // Failures on this path return a `steps: [...]` shape (not a bare
    // `error`) so the UI's per-step renderer has something to draw
    // instead of the generic "No step data returned" fallback. The
    // single step describes exactly which proxy hop failed and why,
    // which is the information the operator actually needs.
    if a.target_node_id != self_id {
        let nodes = state.cluster.get_all_nodes();
        let Some(target) = nodes.iter().find(|n| n.id == a.target_node_id) else {
            return HttpResponse::Ok().json(serde_json::json!({
                "ok": false,
                "steps": [{
                    "step": "Locate target node",
                    "ok": false,
                    "detail": format!(
                        "Target node {} is not in this cluster's membership. \
                         The VM may have been migrated away from it, or the \
                         node was removed. Try running Re-attach from a node \
                         that currently sees {} as a cluster peer.",
                        a.target_node_id, a.target_node_id
                    ),
                }],
            }));
        };
        let urls = build_node_urls(&target.address, target.port,
            &format!("/api/wolfusb/reattach/{}", urlencoding_simple(&busid)));
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => return HttpResponse::Ok().json(serde_json::json!({
                "ok": false,
                "steps": [{
                    "step": "Build inter-node HTTP client",
                    "ok": false,
                    "detail": format!("http client build failed: {}", e),
                }],
            })),
        };
        let mut last_err = String::new();
        for url in &urls {
            let res = client.post(url)
                .header("X-WolfStack-Secret", &state.cluster_secret)
                .send().await;
            match res {
                Ok(r) if r.status().is_success() => {
                    let body = r.bytes().await.unwrap_or_default();
                    return HttpResponse::Ok()
                        .content_type("application/json")
                        .body(body);
                }
                Ok(r) => {
                    // Upstream returned a non-2xx — this usually means
                    // the cluster-secret didn't match or the target has
                    // auth misconfigured. Wrap in a step so the UI can
                    // show it clearly instead of dumping raw bytes.
                    let code = r.status().as_u16();
                    let body_text = r.bytes().await
                        .ok()
                        .and_then(|b| String::from_utf8(b.to_vec()).ok())
                        .unwrap_or_default();
                    let trimmed = body_text.chars().take(400).collect::<String>();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "ok": false,
                        "steps": [{
                            "step": format!("Proxy to target {} (HTTP {})", target.hostname, code),
                            "ok": false,
                            "detail": format!(
                                "The target node returned HTTP {}. Common cause: \
                                 cluster-secret mismatch between this node and {}. \
                                 Workaround: open WolfStack directly on {} and click \
                                 Re-attach there.\n\nUpstream body: {}",
                                code, target.hostname, target.hostname, trimmed
                            ),
                        }],
                    }));
                }
                Err(e) => { last_err = format!("{} → {}", url, e); continue; }
            }
        }
        return HttpResponse::Ok().json(serde_json::json!({
            "ok": false,
            "steps": [{
                "step": format!("Proxy to target {}", target.hostname),
                "ok": false,
                "detail": format!(
                    "Could not reach {} on any of the attempted URLs. Check \
                     that the target node is online (Datacenter page shows \
                     its state) and that this node's cluster secret matches \
                     {}'s. Workaround: open WolfStack directly on {} and \
                     click Re-attach there.\n\nLast error: {}",
                    target.hostname, target.hostname, target.hostname, last_err
                ),
            }],
        }));
    }

    // Step B: we ARE the target. If cross-node, ask source to prepare
    // for export first. Accumulate the source's steps into the result.
    let mut all_steps: Vec<crate::wolfusb::ReattachStep> = Vec::new();
    if a.source_node_id != self_id {
        let nodes = state.cluster.get_all_nodes();
        let Some(source) = nodes.iter().find(|n| n.id == a.source_node_id) else {
            all_steps.push(crate::wolfusb::ReattachStep {
                step: "Locate source node".into(),
                ok: false,
                detail: format!("source node {} not in cluster — check node membership", a.source_node_id),
            });
            return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "steps": all_steps }));
        };
        let urls = build_node_urls(&source.address, source.port, "/api/wolfusb/prepare-for-export");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build().ok();
        let body = serde_json::json!({ "busid": busid });
        let mut source_reached = false;
        if let Some(c) = client {
            for url in &urls {
                if let Ok(resp) = c.post(url)
                    .header("X-WolfStack-Secret", &state.cluster_secret)
                    .json(&body)
                    .send().await
                {
                    if resp.status().is_success() {
                        source_reached = true;
                        if let Ok(v) = resp.json::<serde_json::Value>().await {
                            if let Some(arr) = v.get("steps").and_then(|s| s.as_array()) {
                                for step in arr {
                                    all_steps.push(crate::wolfusb::ReattachStep {
                                        step: format!("[{}] {}", source.hostname,
                                            step.get("step").and_then(|x| x.as_str()).unwrap_or("?")),
                                        ok: step.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                                        detail: step.get("detail").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                    });
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        if !source_reached {
            all_steps.push(crate::wolfusb::ReattachStep {
                step: "Contact source node".into(),
                ok: false,
                detail: format!(
                    "Could not reach {} on any URL — check the node is online and \
                     cluster-secret auth is working.", source.hostname
                ),
            });
            return HttpResponse::Ok().json(serde_json::json!({ "ok": false, "steps": all_steps }));
        }
    }

    // Step C: run the local reattach — cleans stale mount unit and
    // reruns attach_and_passthrough. spawn_blocking because it shells
    // systemctl + wolfusb.
    let busid_c = busid.clone();
    let local_steps = tokio::task::spawn_blocking(move || {
        crate::wolfusb::reattach_local(&busid_c)
    }).await.unwrap_or_else(|e| vec![crate::wolfusb::ReattachStep {
        step: "local reattach task".into(),
        ok: false,
        detail: format!("task panicked: {}", e),
    }]);
    all_steps.extend(local_steps);
    let overall_ok = all_steps.iter().all(|s| s.ok);
    HttpResponse::Ok().json(serde_json::json!({
        "busid": busid,
        "ok": overall_ok,
        "steps": all_steps,
    }))
}

// ─── MySQL Database Editor API ───

/// GET /api/mysql/detect — check if MySQL is installed on this node
pub async fn mysql_detect(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    HttpResponse::Ok().json(crate::mysql_editor::detect_mysql())
}

/// GET /api/mysql/detect-containers — find MySQL/MariaDB in Docker/LXC containers
pub async fn mysql_detect_containers(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let containers = crate::mysql_editor::detect_mysql_containers();
    HttpResponse::Ok().json(serde_json::json!({ "containers": containers }))
}

#[derive(Deserialize)]
pub struct MysqlConnectRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

fn mysql_default_port() -> u16 { 3306 }

/// POST /api/mysql/connect — test a database connection (MySQL or PostgreSQL)
pub async fn mysql_connect(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlConnectRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: None,
        db_type: body.db_type,
    };

    let result = if body.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(10),
            crate::mysql_editor::pg_test_connection(&params)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(10),
            crate::mysql_editor::test_connection(&params)).await
    };

    match result {
        Ok(Ok(version)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "connected": true,
                "version": version,
            }))
        }
        Ok(Err(e)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "connected": false,
                "error": e,
            }))
        }
        Err(_) => {
            HttpResponse::Ok().json(serde_json::json!({
                "connected": false,
                "error": format!("Connection to {}:{} timed out after 10 seconds.", body.host, body.port),
            }))
        }
    }
}

#[derive(Deserialize)]
pub struct MysqlCredsRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

impl MysqlCredsRequest {
    fn to_params(&self) -> crate::mysql_editor::ConnParams {
        crate::mysql_editor::ConnParams {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            password: self.password.clone(),
            database: self.database.clone(),
            db_type: self.db_type,
        }
    }
}

/// POST /api/mysql/databases — list databases
pub async fn mysql_databases(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlCredsRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = body.to_params();
    let result = if params.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(15),
            crate::mysql_editor::pg_list_databases(&params)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(15),
            crate::mysql_editor::list_databases(&params)).await
    };
    match result {
        Ok(Ok(dbs)) => HttpResponse::Ok().json(serde_json::json!({ "databases": dbs })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Database list request timed out after 15 seconds" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlTablesRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

/// POST /api/mysql/tables — list tables in a database
pub async fn mysql_tables(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlTablesRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(), port: body.port, user: body.user.clone(),
        password: body.password.clone(), database: Some(body.database.clone()), db_type: body.db_type,
    };
    let db = body.database.clone();
    let result = if body.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(15),
            crate::mysql_editor::pg_list_tables(&params, &db)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(15),
            crate::mysql_editor::list_tables(&params, &db)).await
    };
    match result {
        Ok(Ok(tables)) => HttpResponse::Ok().json(serde_json::json!({ "tables": tables })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Table list timed out" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlStructureRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
    pub table: String,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

/// POST /api/mysql/structure — get table structure
pub async fn mysql_structure(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlStructureRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(), port: body.port, user: body.user.clone(),
        password: body.password.clone(), database: Some(body.database.clone()), db_type: body.db_type,
    };
    let db = body.database.clone();
    let tbl = body.table.clone();
    let result = if body.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(15),
            crate::mysql_editor::pg_table_structure(&params, &db, &tbl)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            crate::mysql_editor::table_structure(&params, &db, &tbl).await
                .map(serde_json::Value::Array)
        }).await
    };
    match result {
        Ok(Ok(cols)) => HttpResponse::Ok().json(serde_json::json!({ "columns": cols })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Structure request timed out" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlDataRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub database: String,
    pub table: String,
    #[serde(default)]
    pub page: u64,
    #[serde(default = "mysql_default_page_size")]
    pub page_size: u64,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub order_dir: Option<String>,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

fn mysql_default_page_size() -> u64 { 50 }

/// POST /api/mysql/data — get paginated table data
pub async fn mysql_data(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlDataRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(), port: body.port, user: body.user.clone(),
        password: body.password.clone(), database: Some(body.database.clone()), db_type: body.db_type,
    };
    let db = body.database.clone();
    let tbl = body.table.clone();
    let page = body.page;
    let page_size = body.page_size;
    let order_by = body.order_by.clone();
    let order_dir = body.order_dir.clone();
    let ob = order_by.as_deref();
    let od = order_dir.as_deref();
    let result = if body.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(30),
            crate::mysql_editor::pg_table_data(&params, &db, &tbl, page as u32, page_size as u32, ob, od)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(30),
            crate::mysql_editor::table_data(&params, &db, &tbl, page, page_size, ob, od)).await
    };
    match result {
        Ok(Ok(data)) => HttpResponse::Ok().json(data),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Data request timed out" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlQueryRequest {
    pub host: String,
    #[serde(default = "mysql_default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub database: String,
    pub query: String,
    #[serde(default)]
    pub db_type: crate::mysql_editor::DbType,
}

/// POST /api/mysql/query — execute arbitrary SQL
pub async fn mysql_query(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlQueryRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(), port: body.port, user: body.user.clone(),
        password: body.password.clone(),
        database: if body.database.is_empty() { None } else { Some(body.database.clone()) },
        db_type: body.db_type,
    };
    let db = body.database.clone();
    let query = body.query.clone();
    let result = if body.db_type == crate::mysql_editor::DbType::Postgres {
        tokio::time::timeout(std::time::Duration::from_secs(30),
            crate::mysql_editor::pg_execute_query(&params, &db, &query)).await
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(30),
            crate::mysql_editor::execute_query(&params, &db, &query)).await
    };
    match result {
        Ok(Ok(result)) => HttpResponse::Ok().json(result),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Query timed out" })),
    }
}

#[derive(Deserialize)]
pub struct MysqlDumpRequest {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub include_data: bool,
}

/// POST /api/mysql/dump — dump database to SQL
pub async fn mysql_dump(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<MysqlDumpRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let params = crate::mysql_editor::ConnParams {
        host: body.host.clone(),
        port: body.port,
        user: body.user.clone(),
        password: body.password.clone(),
        database: Some(body.database.clone()),
        db_type: crate::mysql_editor::DbType::Mysql, // dump is MySQL-only for now
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        crate::mysql_editor::dump_database(&params, &body.database, body.include_data),
    ).await;
    match result {
        Ok(Ok(sql)) => {
            let filename = format!("{}{}.sql",
                body.database,
                if body.include_data { "_full" } else { "_structure" });
            HttpResponse::Ok()
                .content_type("application/sql")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(sql)
        }
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Dump timed out after 120 seconds" })),
    }
}

// ─── App Store ───

/// GET /api/appstore/apps?q=<query>&category=<cat> — list/search available apps
pub async fn appstore_list(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let q = query.get("q").map(|s| s.as_str());
    let cat = query.get("category").map(|s| s.as_str());
    let apps = appstore::list_apps(q, cat);
    HttpResponse::Ok().json(serde_json::json!({ "apps": apps }))
}

/// GET /api/appstore/apps/{id} — get app details
pub async fn appstore_get(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match appstore::get_app(&id) {
        Some(app) => HttpResponse::Ok().json(app),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": format!("App '{}' not found", id) })),
    }
}

#[derive(Deserialize)]
pub struct AppInstallRequest {
    pub target: String,                              // "docker", "lxc", "bare"
    pub container_name: String,                      // name for the container
    #[serde(default)]
    pub inputs: std::collections::HashMap<String, String>,  // user input values
    #[serde(default)]
    pub storage_path: Option<String>,                // optional storage location
    #[serde(default)]
    pub ports: Option<Vec<String>>,                  // optional custom port mappings (overrides manifest)
    #[serde(default)]
    pub extra_env: Option<Vec<String>>,              // additional env vars (KEY=VALUE)
    #[serde(default)]
    pub extra_volumes: Option<Vec<String>>,           // additional volume mounts (host:container)
    #[serde(default)]
    pub memory_limit: Option<String>,                // e.g. "512m", "2g"
    #[serde(default)]
    pub cpu_limit: Option<String>,                   // e.g. "0.5", "2"
}

/// POST /api/appstore/apps/{id}/install — install an app
pub async fn appstore_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AppInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    // Block raw Docker/LXC installs on nodes running Kubernetes (server or worker)
    if matches!(body.target.as_str(), "docker" | "lxc") &&
       (!crate::kubernetes::list_clusters().is_empty() || !crate::kubernetes::detect_existing_clusters().is_empty()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This node runs Kubernetes — use WolfKube to deploy applications instead of raw Docker/LXC"
        }));
    }

    let mut inputs = body.inputs.clone();
    // Inject CONTAINER_NAME for ${CONTAINER_NAME} substitution in manifests
    inputs.insert("CONTAINER_NAME".to_string(), body.container_name.clone());

    let custom_ports = body.ports.clone();
    match appstore::install_app(&id, &body.target, &body.container_name, &inputs, custom_ports.as_deref()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/system/prepare-install-package — write a shell script that
/// installs a single OS package (currently just the mount-helper packages
/// nfs-common / cifs-utils) and return a session_id the UI opens as a
/// live-terminal console so the user can watch the install run.
#[derive(Deserialize)]
pub struct PreparePkgInstallRequest {
    /// One of the `mount.*` binaries the user needs — e.g. "mount.cifs".
    pub binary: String,
}

pub async fn prepare_install_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PreparePkgInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let (pkg_mgr, pkg_name) = match crate::storage::package_for_helper(&body.binary) {
        Some(v) => v,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("No known package provides '{}'", body.binary)
        })),
    };

    let session_id = format!("pkg-{}-{}",
        pkg_name,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs()
    );
    let script_path = format!("/tmp/wolfstack-pkginstall-{}.sh", session_id);

    // Escaped script; `-y` so apt/dnf/zypper don't block on confirmation,
    // and `--noconfirm` for pacman. set -e so the first failure stops the
    // run instead of muddying the terminal with cascaded errors.
    let install_cmd = match pkg_mgr {
        "apt-get" => format!("apt-get update && apt-get install -y {}", pkg_name),
        "dnf" => format!("dnf install -y {}", pkg_name),
        "zypper" => format!("zypper --non-interactive install {}", pkg_name),
        "pacman" => format!("pacman -Sy --noconfirm {}", pkg_name),
        other => format!("{} install -y {}", other, pkg_name),
    };
    let script = format!(
        "#!/bin/bash\nset -e\n\
         printf '\\033[1;36m━━━ Installing %s (provides %s) ━━━\\033[0m\\n\\n' '{pkg}' '{bin}'\n\
         {cmd}\n\
         printf '\\n\\033[1;32m✓ %s installed\\033[0m\\n' '{pkg}'\n",
        pkg = pkg_name, bin = body.binary, cmd = install_cmd
    );

    if let Err(e) = std::fs::write(&script_path, script) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to write install script: {}", e)
        }));
    }
    let _ = std::process::Command::new("chmod").args(["+x", &script_path]).output();

    HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "package": pkg_name,
        "command": install_cmd,
    }))
}

/// POST /api/appstore/apps/{id}/install-stream — VM-target streaming install
/// Emits progress lines as Server-Sent Events so the UI can show download
/// bytes / elapsed time / stage transitions in a task-log entry instead of
/// freezing on a single blocking POST for several minutes.
pub async fn appstore_install_stream(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AppInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let app_id = path.into_inner();

    let Some(app) = appstore::get_app(&app_id) else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": format!("App '{}' not found", app_id)}));
    };
    if app.vm.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "This app has no VM target"}));
    }

    let mut inputs = body.inputs.clone();
    inputs.insert("CONTAINER_NAME".to_string(), body.container_name.clone());
    let container_name = body.container_name.clone();

    // std::sync::mpsc because install_vm_streamed runs in a blocking thread
    // and needs a Send Sender. Bridge to tokio so the SSE stream can await.
    let (std_tx, std_rx) = std::sync::mpsc::channel::<String>();
    let (tok_tx, mut tok_rx) = tokio::sync::mpsc::channel::<String>(256);

    // Worker: do the install, close the channel when done.
    std::thread::spawn(move || {
        let result = appstore::install_vm_streamed(&app, &container_name, &inputs, std_tx.clone());
        // Final marker — success or error, both go through the stream.
        match result {
            Ok(msg) => { let _ = std_tx.send(format!("[done] {}", msg)); }
            Err(e)  => { let _ = std_tx.send(format!("[error] {}", e)); }
        }
        // std_tx dropping here signals EOF to the bridge.
    });

    // Bridge blocking recv() -> tokio channel.
    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = std_rx.recv() {
            if tok_tx.blocking_send(msg).is_err() { break; }
        }
    });

    let stream = async_stream::stream! {
        while let Some(msg) = tok_rx.recv().await {
            // Embed as SSE data. Newlines inside a message get mapped to
            // `\ndata: ` so the client sees a single event with multi-line
            // body; keeps any future multi-line messages intact.
            let event = format!("data: {}\n\n", msg.replace('\n', "\ndata: "));
            yield Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(event));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}

/// POST /api/appstore/apps/{id}/prepare-install — generate install script for live terminal
pub async fn appstore_prepare_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AppInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    // Block raw Docker/LXC installs on nodes running Kubernetes (server or worker)
    if matches!(body.target.as_str(), "docker" | "lxc") &&
       (!crate::kubernetes::list_clusters().is_empty() || !crate::kubernetes::detect_existing_clusters().is_empty()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This node runs Kubernetes — use WolfKube to deploy applications instead of raw Docker/LXC"
        }));
    }

    let mut inputs = body.inputs.clone();
    inputs.insert("CONTAINER_NAME".to_string(), body.container_name.clone());

    let target = body.target.clone();
    let container_name = body.container_name.clone();
    let storage_path = body.storage_path.clone();
    let custom_ports = body.ports.clone();
    let extra_env = body.extra_env.clone();
    let extra_volumes = body.extra_volumes.clone();
    let memory_limit = body.memory_limit.clone();
    let cpu_limit = body.cpu_limit.clone();

    match web::block(move || {
        appstore::prepare_install(&id, &target, &container_name, &inputs, storage_path.as_deref(), custom_ports.as_deref(),
            extra_env.as_deref(), extra_volumes.as_deref(), memory_limit.as_deref(), cpu_limit.as_deref())
    }).await {
        Ok(Ok((session_id, _script_path))) => HttpResponse::Ok().json(serde_json::json!({
            "session_id": session_id,
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Internal error: {}", e) })),
    }
}

/// GET /api/appstore/installed — list installed apps
pub async fn appstore_installed(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let apps = appstore::list_installed_apps();
    HttpResponse::Ok().json(serde_json::json!({ "installed": apps }))
}

/// DELETE /api/appstore/installed/{id} — uninstall an app
pub async fn appstore_uninstall(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let install_id = path.into_inner();
    match appstore::uninstall_app(&install_id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Kubernetes ───

/// GET /api/kubernetes/clusters
pub async fn k8s_list_clusters(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let self_id = state.cluster.self_id.clone();

    // Get local clusters and tag with owner_node_id
    let mut all_clusters: Vec<crate::kubernetes::K8sCluster> = crate::kubernetes::list_clusters()
        .into_iter()
        .map(|mut c| {
            if c.owner_node_id.is_empty() {
                c.owner_node_id = self_id.clone();
            }
            c
        })
        .collect();

    // Aggregate clusters from remote WolfStack nodes
    let nodes = state.cluster.get_all_nodes();
    let cluster_secret = state.cluster_secret.clone();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(2))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut remote_futures = Vec::new();
    for node in &nodes {
        if node.is_self || node.node_type != "wolfstack" {
            continue;
        }
        let node_id = node.id.clone();
        let urls = build_node_urls(&node.address, node.port, "/api/kubernetes/clusters");
        let client = client.clone();
        let secret = cluster_secret.clone();
        remote_futures.push(async move {
            for url in &urls {
                if let Ok(resp) = client.get(url)
                    .header("X-WolfStack-Secret", &secret)
                    .send()
                    .await
                {
                    if resp.status().is_success() {
                        if let Ok(mut clusters) = resp.json::<Vec<crate::kubernetes::K8sCluster>>().await {
                            for c in &mut clusters {
                                c.owner_node_id = node_id.clone();
                            }
                            return clusters;
                        }
                    }
                    break; // got a response (even if error), don't try other URL schemes
                }
            }
            Vec::new()
        });
    }

    let results = futures::future::join_all(remote_futures).await;
    let local_ids: std::collections::HashSet<String> = all_clusters.iter().map(|c| c.id.clone()).collect();
    for remote_clusters in results {
        for c in remote_clusters {
            if !local_ids.contains(&c.id) {
                all_clusters.push(c);
            }
        }
    }

    HttpResponse::Ok().json(all_clusters)
}

/// GET /api/kubernetes/detect — detect existing k8s installations on this node
pub async fn k8s_detect(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let detected = crate::kubernetes::detect_existing_clusters();
    let already_registered = crate::kubernetes::list_clusters();
    let results: Vec<serde_json::Value> = detected.into_iter()
        .filter(|(_, path, _)| !already_registered.iter().any(|c| c.kubeconfig_path == *path))
        .map(|(name, path, cluster_type)| {
            serde_json::json!({ "name": name, "kubeconfig_path": path, "cluster_type": cluster_type.to_string() })
        })
        .collect();
    HttpResponse::Ok().json(results)
}

/// POST /api/kubernetes/clusters — import a cluster via kubeconfig content or path
#[derive(Deserialize)]
pub struct K8sImportRequest {
    pub name: String,
    #[serde(default)]
    pub kubeconfig: String,       // raw kubeconfig YAML content (for pasted imports)
    #[serde(default)]
    pub kubeconfig_path: Option<String>,  // path to existing kubeconfig (for auto-detected imports)
    #[serde(default)]
    pub cluster_type: Option<String>,
}

pub async fn k8s_create_cluster(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sImportRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = format!("k8s-{}", body.name.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "-"));

    // If a path is provided directly (e.g. auto-detected k3s), use it as-is
    // Otherwise save the pasted kubeconfig content to a file
    let (kubeconfig_path, kubeconfig_content) = if let Some(ref path) = body.kubeconfig_path {
        if !std::path::Path::new(path).exists() {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Kubeconfig file not found: {}", path) }));
        }
        let content = std::fs::read_to_string(path).unwrap_or_default();
        (path.clone(), content)
    } else if !body.kubeconfig.is_empty() {
        let dir = "/etc/wolfstack/kubernetes";
        let _ = std::fs::create_dir_all(dir);
        let path = format!("{}/{}.yaml", dir, id);
        if let Err(e) = std::fs::write(&path, &body.kubeconfig) {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to save kubeconfig: {}", e) }));
        }
        (path, body.kubeconfig.clone())
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Either kubeconfig content or kubeconfig_path is required" }));
    };

    // Try to extract API URL from kubeconfig
    let api_url = kubeconfig_content.lines()
        .find(|l| l.trim().starts_with("server:"))
        .map(|l| l.trim().trim_start_matches("server:").trim().to_string())
        .unwrap_or_default();
    let cluster_type = match body.cluster_type.as_deref() {
        Some("k3s") => crate::kubernetes::K8sClusterType::K3s,
        Some("micro_k8s" | "microk8s") => crate::kubernetes::K8sClusterType::MicroK8s,
        Some("k0s") => crate::kubernetes::K8sClusterType::K0s,
        Some("rke2") => crate::kubernetes::K8sClusterType::Rke2,
        Some("eks") => crate::kubernetes::K8sClusterType::Eks,
        Some("gke") => crate::kubernetes::K8sClusterType::Gke,
        Some("aks") => crate::kubernetes::K8sClusterType::Aks,
        _ => crate::kubernetes::K8sClusterType::K8s,
    };
    match crate::kubernetes::add_cluster(id, body.name.clone(), kubeconfig_path, api_url, cluster_type) {
        Ok(cluster) => HttpResponse::Ok().json(serde_json::json!({ "message": format!("Cluster '{}' imported", body.name), "cluster": cluster })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/kubernetes/clusters/{id}
pub async fn k8s_delete_cluster(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::kubernetes::remove_cluster(&id) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "message": "Cluster removed" })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/status
pub async fn k8s_cluster_status(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    HttpResponse::Ok().json(crate::kubernetes::get_cluster_status(&cluster.kubeconfig_path))
}

/// GET /api/kubernetes/clusters/{id}/namespaces
pub async fn k8s_namespaces(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    HttpResponse::Ok().json(crate::kubernetes::get_namespaces(&cluster.kubeconfig_path))
}

/// POST /api/kubernetes/clusters/{id}/namespaces
#[derive(Deserialize)]
pub struct K8sNameRequest { pub name: String }

pub async fn k8s_create_namespace(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sNameRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    match crate::kubernetes::create_namespace(&cluster.kubeconfig_path, &body.name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/kubernetes/clusters/{id}/namespaces/{name}
pub async fn k8s_delete_namespace(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    match crate::kubernetes::delete_namespace(&cluster.kubeconfig_path, &name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/pods?namespace=
pub async fn k8s_pods(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").filter(|s| !s.is_empty()).map(|s| s.as_str());
    HttpResponse::Ok().json(crate::kubernetes::get_pods(&cluster.kubeconfig_path, ns))
}

/// DELETE /api/kubernetes/clusters/{id}/pods/{name}?namespace=
pub async fn k8s_delete_pod(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::delete_pod(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/deployments?namespace=
pub async fn k8s_deployments(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").filter(|s| !s.is_empty()).map(|s| s.as_str());
    HttpResponse::Ok().json(crate::kubernetes::get_deployments(&cluster.kubeconfig_path, ns))
}

/// DELETE /api/kubernetes/clusters/{id}/deployments/{name}?namespace=
pub async fn k8s_delete_deployment(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::delete_deployment(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// PATCH /api/kubernetes/clusters/{id}/deployments/{name}/scale
#[derive(Deserialize)]
pub struct K8sScaleRequest { pub namespace: String, pub replicas: u32 }

pub async fn k8s_scale_deployment(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<K8sScaleRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    match crate::kubernetes::scale_deployment(&cluster.kubeconfig_path, &name, &body.namespace, body.replicas) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/kubernetes/clusters/{id}/deployments/{name}/restart?namespace=
pub async fn k8s_restart_deployment(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::restart_deployment(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/services?namespace=
pub async fn k8s_services(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").filter(|s| !s.is_empty()).map(|s| s.as_str());
    HttpResponse::Ok().json(crate::kubernetes::get_services(&cluster.kubeconfig_path, ns))
}

/// DELETE /api/kubernetes/clusters/{id}/services/{name}?namespace=
pub async fn k8s_delete_service(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::delete_service(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/nodes
pub async fn k8s_nodes(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    HttpResponse::Ok().json(crate::kubernetes::get_nodes(&cluster.kubeconfig_path))
}

/// GET /api/kubernetes/clusters/{id}/logs/{pod}?namespace=&container=&tail=
pub async fn k8s_pod_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, pod) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    let container = query.get("container").map(|s| s.as_str());
    let tail: u32 = query.get("tail").and_then(|s| s.parse().ok()).unwrap_or(100);
    match crate::kubernetes::get_pod_logs(&cluster.kubeconfig_path, &pod, ns, container, tail) {
        Ok(logs) => HttpResponse::Ok().json(serde_json::json!({ "logs": logs })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/pods/{name}/detail?namespace=
pub async fn k8s_pod_detail(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::get_pod_detail(&cluster.kubeconfig_path, &name, ns) {
        Ok(detail) => HttpResponse::Ok().json(detail),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/pods/{name}/top?namespace=
pub async fn k8s_pod_top(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::get_pod_top(&cluster.kubeconfig_path, &name, ns) {
        Ok(usage) => HttpResponse::Ok().json(usage),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "cpu": "N/A", "memory": "N/A", "error": e })),
    }
}

/// POST /api/kubernetes/clusters/{id}/pods/{name}/exec
#[derive(Deserialize)]
pub struct K8sPodExecRequest {
    pub namespace: String,
    #[serde(default)]
    pub container: Option<String>,
    pub command: Vec<String>,
}

pub async fn k8s_pod_exec(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<K8sPodExecRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    // Security: only allow safe read-only commands
    let allowed_commands = ["ps", "df", "top", "cat", "ls", "whoami", "hostname", "uname", "env", "printenv", "id", "uptime", "free", "du", "mount", "lsblk", "ip", "ss", "netstat", "date"];
    let base_cmd = body.command.first().map(|s| s.as_str()).unwrap_or("");
    // Extract just the command name (strip path like /bin/ps -> ps)
    let cmd_name = base_cmd.rsplit('/').next().unwrap_or(base_cmd);
    if !allowed_commands.contains(&cmd_name) {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": format!("Command '{}' is not allowed. Use the terminal for interactive access.", cmd_name) }));
    }
    let cmd_refs: Vec<&str> = body.command.iter().map(|s| s.as_str()).collect();
    match crate::kubernetes::exec_in_pod(&cluster.kubeconfig_path, &name, &body.namespace, body.container.as_deref(), &cmd_refs) {
        Ok(output) => HttpResponse::Ok().json(serde_json::json!({ "output": output })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/pods/{name}/events?namespace=
pub async fn k8s_pod_events(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::get_pod_events(&cluster.kubeconfig_path, &name, ns) {
        Ok(events) => HttpResponse::Ok().json(serde_json::json!({ "events": events })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/storage — full storage overview
pub async fn k8s_storage_overview(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").filter(|s| !s.is_empty()).map(|s| s.as_str());
    let classes = crate::kubernetes::get_storage_classes(&cluster.kubeconfig_path);
    let pvs = crate::kubernetes::get_persistent_volumes(&cluster.kubeconfig_path);
    let pvcs = crate::kubernetes::get_persistent_volume_claims(&cluster.kubeconfig_path, ns);
    // Include WolfStack storage mounts that are currently mounted (available as backing storage)
    let wolfstack_mounts: Vec<serde_json::Value> = crate::storage::list_mounts()
        .iter()
        .filter(|m| m.status == "mounted")
        .map(|m| {
            let type_label = match m.mount_type {
                crate::storage::MountType::Nfs => "NFS",
                crate::storage::MountType::Smb => "SMB",
                crate::storage::MountType::Sshfs => "SSHFS",
                crate::storage::MountType::Directory => "Directory",
                crate::storage::MountType::S3 => "S3",
                crate::storage::MountType::Wolfdisk => "WolfDisk",
            };
            serde_json::json!({
                "id": m.id,
                "name": m.name,
                "mount_type": type_label,
                "source": m.source,
                "mount_point": m.mount_point,
            })
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({
        "storage_classes": classes,
        "persistent_volumes": pvs,
        "pvcs": pvcs,
        "wolfstack_mounts": wolfstack_mounts,
    }))
}

/// POST /api/kubernetes/clusters/{id}/storage/pvcs — create a PVC
#[derive(Deserialize)]
pub struct K8sCreatePvcRequest {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub storage_class: String,
    pub size: String,
    #[serde(default = "default_access_mode")]
    pub access_mode: String,
    /// Storage type: "dynamic" (default, uses storage_class), "host_path", "nfs", "wolfstack_mount"
    #[serde(default = "default_storage_type")]
    pub storage_type: String,
    #[serde(default)]
    pub host_path: Option<String>,
    #[serde(default)]
    pub nfs_server: Option<String>,
    #[serde(default)]
    pub nfs_path: Option<String>,
    /// WolfStack mount ID — resolved to its mount_point or NFS source
    #[serde(default)]
    pub wolfstack_mount_id: Option<String>,
}
fn default_access_mode() -> String { "ReadWriteOnce".to_string() }
fn default_storage_type() -> String { "dynamic".to_string() }

pub async fn k8s_create_pvc(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sCreatePvcRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };

    match body.storage_type.as_str() {
        "dynamic" | "" => {
            // Dynamic provisioning via StorageClass (existing behavior)
            match crate::kubernetes::create_pvc(&cluster.kubeconfig_path, &body.name, &body.namespace, &body.storage_class, &body.size, &body.access_mode) {
                Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
            }
        }
        "host_path" => {
            match crate::kubernetes::create_pv_and_pvc(
                &cluster.kubeconfig_path, &body.name, &body.namespace, &body.size, &body.access_mode,
                "host_path", body.host_path.as_deref(), None, None,
            ) {
                Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
            }
        }
        "nfs" => {
            match crate::kubernetes::create_pv_and_pvc(
                &cluster.kubeconfig_path, &body.name, &body.namespace, &body.size, &body.access_mode,
                "nfs", None, body.nfs_server.as_deref(), body.nfs_path.as_deref(),
            ) {
                Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
            }
        }
        "wolfstack_mount" => {
            // Resolve WolfStack mount ID to NFS source or local path
            let mount_id = match &body.wolfstack_mount_id {
                Some(id) => id.clone(),
                None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "wolfstack_mount_id is required" })),
            };
            let mounts = crate::storage::list_mounts();
            let mount = match mounts.iter().find(|m| m.id == mount_id) {
                Some(m) => m.clone(),
                None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "WolfStack mount not found" })),
            };
            // NFS mounts → use NFS PV; local/directory mounts → use hostPath PV
            match mount.mount_type {
                crate::storage::MountType::Nfs => {
                    // source is "server:/path"
                    let parts: Vec<&str> = mount.source.splitn(2, ':').collect();
                    if parts.len() != 2 {
                        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid NFS source format" }));
                    }
                    match crate::kubernetes::create_pv_and_pvc(
                        &cluster.kubeconfig_path, &body.name, &body.namespace, &body.size, &body.access_mode,
                        "nfs", None, Some(parts[0]), Some(parts[1]),
                    ) {
                        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
                    }
                }
                _ => {
                    // Use mount_point as hostPath
                    match crate::kubernetes::create_pv_and_pvc(
                        &cluster.kubeconfig_path, &body.name, &body.namespace, &body.size, &body.access_mode,
                        "host_path", Some(&mount.mount_point), None, None,
                    ) {
                        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
                    }
                }
            }
        }
        other => {
            HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Unknown storage type: {}", other) }))
        }
    }
}

/// DELETE /api/kubernetes/clusters/{id}/storage/pvcs/{name}?namespace=
pub async fn k8s_delete_pvc(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::delete_pvc(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/kubernetes/clusters/{id}/deployments/{name}/volumes — add PVC volume mount
#[derive(Deserialize)]
pub struct K8sAddVolumeRequest {
    pub namespace: String,
    pub pvc_name: String,
    pub mount_path: String,
    #[serde(default)]
    pub container: Option<String>,
}

pub async fn k8s_add_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<K8sAddVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, dep_name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    match crate::kubernetes::add_volume_to_deployment(&cluster.kubeconfig_path, &dep_name, &body.namespace, &body.pvc_name, &body.mount_path, body.container.as_deref()) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/kubernetes/clusters/{id}/deployments/{name}/volumes/{vol_name}?namespace=
pub async fn k8s_remove_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, dep_name, vol_name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::remove_volume_from_deployment(&cluster.kubeconfig_path, &dep_name, ns, &vol_name) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/kubernetes/clusters/{id}/apply
#[derive(Deserialize)]
pub struct K8sApplyRequest {
    pub yaml: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// GET /api/kubernetes/clusters/{id}/resource-yaml?kind=deployment&name=myapp&namespace=default
pub async fn k8s_resource_yaml(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let kind = query.get("kind").map(|s| s.as_str()).unwrap_or("pod");
    let name = match query.get("name") {
        Some(n) => n.as_str(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "name parameter required" })),
    };
    let namespace = query.get("namespace").map(|s| s.as_str()).unwrap_or("");
    match crate::kubernetes::get_resource_yaml(&cluster.kubeconfig_path, kind, name, namespace) {
        Ok(yaml) => HttpResponse::Ok().json(serde_json::json!({ "yaml": yaml })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

pub async fn k8s_apply(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sApplyRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    // If namespace specified, prepend it to the yaml or use -n flag via a wrapper
    let yaml = if let Some(ref ns) = body.namespace {
        // Add namespace to yaml if not already present
        if body.yaml.contains("namespace:") {
            body.yaml.clone()
        } else {
            body.yaml.replace("metadata:", &format!("metadata:\n  namespace: {}", ns))
        }
    } else {
        body.yaml.clone()
    };
    match crate::kubernetes::apply_yaml(&cluster.kubeconfig_path, &yaml) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/deployments/{name}/detail?namespace=
pub async fn k8s_deployment_detail(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::get_deployment_detail(&cluster.kubeconfig_path, &name, ns) {
        Ok(detail) => HttpResponse::Ok().json(detail),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// PATCH /api/kubernetes/clusters/{id}/deployments/{name}/image
#[derive(Deserialize)]
pub struct K8sSetImageRequest { pub namespace: String, pub container: String, pub image: String }

pub async fn k8s_set_image(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<K8sSetImageRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    match crate::kubernetes::set_deployment_image(&cluster.kubeconfig_path, &name, &body.namespace, &body.container, &body.image) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// PATCH /api/kubernetes/clusters/{id}/deployments/{name}/env
#[derive(Deserialize)]
pub struct K8sSetEnvRequest { pub namespace: String, pub env: Vec<K8sEnvVar> }
#[derive(Deserialize)]
pub struct K8sEnvVar { pub name: String, pub value: String }

pub async fn k8s_set_env(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<K8sSetEnvRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let env_pairs: Vec<(String, String)> = body.env.iter().map(|e| (e.name.clone(), e.value.clone())).collect();
    match crate::kubernetes::set_deployment_env(&cluster.kubeconfig_path, &name, &body.namespace, &env_pairs) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/kubernetes/clusters/{id}/deployments/{name}/full?namespace= — delete deployment + service
pub async fn k8s_delete_deployment_full(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, name) = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let ns = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    // Clean up WolfNet route if one exists for this deployment
    let _ = crate::kubernetes::remove_wolfnet_route(&id, &name, ns);
    match crate::kubernetes::delete_deployment_and_service(&cluster.kubeconfig_path, &name, ns) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// PATCH /api/kubernetes/clusters/{id}/settings — update cluster WolfNet settings
#[derive(Deserialize)]
pub struct K8sClusterSettingsRequest {
    #[serde(default)]
    pub wolfnet_server: Option<String>,
    #[serde(default)]
    pub wolfnet_network: Option<String>,
    #[serde(default)]
    pub wolfnet_auto_deploy: Option<bool>,
}

pub async fn k8s_cluster_settings(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sClusterSettingsRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::kubernetes::update_cluster_settings(
        &id,
        body.wolfnet_server.as_deref(),
        body.wolfnet_network.as_deref(),
        body.wolfnet_auto_deploy,
    ) {
        Ok(cluster) => HttpResponse::Ok().json(serde_json::json!({ "message": "Settings updated", "cluster": cluster })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/kubernetes/clusters/{id}/deploy-app — deploy an app store app to k8s
#[derive(Deserialize)]
pub struct K8sDeployAppRequest {
    pub app_id: String,
    pub container_name: String,
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    #[serde(default = "default_k8s_replicas")]
    pub replicas: u32,
    #[serde(default)]
    pub inputs: std::collections::HashMap<String, String>,
}
fn default_k8s_namespace() -> String { "default".to_string() }
fn default_k8s_replicas() -> u32 { 1 }

pub async fn k8s_deploy_app(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sDeployAppRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = match crate::kubernetes::get_cluster(&path.into_inner()) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let app = match appstore::get_app(&body.app_id) {
        Some(a) => a,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": format!("App '{}' not found", body.app_id) })),
    };
    let docker = match app.docker {
        Some(ref d) => d,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "App does not support Docker/Kubernetes deployment" })),
    };
    // Substitute user inputs in env vars
    let env: Vec<String> = docker.env.iter().map(|e| {
        let mut val = e.clone();
        for (k, v) in &body.inputs {
            val = val.replace(&format!("${{{}}}", k), v);
        }
        val
    }).collect();
    match crate::kubernetes::deploy_app_to_k8s(
        &cluster.kubeconfig_path, &app.name, &body.container_name,
        &body.namespace, &docker.image, &docker.ports, &env,
        &docker.volumes, body.replicas,
    ) {
        Ok(msg) => {
            // Auto-allocate WolfNet IP if configured and the app exposes ports
            let mut wolfnet_ip = None;
            if cluster.wolfnet_auto_deploy && !docker.ports.is_empty() {
                // Sanitize the container name the same way deploy_app_to_k8s does
                let svc_name: String = body.container_name
                    .to_lowercase()
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
                    .collect::<String>()
                    .trim_matches('-')
                    .to_string();
                match crate::kubernetes::allocate_wolfnet_route(&cluster.id, &svc_name, &body.namespace) {
                    Ok(route) => {
                        // Push route to all cluster nodes immediately
                        let wn_status = crate::networking::get_wolfnet_status();
                        if let Some(ref local_ip) = wn_status.ip {
                            let gateway = local_ip.split('/').next().unwrap_or(local_ip);
                            push_wolfnet_route_to_cluster(&route.wolfnet_ip, gateway, &state).await;
                        }
                        wolfnet_ip = Some(route.wolfnet_ip);
                    },
                    Err(e) => tracing::warn!("Auto WolfNet route allocation failed: {}", e),
                }
            }
            HttpResponse::Ok().json(serde_json::json!({ "message": msg, "wolfnet_ip": wolfnet_ip }))
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/kubernetes/clusters/provision — provision a kubernetes cluster
#[derive(Deserialize)]
pub struct K8sProvisionRequest {
    pub name: String,
    pub server_node_id: String,
    #[serde(default)]
    pub agent_node_ids: Vec<String>,
    #[serde(default = "default_distribution")]
    pub distribution: String,  // "k3s", "microk8s", "kubeadm", "k0s", "rke2"
}

fn default_distribution() -> String { "k3s".to_string() }

/// Run a script locally on this node
fn run_script_locally(script: &str) -> Result<String, String> {
    let script_path = format!("/tmp/wolfstack-k8s-{}.sh", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
    std::fs::write(&script_path, script).map_err(|e| format!("Failed to write script: {}", e))?;
    let output = std::process::Command::new("bash").arg(&script_path).output();
    let _ = std::fs::remove_file(&script_path);
    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).to_string()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
        Err(e) => Err(format!("Failed to run script: {}", e)),
    }
}

/// Run a script on a remote node via the /api/kubernetes/run-script proxy endpoint
async fn run_script_on_remote(address: &str, port: u16, cluster_secret: &str, script: &str) -> Result<String, String> {
    let urls = build_node_urls(address, port, "/api/kubernetes/run-script");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;
    for url in &urls {
        match client.post(url)
            .header("X-WolfStack-Secret", cluster_secret)
            .json(&serde_json::json!({ "script": script }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                return body["output"].as_str().map(|s| s.to_string())
                    .ok_or_else(|| body["error"].as_str().unwrap_or("Unknown error").to_string());
            }
            _ => continue,
        }
    }
    Err(format!("Failed to reach remote node at {}", address))
}

/// Fetch a JSON value from a remote node endpoint
async fn fetch_from_remote(address: &str, port: u16, path: &str, cluster_secret: &str) -> Result<serde_json::Value, String> {
    let urls = build_node_urls(address, port, path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;
    for url in &urls {
        match client.get(url)
            .header("X-WolfStack-Secret", cluster_secret)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                return resp.json().await.map_err(|e| format!("JSON parse error: {}", e));
            }
            _ => continue,
        }
    }
    Err(format!("Failed to reach remote node at {}", address))
}

pub async fn k8s_provision(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sProvisionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let dist = body.distribution.to_lowercase();
    let cluster_type = match dist.as_str() {
        "k3s" => crate::kubernetes::K8sClusterType::K3s,
        "microk8s" => crate::kubernetes::K8sClusterType::MicroK8s,
        "kubeadm" | "k8s" => crate::kubernetes::K8sClusterType::K8s,
        "k0s" => crate::kubernetes::K8sClusterType::K0s,
        "rke2" => crate::kubernetes::K8sClusterType::Rke2,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("Unsupported distribution: {}. Use k3s, microk8s, kubeadm, k0s, or rke2.", dist) })),
    };

    // Find the server node
    let server_node = match state.cluster.get_node(&body.server_node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Server node not found" })),
    };

    let is_self = server_node.is_self;
    let server_address = server_node.address.clone();
    let server_port = server_node.port;
    let cluster_name = body.name.clone();
    let cluster_secret = state.cluster_secret.clone();

    // Generate the server install script based on distribution
    let script = match dist.as_str() {
        "k3s" => crate::kubernetes::provision_k3s_server(&server_address, &cluster_name),
        "microk8s" => crate::kubernetes::provision_microk8s_server(&server_address, &cluster_name),
        "kubeadm" | "k8s" => crate::kubernetes::provision_kubeadm_server(&server_address, &cluster_name),
        "k0s" => crate::kubernetes::provision_k0s_server(&server_address, &cluster_name),
        "rke2" => crate::kubernetes::provision_rke2_server(&server_address, &cluster_name),
        _ => unreachable!(),
    };
    let script = match script {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    };

    // 1. Install server
    let server_result = if is_self {
        run_script_locally(&script)
    } else {
        run_script_on_remote(&server_address, server_port, &cluster_secret, &script).await
    };
    if let Err(e) = server_result {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("{} server install failed: {}", dist, e)
        }));
    }

    // 2. Get the kubeconfig path
    let default_kubeconfig_path = match dist.as_str() {
        "k3s" => "/etc/rancher/k3s/k3s.yaml",
        "microk8s" => "/var/snap/microk8s/current/credentials/client.config",
        "kubeadm" | "k8s" => "/etc/kubernetes/admin.conf",
        "k0s" => "/etc/k0s/kubeconfig",
        "rke2" => "/etc/rancher/rke2/rke2.yaml",
        _ => "/root/.kube/config",
    };

    let api_port: u16 = match dist.as_str() {
        "microk8s" => 16443,
        "rke2" => 9345,
        _ => 6443,
    };
    let api_url = format!("https://{}:{}", server_address, api_port);
    let cluster_id = format!("k8s-{}", cluster_name.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "-"));
    let kubeconfig_path = default_kubeconfig_path.to_string();

    // Register the cluster on the SERVER node (not the UI node)
    // This ensures kubernetes.json, kubeconfig, WolfNet routes, and DNAT all live
    // on the node that actually runs the K8s cluster.
    let cluster = if is_self {
        match crate::kubernetes::add_cluster(cluster_id.clone(), cluster_name.clone(), kubeconfig_path.clone(), api_url.clone(), cluster_type) {
            Ok(c) => c,
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        }
    } else {
        // Register on the remote server node via its /api/kubernetes/clusters endpoint
        let import_body = serde_json::json!({
            "name": cluster_name,
            "kubeconfig_path": kubeconfig_path,
            "cluster_type": dist,
        });
        let urls = build_node_urls(&server_address, server_port, "/api/kubernetes/clusters");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut registered = false;
        let mut cluster_resp = None;
        for url in &urls {
            match client.post(url)
                .header("X-WolfStack-Secret", &cluster_secret)
                .json(&import_body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    cluster_resp = resp.json::<serde_json::Value>().await.ok();
                    registered = true;
                    break;
                }
                _ => continue,
            }
        }
        if !registered {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("{} installed but failed to register cluster on server node {}", dist, server_address)
            }));
        }
        // Return the cluster object from the remote registration
        match cluster_resp.and_then(|v| serde_json::from_value::<crate::kubernetes::K8sCluster>(v["cluster"].clone()).ok()) {
            Some(c) => c,
            None => {
                // Construct a minimal cluster object for the response
                crate::kubernetes::K8sCluster {
                    id: cluster_id.clone(),
                    name: cluster_name.clone(),
                    kubeconfig_path: kubeconfig_path.clone(),
                    api_url: api_url.clone(),
                    cluster_type,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    nodes: Vec::new(),
                    wolfnet_server: String::new(),
                    wolfnet_network: String::new(),
                    wolfnet_auto_deploy: true,
                    wolfnet_routes: Vec::new(),
                    owner_node_id: String::new(),
                }
            }
        }
    };

    // 3. Install agents on worker nodes
    let mut agent_errors = Vec::new();
    if !body.agent_node_ids.is_empty() {
        // Get join credentials from the server
        let join_info: Result<String, String> = if is_self {
            match dist.as_str() {
                "k3s" => crate::kubernetes::get_k3s_token(&kubeconfig_path),
                "microk8s" => crate::kubernetes::get_microk8s_join_command(),
                "kubeadm" | "k8s" => crate::kubernetes::get_kubeadm_join_command(),
                "k0s" => crate::kubernetes::get_k0s_join_token(),
                "rke2" => crate::kubernetes::get_rke2_join_token(),
                _ => Err("Unsupported distribution".to_string()),
            }
        } else {
            // Get join info from remote server
            fetch_from_remote(&server_address, server_port, "/api/kubernetes/join-token", &cluster_secret).await
                .and_then(|body| body["token"].as_str().map(|s| s.to_string())
                    .ok_or_else(|| "No join token in response".to_string()))
        };

        let join_info = match join_info {
            Ok(t) => t,
            Err(e) => {
                return HttpResponse::Ok().json(serde_json::json!({
                    "message": format!("{} server provisioned but failed to get join credentials for agents: {}", dist, e),
                    "cluster": cluster,
                }));
            }
        };

        for agent_node_id in &body.agent_node_ids {
            let agent_node = match state.cluster.get_node(agent_node_id) {
                Some(n) => n,
                None => { agent_errors.push(format!("{}: node not found", agent_node_id)); continue; }
            };
            let agent_script = match dist.as_str() {
                "k3s" => crate::kubernetes::provision_k3s_agent(&agent_node.address, &api_url, &join_info),
                "microk8s" => crate::kubernetes::provision_microk8s_agent(&join_info),
                "kubeadm" | "k8s" => crate::kubernetes::provision_kubeadm_agent(&join_info),
                "k0s" => crate::kubernetes::provision_k0s_agent(&join_info),
                "rke2" => crate::kubernetes::provision_rke2_agent(&api_url, &join_info),
                _ => Err("Unsupported distribution".to_string()),
            };
            let agent_script = match agent_script {
                Ok(s) => s,
                Err(e) => { agent_errors.push(format!("{}: {}", agent_node.hostname, e)); continue; }
            };
            let result = if agent_node.is_self {
                run_script_locally(&agent_script)
            } else {
                run_script_on_remote(&agent_node.address, agent_node.port, &cluster_secret, &agent_script).await
            };
            if let Err(e) = result {
                agent_errors.push(format!("{}: {}", agent_node.hostname, e));
            }
        }
    }

    let mut msg = format!("{} cluster '{}' provisioned successfully", dist, cluster_name);
    if !agent_errors.is_empty() {
        msg.push_str(&format!(". Agent errors: {}", agent_errors.join("; ")));
    }
    HttpResponse::Ok().json(serde_json::json!({ "message": msg, "cluster": cluster }))
}

/// POST /api/kubernetes/prepare-provision — generate provisioning scripts for live terminal execution
/// Returns session IDs that can be used with the k8s-provision console type.
pub async fn k8s_prepare_provision(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sProvisionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let dist = body.distribution.to_lowercase();
    if !["k3s", "microk8s", "kubeadm", "k8s", "k0s", "rke2"].contains(&dist.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Unsupported distribution: {}. Use k3s, microk8s, kubeadm, k0s, or rke2.", dist)
        }));
    }

    let server_node = match state.cluster.get_node(&body.server_node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Server node not found" })),
    };

    let server_address = server_node.address.clone();
    let server_port = server_node.port;
    let cluster_name = body.name.clone();
    let cluster_secret = state.cluster_secret.clone();
    let ts = chrono::Utc::now().timestamp_millis();

    // --- Generate server install script ---
    let cluster_type = match dist.as_str() {
        "k3s" => crate::kubernetes::K8sClusterType::K3s,
        "microk8s" => crate::kubernetes::K8sClusterType::MicroK8s,
        "k0s" => crate::kubernetes::K8sClusterType::K0s,
        "rke2" => crate::kubernetes::K8sClusterType::Rke2,
        _ => crate::kubernetes::K8sClusterType::K8s,
    };

    let server_install = match dist.as_str() {
        "k3s" => crate::kubernetes::provision_k3s_server(&server_address, &cluster_name),
        "microk8s" => crate::kubernetes::provision_microk8s_server(&server_address, &cluster_name),
        "kubeadm" | "k8s" => crate::kubernetes::provision_kubeadm_server(&server_address, &cluster_name),
        "k0s" => crate::kubernetes::provision_k0s_server(&server_address, &cluster_name),
        "rke2" => crate::kubernetes::provision_rke2_server(&server_address, &cluster_name),
        _ => unreachable!(),
    };
    let server_install = match server_install {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    };

    // Wrap in a nicer script with banner
    let server_session_id = format!("{}-server-{}", dist, ts);
    let kubeconfig_path = match dist.as_str() {
        "k3s" => "/etc/rancher/k3s/k3s.yaml",
        "microk8s" => "/var/snap/microk8s/current/credentials/client.config",
        "k0s" => "/etc/k0s/kubeconfig",
        "rke2" => "/etc/rancher/rke2/rke2.yaml",
        _ => "/etc/kubernetes/admin.conf",
    };
    let api_port: u16 = match dist.as_str() {
        "microk8s" => 16443,
        "rke2" => 9345,
        _ => 6443,
    };

    let server_script = format!(
        "#!/bin/bash\nset -e\n\n\
         printf '\\033[1;36m━━━ WolfKube — Installing {dist} server on {addr} ━━━\\033[0m\\n'\n\
         printf '\\033[0;90mCluster: {name}\\033[0m\\n'\n\
         echo ''\n\n\
         {install}\n\n\
         echo ''\n\
         printf '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n'\n\
         printf '\\033[1;32m  {dist} server installed successfully!\\033[0m\\n'\n\
         printf '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n'\n\
         printf '\\033[0;36m  Kubeconfig: {kubeconfig}\\033[0m\\n'\n",
        dist = dist, addr = server_address, name = cluster_name,
        install = server_install, kubeconfig = kubeconfig_path,
    );

    let server_script_path = format!("/tmp/wolfstack-k8s-provision-{}.sh", server_session_id);

    // Write script: locally or on remote node
    let mut sessions = Vec::new();

    if server_node.is_self {
        if let Err(e) = std::fs::write(&server_script_path, &server_script) {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write script: {}", e) }));
        }
        let _ = std::process::Command::new("chmod").args(["+x", &server_script_path]).output();
    } else {
        // Write script on remote node via API
        let write_result = run_script_on_remote(
            &server_address, server_port, &cluster_secret,
            &format!("cat > {} << 'WOLFKUBE_SCRIPT_EOF'\n{}\nWOLFKUBE_SCRIPT_EOF\nchmod +x {}", server_script_path, server_script, server_script_path),
        ).await;
        if let Err(e) = write_result {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write script on remote node: {}", e) }));
        }
    }

    sessions.push(serde_json::json!({
        "session_id": server_session_id,
        "node_id": body.server_node_id,
        "hostname": server_node.hostname,
        "role": "server",
        "is_remote": !server_node.is_self,
    }));

    HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions,
        "cluster_name": cluster_name,
        "distribution": dist,
        "cluster_type": cluster_type.to_string(),
        "kubeconfig_path": kubeconfig_path,
        "api_url": format!("https://{}:{}", server_address, api_port),
        "server_address": server_address,
        "server_node_id": body.server_node_id,
        "agent_node_ids": body.agent_node_ids,
    }))
}

/// POST /api/kubernetes/prepare-provision-agents — generate agent scripts after server is ready
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct K8sPrepareAgentsRequest {
    pub distribution: String,
    pub cluster_name: String,
    pub kubeconfig_path: String,
    pub api_url: String,
    pub server_address: String,
    #[serde(default)]
    pub server_node_id: String,
    pub agent_node_ids: Vec<String>,
}

pub async fn k8s_prepare_provision_agents(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sPrepareAgentsRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let dist = body.distribution.to_lowercase();
    let cluster_secret = state.cluster_secret.clone();
    let ts = chrono::Utc::now().timestamp_millis();

    // Determine if the server node is remote
    let server_is_self = if body.server_node_id.is_empty() {
        true // fallback: assume local
    } else {
        state.cluster.get_node(&body.server_node_id).map(|n| n.is_self).unwrap_or(true)
    };
    let server_address = body.server_address.clone();
    let server_port = if !body.server_node_id.is_empty() {
        state.cluster.get_node(&body.server_node_id).map(|n| n.port).unwrap_or(8553)
    } else {
        8553
    };

    // Get join token/command — from local node or remote server
    let join_info: Result<String, String> = if server_is_self {
        match dist.as_str() {
            "k3s" => crate::kubernetes::get_k3s_token(&body.kubeconfig_path),
            "microk8s" => crate::kubernetes::get_microk8s_join_command(),
            "kubeadm" | "k8s" => crate::kubernetes::get_kubeadm_join_command(),
            "k0s" => crate::kubernetes::get_k0s_join_token(),
            "rke2" => crate::kubernetes::get_rke2_join_token(),
            _ => Err("Unsupported distribution".to_string()),
        }
    } else {
        // Fetch join token from the remote server node
        fetch_from_remote(&server_address, server_port, "/api/kubernetes/join-token", &cluster_secret).await
            .and_then(|body| body["token"].as_str().map(|s| s.to_string())
                .ok_or_else(|| "No join token in response".to_string()))
    };
    let join_info = match join_info {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get join credentials: {}", e)
        })),
    };

    let mut sessions = Vec::new();
    let mut errors = Vec::new();

    for (i, agent_node_id) in body.agent_node_ids.iter().enumerate() {
        let agent_node = match state.cluster.get_node(agent_node_id) {
            Some(n) => n,
            None => { errors.push(format!("{}: node not found", agent_node_id)); continue; }
        };

        let agent_install = match dist.as_str() {
            "k3s" => crate::kubernetes::provision_k3s_agent(&agent_node.address, &body.api_url, &join_info),
            "microk8s" => crate::kubernetes::provision_microk8s_agent(&join_info),
            "kubeadm" | "k8s" => crate::kubernetes::provision_kubeadm_agent(&join_info),
            "k0s" => crate::kubernetes::provision_k0s_agent(&join_info),
            "rke2" => crate::kubernetes::provision_rke2_agent(&body.api_url, &join_info),
            _ => Err("Unsupported".to_string()),
        };
        let agent_install = match agent_install {
            Ok(s) => s,
            Err(e) => { errors.push(format!("{}: {}", agent_node.hostname, e)); continue; }
        };

        let session_id = format!("{}-agent{}-{}", dist, i, ts);
        let script = format!(
            "#!/bin/bash\nset -e\n\n\
             printf '\\033[1;36m━━━ WolfKube — Joining {hostname} as {dist} worker ━━━\\033[0m\\n'\n\
             echo ''\n\n\
             {install}\n\n\
             echo ''\n\
             printf '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n'\n\
             printf '\\033[1;32m  {hostname} joined the cluster!\\033[0m\\n'\n\
             printf '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n'\n",
            hostname = agent_node.hostname, dist = dist, install = agent_install,
        );

        let script_path = format!("/tmp/wolfstack-k8s-provision-{}.sh", session_id);
        if agent_node.is_self {
            if let Err(e) = std::fs::write(&script_path, &script) {
                errors.push(format!("{}: {}", agent_node.hostname, e));
                continue;
            }
            let _ = std::process::Command::new("chmod").args(["+x", &script_path]).output();
        } else {
            let write_result = run_script_on_remote(
                &agent_node.address, agent_node.port, &cluster_secret,
                &format!("cat > {} << 'WOLFKUBE_SCRIPT_EOF'\n{}\nWOLFKUBE_SCRIPT_EOF\nchmod +x {}", script_path, script, script_path),
            ).await;
            if let Err(e) = write_result {
                errors.push(format!("{}: {}", agent_node.hostname, e));
                continue;
            }
        }

        sessions.push(serde_json::json!({
            "session_id": session_id,
            "node_id": agent_node_id,
            "hostname": agent_node.hostname,
            "role": "agent",
            "is_remote": !agent_node.is_self,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions,
        "errors": errors,
    }))
}

/// POST /api/kubernetes/run-script — run a provisioning script on this node (cluster-secret auth)
#[derive(Deserialize)]
pub struct K8sRunScriptRequest {
    pub script: String,
}

pub async fn k8s_run_script(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sRunScriptRequest>) -> HttpResponse {
    // Agent-style auth: cluster secret header
    let secret = req.headers().get("X-WolfStack-Secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if secret != state.cluster_secret {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }
    let script_path = format!("/tmp/wolfstack-k8s-provision-{}.sh",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
    if let Err(e) = std::fs::write(&script_path, &body.script) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write script: {}", e) }));
    }
    let output = std::process::Command::new("bash").arg(&script_path).output();
    let _ = std::fs::remove_file(&script_path);
    match output {
        Ok(o) if o.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "output": String::from_utf8_lossy(&o.stdout).to_string() }))
        }
        Ok(o) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": String::from_utf8_lossy(&o.stderr).to_string() }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to run script: {}", e) })),
    }
}

/// GET /api/kubernetes/kubeconfig — return the local kubeconfig (cluster-secret auth)
/// Tries k3s, microk8s, kubeadm in order of detection
pub async fn k8s_kubeconfig(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let secret = req.headers().get("X-WolfStack-Secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if secret != state.cluster_secret {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }
    // Try known kubeconfig paths in order
    let paths = [
        "/etc/rancher/k3s/k3s.yaml",
        "/var/snap/microk8s/current/credentials/client.config",
        "/etc/kubernetes/admin.conf",
        "/etc/k0s/kubeconfig",
        "/etc/rancher/rke2/rke2.yaml",
        "/root/.kube/config",
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return HttpResponse::Ok().json(serde_json::json!({ "kubeconfig": content, "path": path }));
        }
    }
    HttpResponse::NotFound().json(serde_json::json!({ "error": "No kubeconfig found on this node" }))
}

/// GET /api/kubernetes/join-token — return the join token/command for this node (cluster-secret auth)
pub async fn k8s_join_token(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let secret = req.headers().get("X-WolfStack-Secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if secret != state.cluster_secret {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }
    // Try k3s token
    if std::path::Path::new("/var/lib/rancher/k3s/server/node-token").exists() {
        match crate::kubernetes::get_k3s_token("/etc/rancher/k3s/k3s.yaml") {
            Ok(token) => return HttpResponse::Ok().json(serde_json::json!({ "token": token, "type": "k3s" })),
            Err(_) => {}
        }
    }
    // Try microk8s join
    if let Ok(join) = crate::kubernetes::get_microk8s_join_command() {
        return HttpResponse::Ok().json(serde_json::json!({ "token": join, "type": "microk8s" }));
    }
    // Try kubeadm join
    if let Ok(join) = crate::kubernetes::get_kubeadm_join_command() {
        return HttpResponse::Ok().json(serde_json::json!({ "token": join, "type": "kubeadm" }));
    }
    // Try k0s join
    if let Ok(token) = crate::kubernetes::get_k0s_join_token() {
        return HttpResponse::Ok().json(serde_json::json!({ "token": token, "type": "k0s" }));
    }
    // Try RKE2 join
    if let Ok(token) = crate::kubernetes::get_rke2_join_token() {
        return HttpResponse::Ok().json(serde_json::json!({ "token": token, "type": "rke2" }));
    }
    HttpResponse::NotFound().json(serde_json::json!({ "error": "No join token available on this node" }))
}

/// POST /api/kubernetes/uninstall — prepare an uninstall script and return a session for terminal
#[derive(Deserialize)]
pub struct K8sUninstallRequest {
    pub cluster_type: String,
}

pub async fn k8s_uninstall(req: HttpRequest, state: web::Data<AppState>, body: web::Json<K8sUninstallRequest>) -> HttpResponse {
    // Accept either session auth or cluster-secret auth (for proxied calls)
    let secret = req.headers().get("X-WolfStack-Secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if secret != state.cluster_secret {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    let script = match crate::kubernetes::uninstall_script(&body.cluster_type) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    let ts = chrono::Utc::now().timestamp_millis();
    let session_id = format!("{}-uninstall-{}", body.cluster_type, ts);

    let full_script = format!(
        "#!/bin/bash\n\
         printf '\\033[1;31m━━━ WolfKube — Uninstalling {} ━━━\\033[0m\\n'\n\
         echo ''\n\
         {}\n\
         echo ''\n\
         printf '\\033[1;32m━━━ Uninstall complete ━━━\\033[0m\\n'\n",
        body.cluster_type, script
    );

    let script_path = format!("/tmp/wolfstack-k8s-provision-{}.sh", session_id);
    if let Err(e) = std::fs::write(&script_path, &full_script) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to write uninstall script: {}", e)
        }));
    }
    let _ = std::process::Command::new("chmod").args(["+x", &script_path]).output();

    HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
    }))
}

/// Push a WolfNet route to all other WolfStack nodes in the cluster.
/// This ensures K8s WolfNet IPs are immediately reachable from all nodes
/// without waiting for the next polling cycle.
async fn push_wolfnet_route_to_cluster(wolfnet_ip: &str, gateway_ip: &str, state: &web::Data<AppState>) {
    let nodes = state.cluster.get_all_nodes();
    let secret = state.cluster_secret.clone();
    let route_body = serde_json::json!({
        "routes": { wolfnet_ip: gateway_ip }
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(2))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    for node in &nodes {
        if node.is_self || node.node_type != "wolfstack" {
            continue;
        }
        let urls = build_node_urls(&node.address, node.port, "/api/agent/wolfnet-routes");
        let client = client.clone();
        let secret = secret.clone();
        let body = route_body.clone();
        tokio::spawn(async move {
            for url in &urls {
                if let Ok(resp) = client.post(url)
                    .header("X-WolfStack-Secret", &secret)
                    .json(&body)
                    .send()
                    .await
                {
                    if resp.status().is_success() { break; }
                }
            }
        });
    }
}

/// POST /api/kubernetes/clusters/{id}/wolfnet — allocate a WolfNet IP route for a deployment
#[derive(Deserialize)]
pub struct K8sWolfNetRouteRequest {
    pub deployment_name: String,
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
}

pub async fn k8s_deploy_wolfnet(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<K8sWolfNetRouteRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::kubernetes::allocate_wolfnet_route(&id, &body.deployment_name, &body.namespace) {
        Ok(route) => {
            // Push route to all cluster nodes immediately
            let wn_status = crate::networking::get_wolfnet_status();
            if let Some(ref local_ip) = wn_status.ip {
                let gateway = local_ip.split('/').next().unwrap_or(local_ip);
                push_wolfnet_route_to_cluster(&route.wolfnet_ip, gateway, &state).await;
            }
            HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Allocated WolfNet IP {} for {}", route.wolfnet_ip, route.deployment_name),
                "route": route,
            }))
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/kubernetes/clusters/{id}/wolfnet — remove a WolfNet route for a deployment
pub async fn k8s_remove_wolfnet(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let deployment_name = match query.get("deployment") {
        Some(n) => n.as_str(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Missing 'deployment' query parameter" })),
    };
    let namespace = query.get("namespace").map(|s| s.as_str()).unwrap_or("default");
    match crate::kubernetes::remove_wolfnet_route(&id, deployment_name, namespace) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "message": format!("WolfNet route removed for {}", deployment_name) })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/kubernetes/clusters/{id}/wolfnet — WolfNet status for k8s cluster nodes + deployment routes
pub async fn k8s_wolfnet_status(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let cluster = match crate::kubernetes::get_cluster(&id) {
        Some(c) => c,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Cluster not found" })),
    };
    let mut status = crate::kubernetes::get_wolfnet_node_status(&cluster.kubeconfig_path);
    status["routes"] = serde_json::json!(cluster.wolfnet_routes);
    status["wolfnet_auto_deploy"] = serde_json::json!(cluster.wolfnet_auto_deploy);
    HttpResponse::Ok().json(status)
}

// ─── Security (Fail2ban, iptables, UFW) ───

/// Helper: check if a command exists on the system
fn command_exists(cmd: &str) -> bool {
    std::process::Command::new("which").arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Helper: run a shell command, return stdout
fn run_shell(cmd: &str) -> Result<String, String> {
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| format!("Failed to execute: {}", e))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(if stderr.is_empty() { "Command failed".into() } else { stderr })
    }
}

/// GET /api/security/status — get fail2ban, iptables, and ufw status
pub async fn security_status(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Fail2ban
    let f2b_installed = command_exists("fail2ban-client");
    let f2b_status = if f2b_installed {
        match run_shell("fail2ban-client status 2>/dev/null") {
            Ok(out) => Some(out),
            Err(_) => Some("installed but not running".to_string()),
        }
    } else { None };
    let f2b_banned = if f2b_installed {
        run_shell("fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' || fail2ban-client status sshd 2>/dev/null | grep -i 'ban' || echo ''")
            .unwrap_or_default()
    } else { String::new() };
    let f2b_jails = if f2b_installed {
        run_shell("fail2ban-client status 2>/dev/null | grep 'Jail list' | sed 's/.*Jail list:\\s*//' | tr -d '\\t'")
            .unwrap_or_default().trim().to_string()
    } else { String::new() };
    // jail.local config
    let jail_local_exists = std::path::Path::new("/etc/fail2ban/jail.local").exists();
    let jail_local_content = if jail_local_exists {
        std::fs::read_to_string("/etc/fail2ban/jail.local").unwrap_or_default()
    } else { String::new() };
    // Parse key settings from jail.local
    let parse_val = |content: &str, key: &str| -> String {
        content.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find(|l| l.trim().starts_with(key))
            .and_then(|l| l.split('=').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let bantime = parse_val(&jail_local_content, "bantime");
    let findtime = parse_val(&jail_local_content, "findtime");
    let maxretry = parse_val(&jail_local_content, "maxretry");
    let ignoreip = parse_val(&jail_local_content, "ignoreip");

    // iptables — always available
    let iptables_rules = run_shell("iptables -L -n --line-numbers 2>/dev/null || echo 'iptables not available'")
        .unwrap_or_else(|e| e);

    // UFW
    let ufw_installed = command_exists("ufw");
    let ufw_status = if ufw_installed {
        run_shell("ufw status verbose 2>/dev/null").unwrap_or_else(|e| e)
    } else { String::new() };

    // System updates — detect package manager and count pending updates
    let (pkg_manager, updates_count, updates_list) = if command_exists("apt") {
        let list = run_shell("apt list --upgradable 2>/dev/null | grep -v '^Listing'")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("apt", count, list.trim().to_string())
    } else if command_exists("dnf") {
        let list = run_shell("dnf check-update --quiet 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("dnf", count, list.trim().to_string())
    } else if command_exists("yum") {
        let list = run_shell("yum check-update --quiet 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("yum", count, list.trim().to_string())
    } else if command_exists("pacman") {
        let list = run_shell("pacman -Qu 2>/dev/null")
            .unwrap_or_default();
        let count = list.lines().filter(|l| !l.trim().is_empty()).count();
        ("pacman", count, list.trim().to_string())
    } else {
        ("unknown", 0, String::new())
    };

    HttpResponse::Ok().json(serde_json::json!({
        "fail2ban": {
            "installed": f2b_installed,
            "status": f2b_status,
            "banned": f2b_banned,
            "jails": f2b_jails,
            "jail_local_exists": jail_local_exists,
            "bantime": bantime,
            "findtime": findtime,
            "maxretry": maxretry,
            "ignoreip": ignoreip,
        },
        "iptables": {
            "rules": iptables_rules,
        },
        "ufw": {
            "installed": ufw_installed,
            "status": ufw_status,
        },
        "updates": {
            "package_manager": pkg_manager,
            "count": updates_count,
            "list": updates_list,
        }
    }))
}

/// Generate a distro-appropriate jail.local configuration
fn generate_jail_local() -> String {
    // ── Detect distro from /etc/os-release ──
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get_field = |key: &str| -> String {
        for line in os_release.lines() {
            if line.starts_with(key) {
                return line.splitn(2, '=').nth(1).unwrap_or("").trim_matches('"').to_string();
            }
        }
        String::new()
    };
    let distro_id = get_field("ID=").to_lowercase();
    let version_id = get_field("VERSION_ID=");
    let version_num: f32 = version_id.parse().unwrap_or(0.0);

    // ── Determine backend ──
    // Debian 12+, Ubuntu 22.04+, and most modern systemd distros don't ship rsyslog
    // and need backend = systemd to read from journald
    let use_systemd_backend = match distro_id.as_str() {
        "debian" => version_num >= 12.0,
        "ubuntu" => version_num >= 22.04,
        _ => {
            // Check if rsyslog is installed; if not, use systemd
            !std::path::Path::new("/var/log/auth.log").exists()
                || std::path::Path::new("/run/systemd/system").exists()
        }
    };

    // ── Determine banaction ──
    // Debian 13+ defaults to nftables; also check if nft binary exists
    let use_nftables = match distro_id.as_str() {
        "debian" => version_num >= 13.0,
        _ => false,
    } || command_exists("nft");

    let backend = if use_systemd_backend { "systemd" } else { "auto" };
    let banaction = if use_nftables { "nftables-multiport" } else { "iptables-multiport" };

    let mut config = format!(
        "# Generated by WolfStack for {distro} {version}\n\
         # Last generated: {timestamp}\n\n\
         [DEFAULT]\n\
         bantime  = 1h\n\
         findtime = 10m\n\
         maxretry = 5\n\
         ignoreip = 127.0.0.1/8 ::1\n\
         backend  = {backend}\n\
         banaction = {banaction}\n\n\
         [sshd]\n\
         enabled  = true\n\
         port     = ssh\n\
         filter   = sshd\n\
         maxretry = 3\n",
        distro = if distro_id.is_empty() { "unknown".to_string() } else { distro_id.clone() },
        version = version_id,
        timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        backend = backend,
        banaction = banaction,
    );

    // Only set logpath for file-based backends (not systemd)
    if !use_systemd_backend {
        config.push_str("logpath  = /var/log/auth.log\n");
    }

    config
}

/// POST /api/security/fail2ban/install — install fail2ban + create default jail.local
pub async fn security_fail2ban_install(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Install fail2ban + python3-systemd (needed for systemd backend)
    if let Err(_) = run_shell("apt-get update && apt-get install -y fail2ban python3-systemd") {
        // Try without python3-systemd (may not exist on all distros)
        if let Err(e) = run_shell("apt-get install -y fail2ban") {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
    }

    // Create default jail.local if it doesn't exist
    if !std::path::Path::new("/etc/fail2ban/jail.local").exists() {
        let config = generate_jail_local();
        let _ = std::fs::write("/etc/fail2ban/jail.local", config);
    }

    match run_shell("systemctl enable --now fail2ban && systemctl restart fail2ban") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/fail2ban/rebuild — regenerate jail.local with distro-appropriate settings
pub async fn security_fail2ban_rebuild(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }

    // Ensure python3-systemd is present
    let _ = run_shell("apt-get install -y python3-systemd 2>/dev/null");

    let config = generate_jail_local();
    if let Err(e) = std::fs::write("/etc/fail2ban/jail.local", &config) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to write jail.local: {}", e)
        }));
    }

    match run_shell("systemctl restart fail2ban") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "output": out,
            "config": config,
            "message": "jail.local regenerated with distro-appropriate settings"
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "warning": format!("Config written but restart failed: {}", e),
            "config": config
        })),
    }
}


/// GET /api/security/fail2ban/config — read jail.local
pub async fn security_fail2ban_config_get(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let exists = std::path::Path::new("/etc/fail2ban/jail.local").exists();
    let content = if exists {
        std::fs::read_to_string("/etc/fail2ban/jail.local").unwrap_or_default()
    } else { String::new() };
    HttpResponse::Ok().json(serde_json::json!({
        "exists": exists,
        "content": content,
    }))
}

/// POST /api/security/fail2ban/config — save jail.local and restart fail2ban
pub async fn security_fail2ban_config_save(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
    if content.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Content required" }));
    }
    if let Err(e) = std::fs::write("/etc/fail2ban/jail.local", content) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write: {}", e) }));
    }
    match run_shell("systemctl restart fail2ban") {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "warning": format!("Saved but restart failed: {}", e) })),
    }
}

/// POST /api/security/fail2ban/unban — unban an IP { "ip": "1.2.3.4", "jail": "sshd" }
pub async fn security_fail2ban_unban(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let ip = body.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let jail = body.get("jail").and_then(|v| v.as_str()).unwrap_or("sshd");
    if ip.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "IP required" }));
    }
    // Sanitise IP — allow only digits, dots, colons (IPv6)
    if !ip.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid IP" }));
    }
    match run_shell(&format!("fail2ban-client set {} unbanip {}", jail, ip)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/install — install UFW
pub async fn security_ufw_install(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    match run_shell("apt-get update && apt-get install -y ufw") {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/rule — add a UFW rule { "rule": "allow 22/tcp" }
pub async fn security_ufw_add_rule(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let rule = body.get("rule").and_then(|v| v.as_str()).unwrap_or("");
    if rule.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Rule required" }));
    }
    // Basic sanitisation — only allow alphanumeric, spaces, slashes, dots, colons
    if !rule.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '/' || c == '.' || c == ':') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid rule characters" }));
    }
    match run_shell(&format!("ufw {}", rule)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/security/ufw/rule — delete a UFW rule { "rule_number": "3" }
pub async fn security_ufw_delete_rule(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let num = body.get("rule_number").and_then(|v| v.as_str()).unwrap_or("");
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Valid rule number required" }));
    }
    match run_shell(&format!("echo y | ufw delete {}", num)) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/security/ufw/toggle — enable or disable UFW { "enable": true }
pub async fn security_ufw_toggle(
    _req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let enable = body.get("enable").and_then(|v| v.as_bool()).unwrap_or(false);
    let cmd = if enable { "echo y | ufw enable" } else { "ufw disable" };
    match run_shell(cmd) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/security/iptables/rules — get iptables rules
pub async fn security_iptables_rules(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let rules = run_shell("iptables -L -n --line-numbers 2>/dev/null")
        .unwrap_or_else(|e| format!("Error: {}", e));
    HttpResponse::Ok().json(serde_json::json!({ "rules": rules }))
}

/// POST /api/security/updates/check — refresh package cache and list pending updates
pub async fn security_check_updates(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let (pkg_manager, output) = if command_exists("apt") {
        let _ = run_shell("apt-get update -qq 2>/dev/null");
        let list = run_shell("apt list --upgradable 2>/dev/null | grep -v '^Listing'")
            .unwrap_or_default();
        ("apt", list)
    } else if command_exists("dnf") {
        let list = run_shell("dnf check-update --quiet 2>/dev/null").unwrap_or_default();
        ("dnf", list)
    } else if command_exists("yum") {
        let list = run_shell("yum check-update --quiet 2>/dev/null").unwrap_or_default();
        ("yum", list)
    } else if command_exists("pacman") {
        let _ = run_shell("pacman -Sy 2>/dev/null");
        let list = run_shell("pacman -Qu 2>/dev/null").unwrap_or_default();
        ("pacman", list)
    } else {
        ("unknown", String::new())
    };
    let count = output.lines().filter(|l| !l.trim().is_empty()).count();
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "package_manager": pkg_manager,
        "count": count,
        "list": output.trim(),
    }))
}

/// POST /api/security/updates/apply — apply all pending updates
pub async fn security_apply_updates(
    _req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&_req, &state) { return resp; }
    let cmd = if command_exists("apt") {
        "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1"
    } else if command_exists("dnf") {
        "dnf upgrade -y 2>&1"
    } else if command_exists("yum") {
        "yum update -y 2>&1"
    } else if command_exists("pacman") {
        "pacman -Syu --noconfirm 2>&1"
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "No supported package manager found" }));
    };
    match run_shell(cmd) {
        Ok(out) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "output": out })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── Issues Scanner ───

/// Parse human-readable size strings (e.g. "1.2G", "450M", "32K") to MB
fn parse_size_to_mb(s: &str) -> f64 {
    let s = s.trim();
    if s.is_empty() { return 0.0; }
    let (num_str, suffix) = if s.ends_with(|c: char| c.is_alphabetic()) {
        let idx = s.len() - 1;
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };
    let num: f64 = num_str.parse().unwrap_or(0.0);
    match suffix.to_uppercase().as_str() {
        "T" => num * 1024.0 * 1024.0,
        "G" => num * 1024.0,
        "M" => num,
        "K" => num / 1024.0,
        "B" => num / (1024.0 * 1024.0),
        _ => num, // assume MB
    }
}

#[derive(Serialize, Clone)]
pub struct Issue {
    pub severity: String,   // "critical", "warning", "info"
    pub category: String,   // "cpu", "memory", "disk", "swap", "load", "service", "container"
    pub title: String,
    pub detail: String,
}

/// Collect system issues (reusable — called by HTTP handler and background scheduler)
pub fn collect_issues(metrics: &crate::monitoring::SystemMetrics) -> Vec<Issue> {
    let mut issues: Vec<Issue> = Vec::new();
    let mem_pct = metrics.memory_percent;

    // ── CPU check ──
    if metrics.cpu_usage_percent > 90.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "cpu".into(),
            title: "CPU usage critically high".into(),
            detail: format!("CPU at {:.1}% — system may be unresponsive", metrics.cpu_usage_percent),
        });
    } else if metrics.cpu_usage_percent > 75.0 {
        issues.push(Issue {
            severity: "warning".into(),
            category: "cpu".into(),
            title: "CPU usage elevated".into(),
            detail: format!("CPU at {:.1}% — monitor for sustained load", metrics.cpu_usage_percent),
        });
    }

    // ── Memory check ──
    if mem_pct > 90.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "memory".into(),
            title: "Memory usage critically high".into(),
            detail: format!("Memory at {:.1}% — OOM risk", mem_pct),
        });
    } else if mem_pct > 80.0 {
        issues.push(Issue {
            severity: "warning".into(),
            category: "memory".into(),
            title: "Memory usage elevated".into(),
            detail: format!("Memory at {:.1}%", mem_pct),
        });
    }

    // ── Disk checks (free space, not just %) ──
    for disk in &metrics.disks {
        // Skip /boot/ and /etc/pve mounts unless >99% — managed by the OS/Proxmox
        if (disk.mount_point.starts_with("/boot") || disk.mount_point == "/etc/pve") && disk.usage_percent <= 99.0 {
            continue;
        }

        let total_gb = disk.total_bytes as f64 / 1_073_741_824.0;
        let used_gb = disk.used_bytes as f64 / 1_073_741_824.0;
        let free_gb = disk.available_bytes as f64 / 1_073_741_824.0;
        let size_detail = format!("{} — {:.1} GB used / {:.1} GB total ({:.1} GB free, {:.1}%)",
            disk.mount_point, used_gb, total_gb, free_gb, disk.usage_percent);

        if free_gb < 2.0 {
            issues.push(Issue {
                severity: "critical".into(),
                category: "disk".into(),
                title: format!("Disk {} almost full ({:.1} GB free)", disk.mount_point, free_gb),
                detail: size_detail,
            });
        } else if free_gb < 10.0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "disk".into(),
                title: format!("Disk {} low on space ({:.1} GB free)", disk.mount_point, free_gb),
                detail: size_detail,
            });
        }
    }

    // ── Swap check ──
    if metrics.swap_total_bytes > 0 {
        let swap_pct = (metrics.swap_used_bytes as f64 / metrics.swap_total_bytes as f64) * 100.0;
        if swap_pct > 50.0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "swap".into(),
                title: "Significant swap usage".into(),
                detail: format!("Swap at {:.1}% — system may be low on RAM", swap_pct),
            });
        }
    }

    // ── Load average check ──
    let cpu_count = metrics.cpu_count.max(1) as f64;
    if metrics.load_avg.one > cpu_count * 2.0 {
        issues.push(Issue {
            severity: "critical".into(),
            category: "load".into(),
            title: "Load average extremely high".into(),
            detail: format!("Load {:.2} ({:.1}× CPU count {})", metrics.load_avg.one, metrics.load_avg.one / cpu_count, metrics.cpu_count),
        });
    } else if metrics.load_avg.one > cpu_count {
        issues.push(Issue {
            severity: "warning".into(),
            category: "load".into(),
            title: "Load average high".into(),
            detail: format!("Load {:.2} (>{} CPUs)", metrics.load_avg.one, metrics.cpu_count),
        });
    }

    // ── Failed systemd services ──
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["--failed", "--no-legend", "--plain"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(unit) = parts.first() {
                if !unit.is_empty() {
                    issues.push(Issue {
                        severity: "warning".into(),
                        category: "service".into(),
                        title: format!("Service {} failed", unit),
                        detail: format!("systemd unit {} is in failed state", unit),
                    });
                }
            }
        }
    }

    // ── Stopped Docker containers ──
    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "-a", "--filter", "status=exited", "--format", "{{.Names}}"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stopped: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
        if !stopped.is_empty() {
            issues.push(Issue {
                severity: "info".into(),
                category: "container".into(),
                title: format!("{} stopped Docker container(s)", stopped.len()),
                detail: format!("Stopped: {}", stopped.join(", ")),
            });
        }
    }

    // ── Kubernetes cluster issues ──
    let k8s_clusters = crate::kubernetes::list_clusters();
    for cluster in &k8s_clusters {
        let status = crate::kubernetes::get_cluster_status(&cluster.kubeconfig_path);
        if !status.healthy {
            issues.push(Issue {
                severity: "warning".into(),
                category: "kubernetes".into(),
                title: format!("K8s cluster '{}' unhealthy", cluster.name),
                detail: format!("{}/{} nodes ready, {}/{} pods running",
                    status.nodes_ready, status.nodes_total,
                    status.pods_running, status.pods_total),
            });
        }

        // Check for NotReady nodes
        let nodes = crate::kubernetes::get_nodes(&cluster.kubeconfig_path);
        for n in &nodes {
            if n.status != "Ready" {
                issues.push(Issue {
                    severity: "critical".into(),
                    category: "kubernetes".into(),
                    title: format!("K8s node '{}' not ready", n.name),
                    detail: format!("Cluster '{}', status: {}, role: {}", cluster.name, n.status, n.roles),
                });
            }
        }

        // Check for problem pods (exclude Succeeded/Completed pods — these are finished Jobs/init containers)
        let pods = crate::kubernetes::get_pods(&cluster.kubeconfig_path, None);
        let active_pods: Vec<_> = pods.iter().filter(|p| p.status != "Succeeded").collect();
        let failed = active_pods.iter().filter(|p| p.status == "Failed" || p.status == "Unknown").count();
        let pending = active_pods.iter().filter(|p| p.status == "Pending").count();
        let high_restarts = active_pods.iter().filter(|p| p.restarts >= 10).count();

        if failed > 0 {
            issues.push(Issue {
                severity: "critical".into(),
                category: "kubernetes".into(),
                title: format!("{} failed pod(s) in cluster '{}'", failed, cluster.name),
                detail: active_pods.iter().filter(|p| p.status == "Failed" || p.status == "Unknown")
                    .take(5).map(|p| format!("{}/{}", p.namespace, p.name)).collect::<Vec<_>>().join(", "),
            });
        }
        if pending > 0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "kubernetes".into(),
                title: format!("{} pending pod(s) in cluster '{}'", pending, cluster.name),
                detail: active_pods.iter().filter(|p| p.status == "Pending")
                    .take(5).map(|p| format!("{}/{}", p.namespace, p.name)).collect::<Vec<_>>().join(", "),
            });
        }
        if high_restarts > 0 {
            issues.push(Issue {
                severity: "warning".into(),
                category: "kubernetes".into(),
                title: format!("{} pod(s) with high restarts in cluster '{}'", high_restarts, cluster.name),
                detail: active_pods.iter().filter(|p| p.restarts >= 10)
                    .take(5).map(|p| format!("{}/{} ({}x)", p.namespace, p.name, p.restarts)).collect::<Vec<_>>().join(", "),
            });
        }
    }

    // ── Clearable disk space ──

    // Journal logs
    if let Ok(output) = std::process::Command::new("journalctl")
        .args(["--disk-usage"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "Archived and active journals take up 1.2G in the file system."
        if let Some(size_str) = stdout.split("take up ").nth(1).and_then(|s| s.split(' ').next()) {
            let size_mb = parse_size_to_mb(size_str);
            if size_mb > 500.0 {
                issues.push(Issue {
                    severity: "info".into(),
                    category: "disk".into(),
                    title: format!("Journal logs using {}", size_str),
                    detail: format!("Run 'journalctl --vacuum-size=200M' to reclaim space"),
                });
            }
        }
    }

    // Package cache (apt)
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/var/cache/apt/archives"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 200.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("APT cache using {}", size_str),
                        detail: "Run 'apt clean' to reclaim space".into(),
                    });
                }
            }
        }
    }

    // Package cache (dnf/yum)
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/var/cache/dnf"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 200.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("DNF cache using {}", size_str),
                        detail: "Run 'dnf clean all' to reclaim space".into(),
                    });
                }
            }
        }
    }

    // /tmp usage
    if let Ok(output) = std::process::Command::new("du")
        .args(["-sh", "/tmp"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = stdout.split_whitespace().next() {
                let size_mb = parse_size_to_mb(size_str);
                if size_mb > 500.0 {
                    issues.push(Issue {
                        severity: "info".into(),
                        category: "disk".into(),
                        title: format!("/tmp using {}", size_str),
                        detail: "Temporary files may be safe to clean up".into(),
                    });
                }
            }
        }
    }

    // Docker unused images
    if let Ok(output) = std::process::Command::new("docker")
        .args(["system", "df", "--format", "{{.Reclaimable}}"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Sum up any reclaimable amounts
            let mut total_mb = 0.0f64;
            let mut total_str = String::new();
            for line in stdout.lines() {
                let clean = line.trim().split('(').next().unwrap_or("").trim();
                if !clean.is_empty() && clean != "0B" {
                    let mb = parse_size_to_mb(clean);
                    total_mb += mb;
                    if total_str.is_empty() { total_str = clean.to_string(); }
                }
            }
            if total_mb > 500.0 {
                issues.push(Issue {
                    severity: "info".into(),
                    category: "container".into(),
                    title: format!("Docker reclaimable space: {:.0} MB", total_mb),
                    detail: "Run 'docker system prune' to reclaim unused images/containers".into(),
                });
            }
        }
    }

    issues
}

/// GET /api/issues/scan — scan system for issues
pub async fn scan_issues(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let st = state.clone().into_inner();
    let metrics = tokio::task::spawn_blocking(move || {
        st.monitor.lock().unwrap().collect()
    }).await.unwrap();
    let issues = collect_issues(&metrics);

    HttpResponse::Ok().json(serde_json::json!({
        "hostname": metrics.hostname,
        "version": env!("CARGO_PKG_VERSION"),
        "issues": issues,
        "ai_analysis": null,
    }))
}

/// GET /api/alerts?since=ID — get recent alerts for the Tasks window
pub async fn get_alert_log(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let since_id: u64 = query.get("since")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let log = state.alert_log.read().unwrap();
    let new_entries: Vec<&AlertLogEntry> = log.iter()
        .filter(|e| e.id > since_id)
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "alerts": new_entries,
    }))
}

/// GET /api/settings/paths — get file location configuration
pub async fn get_file_locations(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::paths::get())
}

/// POST /api/settings/paths — update file location configuration
pub async fn update_file_locations(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<crate::paths::FileLocations>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match crate::paths::update(body.into_inner()) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// POST /api/issues/clean — run safe cleanup to free disk space
pub async fn clean_system(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let mut cleaned = Vec::new();
    let mut total_freed_mb: f64 = 0.0;

    // ── Journal logs → vacuum to 200M ──
    if let Ok(before_out) = run_shell("journalctl --disk-usage 2>/dev/null") {
        let before_mb = before_out.split("take up ").nth(1)
            .and_then(|s| s.split(' ').next())
            .map(|s| parse_size_to_mb(s))
            .unwrap_or(0.0);

        let _ = run_shell("journalctl --vacuum-size=200M 2>/dev/null");

        let after_mb = run_shell("journalctl --disk-usage 2>/dev/null").ok()
            .and_then(|o| o.split("take up ").nth(1).and_then(|s| s.split(' ').next()).map(|s| parse_size_to_mb(s)))
            .unwrap_or(before_mb);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("Journal logs: freed {:.0} MB", freed));
        }
    }

    // ── APT cache ──
    if command_exists("apt") {
        let before_mb = run_shell("du -sm /var/cache/apt/archives 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let _ = run_shell("apt-get clean -y 2>/dev/null");
        let _ = run_shell("apt-get autoremove -y 2>/dev/null");

        let after_mb = run_shell("du -sm /var/cache/apt/archives 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("APT cache: freed {:.0} MB", freed));
        }
    }

    // ── DNF/YUM cache ──
    if command_exists("dnf") {
        let before_mb = run_shell("du -sm /var/cache/dnf 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let _ = run_shell("dnf clean all 2>/dev/null");

        let after_mb = run_shell("du -sm /var/cache/dnf 2>/dev/null").ok()
            .and_then(|o| o.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);

        let freed = (before_mb - after_mb).max(0.0);
        if freed > 1.0 {
            total_freed_mb += freed;
            cleaned.push(format!("DNF cache: freed {:.0} MB", freed));
        }
    } else if command_exists("yum") {
        let _ = run_shell("yum clean all 2>/dev/null");
        cleaned.push("YUM cache: cleaned".into());
    }

    // ── Old kernels (keep current + 1 previous) ──
    if command_exists("apt") {
        let out = run_shell("dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v $(uname -r | sed 's/-generic//') | head -5").ok().unwrap_or_default();
        let old_kernels: Vec<&str> = out.lines().filter(|l| !l.is_empty() && l.contains("linux-image")).collect();
        if !old_kernels.is_empty() {
            for kernel in &old_kernels {
                let _ = run_shell(&format!("DEBIAN_FRONTEND=noninteractive apt-get remove -y {} 2>/dev/null", kernel));
            }
            cleaned.push(format!("Old kernels: removed {} package(s)", old_kernels.len()));
        }
    }

    // ── Docker prune ──
    if command_exists("docker") {
        let out = run_shell("docker system prune -f 2>/dev/null").ok().unwrap_or_default();
        // Parse "Total reclaimed space: 1.23GB" from output
        if let Some(line) = out.lines().find(|l| l.contains("reclaimed space")) {
            if let Some(size_str) = line.split(": ").nth(1) {
                let mb = parse_size_to_mb(size_str.trim());
                if mb > 1.0 {
                    total_freed_mb += mb;
                    cleaned.push(format!("Docker prune: freed {}", size_str.trim()));
                }
            }
        }
    }

    // ── /tmp old files (>7 days) ──
    let _ = run_shell("find /tmp -type f -atime +7 -delete 2>/dev/null");

    if cleaned.is_empty() {
        cleaned.push("System is already clean — nothing to free.".into());
    }

    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "cleaned": cleaned,
        "freed_mb": total_freed_mb.round() as u64,
    }))
}

// ═══════════════════════════════════════════════
// ─── Alerting & Notifications ───
// ═══════════════════════════════════════════════

pub async fn alerts_config_get(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::alerting::AlertConfig::load();
    HttpResponse::Ok().json(config.to_masked_json())
}

pub async fn alerts_config_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::alerting::AlertConfig::load();
    let v = body.into_inner();

    if let Some(enabled) = v.get("enabled").and_then(|v| v.as_bool()) { config.enabled = enabled; }
    if let Some(url) = v.get("discord_webhook").and_then(|v| v.as_str()) { config.discord_webhook = url.to_string(); }
    if let Some(url) = v.get("slack_webhook").and_then(|v| v.as_str()) { config.slack_webhook = url.to_string(); }
    if let Some(token) = v.get("telegram_bot_token").and_then(|v| v.as_str()) { config.telegram_bot_token = token.to_string(); }
    if let Some(id) = v.get("telegram_chat_id").and_then(|v| v.as_str()) { config.telegram_chat_id = id.to_string(); }
    if let Some(t) = v.get("cpu_threshold").and_then(|v| v.as_f64()) { config.cpu_threshold = t as f32; }
    if let Some(t) = v.get("memory_threshold").and_then(|v| v.as_f64()) { config.memory_threshold = t as f32; }
    if let Some(t) = v.get("disk_threshold").and_then(|v| v.as_f64()) { config.disk_threshold = t as f32; }
    if let Some(b) = v.get("alert_node_offline").and_then(|v| v.as_bool()) { config.alert_node_offline = b; }
    if let Some(b) = v.get("alert_node_restored").and_then(|v| v.as_bool()) { config.alert_node_restored = b; }
    if let Some(b) = v.get("alert_cpu").and_then(|v| v.as_bool()) { config.alert_cpu = b; }
    if let Some(b) = v.get("alert_memory").and_then(|v| v.as_bool()) { config.alert_memory = b; }
    if let Some(b) = v.get("alert_disk").and_then(|v| v.as_bool()) { config.alert_disk = b; }
    if let Some(i) = v.get("check_interval_secs").and_then(|v| v.as_u64()) {
        // Clamp to sensible range: 30 seconds to 1 hour
        config.check_interval_secs = i.max(30).min(3600);
    }
    if let Some(i) = v.get("security_scan_interval_secs").and_then(|v| v.as_u64()) {
        // Clamp to 1 hour minimum (matches the UI dropdown floor) and
        // 24 hours maximum to keep at least one scan per day even if
        // a user picks the highest setting offered.
        config.security_scan_interval_secs = i.max(3600).min(24 * 3600);
    }
    // Discord bot token is write-only from the UI's perspective —
    // masked in to_masked_json so the frontend never sees it back.
    // Only overwrite when a non-empty value arrives, so a save with
    // the field blank doesn't wipe a previously-configured token.
    if let Some(t) = v.get("discord_bot_token").and_then(|v| v.as_str()) {
        let trimmed = t.trim();
        if !trimmed.is_empty() {
            config.discord_bot_token = trimmed.to_string();
        }
    }
    // Telegram receiver flag — boolean. No secret-handling special-
    // casing; the *token* is already in telegram_bot_token (long-
    // standing outbound field).
    if let Some(b) = v.get("telegram_receiver_enabled").and_then(|v| v.as_bool()) {
        config.telegram_receiver_enabled = b;
    }
    if let Some(s) = v.get("twilio_account_sid").and_then(|v| v.as_str()) {
        config.twilio_account_sid = s.trim().to_string();
    }
    // Twilio auth token: write-only, same shape as discord_bot_token.
    if let Some(t) = v.get("twilio_auth_token").and_then(|v| v.as_str()) {
        let trimmed = t.trim();
        if !trimmed.is_empty() {
            config.twilio_auth_token = trimmed.to_string();
        }
    }
    if let Some(s) = v.get("twilio_whatsapp_from").and_then(|v| v.as_str()) {
        config.twilio_whatsapp_from = s.trim().to_string();
    }

    match config.save() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "saved": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

pub async fn alerts_test(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::alerting::AlertConfig::load();
    config.enabled = true; // Force enable for test
    let results = crate::alerting::send_test(&config).await;
    let ok_count = results.iter().filter(|(_, r)| r.is_ok()).count();
    let details: Vec<serde_json::Value> = results.iter().map(|(ch, r)| {
        serde_json::json!({ "channel": ch, "success": r.is_ok(), "error": r.as_ref().err().map(|e| e.to_string()) })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({ "sent": ok_count, "results": details }))
}

// ─── System package install ───

#[derive(Deserialize)]
pub struct InstallPackageRequest {
    /// Logical package name from the allowlist in
    /// `crate::installer::packages` — `cron`, `qemu`, etc. The
    /// per-distro mapping happens server-side; the caller never sees
    /// the actual apt/pacman name.
    pub package: String,
}

/// POST /api/system/install-package — install a system package by
/// its WolfStack-internal logical name. Used by the System Check UI's
/// "Install" button when a dependency is missing. Restricted to the
/// fixed allowlist server-side so the endpoint can't be abused as a
/// generic apt/pacman shell. Runs the install synchronously off the
/// async executor since package managers are blocking subprocesses.
pub async fn system_install_package(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InstallPackageRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let pkg = body.into_inner().package;
    let result = tokio::task::spawn_blocking(move || {
        crate::installer::packages::install(&pkg)
    }).await;
    match result {
        Ok(Ok(report)) => HttpResponse::Ok().json(serde_json::json!({
            "success": report.success,
            "package": report.package,
            "binary": report.binary,
            "message": report.message,
            "service_started": report.service_started,
        })),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": e,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("install task panicked: {}", e),
        })),
    }
}

// ─── WhatsApp webhook (inbound via Twilio) ───

/// POST /api/whatsapp/webhook — Twilio delivers inbound WhatsApp
/// messages here as `application/x-www-form-urlencoded` form data.
///
/// This endpoint is reachable without a session cookie because Twilio
/// doesn't hold one — instead we validate the `X-Twilio-Signature`
/// header (HMAC-SHA1 of URL+sorted-params signed with our Twilio auth
/// token). Any request that fails the signature check is rejected
/// with 403 without touching agents or the LLM.
///
/// The reply comes back as TwiML in the response body so Twilio
/// delivers it to the user synchronously — no outbound API call
/// needed for the common case.
// ─── Cluster filesystem proxy ───
//
// These three endpoints let a WolfAgent tool on one node read, write,
// or delete a file on a different cluster node. They require
// X-WolfStack-Secret (inter-node auth) — a human session token is not
// accepted. The wolfagents safety denylist (the same one that guards
// exec_* and wolfstack_api) is applied on BOTH sides so both the
// caller's node and the target node enforce the path allowlist.

#[derive(Deserialize)]
pub struct ClusterFileOp {
    pub path: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub append: bool,
}

pub async fn cluster_file_read(
    req: HttpRequest, state: web::Data<AppState>, body: web::Json<ClusterFileOp>,
) -> HttpResponse {
    // Only accept cluster-secret auth — user sessions MUST NOT hit this
    // endpoint. A logged-in user who wants cross-node file access goes
    // through the dashboard's own per-node browser, not through this
    // inter-node channel.
    match require_auth(&req, &state) {
        Ok(u) if u == "cluster-node" => {}
        Ok(_) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "cluster file endpoint requires cluster-secret auth, not a user session"
        })),
        Err(resp) => return resp,
    }
    let path = body.path.trim();
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "path required"}));
    }
    if let Err(e) = crate::wolfagents::safety::validate_path(path) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": e}));
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let max = 1024 * 1024;
            let truncated = bytes.len() > max;
            let slice = &bytes[..max.min(bytes.len())];
            HttpResponse::Ok().json(serde_json::json!({
                "path": path,
                "content": String::from_utf8_lossy(slice),
                "total_bytes": bytes.len(),
                "truncated": truncated,
            }))
        }
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": format!("read: {}", e)})),
    }
}

pub async fn cluster_file_write(
    req: HttpRequest, state: web::Data<AppState>, body: web::Json<ClusterFileOp>,
) -> HttpResponse {
    match require_auth(&req, &state) {
        Ok(u) if u == "cluster-node" => {}
        Ok(_) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "cluster file endpoint requires cluster-secret auth"
        })),
        Err(resp) => return resp,
    }
    let path = body.path.trim();
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "path required"}));
    }
    if body.content.len() > 8 * 1024 * 1024 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "content exceeds 8 MB"}));
    }
    if let Err(e) = crate::wolfagents::safety::validate_path(path) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": e}));
    }
    let res = if body.append {
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(path)
            .and_then(|mut f| f.write_all(body.content.as_bytes()))
    } else {
        std::fs::write(path, body.content.as_bytes())
    };
    match res {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "path": path, "bytes": body.content.len(), "appended": body.append,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("write: {}", e)
        })),
    }
}

pub async fn cluster_file_delete(
    req: HttpRequest, state: web::Data<AppState>, body: web::Json<ClusterFileOp>,
) -> HttpResponse {
    match require_auth(&req, &state) {
        Ok(u) if u == "cluster-node" => {}
        Ok(_) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "cluster file endpoint requires cluster-secret auth"
        })),
        Err(resp) => return resp,
    }
    let path = body.path.trim();
    if path.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "path required"}));
    }
    if let Err(e) = crate::wolfagents::safety::validate_path(path) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": e}));
    }
    match std::fs::remove_file(path) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"path": path})),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": format!("delete: {}", e)})),
    }
}

pub async fn whatsapp_webhook(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> HttpResponse {
    let cfg = crate::alerting::AlertConfig::load();
    if cfg.twilio_auth_token.is_empty() {
        return HttpResponse::ServiceUnavailable()
            .body("WhatsApp receiver not configured — set Twilio auth token in Settings → Alerting");
    }

    // Parse x-www-form-urlencoded body. Twilio always uses this
    // content type for webhook calls. We parse manually rather than
    // pulling in the `url` crate — the format is well-defined and
    // we already have `urlencoding` for the per-value decode.
    let form_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return HttpResponse::BadRequest().body("non-utf8 body"),
    };
    let params: Vec<(String, String)> = form_str
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            // `+` → space is an x-www-form-urlencoded thing that
            // straight %-decoding doesn't handle. Swap before decoding.
            let replace_plus = |s: &str| s.replace('+', " ");
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let dk = urlencoding::decode(&replace_plus(k)).ok()?.into_owned();
            let dv = urlencoding::decode(&replace_plus(v)).ok()?.into_owned();
            Some((dk, dv))
        })
        .collect();

    // Build the signed URL: Twilio signs the full URL it posted to
    // (scheme + host + path + query). Reconstruct from actix's
    // connection_info which respects X-Forwarded-* when a proxy is
    // in front of us.
    let conn = req.connection_info();
    let scheme = conn.scheme();
    let host = conn.host();
    let path = req.uri().path();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    let webhook_url = format!("{}://{}{}{}", scheme, host, path, query);

    let signature = req.headers().get("X-Twilio-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !crate::whatsapp_bot::validate_twilio_signature(
        &cfg.twilio_auth_token, &webhook_url, &params, signature
    ) {
        tracing::warn!("whatsapp_webhook: signature validation failed — rejecting");
        return HttpResponse::Forbidden().body("signature validation failed");
    }

    // Pull the `From` and `Body` fields out of the validated params.
    let from = params.iter().find(|(k, _)| k == "From").map(|(_, v)| v.clone()).unwrap_or_default();
    let msg_body = params.iter().find(|(k, _)| k == "Body").map(|(_, v)| v.clone()).unwrap_or_default();
    if from.is_empty() || msg_body.is_empty() {
        return HttpResponse::Ok()
            .content_type("application/xml")
            .body(crate::whatsapp_bot::twiml_empty());
    }

    // Route to agent. `handle_inbound` does the rate-limiting + agent
    // lookup + chat_with_agent call; returns None when no agent is
    // bound to this phone number (empty TwiML so Twilio doesn't retry).
    let reply = crate::whatsapp_bot::handle_inbound(&from, &msg_body, state.get_ref()).await;
    let twiml = match reply {
        Some(text) => crate::whatsapp_bot::twiml_reply(&text),
        None => crate::whatsapp_bot::twiml_empty(),
    };
    HttpResponse::Ok()
        .content_type("application/xml")
        .body(twiml)
}

// ─── MCP-shaped tool surface ───

/// POST /api/mcp/tools/list — MCP-compatible tool catalogue.
/// Returns `{ "tools": [...] }` with each entry carrying name,
/// description, and a JSON Schema for its arguments.
pub async fn mcp_tools_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(serde_json::json!({
        "tools": crate::mcp::catalogue(),
    }))
}

/// POST /api/mcp/tools/call — invoke a tool by name.
/// Body: `{ "name": "...", "arguments": {...} }`
/// Returns MCP-shaped `{ "content": [{ "type": "text", "text": ... }] }`.
pub async fn mcp_tools_call(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<crate::mcp::ToolCall>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match crate::mcp::dispatch(body.into_inner(), state.get_ref()).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "isError": true,
            "content": [{ "type": "text", "text": e }],
        })),
    }
}

// ─── WolfAgents API ───

/// GET /api/agents — list every registered agent.
pub async fn agents_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::wolfagents::load_all())
}

/// GET /api/agents/{id} — one agent by id.
pub async fn agents_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::wolfagents::load(&id) {
        Some(a) => HttpResponse::Ok().json(a),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"})),
    }
}

/// POST /api/agents — create a new agent. Body: `{"name": "..."}`
/// (plus optional overrides for system_prompt, model, provider,
/// allowed_tools, discord). Missing fields pick up defaults from
/// `wolfagents::new_default` which seeds from AiConfig.
/// POST /api/agents/build — draft a WolfAgent from a natural-language
/// request. The main AI chat calls this when the operator says "build
/// me an agent that..." — we ask the configured LLM to translate the
/// request into a concrete agent record (name, system_prompt, access
/// level, target scope, tool allowlist). The response is NOT persisted
/// — the frontend renders it as a preview with a Create button so the
/// operator can review + edit before committing. This keeps the LLM
/// from silently creating agents that the operator didn't authorise.
pub async fn agents_build_proposal(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let request_text = body.get("request").and_then(|v| v.as_str()).unwrap_or("").trim();
    if request_text.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "`request` field is required"
        }));
    }
    let ai_config = state.ai_agent.config.lock()
        .unwrap_or_else(|p| p.into_inner()).clone();
    if !ai_config.is_configured() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "AI is not configured — set provider + key in Settings → AI Agent first"
        }));
    }
    // Build the tool catalogue string the LLM will pick from.
    let tool_lines: Vec<String> = crate::wolfagents::tools::ToolId::ALL.iter().map(|t| {
        let danger = match t.danger() {
            crate::wolfagents::tools::Danger::Safe => "safe",
            crate::wolfagents::tools::Danger::Mutating => "mutating",
            crate::wolfagents::tools::Danger::Destructive => "destructive",
        };
        format!("- {} ({}): {}", t.as_str(), danger, t.label())
    }).collect();
    let clusters: Vec<String> = state.cluster.get_all_nodes().iter()
        .filter_map(|n| n.cluster_name.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter().collect();

    let system = format!(
        "You are a WolfStack agent designer. The operator describes the agent they \
         want in natural language; you respond with a single JSON object describing \
         the agent. No prose, no markdown fences, just the JSON.\n\n\
         Known clusters: [{}]\n\n\
         Tool catalogue (pick the MINIMUM set — unchecked tools are refused):\n{}\n\n\
         Schema:\n\
         {{\n\
           \"name\": string (short, memorable — e.g. \"DiskWatchdog\"),\n\
           \"system_prompt\": string (1-3 sentences describing the agent's role + output format),\n\
           \"access_level\": \"read_only\" | \"read_write\" | \"confirm_all\" | \"trusted\",\n\
           \"allowed_tools\": [\"tool_name\", ...],\n\
           \"target_scope\": {{\n\
             \"allowed_clusters\": [string, ...],\n\
             \"allowed_container_patterns\": [string, ...],\n\
             \"allowed_hosts\": [string, ...],\n\
             \"allowed_paths\": [string, ...],\n\
             \"allowed_api_paths\": [string, ...],\n\
             \"allowed_email_recipients\": [string, ...]\n\
           }}\n\
         }}\n\n\
         Rules:\n\
         - Default access_level to read_only unless the request clearly implies mutation.\n\
         - Grant send_email only when the request asks to 'report', 'email', 'notify', or 'alert'. \
           Set allowed_email_recipients to the user's email if they give one, otherwise leave empty.\n\
         - Use glob patterns for allowed_container_patterns (e.g. 'regions-*').\n\
         - Use exact cluster names; if the request names a cluster, put it in allowed_clusters.\n\
         - Never add a destructive tool unless the request clearly asks for destructive action.\n\
         - Output ONLY the JSON object. No explanation, no fences.",
        clusters.join(", "),
        tool_lines.join("\n"),
    );
    let reply = match crate::ai::simple_chat(&ai_config, &system, &[], request_text).await {
        Ok(r) => r,
        Err(e) => return HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("AI call failed: {}", e)
        })),
    };
    // Extract the JSON object from the reply. Models sometimes wrap it
    // in ```json fences despite the instruction; strip those tolerantly.
    let cleaned = extract_json_object(&reply);
    let proposal: serde_json::Value = match serde_json::from_str(&cleaned) {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("AI response was not valid JSON: {}", e),
            "raw_response": reply,
        })),
    };
    // Validate tool names so the UI doesn't offer a proposal the
    // backend would later reject on create. Silently drop unknowns
    // rather than failing outright — the operator can edit anyway.
    let mut proposal = proposal;
    if let Some(tools) = proposal.get_mut("allowed_tools").and_then(|v| v.as_array_mut()) {
        tools.retain(|t| t.as_str()
            .and_then(crate::wolfagents::tools::ToolId::from_str)
            .is_some());
    }
    HttpResponse::Ok().json(serde_json::json!({ "proposal": proposal, "raw": reply }))
}

/// Best-effort extraction of a JSON object from an LLM response that
/// might be wrapped in ```json fences or trailing prose. Returns the
/// substring from the first `{` to the last `}`.
fn extract_json_object(s: &str) -> String {
    let start = s.find('{');
    let end = s.rfind('}');
    match (start, end) {
        (Some(a), Some(b)) if b > a => s[a..=b].to_string(),
        _ => s.to_string(),
    }
}

pub async fn agents_create(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let v = body.into_inner();
    let name = match v.get("name").and_then(|n| n.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "name is required"})),
    };
    let mut agent = crate::wolfagents::new_default(name);
    // Apply optional overrides from the body so the create-and-
    // customise-in-one-call path works from the UI.
    if let Some(s) = v.get("system_prompt").and_then(|x| x.as_str()) {
        agent.system_prompt = s.to_string();
    }
    if let Some(m) = v.get("model").and_then(|x| x.as_str()) {
        agent.model = m.to_string();
    }
    if let Some(p) = v.get("provider").and_then(|x| x.as_str()) {
        agent.provider = p.to_string();
    }
    if let Some(arr) = v.get("allowed_tools").and_then(|x| x.as_array()) {
        agent.allowed_tools = arr.iter().filter_map(|t| t.as_str().map(String::from)).collect();
    }
    if let Some(n) = v.get("memory_max_lines").and_then(|x| x.as_u64()) {
        agent.memory_max_lines = (n as usize).clamp(4, 4096);
    }
    if let Some(d) = v.get("discord") {
        if let Ok(parsed) = serde_json::from_value::<crate::wolfagents::DiscordBinding>(d.clone()) {
            agent.discord = Some(parsed);
        }
    }
    apply_access_fields(&mut agent, &v);
    match crate::wolfagents::upsert(agent.clone()) {
        Ok(()) => HttpResponse::Ok().json(agent),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// Apply access_level + target_scope + include_cluster_context from
/// the incoming JSON body to an agent record. Shared between create
/// and update so the two paths stay in sync. Missing fields leave
/// the existing value in place; setting target_scope to an empty
/// object clears all scope restrictions (intentional — the operator
/// may want to widen scope).
fn apply_access_fields(agent: &mut crate::wolfagents::Agent, v: &serde_json::Value) {
    // Avatar: either a bare filename (e.g. "wolf-grey.svg" → served from
    // /images/agent-avatars/) or a data: URL from a user upload. null
    // clears the field, which makes the UI fall back to a deterministic
    // built-in pick. We cap data URLs at 512 KB to keep agents.json from
    // ballooning when lots of agents carry custom uploads.
    if let Some(v_av) = v.get("avatar") {
        if v_av.is_null() {
            agent.avatar = None;
        } else if let Some(s) = v_av.as_str() {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                agent.avatar = None;
            } else if trimmed.len() > 512 * 1024 {
                tracing::warn!(
                    "wolfagents: rejecting avatar >512 KB for agent {} ({} bytes)",
                    agent.id, trimmed.len());
                // Preserve the existing avatar rather than failing the
                // whole update on this one field.
            } else {
                agent.avatar = Some(trimmed.to_string());
            }
        }
    }
    if let Some(level) = v.get("access_level").and_then(|x| x.as_str()) {
        agent.access_level = match level {
            "read_only" => crate::wolfagents::AccessLevel::ReadOnly,
            "read_write" => crate::wolfagents::AccessLevel::ReadWrite,
            "confirm_all" => crate::wolfagents::AccessLevel::ConfirmAll,
            "trusted" => crate::wolfagents::AccessLevel::Trusted,
            _ => agent.access_level, // unknown value: keep existing
        };
    }
    if let Some(scope_v) = v.get("target_scope") {
        if let Ok(parsed) = serde_json::from_value::<crate::wolfagents::TargetScope>(scope_v.clone()) {
            agent.target_scope = parsed;
        }
    }
    if let Some(b) = v.get("include_cluster_context").and_then(|x| x.as_bool()) {
        agent.include_cluster_context = b;
    }
    // Telegram binding: same convention as discord — null clears,
    // missing leaves alone, object replaces. Historically only discord
    // was processed here, which meant the frontend's telegram payload
    // silently dropped on every save and the operator saw "chat_id
    // set in the UI but nothing routes".
    if let Some(t) = v.get("telegram") {
        if t.is_null() {
            agent.telegram = None;
        } else if let Ok(parsed) = serde_json::from_value::<crate::wolfagents::TelegramBinding>(t.clone()) {
            agent.telegram = Some(parsed);
        }
    }
    // WhatsApp binding: same null/missing/object semantics.
    if let Some(w) = v.get("whatsapp") {
        if w.is_null() {
            agent.whatsapp = None;
        } else if let Ok(parsed) = serde_json::from_value::<crate::wolfagents::WhatsAppBinding>(w.clone()) {
            agent.whatsapp = Some(parsed);
        }
    }
}

/// PUT /api/agents/{id} — update fields on an existing agent. Body
/// is the full agent JSON (same shape as create). Missing fields fall
/// back to the stored agent's values so partial updates work.
pub async fn agents_update(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mut agent = match crate::wolfagents::load(&id) {
        Some(a) => a,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"})),
    };
    let v = body.into_inner();
    if let Some(n) = v.get("name").and_then(|x| x.as_str()) { if !n.trim().is_empty() { agent.name = n.trim().to_string(); } }
    if let Some(s) = v.get("system_prompt").and_then(|x| x.as_str()) { agent.system_prompt = s.to_string(); }
    if let Some(m) = v.get("model").and_then(|x| x.as_str()) { agent.model = m.to_string(); }
    if let Some(p) = v.get("provider").and_then(|x| x.as_str()) { agent.provider = p.to_string(); }
    if let Some(arr) = v.get("allowed_tools").and_then(|x| x.as_array()) {
        agent.allowed_tools = arr.iter().filter_map(|t| t.as_str().map(String::from)).collect();
    }
    if let Some(n) = v.get("memory_max_lines").and_then(|x| x.as_u64()) {
        agent.memory_max_lines = (n as usize).clamp(4, 4096);
    }
    // Discord block: null clears the binding, missing leaves it as-is,
    // object replaces.
    if let Some(d) = v.get("discord") {
        if d.is_null() {
            agent.discord = None;
        } else if let Ok(parsed) = serde_json::from_value::<crate::wolfagents::DiscordBinding>(d.clone()) {
            agent.discord = Some(parsed);
        }
    }
    apply_access_fields(&mut agent, &v);
    match crate::wolfagents::upsert(agent.clone()) {
        Ok(()) => HttpResponse::Ok().json(agent),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// DELETE /api/agents/{id} — remove an agent and its memory.
pub async fn agents_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::wolfagents::delete(&id) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": e})),
    }
}

#[derive(Deserialize)]
pub struct AgentChatRequest {
    /// The user's message. No templating here — that's a WolfFlow
    /// concern; this endpoint is the raw chat surface.
    pub message: String,
}

/// POST /api/agents/{id}/chat — send a message to an agent and get
/// its reply. Appends both sides to the agent's JSONL memory. The
/// chat runs synchronously; calls with very long-running agent turns
/// (future tool-use) will move to a job-queue shape — not needed yet.
pub async fn agents_chat(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>, body: web::Json<AgentChatRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let msg = body.into_inner().message;
    if msg.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "message is empty"}));
    }
    // Dashboard chats use the full tool_use loop — Claude-provider
    // agents with allowed_tools can actually call the dispatcher.
    // Discord/Telegram/WhatsApp receivers stay on the no-AppState
    // `chat_with_agent` fallback because they don't plumb AppState.
    match crate::wolfagents::chat_with_agent_full(
        &id, &msg, state.get_ref(),
        crate::wolfagents::ChatSurface::Dashboard,
    ).await {
        Ok(reply) => HttpResponse::Ok().json(serde_json::json!({
            "agent_id": id,
            "response": reply,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/agents/tools — the catalogue of tools an agent can be
/// granted. Drives the checklist in the Edit Agent modal. Static — the
/// set is hard-coded in the binary, so the list itself doesn't
/// require auth, but we still gate behind the normal session check
/// since the rest of the agent surface is authenticated.
pub async fn agents_tool_catalogue(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::wolfagents::tools::catalogue())
}

/// GET /api/agents/{id}/pending — list pending tool-use actions for
/// this agent. Each entry has {seq, tool, arguments, reason, ts_queued}
/// and is status=pending (approve/deny entries with other status are
/// included too so the UI can show recent history).
pub async fn agents_pending_list(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if crate::wolfagents::load(&id).is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
    }
    // Load everything — UI filters by status. Keeps the history
    // viewable on the same tab.
    let all = crate::wolfagents::pending::load_all(&id);
    HttpResponse::Ok().json(serde_json::json!({ "entries": all }))
}

#[derive(Deserialize)]
pub struct PendingDecisionBody {
    #[serde(default)]
    pub note: Option<String>,
}

/// POST /api/agents/{id}/pending/{seq}/approve — run the tool now,
/// record the result. The agent sees the outcome on its next chat turn.
pub async fn agents_pending_approve(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<(String, u64)>,
    body: web::Json<PendingDecisionBody>,
) -> HttpResponse {
    let Ok(user) = require_auth(&req, &state) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorised"}));
    };
    let (agent_id, seq) = path.into_inner();
    let Some(agent) = crate::wolfagents::load(&agent_id) else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
    };
    let entry = match crate::wolfagents::pending::approve(&agent_id, seq, &user, body.into_inner().note) {
        Ok(e) => e,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    // Re-run the tool with the approval in hand. Dispatcher will
    // re-check authorise() and see our overriding "skip_auth_for_seq"
    // hint — but we don't carry that yet; simplest path: call the
    // individual tool branch directly by simulating a Trusted agent
    // for just this call.
    let trusted = crate::wolfagents::Agent {
        access_level: crate::wolfagents::AccessLevel::Trusted,
        ..agent
    };
    let result = crate::wolfagents::dispatch::dispatch(
        &trusted, &entry.tool, &entry.arguments, state.get_ref()
    ).await;
    let result_json = serde_json::json!({
        "ok": result.ok, "status": result.status, "data": result.data,
    });
    let _ = crate::wolfagents::pending::record_execution(&agent_id, seq, result_json.clone());
    HttpResponse::Ok().json(serde_json::json!({
        "approved": true,
        "seq": seq,
        "execution": result_json,
    }))
}

/// POST /api/agents/{id}/pending/{seq}/deny — reject the pending action.
/// Agent sees the denial on next turn.
pub async fn agents_pending_deny(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<(String, u64)>,
    body: web::Json<PendingDecisionBody>,
) -> HttpResponse {
    let Ok(user) = require_auth(&req, &state) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorised"}));
    };
    let (agent_id, seq) = path.into_inner();
    if crate::wolfagents::load(&agent_id).is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
    }
    match crate::wolfagents::pending::deny(&agent_id, seq, &user, body.into_inner().note) {
        Ok(entry) => HttpResponse::Ok().json(serde_json::json!({ "denied": true, "entry": entry })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// GET /api/agents/{id}/audit?limit=N — last N tool invocations for
/// this agent. Included the "denied" entries so operators can see when
/// the agent has tried to do things it's not allowed to do (a signal
/// the system prompt and tool allowlist may be out of sync).
pub async fn agents_audit(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if crate::wolfagents::load(&id).is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
    }
    let limit: usize = query.get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(1000);
    HttpResponse::Ok().json(crate::wolfagents::tools::tail_audit(&id, limit))
}

/// GET /api/agents/{id}/memory?limit=N — return the last N memory
/// entries for an agent. Used by the UI to hydrate the conversation
/// panel when opening an agent. Default N=40.
pub async fn agents_memory(
    req: HttpRequest, state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    // Confirm the agent exists — otherwise a stale UI can keep
    // pulling memory for a deleted agent indefinitely.
    if crate::wolfagents::load(&id).is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "agent not found"}));
    }
    let limit: usize = query.get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(40)
        .min(500);
    HttpResponse::Ok().json(crate::wolfagents::load_recent_memory(&id, limit))
}

// ─── WolfRun API ───

/// GET /api/wolfrun/services — list all WolfRun services
pub async fn wolfrun_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cluster = req.query_string().split('&')
        .find_map(|p| p.strip_prefix("cluster="))
        .map(|s| s.replace("%20", " "));
    let services = state.wolfrun.list(cluster.as_deref());
    HttpResponse::Ok().json(services)
}

/// GET /api/wolfrun/services/{id} — get a single service
pub async fn wolfrun_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match state.wolfrun.get(&path.into_inner()) {
        Some(svc) => HttpResponse::Ok().json(svc),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    }
}

#[derive(Deserialize)]
pub struct WolfRunCreateRequest {
    pub name: String,
    pub image: Option<String>,
    pub replicas: Option<u32>,
    pub cluster_name: String,
    #[serde(default)]
    pub runtime: Option<String>,     // "docker" (default) or "lxc"
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub placement: Option<String>,   // "any", "prefer:<node_id>", "require:<node_id>"
    #[serde(default)]
    pub restart_policy: Option<String>, // "always", "on-failure", "never"
    // LXC-specific
    #[serde(default)]
    pub lxc_distribution: Option<String>,
    #[serde(default)]
    pub lxc_release: Option<String>,
    #[serde(default)]
    pub lxc_architecture: Option<String>,
    #[serde(default)]
    pub failover: Option<bool>,
}

/// POST /api/wolfrun/services — create a new service
pub async fn wolfrun_create(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfRunCreateRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = match body.runtime.as_deref().unwrap_or("docker") {
        "lxc" => crate::wolfrun::Runtime::Lxc,
        _ => crate::wolfrun::Runtime::Docker,
    };

    // Docker requires an image
    if runtime == crate::wolfrun::Runtime::Docker && body.image.as_deref().unwrap_or("").is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Docker services require an image" }));
    }

    let placement = match body.placement.as_deref() {
        Some(p) if p.starts_with("prefer:") => crate::wolfrun::Placement::PreferNode(p[7..].to_string()),
        Some(p) if p.starts_with("require:") => crate::wolfrun::Placement::RequireNode(p[8..].to_string()),
        _ => crate::wolfrun::Placement::Any,
    };

    let restart_policy = match body.restart_policy.as_deref() {
        Some("on-failure") => crate::wolfrun::RestartPolicy::OnFailure,
        Some("never") => crate::wolfrun::RestartPolicy::Never,
        _ => crate::wolfrun::RestartPolicy::Always,
    };

    let lxc_config = if runtime == crate::wolfrun::Runtime::Lxc {
        Some(crate::wolfrun::LxcConfig {
            distribution: body.lxc_distribution.clone().unwrap_or_else(|| "ubuntu".to_string()),
            release: body.lxc_release.clone().unwrap_or_else(|| "jammy".to_string()),
            architecture: body.lxc_architecture.clone().unwrap_or_else(|| "amd64".to_string()),
        })
    } else {
        None
    };

    let svc = state.wolfrun.create(
        body.name.clone(),
        body.image.clone().unwrap_or_default(),
        body.replicas.unwrap_or(1),
        body.cluster_name.clone(),
        body.env.clone(),
        body.ports.clone(),
        body.volumes.clone(),
        placement,
        restart_policy,
        runtime,
        lxc_config,
        body.failover.unwrap_or(false),
    );

    // Broadcast to cluster peers
    let wolfrun = Arc::clone(&state.wolfrun);
    let cluster = Arc::clone(&state.cluster);
    let secret = state.cluster_secret.clone();
    actix_web::rt::spawn(async move {
        crate::wolfrun::broadcast_to_cluster(&wolfrun, &cluster, &secret).await;
    });

    HttpResponse::Ok().json(svc)
}

/// DELETE /api/wolfrun/services/{id} — delete a service and stop all instances
pub async fn wolfrun_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let mut destroyed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();

    // Clean up cloned containers (names containing "wolfrun") but keep the original template
    if let Some(svc) = state.wolfrun.get(&id) {
        // Clean up LB iptables rules
        if let Some(ref vip) = svc.service_ip {
            crate::wolfrun::remove_lb_rules_for_vip(vip);
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .ok();

        for inst in &svc.instances {
            // Destroy clones (contain "wolfrun" in name) and standby instances, leave original template
            if !inst.container_name.contains("wolfrun") && !inst.standby {
                kept.push(inst.container_name.clone());
                continue;
            }

            if let Some(node) = state.cluster.get_node(&inst.node_id) {
                if node.is_self {
                    match svc.runtime {
                        crate::wolfrun::Runtime::Docker => {
                            let _ = crate::containers::docker_stop(&inst.container_name);
                            let _ = crate::containers::docker_remove(&inst.container_name);
                        }
                        crate::wolfrun::Runtime::Lxc => {
                            let _ = crate::containers::lxc_stop(&inst.container_name);
                            let _ = crate::containers::lxc_destroy(&inst.container_name);
                        }
                    }
                    destroyed.push(inst.container_name.clone());
                } else if let Some(ref c) = client {
                    // Remote node: use the action API to stop then remove
                    let action_path = match svc.runtime {
                        crate::wolfrun::Runtime::Docker => format!("/api/containers/docker/{}/action", inst.container_name),
                        crate::wolfrun::Runtime::Lxc => format!("/api/containers/lxc/{}/action", inst.container_name),
                    };
                    let action_urls = build_node_urls(&node.address, node.port, &action_path);

                    // Stop the container first
                    for url in &action_urls {
                        match c.post(url)
                            .header("X-WolfStack-Secret", &state.cluster_secret)
                            .header("Content-Type", "application/json")
                            .body(r#"{"action":"stop"}"#)
                            .send().await
                        {
                            Ok(_) => break,
                            Err(_) => continue,
                        }
                    }

                    // Small delay for container to stop
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    // Now remove/destroy the container
                    let remove_action = match svc.runtime {
                        crate::wolfrun::Runtime::Docker => r#"{"action":"remove"}"#,
                        crate::wolfrun::Runtime::Lxc => r#"{"action":"destroy"}"#,
                    };
                    for url in &action_urls {
                        match c.post(url)
                            .header("X-WolfStack-Secret", &state.cluster_secret)
                            .header("Content-Type", "application/json")
                            .body(remove_action)
                            .send().await
                        {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    destroyed.push(inst.container_name.clone());
                                }
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
    }

    match state.wolfrun.delete(&id) {
        Some(_) => {
            // Broadcast deletion to cluster peers
            let wolfrun = Arc::clone(&state.wolfrun);
            let cluster = Arc::clone(&state.cluster);
            let secret = state.cluster_secret.clone();
            actix_web::rt::spawn(async move {
                crate::wolfrun::broadcast_to_cluster(&wolfrun, &cluster, &secret).await;
            });
            HttpResponse::Ok().json(serde_json::json!({
                "deleted": true,
                "destroyed": destroyed,
                "kept": kept,
            }))
        }
        None => {
            // Log available service IDs for debugging
            let available: Vec<String> = state.wolfrun.list(None).iter().map(|s| format!("{} ({})", s.id, s.name)).collect();
            warn!("WolfRun delete: service '{}' not found. Available: {:?}", id, available);
            HttpResponse::NotFound().json(serde_json::json!({ "error": format!("Service not found: {}", id) }))
        }
    }
}

#[derive(Deserialize)]
pub struct WolfRunActionRequest {
    pub action: String, // start, stop, restart
}

pub async fn wolfrun_service_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let action = &body.action;

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let runtime_path = match svc.runtime {
        crate::wolfrun::Runtime::Docker => "docker",
        crate::wolfrun::Runtime::Lxc => "lxc",
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut ok_count = 0u32;
    let mut fail_count = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for inst in &svc.instances {
        // Skip standby instances — they're managed by the failover system
        if inst.standby { continue; }
        if let Some(node) = state.cluster.get_node(&inst.node_id) {
            if node.is_self {
                // Local container — call functions directly (avoids HTTP self-call issues)
                let result = match (&svc.runtime, action.as_str()) {
                    (crate::wolfrun::Runtime::Docker, "start") => crate::containers::docker_start(&inst.container_name),
                    (crate::wolfrun::Runtime::Docker, "stop") => crate::containers::docker_stop(&inst.container_name),
                    (crate::wolfrun::Runtime::Docker, "restart") => crate::containers::docker_restart(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "start") => crate::containers::lxc_start(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "stop") => crate::containers::lxc_stop(&inst.container_name),
                    (crate::wolfrun::Runtime::Lxc, "restart") => {
                        let _ = crate::containers::lxc_stop(&inst.container_name);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        crate::containers::lxc_start(&inst.container_name)
                    }
                    _ => Err(format!("Unknown action: {}", action)),
                };
                match result {
                    Ok(_) => { ok_count += 1; }
                    Err(e) => {
                        errors.push(format!("{}: {}", inst.container_name, e));
                        fail_count += 1;
                    }
                }
            } else {
                // Remote node
                let api_path = format!("/api/containers/{}/{}/action", runtime_path, inst.container_name);
                let urls = build_node_urls(&node.address, node.port, &api_path);
                let payload = serde_json::json!({ "action": action });
                let mut success = false;
                for url in &urls {
                    match client.post(url)
                        .header("X-WolfStack-Secret", &state.cluster_secret)
                        .json(&payload)
                        .send().await {
                        Ok(resp) if resp.status().is_success() => { success = true; break; }
                        Ok(resp) => {
                            let body = resp.text().await.unwrap_or_default();
                            errors.push(format!("{} on {}: {}", inst.container_name, node.hostname, body));
                        }
                        Err(e) => {
                            errors.push(format!("{} on {}: {}", inst.container_name, node.hostname, e));
                        }
                    }
                }
                if success { ok_count += 1; } else { fail_count += 1; }
            }
        } else {
            errors.push(format!("{}: node not found", inst.container_name));
            fail_count += 1;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "action": action,
        "ok": ok_count,
        "failed": fail_count,
        "errors": errors,
    }))
}

#[derive(Deserialize)]
pub struct WolfRunPortForwardRequest {
    pub public_ip: String,
    pub ports: Option<String>,       // Source ports on public IP
    pub dest_ports: Option<String>,   // Destination ports on VIP
    pub protocol: String,             // "tcp", "udp", "all"
    pub label: Option<String>,
}

/// POST /api/wolfrun/services/{id}/portforward — add external port forward to service VIP
pub async fn wolfrun_portforward_add(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunPortForwardRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let vip = match &svc.service_ip {
        Some(ip) => ip.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Service has no VIP assigned" })),
    };

    let default_label = format!("WolfRun: {}", svc.name);
    let label = body.label.as_deref().unwrap_or(&default_label);

    match crate::networking::add_ip_mapping(
        &body.public_ip,
        &vip,
        body.ports.as_deref(),
        body.dest_ports.as_deref(),
        &body.protocol,
        label,
    ) {
        Ok(mapping) => HttpResponse::Ok().json(mapping),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfrun/services/{id}/portforward — list port forwards for a service
pub async fn wolfrun_portforward_list(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();

    let svc = match state.wolfrun.get(&id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" })),
    };

    let vip = match &svc.service_ip {
        Some(ip) => ip.clone(),
        None => return HttpResponse::Ok().json(serde_json::json!([])),
    };

    // Filter IP mappings that target this service's VIP
    let all_mappings = crate::networking::list_ip_mappings();
    let service_mappings: Vec<_> = all_mappings.into_iter()
        .filter(|m| m.wolfnet_ip == vip)
        .collect();

    HttpResponse::Ok().json(service_mappings)
}

/// DELETE /api/wolfrun/services/{id}/portforward/{rule_id} — remove a port forward
pub async fn wolfrun_portforward_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (_service_id, rule_id) = path.into_inner();

    match crate::networking::remove_ip_mapping(&rule_id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "deleted": true })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct WolfRunScaleRequest {
    pub replicas: u32,
}

/// POST /api/wolfrun/services/{id}/scale — scale replicas
pub async fn wolfrun_scale(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunScaleRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.wolfrun.scale(&id, body.replicas) {
        // Trigger an immediate reconcile in the background (retry if lock held)
        let wolfrun = Arc::clone(&state.wolfrun);
        let cluster = Arc::clone(&state.cluster);
        let secret = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            for attempt in 0..3 {
                if attempt > 0 {
                    actix_web::rt::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                crate::wolfrun::reconcile(&wolfrun, &cluster, &secret).await;
            }
        });
        // Broadcast to cluster peers
        let wolfrun2 = Arc::clone(&state.wolfrun);
        let cluster2 = Arc::clone(&state.cluster);
        let secret2 = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            crate::wolfrun::broadcast_to_cluster(&wolfrun2, &cluster2, &secret2).await;
        });
        HttpResponse::Ok().json(serde_json::json!({ "scaled": true, "replicas": body.replicas }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunUpdateRequest {
    pub image: Option<String>,
}

/// POST /api/wolfrun/services/{id}/update — rolling update (change image)
pub async fn wolfrun_update(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunUpdateRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if let Some(image) = &body.image {
        if state.wolfrun.update_image(&id, image.clone()) {
            // Clear instances so reconciliation redeploys with new image
            state.wolfrun.update_instances(&id, Vec::new());
            // Broadcast to cluster peers
            let wolfrun = Arc::clone(&state.wolfrun);
            let cluster = Arc::clone(&state.cluster);
            let secret = state.cluster_secret.clone();
            actix_web::rt::spawn(async move {
                crate::wolfrun::broadcast_to_cluster(&wolfrun, &cluster, &secret).await;
            });
            HttpResponse::Ok().json(serde_json::json!({ "updated": true, "image": image }))
        } else {
            HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
        }
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({ "error": "No image specified" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunSettingsRequest {
    pub min_replicas: Option<u32>,
    pub max_replicas: Option<u32>,
    pub desired: Option<u32>,
    pub lb_policy: Option<String>,
    pub allowed_nodes: Option<Vec<String>>,
    pub failover: Option<bool>,
}

/// POST /api/wolfrun/services/{id}/settings — update service settings
pub async fn wolfrun_settings(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<WolfRunSettingsRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    if state.wolfrun.update_settings(&id, body.min_replicas, body.max_replicas, body.desired, body.lb_policy.clone(), body.allowed_nodes.clone(), body.failover) {
        let wolfrun = Arc::clone(&state.wolfrun);
        let cluster = Arc::clone(&state.cluster);
        let secret = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            crate::wolfrun::reconcile(&wolfrun, &cluster, &secret).await;
        });
        // Broadcast to cluster peers
        let wolfrun2 = Arc::clone(&state.wolfrun);
        let cluster2 = Arc::clone(&state.cluster);
        let secret2 = state.cluster_secret.clone();
        actix_web::rt::spawn(async move {
            crate::wolfrun::broadcast_to_cluster(&wolfrun2, &cluster2, &secret2).await;
        });
        if let Some(svc) = state.wolfrun.get(&id) {
            HttpResponse::Ok().json(serde_json::json!({
                "updated": true,
                "replicas": svc.replicas,
                "min_replicas": svc.min_replicas,
                "max_replicas": svc.max_replicas,
                "lb_policy": svc.lb_policy,
                "allowed_nodes": svc.allowed_nodes,
                "failover": svc.failover,
            }))
        } else {
            HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
        }
    } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Service not found" }))
    }
}

#[derive(Deserialize)]
pub struct WolfRunAdoptRequest {
    pub name: String,              // WolfRun service name
    pub container_name: String,    // Existing container name
    pub node_id: String,           // Node where container runs
    pub image: String,             // Container image (for Docker)
    pub runtime: Option<String>,   // "docker" or "lxc"
    pub cluster_name: String,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// POST /api/wolfrun/services/adopt — adopt an existing container into WolfRun
pub async fn wolfrun_adopt(req: HttpRequest, state: web::Data<AppState>, body: web::Json<WolfRunAdoptRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let runtime = match body.runtime.as_deref().unwrap_or("docker") {
        "lxc" => crate::wolfrun::Runtime::Lxc,
        _ => crate::wolfrun::Runtime::Docker,
    };

    let svc = state.wolfrun.adopt(
        body.name.clone(),
        body.container_name.clone(),
        body.node_id.clone(),
        body.image.clone(),
        runtime,
        body.cluster_name.clone(),
        body.env.clone(),
        body.ports.clone(),
        body.volumes.clone(),
    );

    // Broadcast to cluster peers
    let wolfrun = Arc::clone(&state.wolfrun);
    let cluster = Arc::clone(&state.cluster);
    let secret = state.cluster_secret.clone();
    actix_web::rt::spawn(async move {
        crate::wolfrun::broadcast_to_cluster(&wolfrun, &cluster, &secret).await;
    });

    HttpResponse::Ok().json(svc)
}

/// GET /api/wolfrun/failover-events — list failover events
pub async fn wolfrun_failover_events(req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let service_id = query.get("service_id").map(|s| s.as_str());
    let events = state.wolfrun.get_failover_events(service_id);
    HttpResponse::Ok().json(events)
}

/// POST /api/wolfrun/sync — receive WolfRun services from a cluster peer
pub async fn wolfrun_sync(req: HttpRequest, state: web::Data<AppState>, body: web::Json<Vec<crate::wolfrun::WolfRunService>>) -> HttpResponse {
    // Authenticate via cluster secret (inter-node auth) or session auth
    let secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::validate_cluster_secret(secret, &state.cluster_secret)
        && !crate::auth::validate_cluster_secret(secret, crate::auth::default_cluster_secret())
        && !crate::auth::validate_cluster_secret(secret, &crate::auth::load_cluster_secret())
    {
        // Also try cookie auth (in case admin calls it manually)
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    let peer_services = body.into_inner();
    state.wolfrun.merge_from_peer(peer_services);
    HttpResponse::Ok().json(serde_json::json!({ "synced": true }))
}

/// POST /api/wolfrun/reconcile — trigger an immediate reconcile + broadcast
pub async fn wolfrun_reconcile(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let wolfrun = Arc::clone(&state.wolfrun);
    let cluster = Arc::clone(&state.cluster);
    let secret = state.cluster_secret.clone();

    // Run reconcile synchronously so the response has fresh data
    crate::wolfrun::reconcile(&wolfrun, &cluster, &secret).await;
    crate::wolfrun::broadcast_to_cluster(&wolfrun, &cluster, &secret).await;

    HttpResponse::Ok().json(serde_json::json!({ "reconciled": true }))
}

// ═══════════════════════════════════════════════
// ─── Status Page API ───
// ═══════════════════════════════════════════════

/// GET /api/statuspage/config — get full config (monitors + pages)
pub async fn statuspage_config_get(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    // Accept cluster secret (for inter-node pull) or cookie auth
    let secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::validate_cluster_secret(secret, &state.cluster_secret)
        && !crate::auth::validate_cluster_secret(secret, crate::auth::default_cluster_secret())
        && !crate::auth::validate_cluster_secret(secret, &crate::auth::load_cluster_secret())
    {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }
    let config = state.statuspage.config.read().unwrap().clone();
    HttpResponse::Ok().json(config)
}

/// POST /api/statuspage/config — save full config
pub async fn statuspage_config_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::statuspage::StatusPageConfig>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = body.into_inner();
    if let Err(e) = config.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    *state.statuspage.config.write().unwrap() = config;
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "saved": true }))
}

/// GET /api/statuspage/monitors — list all monitors with current status
pub async fn statuspage_monitors_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.statuspage.config.read().unwrap();
    let monitors: Vec<serde_json::Value> = config.monitors.iter().map(|m| {
        let status = state.statuspage.monitor_status(&m.id);
        let latest = state.statuspage.latest_result(&m.id);
        let uptime = state.statuspage.uptime_percent(&m.id);
        let history = state.statuspage.get_daily_uptime(&m.id);
        let recent_checks: Vec<_> = {
            let results = state.statuspage.results.read().unwrap();
            results.get(&m.id)
                .map(|d| d.iter().rev().take(20).cloned().collect())
                .unwrap_or_default()
        };
        serde_json::json!({
            "monitor": m,
            "status": status,
            "status_label": status.label(),
            "latest": latest,
            "uptime_percent": uptime,
            "history": history,
            "recent_checks": recent_checks,
        })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({ "monitors": monitors }))
}

/// POST /api/statuspage/monitors — create or update a monitor
pub async fn statuspage_monitor_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::statuspage::Monitor>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let monitor = body.into_inner();
    {
        let mut config = state.statuspage.config.write().unwrap();
        if let Some(existing) = config.monitors.iter_mut().find(|m| m.id == monitor.id) {
            *existing = monitor.clone();
        } else {
            config.monitors.push(monitor.clone());
        }
        if let Err(e) = config.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
    }
    // Trigger immediate check cycle so status is available right away
    let sp = state.statuspage.clone();
    tokio::spawn(async move { crate::statuspage::run_checks(&sp).await; });
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "saved": true, "monitor": monitor }))
}

/// DELETE /api/statuspage/monitors/{id} — delete a monitor
pub async fn statuspage_monitor_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mut config = state.statuspage.config.write().unwrap();
    let before = config.monitors.len();
    config.monitors.retain(|m| m.id != id);
    // Also remove this monitor from all pages
    for page in config.pages.iter_mut() {
        page.monitor_ids.retain(|mid| mid != &id);
    }
    if config.monitors.len() == before {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Monitor not found" }));
    }
    let _ = config.save();
    drop(config);
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "deleted": true }))
}

/// GET /api/statuspage/pages — list all status pages with current status
pub async fn statuspage_pages_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.statuspage.config.read().unwrap();
    let pages: Vec<serde_json::Value> = config.pages.iter().map(|p| {
        let overall = state.statuspage.page_overall_status(p);
        // Calculate 30-day uptime across all monitors on this page
        let uptime_30d: Option<f64> = if p.monitor_ids.is_empty() {
            None
        } else {
            let uptimes: Vec<f32> = p.monitor_ids.iter()
                .map(|mid| state.statuspage.uptime_percent(mid))
                .collect();
            if uptimes.is_empty() { None }
            else { Some(uptimes.iter().sum::<f32>() as f64 / uptimes.len() as f64) }
        };
        // Collect active incidents for this page
        let active_incidents: Vec<_> = config.incidents.iter()
            .filter(|i| p.incident_ids.contains(&i.id) && i.status != crate::statuspage::IncidentStatus::Resolved)
            .cloned()
            .collect();
        serde_json::json!({
            "page": {
                "id": p.id,
                "slug": p.slug,
                "title": p.title,
                "cluster": p.cluster,
                "logo_url": p.logo_url,
                "footer_text": p.footer_text,
                "theme": p.theme,
                "monitor_ids": p.monitor_ids,
                "incident_ids": p.incident_ids,
                "enabled": p.enabled,
                "incidents": active_incidents,
                "services": p.monitor_ids,
            },
            "overall_status": overall,
            "overall_label": overall.label(),
            "uptime_30d": uptime_30d,
        })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({ "pages": pages }))
}

/// POST /api/statuspage/pages — create or update a status page
pub async fn statuspage_page_save(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::statuspage::StatusPage>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let page = body.into_inner();

    // Validate slug: lowercase alphanumeric + hyphens only
    if page.slug.is_empty() || !page.slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Slug must be lowercase alphanumeric with hyphens only"
        }));
    }

    let mut config = state.statuspage.config.write().unwrap();

    // Check slug uniqueness within the same cluster (except for self)
    if config.pages.iter().any(|p| p.slug == page.slug && p.id != page.id && p.cluster == page.cluster) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "A page with this slug already exists"
        }));
    }

    if let Some(existing) = config.pages.iter_mut().find(|p| p.id == page.id) {
        *existing = page.clone();
    } else {
        config.pages.push(page.clone());
    }
    if let Err(e) = config.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    drop(config);
    // Trigger immediate check cycle so status is available right away
    let sp = state.statuspage.clone();
    tokio::spawn(async move { crate::statuspage::run_checks(&sp).await; });
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "saved": true, "page": page }))
}

/// DELETE /api/statuspage/pages/{id} — delete a status page
pub async fn statuspage_page_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mut config = state.statuspage.config.write().unwrap();
    let before = config.pages.len();
    config.pages.retain(|p| p.id != id);
    if config.pages.len() == before {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Page not found" }));
    }
    let _ = config.save();
    drop(config);
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "deleted": true }))
}

/// GET /api/statuspage/incidents — list all incidents
pub async fn statuspage_incidents_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = state.statuspage.config.read().unwrap();
    HttpResponse::Ok().json(serde_json::json!({ "incidents": config.incidents }))
}

/// POST /api/statuspage/incidents — create or update an incident
pub async fn statuspage_incident_save(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<crate::statuspage::Incident>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let incident = body.into_inner();

    let mut config = state.statuspage.config.write().unwrap();
    if let Some(existing) = config.incidents.iter_mut().find(|i| i.id == incident.id) {
        // If status changed to resolved and we didn't have a resolved_at, set it
        if incident.status == crate::statuspage::IncidentStatus::Resolved && existing.status != crate::statuspage::IncidentStatus::Resolved {
            let mut updated_incident = incident.clone();
            updated_incident.resolved_at = Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
            *existing = updated_incident;
        } else {
            *existing = incident.clone();
        }
    } else {
        config.incidents.push(incident.clone());
    }

    if let Err(e) = config.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    drop(config);
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "saved": true, "incident": incident }))
}

/// DELETE /api/statuspage/incidents/{id} — delete an incident
pub async fn statuspage_incident_delete(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let mut config = state.statuspage.config.write().unwrap();
    let before = config.incidents.len();
    config.incidents.retain(|i| i.id != id);

    // Also remove this incident from all pages
    for page in config.pages.iter_mut() {
        page.incident_ids.retain(|iid| iid != &id);
    }

    if config.incidents.len() == before {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Incident not found" }));
    }
    let _ = config.save();
    drop(config);
    sp_broadcast(&state);
    HttpResponse::Ok().json(serde_json::json!({ "deleted": true }))
}

/// Broadcast status page config to cluster peers (fire-and-forget)
fn sp_broadcast(state: &web::Data<AppState>) {
    let sp = state.statuspage.clone();
    let cluster = state.cluster.clone();
    let secret = state.cluster_secret.clone();
    actix_web::rt::spawn(async move {
        crate::statuspage::broadcast_to_cluster(&sp, &cluster, &secret).await;
    });
}

/// POST /api/statuspage/sync — receive status page config from a cluster peer
pub async fn statuspage_sync(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::statuspage::StatusPageConfig>) -> HttpResponse {
    // Authenticate via cluster secret (inter-node auth) or session auth
    let secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::validate_cluster_secret(secret, &state.cluster_secret)
        && !crate::auth::validate_cluster_secret(secret, crate::auth::default_cluster_secret())
        && !crate::auth::validate_cluster_secret(secret, &crate::auth::load_cluster_secret())
    {
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    let peer_config = body.into_inner();
    tracing::info!("StatusPage sync: received {} pages, {} monitors, {} incidents from peer",
        peer_config.pages.len(), peer_config.monitors.len(), peer_config.incidents.len());
    state.statuspage.merge_from_peer(peer_config);
    HttpResponse::Ok().json(serde_json::json!({ "synced": true }))
}

/// Get the local cluster name from cluster state
fn local_cluster_name(cluster: &crate::agent::ClusterState) -> String {
    let nodes = cluster.nodes.read().unwrap();
    nodes.get(&cluster.self_id)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string())
}

/// GET /status — public index listing all enabled status pages (or redirect if only one)
pub async fn statuspage_public_index(state: web::Data<AppState>) -> HttpResponse {
    let cluster_name = local_cluster_name(&state.cluster);
    let html = crate::statuspage::render_index_page(&state.statuspage, &cluster_name);
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

/// GET /status/{slug} — public status page for a specific application
pub async fn statuspage_public_page(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let slug = path.into_inner();
    let cluster_name = local_cluster_name(&state.cluster);
    match crate::statuspage::render_public_page(&state.statuspage, &slug, &cluster_name) {
        Some(html) => HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html),
        None => {
            // Log what we have vs what we're looking for
            let config = state.statuspage.config.read().unwrap();
            let available: Vec<String> = config.pages.iter()
                .map(|p| format!("{}(cluster={})", p.slug, p.cluster))
                .collect();
            tracing::warn!("Status page 404: slug='{}' cluster='{}' — available pages: {:?}", slug, cluster_name, available);
            drop(config);
            HttpResponse::NotFound().content_type("text/html; charset=utf-8").body(
                r#"<!DOCTYPE html><html><head><title>Not Found</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;"><p>Status page not found.</p></body></html>"#
            )
        },
    }
}

// ─── Configurator API ───

/// Query parameters for targeting a container or the host
#[derive(Debug, Deserialize)]
pub struct ConfiguratorTarget {
    pub runtime: Option<String>,
    pub target: Option<String>,
}

/// Parse query params into an ExecTarget
fn parse_exec_target(query: &web::Query<ConfiguratorTarget>) -> Result<crate::configurator::ExecTarget, HttpResponse> {
    use crate::configurator::ExecTarget;
    match (query.runtime.as_deref(), query.target.as_deref()) {
        (None, None) | (Some("host"), _) => Ok(ExecTarget::Host),
        (Some("docker"), Some(name)) if !name.is_empty() => Ok(ExecTarget::Docker(name.to_string())),
        (Some("lxc"), Some(name)) if !name.is_empty() => Ok(ExecTarget::Lxc(name.to_string())),
        (Some(rt), None) | (Some(rt), Some("")) => Err(HttpResponse::BadRequest().json(
            serde_json::json!({"error": format!("runtime '{}' requires a 'target' parameter", rt)})
        )),
        (Some(rt), _) => Err(HttpResponse::BadRequest().json(
            serde_json::json!({"error": format!("Unsupported runtime: '{}'", rt)})
        )),
        (None, Some(_)) => Err(HttpResponse::BadRequest().json(
            serde_json::json!({"error": "'target' requires a 'runtime' parameter"})
        )),
    }
}

/// GET /api/configurator/nginx/sites — list all nginx sites
pub async fn nginx_list_sites(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::nginx::list_sites(&target)).await {
        Ok(Ok(sites)) => HttpResponse::Ok().json(serde_json::json!({ "sites": sites })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/configurator/nginx/sites/{name} — read a site config
pub async fn nginx_read_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::nginx::read_site(&target, &name)).await {
        Ok(Ok(content)) => HttpResponse::Ok().json(serde_json::json!({ "content": content })),
        Ok(Err(e)) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

#[derive(Deserialize)]
pub struct SiteConfigRequest {
    pub name: Option<String>,
    pub content: String,
}

/// POST /api/configurator/nginx/sites — create a new site
pub async fn nginx_create_site(req: HttpRequest, state: web::Data<AppState>, body: web::Json<SiteConfigRequest>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = match &body.name {
        Some(n) => n.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Name is required" })),
    };
    let content = body.content.clone();
    match web::block(move || crate::configurator::nginx::save_site(&target, &name, &content)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// PUT /api/configurator/nginx/sites/{name} — update a site config
pub async fn nginx_update_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<SiteConfigRequest>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    let content = body.content.clone();
    match web::block(move || crate::configurator::nginx::save_site(&target, &name, &content)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /api/configurator/nginx/sites/{name} — delete a site
pub async fn nginx_delete_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::nginx::delete_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/nginx/sites/{name}/enable
pub async fn nginx_enable_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::nginx::enable_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/nginx/sites/{name}/disable
pub async fn nginx_disable_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::nginx::disable_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/nginx/test — run nginx -t
pub async fn nginx_test_config(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::nginx::test_config(&target)).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/nginx/reload — reload nginx
pub async fn nginx_reload(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::nginx::reload(&target)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/configurator/nginx/error-log — recent error log
pub async fn nginx_error_log(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::nginx::error_log(&target, 100)).await {
        Ok(lines) => HttpResponse::Ok().json(serde_json::json!({ "lines": lines })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/nginx/generate — generate nginx config from form params
pub async fn nginx_generate_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::configurator::nginx::NginxSiteParams>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::configurator::nginx::generate_site_config(&body);
    HttpResponse::Ok().json(serde_json::json!({ "config": config }))
}

/// POST /api/configurator/nginx/bootstrap — install nginx and create default config
pub async fn nginx_bootstrap(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::nginx::bootstrap_nginx(&target)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── Apache Configurator API ───

/// GET /api/configurator/apache/sites — list all Apache vhosts
pub async fn apache_list_sites(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::list_sites(&target)).await {
        Ok(Ok(sites)) => HttpResponse::Ok().json(serde_json::json!({ "sites": sites })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/configurator/apache/sites/{name} — read a vhost config
pub async fn apache_read_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::read_site(&target, &name)).await {
        Ok(Ok(content)) => HttpResponse::Ok().json(serde_json::json!({ "content": content })),
        Ok(Err(e)) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/sites — create a new vhost
pub async fn apache_create_site(req: HttpRequest, state: web::Data<AppState>, body: web::Json<SiteConfigRequest>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = match &body.name {
        Some(n) => n.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Name is required" })),
    };
    let content = body.content.clone();
    match web::block(move || crate::configurator::apache::save_site(&target, &name, &content)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// PUT /api/configurator/apache/sites/{name} — update a vhost config
pub async fn apache_update_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<SiteConfigRequest>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    let content = body.content.clone();
    match web::block(move || crate::configurator::apache::save_site(&target, &name, &content)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /api/configurator/apache/sites/{name} — delete a vhost
pub async fn apache_delete_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::delete_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/sites/{name}/enable
pub async fn apache_enable_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::enable_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/sites/{name}/disable
pub async fn apache_disable_site(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::disable_site(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/configurator/apache/modules — list Apache modules
pub async fn apache_list_modules(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::list_modules(&target)).await {
        Ok(Ok(mods)) => HttpResponse::Ok().json(serde_json::json!({ "modules": mods })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/modules/{name}/enable
pub async fn apache_enable_module(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::enable_module(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/modules/{name}/disable
pub async fn apache_disable_module(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let name = path.into_inner();
    match web::block(move || crate::configurator::apache::disable_module(&target, &name)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/test — run apachectl configtest
pub async fn apache_test_config(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::test_config(&target)).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/reload — reload Apache
pub async fn apache_reload(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::reload(&target)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/configurator/apache/error-log — recent error log
pub async fn apache_error_log(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::error_log(&target, 100)).await {
        Ok(lines) => HttpResponse::Ok().json(serde_json::json!({ "lines": lines })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/apache/generate — generate Apache vhost from form params
pub async fn apache_generate_config(req: HttpRequest, state: web::Data<AppState>, body: web::Json<crate::configurator::apache::ApacheVhostParams>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::configurator::apache::generate_vhost_config(&body);
    HttpResponse::Ok().json(serde_json::json!({ "config": config }))
}

/// POST /api/configurator/apache/bootstrap — install Apache and create default config
pub async fn apache_bootstrap(req: HttpRequest, state: web::Data<AppState>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    match web::block(move || crate::configurator::apache::bootstrap_apache(&target)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── TOML Configurator API ───

/// GET /api/configurator/toml/{component}/structured — parsed config as JSON
pub async fn toml_get_structured(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let component = path.into_inner();
    match web::block(move || crate::configurator::toml_editor::parse_config(&target, &component)).await {
        Ok(Ok(data)) => HttpResponse::Ok().json(data),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/configurator/toml/{component}/structured — save JSON as TOML
pub async fn toml_save_structured(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<serde_json::Value>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let component = path.into_inner();
    let data = body.into_inner();
    match web::block(move || crate::configurator::toml_editor::save_config(&target, &component, &data)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

#[derive(Deserialize)]
pub struct TomlValidateRequest {
    pub content: String,
}

/// POST /api/configurator/toml/{component}/validate — validate TOML string
pub async fn toml_validate(req: HttpRequest, state: web::Data<AppState>, body: web::Json<TomlValidateRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let content = body.content.clone();
    match crate::configurator::toml_editor::validate_toml(&content) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "valid": true })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "valid": false, "error": e })),
    }
}

/// POST /api/configurator/toml/{component}/bootstrap — create default TOML config
pub async fn toml_bootstrap(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, query: web::Query<ConfiguratorTarget>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let target = match parse_exec_target(&query) { Ok(t) => t, Err(r) => return r };
    let component = path.into_inner();
    match web::block(move || crate::configurator::toml_editor::bootstrap_config(&target, &component)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ─── Patreon Integration ─────────────────────────────────────────────────────

/// GET /api/patreon/connect — start OAuth flow, redirect to Patreon
async fn patreon_connect(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) {
        return resp;
    }
    // Build the callback URL for this WolfStack instance
    let conn = req.connection_info();
    let scheme = conn.scheme();
    let host = conn.host();
    let callback_url = format!("{}://{}/api/patreon/callback", scheme, host);
    let auth_url = state.patreon.authorize_url(&callback_url);
    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

/// GET /api/patreon/callback — receive tokens from wolfscale.org proxy
/// The proxy already exchanged the code for tokens using the client secret.
/// We receive: ?access_token=...&refresh_token=... (or ?error=...)
async fn patreon_callback(_req: HttpRequest, state: web::Data<AppState>, query: web::Query<std::collections::HashMap<String, String>>) -> HttpResponse {
    // Check for error from proxy
    if let Some(error) = query.get("error") {
        return HttpResponse::Ok().content_type("text/html").body(format!(
            r#"<!DOCTYPE html><html><head><title>Patreon Link Failed</title></head>
            <body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;">
            <div style="text-align:center"><h2>Patreon Link Failed</h2><p>Error: {}</p>
            <p><a href="/" style="color:#22c55e;">Return to dashboard</a></p></div></body></html>"#,
            error
        ));
    }

    // Receive tokens from proxy
    let access_token = match query.get("access_token") {
        Some(t) => t.clone(),
        None => {
            return HttpResponse::Ok().content_type("text/html").body(
                r#"<!DOCTYPE html><html><head><title>Patreon Link Failed</title></head>
                <body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;">
                <div style="text-align:center"><h2>Patreon Link Failed</h2><p>No access token received</p>
                <p><a href="/" style="color:#22c55e;">Return to dashboard</a></p></div></body></html>"#
            );
        }
    };
    let refresh_token = query.get("refresh_token").cloned().unwrap_or_default();

    // Save tokens
    {
        let mut config = state.patreon.config.write().unwrap();
        config.access_token = Some(access_token);
        config.refresh_token = Some(refresh_token);
        config.linked = true;
        let _ = config.save();
    }

    // Immediately sync membership info
    match state.patreon.sync_membership().await {
        Ok(tier) => {
            tracing::info!("Patreon linked successfully, tier: {:?}", tier);
        }
        Err(e) => {
            tracing::warn!("Patreon linked but membership sync failed: {}", e);
        }
    }

    HttpResponse::Ok().content_type("text/html").body(
        r#"<!DOCTYPE html><html><head><title>Patreon Linked</title></head>
        <body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;">
        <div style="text-align:center"><h2 style="color:#22c55e;">Patreon Linked Successfully!</h2>
        <p>Your support tier has been detected. You can close this window.</p>
        <p><a href="/" style="color:#22c55e;">Return to dashboard</a></p></div></body></html>"#
    )
}

/// GET /api/patreon/status — return current Patreon link status and tier
async fn patreon_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) {
        return resp;
    }
    let config = state.patreon.config.read().unwrap();
    HttpResponse::Ok().json(serde_json::json!({
        "linked": config.linked,
        "user_name": config.patreon_user_name,
        "email": config.patreon_email,
        "tier": config.tier,
        "pledge_amount_cents": config.pledge_amount_cents,
        "has_beta_access": config.tier.has_beta_access(),
        "last_checked": config.last_checked,
    }))
}

/// POST /api/patreon/sync — manually refresh membership status
async fn patreon_sync(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) {
        return resp;
    }
    match state.patreon.sync_membership().await {
        Ok(tier) => {
            let config = state.patreon.config.read().unwrap();
            HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "tier": tier,
                "has_beta_access": tier.has_beta_access(),
                "user_name": config.patreon_user_name,
                "last_checked": config.last_checked,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/patreon/disconnect — unlink Patreon account
async fn patreon_disconnect(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) {
        return resp;
    }
    let mut config = state.patreon.config.write().unwrap();
    *config = crate::patreon::PatreonConfig::default();
    let _ = config.save();
    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}

// ─── Icon Pack Endpoints ───

/// GET /api/icon-packs — list all available icon packs (system + custom)
async fn icon_packs_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let packs = crate::icons::scan_all_packs();
    HttpResponse::Ok().json(serde_json::json!({ "packs": packs }))
}

/// GET /api/icon-packs/semantic-names — list all supported semantic icon names
async fn icon_packs_semantic_names(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(serde_json::json!({ "names": crate::icons::semantic_names() }))
}

/// POST /api/icon-packs/install — install from GitHub URL { "url": "https://github.com/..." }
async fn icon_packs_install(req: HttpRequest, state: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let url = match body.get("url").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "missing 'url' field" })),
    };
    match crate::icons::install_from_github(url).await {
        Ok(pack) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "pack": pack })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/icon-packs/{pack_id} — remove a custom-installed pack
async fn icon_packs_remove(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let pack_id = path.into_inner();
    match crate::icons::remove_pack(&pack_id) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "ok": true })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/icon-packs/{pack_id}/icon/{icon_name} — serve a single icon file
/// Resolves semantic name → freedesktop icon → file on disk
async fn icon_packs_serve(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (pack_id, icon_name) = path.into_inner();

    // Find the pack directory
    let packs = crate::icons::scan_all_packs();
    let pack = match packs.iter().find(|p| p.id == pack_id) {
        Some(p) => p,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "pack not found" })),
    };

    let theme_dir = std::path::Path::new(&pack.path);
    match crate::icons::resolve_icon(theme_dir, &icon_name) {
        Some(file_path) => {
            let mime = crate::icons::icon_mime(&file_path);
            match std::fs::read(&file_path) {
                Ok(data) => HttpResponse::Ok()
                    .content_type(mime)
                    .insert_header(("Cache-Control", "public, max-age=86400"))
                    .body(data),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "icon not found in pack" })),
    }
}

/// GET /api/icon-packs/{pack_id}/preview — serve a grid of sample icons for previewing
async fn icon_packs_preview(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let pack_id = path.into_inner();

    let packs = crate::icons::scan_all_packs();
    let pack = match packs.iter().find(|p| p.id == pack_id) {
        Some(p) => p,
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "pack not found" })),
    };

    // Return a list of which semantic icons are available
    let theme_dir = std::path::Path::new(&pack.path);
    let names = crate::icons::semantic_names();
    let mut available: Vec<&str> = Vec::new();
    for name in &names {
        if crate::icons::resolve_icon(theme_dir, name).is_some() {
            available.push(name);
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "pack_id": pack_id,
        "total_semantic": names.len(),
        "available": available,
    }))
}

// ═══════════════════════════════════════════════════════════════════
// Docker Compose Management
// ═══════════════════════════════════════════════════════════════════

const COMPOSE_DIR: &str = "/etc/wolfstack/compose";
const SECRETS_FILE: &str = "/etc/wolfstack/secrets.json";

#[derive(Deserialize)]
struct ComposeCreateRequest {
    name: String,
    #[serde(default)]
    compose_yaml: String,
    #[serde(default)]
    env_content: String,
}

#[derive(Deserialize)]
struct ComposeFileRequest {
    content: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct SecretEntry {
    key: String,
    value: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    created: String,
    #[serde(default)]
    updated: String,
}

#[derive(Deserialize)]
struct SecretRequest {
    key: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

fn compose_project_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(COMPOSE_DIR).join(name)
}

/// Validate compose stack name — alphanumeric, dash, underscore only
fn is_safe_compose_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !name.starts_with('-')
}

/// Validate a name from a URL path parameter; returns Err(HttpResponse) on failure
fn require_safe_compose_name(name: &str) -> Result<(), HttpResponse> {
    if !is_safe_compose_name(name) {
        Err(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid stack name — only alphanumeric, dash, and underscore allowed"
        })))
    } else {
        Ok(())
    }
}

/// GET /api/compose/stacks — list all compose projects
async fn compose_list_stacks(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let dir = std::path::Path::new(COMPOSE_DIR);
    if !dir.exists() {
        return HttpResponse::Ok().json(serde_json::json!({ "stacks": [] }));
    }

    let mut stacks = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            let name = entry.file_name().to_string_lossy().to_string();
            let compose_file = path.join("docker-compose.yml");
            let env_file = path.join(".env");
            if !compose_file.exists() { continue; }

            // Get stack status via docker compose ps
            let status = Command::new("docker")
                .args(["compose", "-f", &compose_file.to_string_lossy(), "ps", "--format", "json"])
                .current_dir(&path)
                .output();

            let mut services = Vec::new();
            let mut running = 0u32;
            let mut total = 0u32;
            if let Ok(out) = &status {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if let Ok(svc) = serde_json::from_str::<serde_json::Value>(line) {
                        total += 1;
                        let state = svc.get("State").and_then(|s| s.as_str()).unwrap_or("unknown");
                        if state == "running" { running += 1; }
                        services.push(serde_json::json!({
                            "name": svc.get("Service").and_then(|s| s.as_str()).unwrap_or(""),
                            "state": state,
                            "status": svc.get("Status").and_then(|s| s.as_str()).unwrap_or(""),
                            "image": svc.get("Image").and_then(|s| s.as_str()).unwrap_or(""),
                            "ports": svc.get("Publishers").unwrap_or(&serde_json::Value::Null),
                        }));
                    }
                }
            }

            let has_env = env_file.exists();
            stacks.push(serde_json::json!({
                "name": name,
                "path": path.to_string_lossy(),
                "running": running,
                "total": total,
                "services": services,
                "has_env": has_env,
                "status": if total == 0 { "stopped" } else if running == total { "running" } else { "partial" },
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "stacks": stacks }))
}

/// POST /api/compose/stacks — create a new compose project
async fn compose_create_stack(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ComposeCreateRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = body.name.trim();
    if let Err(e) = require_safe_compose_name(name) { return e; }

    let dir = compose_project_dir(name);
    if dir.exists() {
        return HttpResponse::Conflict().json(serde_json::json!({ "error": "Stack already exists" }));
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to create directory: {}", e) }));
    }

    let yaml = if body.compose_yaml.is_empty() {
        format!("# Docker Compose for {}\nservices:\n  app:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n    restart: unless-stopped\n", name)
    } else {
        body.compose_yaml.clone()
    };

    if let Err(e) = std::fs::write(dir.join("docker-compose.yml"), &yaml) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write compose file: {}", e) }));
    }

    if !body.env_content.is_empty() {
        if let Err(e) = std::fs::write(dir.join(".env"), &body.env_content) {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to write .env: {}", e) }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Stack created", "name": name }))
}

/// DELETE /api/compose/stacks/{name} — delete a compose project (runs down first)
async fn compose_delete_stack(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    if !dir.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    // Run docker compose down first
    let compose_file = dir.join("docker-compose.yml");
    match Command::new("docker")
        .args(["compose", "-f", &compose_file.to_string_lossy(), "down", "--remove-orphans"])
        .current_dir(&dir)
        .output()
    {
        Ok(out) if !out.status.success() => {
            warn!("compose down failed for '{}': {}", name, String::from_utf8_lossy(&out.stderr).trim());
        }
        Err(e) => {
            warn!("compose down failed for '{}': {}", name, e);
        }
        _ => {}
    }

    if let Err(e) = std::fs::remove_dir_all(&dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to delete: {}", e) }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Stack deleted" }))
}

/// GET /api/compose/stacks/{name}/compose — read docker-compose.yml
async fn compose_read_yaml(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let file = compose_project_dir(&name).join("docker-compose.yml");
    match std::fs::read_to_string(&file) {
        Ok(content) => HttpResponse::Ok().json(serde_json::json!({ "content": content })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/compose — write docker-compose.yml
async fn compose_write_yaml(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ComposeFileRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let file = compose_project_dir(&name).join("docker-compose.yml");
    match std::fs::write(&file, &body.content) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "message": "Saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/compose/stacks/{name}/env — read .env file
async fn compose_read_env(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let file = compose_project_dir(&name).join(".env");
    let content = std::fs::read_to_string(&file).unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({ "content": content }))
}

/// POST /api/compose/stacks/{name}/env — write .env file
async fn compose_write_env(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ComposeFileRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let file = compose_project_dir(&name).join(".env");
    match std::fs::write(&file, &body.content) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "message": "Saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/up — docker compose up -d
async fn compose_up(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let output = Command::new("docker")
        .args(["compose", "-f", &compose_file.to_string_lossy(), "up", "-d", "--remove-orphans"])
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if out.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Stack started", "output": format!("{}{}", stdout, stderr) }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({ "error": stderr, "output": stdout }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/down — docker compose down
async fn compose_down(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let output = Command::new("docker")
        .args(["compose", "-f", &compose_file.to_string_lossy(), "down", "--remove-orphans"])
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if out.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Stack stopped", "output": stderr }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({ "error": stderr }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/pull — docker compose pull
async fn compose_pull(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let output = Command::new("docker")
        .args(["compose", "-f", &compose_file.to_string_lossy(), "pull"])
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if out.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Images pulled", "output": stderr }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({ "error": stderr }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/restart — docker compose restart
async fn compose_restart(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let output = Command::new("docker")
        .args(["compose", "-f", &compose_file.to_string_lossy(), "restart"])
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if out.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Stack restarted", "output": stderr }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({ "error": stderr }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// GET /api/compose/stacks/{name}/logs — docker compose logs (last 200 lines)
async fn compose_logs(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let lines = query.get("lines").and_then(|l| l.parse::<u32>().ok()).unwrap_or(200).min(5000);
    let file_str = compose_file.to_string_lossy().into_owned();
    let lines_str = lines.to_string();
    let mut cmd_args = vec!["compose", "-f", &file_str, "logs", "--no-color", "--tail", &lines_str];

    // Validate service name to prevent argument injection
    let service_owned: String;
    if let Some(service) = query.get("service") {
        if !service.is_empty() {
            if !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid service name" }));
            }
            service_owned = service.clone();
            cmd_args.push(&service_owned);
        }
    }

    let output = Command::new("docker")
        .args(&cmd_args)
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            let logs = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({ "logs": format!("{}{}", logs, stderr) }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// POST /api/compose/stacks/{name}/validate — validate docker-compose.yml
async fn compose_validate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let name = path.into_inner();
    if let Err(e) = require_safe_compose_name(&name) { return e; }
    let dir = compose_project_dir(&name);
    let compose_file = dir.join("docker-compose.yml");
    if !compose_file.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Stack not found" }));
    }

    let file_str = compose_file.to_string_lossy().into_owned();
    let output = Command::new("docker")
        .args(["compose", "-f", &file_str, "config", "--quiet"])
        .current_dir(&dir)
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                HttpResponse::Ok().json(serde_json::json!({ "valid": true }))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                HttpResponse::Ok().json(serde_json::json!({ "valid": false, "error": stderr }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Secrets Manager
// ═══════════════════════════════════════════════════════════════════

fn load_secrets() -> Vec<SecretEntry> {
    let path = std::path::Path::new(SECRETS_FILE);
    if !path.exists() { return Vec::new(); }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_secrets(secrets: &[SecretEntry]) -> Result<(), String> {
    let dir = std::path::Path::new(SECRETS_FILE).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("{}", e))?;
    let json = serde_json::to_string_pretty(secrets).map_err(|e| format!("{}", e))?;

    // Atomic write: write to temp file with restricted permissions, then rename
    let tmp = format!("{}.tmp.{}.{}", SECRETS_FILE, std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
    std::fs::write(&tmp, &json).map_err(|e| format!("{}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, SECRETS_FILE).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}", e)
    })?;
    Ok(())
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// GET /api/secrets — list all secrets (values masked)
async fn secrets_list(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let secrets = load_secrets();
    let masked: Vec<serde_json::Value> = secrets.iter().map(|s| {
        let masked_val = if s.value.len() > 4 {
            format!("****{}", &s.value[s.value.len()-4..])
        } else {
            "****".to_string()
        };
        serde_json::json!({
            "key": s.key,
            "value_masked": masked_val,
            "description": s.description,
            "created": s.created,
            "updated": s.updated,
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({ "secrets": masked }))
}

/// GET /api/secrets/{key} — get a single secret (full value)
async fn secrets_get(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let key = path.into_inner();
    let secrets = load_secrets();
    match secrets.iter().find(|s| s.key == key) {
        Some(s) => HttpResponse::Ok().json(serde_json::json!({
            "key": s.key,
            "value": s.value,
            "description": s.description,
            "created": s.created,
            "updated": s.updated,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Secret not found" })),
    }
}

/// POST /api/secrets — create or update a secret
async fn secrets_save(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SecretRequest>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let key = body.key.trim().to_string();
    if key.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Key is required" }));
    }

    let mut secrets = load_secrets();
    let now = now_iso();

    if let Some(existing) = secrets.iter_mut().find(|s| s.key == key) {
        if let Some(ref v) = body.value { existing.value = v.clone(); }
        if let Some(ref d) = body.description { existing.description = d.clone(); }
        existing.updated = now;
    } else {
        secrets.push(SecretEntry {
            key: key.clone(),
            value: body.value.clone().unwrap_or_default(),
            description: body.description.clone().unwrap_or_default(),
            created: now.clone(),
            updated: now,
        });
    }

    match save_secrets(&secrets) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "message": "Secret saved", "key": key })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/secrets/{key} — delete a secret
async fn secrets_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }

    let key = path.into_inner();
    let mut secrets = load_secrets();
    let len = secrets.len();
    secrets.retain(|s| s.key != key);
    if secrets.len() == len {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Secret not found" }));
    }

    match save_secrets(&secrets) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "message": "Secret deleted" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── WolfNote Integration ───

/// POST /api/wolfnote/login — login to WolfNote and store the token
#[derive(Deserialize)]
pub struct WolfNoteLoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub company: String,
    #[serde(default = "wolfnote_default_url")]
    pub url: String,
}
fn wolfnote_default_url() -> String { "https://app.wolfnote.org".to_string() }

pub async fn wolfnote_login(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<WolfNoteLoginRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let base_url = if body.url.is_empty() { "https://app.wolfnote.org" } else { &body.url };

    match crate::wolfnote::WolfNoteClient::login(base_url, &body.username, &body.password, &body.company).await {
        Ok(login_resp) => {
            // Save token and config
            let mut config = crate::wolfnote::WolfNoteConfig::load();
            config.url = base_url.to_string();
            config.token = login_resp.token;
            config.username = login_resp.user.username.clone();
            config.company = body.company.clone();
            if let Err(e) = config.save() {
                return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
            }
            HttpResponse::Ok().json(serde_json::json!({
                "connected": true,
                "username": login_resp.user.username,
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "connected": false,
            "error": e,
        })),
    }
}

/// POST /api/wolfnote/disconnect — clear the stored token
pub async fn wolfnote_disconnect(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::wolfnote::WolfNoteConfig::load();
    config.token.clear();
    config.username.clear();
    if let Err(e) = config.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    HttpResponse::Ok().json(serde_json::json!({ "disconnected": true }))
}

/// GET /api/wolfnote/config — get current WolfNote config (token masked)
pub async fn wolfnote_config_get(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfnote::WolfNoteConfig::load();
    HttpResponse::Ok().json(serde_json::json!({
        "url": config.url,
        "connected": config.is_connected(),
        "username": config.username,
        "company": config.company,
        "features": config.features,
    }))
}

/// POST /api/wolfnote/config — save feature toggles
pub async fn wolfnote_config_save(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let mut config = crate::wolfnote::WolfNoteConfig::load();

    if let Some(features) = body.get("features") {
        if let Ok(f) = serde_json::from_value::<crate::wolfnote::WolfNoteFeatures>(features.clone()) {
            config.features = f;
        }
    }
    if let Some(url) = body.get("url").and_then(|v| v.as_str()) {
        if !url.is_empty() {
            config.url = url.to_string();
        }
    }

    match config.save() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "saved": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfnote/folders — list folders from WolfNote
pub async fn wolfnote_folders_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfnote::WolfNoteConfig::load();
    if !config.is_connected() {
        return HttpResponse::Ok().json(serde_json::json!({ "error": "Not connected to WolfNote" }));
    }
    let client = crate::wolfnote::WolfNoteClient::new(&config.url, &config.token);
    match client.list_folders().await {
        Ok(folders) => HttpResponse::Ok().json(folders),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/wolfnote/folders — create a folder in WolfNote
#[derive(Deserialize)]
pub struct WolfNoteCreateFolderRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

pub async fn wolfnote_folders_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<WolfNoteCreateFolderRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfnote::WolfNoteConfig::load();
    if !config.is_connected() {
        return HttpResponse::Ok().json(serde_json::json!({ "error": "Not connected to WolfNote" }));
    }
    let client = crate::wolfnote::WolfNoteClient::new(&config.url, &config.token);
    match client.create_folder(&body.name, body.parent_id.as_deref(), body.color.as_deref()).await {
        Ok(folder) => HttpResponse::Ok().json(folder),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/wolfnote/notes — list notes from WolfNote
pub async fn wolfnote_notes_list(
    req: HttpRequest, state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfnote::WolfNoteConfig::load();
    if !config.is_connected() {
        return HttpResponse::Ok().json(serde_json::json!({ "error": "Not connected to WolfNote" }));
    }
    let client = crate::wolfnote::WolfNoteClient::new(&config.url, &config.token);
    match client.list_notes().await {
        Ok(notes) => HttpResponse::Ok().json(notes),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/wolfnote/notes — create a note in WolfNote
#[derive(Deserialize)]
pub struct WolfNoteCreateNoteRequest {
    pub title: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub folder_id: Option<String>,
}

pub async fn wolfnote_notes_create(
    req: HttpRequest, state: web::Data<AppState>,
    body: web::Json<WolfNoteCreateNoteRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let config = crate::wolfnote::WolfNoteConfig::load();
    if !config.is_connected() {
        return HttpResponse::Ok().json(serde_json::json!({ "error": "Not connected to WolfNote" }));
    }
    let client = crate::wolfnote::WolfNoteClient::new(&config.url, &config.token);
    match client.create_note(&body.title, &body.content, body.folder_id.as_deref()).await {
        Ok(note) => HttpResponse::Ok().json(note),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({ "error": e })),
    }
}

// ─── Plugin System ───

/// GET /api/plugins — list all plugins
pub async fn plugins_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::plugins::list())
}

/// POST /api/plugins/reload — rescan plugins directory
pub async fn plugins_reload(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    crate::plugins::reload();
    HttpResponse::Ok().json(serde_json::json!({ "message": "Plugins reloaded" }))
}

const PLUGIN_INDEX_URL: &str = "https://raw.githubusercontent.com/wolfsoftwaresystemsltd/WolfStack/master/pkg/index.json";

/// GET /api/plugins/store — fetch available plugins from the plugin store (Enterprise only)
pub async fn plugins_store(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Plugin store requires an Enterprise license",
            "feature": "plugins"
        }));
    }
    // Fetch the index from the remote store. Cache-bust per-request with
    // `?t=<epoch-ms>` and send `Cache-Control: no-cache` so neither the
    // GitHub raw CDN (max-age=300) nor any upstream proxy hands back a
    // stale index after someone publishes a new plugin. Without this,
    // users could wait up to 5 minutes for a new plugin to appear in
    // the store, and stale-cache debugging ate a chunk of v17.4.14
    // support time.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();
    let bust = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis()).unwrap_or(0);
    let url = format!("{}?t={}", PLUGIN_INDEX_URL, bust);
    match client.get(&url)
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_else(|_| "[]".to_string());
            // Parse to validate, then return. Tag each plugin with installed status.
            let mut plugins: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();
            let installed = crate::plugins::list();
            for p in &mut plugins {
                let id = p["id"].as_str().unwrap_or("");
                let is_installed = installed.iter().any(|i| i.manifest.id == id);
                p["installed"] = serde_json::json!(is_installed);
            }
            // Prevent browser from caching this response — otherwise the user
            // has to hard-refresh to see a newly-published plugin, which is
            // the "it's still not showing" support pattern.
            HttpResponse::Ok()
                .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate"))
                .insert_header(("Pragma", "no-cache"))
                .json(plugins)
        }
        Ok(resp) => HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("Plugin store returned HTTP {}", resp.status())
        })),
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("Failed to reach plugin store: {}", e)
        })),
    }
}

#[derive(Deserialize)]
pub struct PluginInstallRequest {
    pub url: String,
}

/// POST /api/plugins/install — install a plugin from URL (Enterprise only)
pub async fn plugins_install(req: HttpRequest, state: web::Data<AppState>, body: web::Json<PluginInstallRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Plugins require an Enterprise license",
            "feature": "plugins"
        }));
    }
    match web::block(move || crate::plugins::install_from_url(&body.url)).await {
        Ok(Ok(msg)) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{}", e) })),
    }
}

/// DELETE /api/plugins/{id} — uninstall a plugin
pub async fn plugins_uninstall(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::plugins::uninstall(&id) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
pub struct PluginToggleRequest {
    pub enabled: bool,
}

/// POST /api/plugins/{id}/toggle — enable/disable a plugin
pub async fn plugins_toggle(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<PluginToggleRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match crate::plugins::set_enabled(&id, body.enabled) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/plugins/{id}/file/{path} — serve plugin web assets (JS/CSS) (Enterprise only)
pub async fn plugins_file(_req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    // No auth required for static assets (they're loaded by the browser)
    // But plugins are an Enterprise feature — don't serve assets without a license
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().finish();
    }
    let (plugin_id, file_path) = path.into_inner();

    match crate::plugins::read_file(&plugin_id, &file_path) {
        Some(data) => {
            let content_type = if file_path.ends_with(".js") {
                "application/javascript"
            } else if file_path.ends_with(".css") {
                "text/css"
            } else if file_path.ends_with(".json") {
                "application/json"
            } else if file_path.ends_with(".svg") {
                "image/svg+xml"
            } else if file_path.ends_with(".png") {
                "image/png"
            } else {
                "application/octet-stream"
            };
            HttpResponse::Ok()
                .content_type(content_type)
                .body(data)
        }
        None => HttpResponse::NotFound().finish(),
    }
}

/// Proxy requests to plugin backends: /api/plugins/{id}/api/{path}
pub async fn plugins_proxy(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Bytes) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (plugin_id, sub_path) = path.into_inner();

    let method = req.method().as_str();
    let headers: Vec<(String, String)> = req.headers().iter()
        .filter(|(k, _)| !["host", "connection", "content-length"].contains(&k.as_str()))
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_data = if body.is_empty() { None } else { Some(body.as_ref()) };

    match crate::plugins::proxy_request(&plugin_id, method, &sub_path, body_data, &headers).await {
        Ok((status, content_type, data)) => {
            HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK))
                .content_type(content_type)
                .body(data)
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({ "error": e })),
    }
}

// ─── Plugin Data Storage ───
// Generic config read/write + file upload for plugins that don't have a backend binary.
// Data stored in /etc/wolfstack/plugins/{id}/data/

/// GET /api/plugins/{id}/data/config — read plugin config JSON
pub async fn plugin_data_config_get(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let config_path = format!("/etc/wolfstack/plugins/{}/data/config.json", id);
    match std::fs::read_to_string(&config_path) {
        Ok(data) => HttpResponse::Ok().content_type("application/json").body(data),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({})),
    }
}

/// POST /api/plugins/{id}/data/config — write plugin config JSON
pub async fn plugin_data_config_set(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Bytes) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    let data_dir = format!("/etc/wolfstack/plugins/{}/data", id);
    let _ = std::fs::create_dir_all(&data_dir);
    let config_path = format!("{}/config.json", data_dir);
    match std::fs::write(&config_path, &body) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

/// POST /api/plugins/{id}/data/upload/{filename} — upload a file to plugin data dir
pub async fn plugin_data_upload(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Bytes) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, filename) = path.into_inner();
    // Security: reject path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid filename"}));
    }
    let data_dir = format!("/etc/wolfstack/plugins/{}/data", id);
    let _ = std::fs::create_dir_all(&data_dir);
    let file_path = format!("{}/{}", data_dir, filename);
    match std::fs::write(&file_path, &body) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "url": format!("/api/plugins/{}/data/file/{}", id, filename),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

/// GET /api/plugins/{id}/data/file/{filename} — serve a file from plugin data dir
pub async fn plugin_data_file(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (id, filename) = path.into_inner();
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return HttpResponse::BadRequest().finish();
    }
    let file_path = format!("/etc/wolfstack/plugins/{}/data/{}", id, filename);
    match std::fs::read(&file_path) {
        Ok(data) => {
            let ct = if filename.ends_with(".png") { "image/png" }
                else if filename.ends_with(".jpg") || filename.ends_with(".jpeg") { "image/jpeg" }
                else if filename.ends_with(".svg") { "image/svg+xml" }
                else if filename.ends_with(".ico") { "image/x-icon" }
                else if filename.ends_with(".webp") { "image/webp" }
                else { "application/octet-stream" };
            HttpResponse::Ok().content_type(ct).body(data)
        }
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

// ─── Access Token Management ───

/// GET /api/platform/status
pub async fn platform_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::compat::runtime_status())
}

#[derive(Deserialize)]
pub struct ApplyManifestRequest {
    pub key: String,
}

/// POST /api/platform/apply
pub async fn platform_apply(req: HttpRequest, state: web::Data<AppState>, body: web::Json<ApplyManifestRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    let key = body.key.trim();
    if key.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Key data is required" }));
    }

    // Validate it's valid JSON with the expected structure
    if serde_json::from_str::<serde_json::Value>(key).is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid key format" }));
    }

    // Write to the manifest file
    let path = crate::compat::dm_path();
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    if let Err(e) = std::fs::write(&path, key) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save: {}", e)
        }));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    // Schedule a restart
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = std::process::Command::new("systemctl").args(["restart", "wolfstack"]).spawn();
    });

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Key applied. WolfStack will restart in a moment."
    }))
}

/// GET /api/tokens
pub async fn list_tokens(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": crate::compat::rt_msg(1),
            "feature": "api_keys",
        }));
    }
    HttpResponse::Ok().json(crate::compat::list_keys())
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

/// POST /api/tokens
pub async fn create_token(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CreateTokenRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    // Dual verification — independent check paths
    if !crate::compat::platform_ready() || !crate::compat::probe_runtime() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": crate::compat::rt_msg(1),
            "feature": "api_keys",
        }));
    }

    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "API key name is required"
        }));
    }

    let scopes = if body.scopes.is_empty() {
        vec!["read".to_string()]
    } else {
        body.scopes.clone()
    };

    match crate::compat::create_key(body.name.trim(), scopes, body.expires.clone()) {
        Ok((key, raw_key)) => HttpResponse::Ok().json(serde_json::json!({
            "key": key,
            "raw_key": raw_key,
            "message": "Save this key now — it will not be shown again",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// DELETE /api/tokens/{id}
pub async fn revoke_token(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": crate::compat::rt_msg(1),
        }));
    }

    let id = path.into_inner();
    match crate::compat::delete_key(&id) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "message": "API key revoked" })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/tokens/scopes
pub async fn list_token_scopes(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let scopes: Vec<serde_json::Value> = crate::compat::SCOPES.iter()
        .map(|(id, desc)| serde_json::json!({ "id": id, "description": desc }))
        .collect();
    HttpResponse::Ok().json(scopes)
}

/// GET /api/tokens/events
pub async fn token_events(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    if !crate::compat::platform_ready() {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": crate::compat::rt_msg(1),
        }));
    }
    let entries = crate::compat::read_audit_log(200);
    HttpResponse::Ok().json(entries)
}

// ═══════════════════════════════════════════════════════════════════════════
// ─── OIDC Authentication Endpoints ───
// ═══════════════════════════════════════════════════════════════════════════

/// GET /api/auth/oidc/providers — list available OIDC providers (no auth)
pub async fn oidc_providers() -> HttpResponse {
    if !crate::compat::platform_ready() {
        return HttpResponse::Ok().json(serde_json::json!([]));
    }
    let config = crate::auth::oidc::OidcConfig::load();
    if !config.enabled {
        return HttpResponse::Ok().json(serde_json::json!([]));
    }
    let providers: Vec<serde_json::Value> = config.providers.iter()
        .filter(|p| p.enabled)
        .map(|p| serde_json::json!({
            "id": p.id,
            "name": p.name,
            "button_label": format!("Sign in with {}", p.name),
        }))
        .collect();
    HttpResponse::Ok().json(providers)
}

/// GET /api/auth/oidc/login/{provider_id} — initiate OIDC login (no auth, returns 302)
pub async fn oidc_login(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let provider_id = path.into_inner();
    let config = crate::auth::oidc::OidcConfig::load();
    if !config.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "OIDC is not enabled" }));
    }
    let provider = match config.providers.iter().find(|p| p.id == provider_id && p.enabled) {
        Some(p) => p.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({ "error": "Provider not found" })),
    };

    let conn = req.connection_info();
    let redirect_uri_base = format!("{}://{}", conn.scheme(), conn.host());

    match crate::auth::oidc::build_auth_url(&provider, &redirect_uri_base).await {
        Ok((auth_url, pending)) => {
            let csrf_state = pending.csrf_state.clone();
            state.oidc_pending_flows.write().unwrap().insert(csrf_state, pending);
            HttpResponse::Found().append_header(("Location", auth_url)).finish()
        }
        Err(e) => {
            error!("OIDC build_auth_url failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }))
        }
    }
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: String,
    pub state: String,
}

/// GET /api/auth/oidc/callback — OIDC callback (no auth, returns 302 to dashboard)
pub async fn oidc_callback(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<OidcCallbackQuery>,
) -> HttpResponse {
    // Look up and remove the pending flow (single use)
    let pending = {
        let mut flows = state.oidc_pending_flows.write().unwrap();
        flows.remove(&query.state)
    };
    let pending = match pending {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid or expired OIDC state token"
        })),
    };

    // Find the provider
    let config = crate::auth::oidc::OidcConfig::load();
    let provider = match config.providers.iter().find(|p| p.id == pending.provider_id) {
        Some(p) => p.clone(),
        None => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "OIDC provider no longer configured"
        })),
    };

    let conn = req.connection_info();
    let redirect_uri_base = format!("{}://{}", conn.scheme(), conn.host());

    // Exchange the authorization code for claims
    let claims = match crate::auth::oidc::exchange_code(
        &provider, &query.code, &pending, &redirect_uri_base, &state.cluster_secret,
    ).await {
        Ok(c) => c,
        Err(e) => {
            error!("OIDC code exchange failed: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
    };

    // Extract username from claims (preferred_username → email → sub)
    let username = claims.get("preferred_username")
        .or_else(|| claims.get("email"))
        .or_else(|| claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("oidc-user")
        .to_string();

    // Map IdP claims to a WolfStack role using the provider's role_claim + role_mappings
    let role = crate::auth::oidc::map_claims_to_role(&claims, &provider);
    tracing::info!("OIDC login: user='{}', provider='{}', role='{}'", username, provider.id, role);

    // Create session and set cookie
    let token = state.sessions.create_session(&username);
    let mut cookie = Cookie::build("wolfstack_session", &token)
        .path("/")
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::hours(8))
        .finish();
    if state.tls_enabled {
        cookie.set_secure(true);
    }

    HttpResponse::Found()
        .cookie(cookie)
        .append_header(("Location", "/index.html"))
        .finish()
}

// ═══════════════════════════════════════════════════════════════════════════
// ─── Image Watcher Endpoints ───
// ═══════════════════════════════════════════════════════════════════════════

/// GET /api/image-watcher/config
pub async fn image_watcher_config_get(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    HttpResponse::Ok().json(crate::containers::image_watcher::ImageWatcherConfig::load())
}

/// PUT /api/image-watcher/config
pub async fn image_watcher_config_save(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<crate::containers::image_watcher::ImageWatcherConfig>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match body.into_inner().save() {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "message": "Image watcher config saved" })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/image-watcher/status
pub async fn image_watcher_status(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let cache = state.image_watcher_cache.read().unwrap();
    let results: Vec<&crate::containers::image_watcher::ImageCheckResult> = cache.values().collect();
    HttpResponse::Ok().json(results)
}

/// POST /api/image-watcher/check/{container}
pub async fn image_watcher_check(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let container = path.into_inner();
    match crate::containers::image_watcher::check_container_update(&container).await {
        Ok(result) => {
            state.image_watcher_cache.write().unwrap()
                .insert(result.container_name.clone(), result.clone());
            HttpResponse::Ok().json(result)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ─── Integration Framework Endpoints ───
// ═══════════════════════════════════════════════════════════════════════════

/// GET /api/integrations/connectors — list available connector types
pub async fn integrations_connectors(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let infos: Vec<crate::integrations::ConnectorInfo> = state.integrations.connectors
        .values().map(|c| c.info()).collect();
    HttpResponse::Ok().json(infos)
}

/// GET /api/integrations — list configured integration instances
pub async fn integrations_list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let instances = state.integrations.list_instances();
    let result: Vec<serde_json::Value> = instances.iter().map(|inst| {
        let health = state.integrations.get_health(&inst.id);
        serde_json::json!({
            "instance": inst,
            "health": health,
        })
    }).collect();
    HttpResponse::Ok().json(result)
}

/// POST /api/integrations — create a new integration instance
pub async fn integrations_create(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<crate::integrations::IntegrationInstance>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    match state.integrations.create_instance(body.into_inner()) {
        Ok(inst) => HttpResponse::Ok().json(inst),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// GET /api/integrations/{id} — get a single integration instance
pub async fn integrations_get(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match state.integrations.get_instance(&id) {
        Some(inst) => {
            let health = state.integrations.get_health(&id);
            HttpResponse::Ok().json(serde_json::json!({
                "instance": inst,
                "health": health,
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "Integration not found" })),
    }
}

/// DELETE /api/integrations/{id} — delete an integration instance
pub async fn integrations_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let id = path.into_inner();
    match state.integrations.delete_instance(&id) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "message": "Integration deleted" })),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({ "error": e })),
    }
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .configure(crate::vms::api::config)
        .configure(crate::tui::configure)
        .configure(crate::networking::router::api::configure)
        // Auth (no auth required)
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))
        .route("/api/auth/check", web::get().to(auth_check))
        .route("/api/settings/login-disabled", web::get().to(login_disabled_status))
        .route("/api/settings/login-disabled", web::post().to(set_login_disabled))
        .route("/api/auth/smtp-configured", web::get().to(smtp_configured))
        .route("/api/auth/forgot-password", web::post().to(forgot_password))
        .route("/api/auth/reset-password", web::post().to(reset_password))
        // OIDC Authentication (no auth required)
        .route("/api/auth/oidc/providers", web::get().to(oidc_providers))
        .route("/api/auth/oidc/login/{provider_id}", web::get().to(oidc_login))
        .route("/api/auth/oidc/callback", web::get().to(oidc_callback))
        // User management (auth required)
        .route("/api/auth/config", web::get().to(get_auth_config))
        .route("/api/auth/config", web::post().to(save_auth_config))
        .route("/api/auth/users", web::get().to(list_users))
        .route("/api/auth/users", web::post().to(create_user))
        .route("/api/auth/users/{username}", web::delete().to(delete_user))
        .route("/api/auth/users/{username}/password", web::post().to(change_user_password))
        .route("/api/auth/users/{username}/2fa/setup", web::post().to(setup_2fa))
        .route("/api/auth/users/{username}/2fa/confirm", web::post().to(confirm_2fa))
        .route("/api/auth/users/{username}/2fa/disable", web::post().to(disable_2fa))
        .route("/api/auth/users/{username}/clusters", web::put().to(update_user_clusters))
        // Dashboard
        .route("/api/metrics", web::get().to(get_metrics))
        .route("/api/metrics/history", web::get().to(get_metrics_history))
        .route("/api/metrics/processes", web::get().to(get_top_processes))
        .route("/api/metrics/processes/{pid}/kill", web::post().to(kill_process))
        .route("/api/systemd", web::get().to(list_services))
        .route("/api/systemd/{name}/action", web::post().to(systemd_service_action))
        .route("/api/auth/join-token", web::get().to(get_join_token))
        // Cluster
        .route("/api/cluster/verify-token", web::get().to(verify_join_token))
        .route("/api/cluster/secret-status", web::get().to(cluster_secret_status))
        .route("/api/cluster/secret/generate", web::post().to(cluster_secret_generate))
        .route("/api/cluster/secret/repush", web::post().to(cluster_secret_repush))
        .route("/api/cluster/secret/receive", web::post().to(cluster_secret_receive))
        .route("/api/cluster/wolfnet-sync", web::post().to(wolfnet_sync_cluster))
        .route("/api/cluster/diagnose", web::post().to(cluster_diagnose))
        .route("/api/nodes", web::get().to(get_nodes))
        .route("/api/nodes", web::post().to(add_node))
        .route("/api/nodes/{id}", web::get().to(get_node))
        .route("/api/nodes/{id}", web::delete().to(remove_node))
        .route("/api/nodes/{id}/settings", web::patch().to(update_node_settings))
        // Proxmox integration
        .route("/api/nodes/{id}/pve/resources", web::get().to(get_pve_resources))
        .route("/api/nodes/{id}/pve/test", web::post().to(pve_test_connection))
        .route("/api/nodes/{id}/pve/{vmid}/{action}", web::post().to(pve_guest_action))
        // Components
        .route("/api/components", web::get().to(get_components))
        .route("/api/components/{name}/detail", web::get().to(get_component_detail))
        .route("/api/components/{name}/config", web::put().to(save_component_config))
        .route("/api/components/{name}/install", web::post().to(install_component))
        .route("/api/install/{tech}", web::post().to(install_runtime))
        // Services
        .route("/api/services/{name}/action", web::post().to(service_action))
        // Cron Jobs
        .route("/api/cron", web::get().to(cron_list))
        .route("/api/cron", web::post().to(cron_save))
        .route("/api/cron/{index}", web::delete().to(cron_delete))
        // Container Cron Jobs
        .route("/api/containers/{runtime}/{id}/cron", web::get().to(container_cron_list))
        .route("/api/containers/{runtime}/{id}/cron", web::post().to(container_cron_save))
        .route("/api/containers/{runtime}/{id}/cron/{index}", web::delete().to(container_cron_delete))
        // Container Updates
        .route("/api/containers/updates/summary", web::post().to(container_updates_summary))
        .route("/api/containers/{runtime}/{id}/updates/check", web::post().to(container_updates_check))
        .route("/api/containers/{runtime}/{id}/updates/apply", web::post().to(container_updates_apply))
        .route("/api/containers/{runtime}/{id}/exec", web::post().to(container_exec))
        // Image Watcher (auth required)
        .route("/api/image-watcher/config", web::get().to(image_watcher_config_get))
        .route("/api/image-watcher/config", web::put().to(image_watcher_config_save))
        .route("/api/image-watcher/status", web::get().to(image_watcher_status))
        .route("/api/image-watcher/check/{container}", web::post().to(image_watcher_check))
        // Certificates
        .route("/api/certificates", web::post().to(request_certificate))
        .route("/api/certificates/list", web::get().to(list_certificates))
        // Containers
        .route("/api/containers/status", web::get().to(container_runtime_status))
        .route("/api/containers/install", web::post().to(install_container_runtime))
        .route("/api/containers/install-component", web::post().to(install_component_in_container))
        .route("/api/containers/running", web::get().to(list_running_containers))
        .route("/api/containers/component-version", web::get().to(container_component_version))
        // Docker
        .route("/api/containers/docker", web::get().to(docker_list))
        .route("/api/containers/docker/search", web::get().to(docker_search))
        .route("/api/containers/docker/pull", web::post().to(docker_pull))
        .route("/api/containers/docker/create", web::post().to(docker_create))
        .route("/api/containers/docker/stats", web::get().to(docker_stats))
        .route("/api/containers/docker/images", web::get().to(docker_images))
        .route("/api/containers/docker/images/{id}", web::delete().to(docker_remove_image))
        .route("/api/containers/docker/{id}/logs", web::get().to(docker_logs))
        .route("/api/containers/docker/{id}/action", web::post().to(docker_action))
        .route("/api/containers/docker/{id}/clone", web::post().to(docker_clone))
        .route("/api/containers/docker/{id}/migrate", web::post().to(docker_migrate))
        .route("/api/containers/docker/{id}/volumes", web::get().to(docker_volumes))
        .route("/api/containers/docker/import", web::post().to(docker_import))
        .route("/api/containers/docker/{id}/config", web::post().to(docker_update_config))
        .route("/api/containers/docker/{id}/env", web::post().to(docker_update_env))
        .route("/api/containers/docker/{id}/inspect", web::get().to(docker_inspect))
        // LXC
        .route("/api/containers/lxc", web::get().to(lxc_list))
        .route("/api/containers/lxc/templates", web::get().to(lxc_templates))
        .route("/api/containers/lxc/create", web::post().to(lxc_create))
        .route("/api/containers/lxc/import", web::post().to(lxc_import_endpoint))
        .route("/api/containers/lxc/import-external", web::post().to(lxc_import_external))
        .route("/api/containers/transfer-token", web::post().to(generate_transfer_token))
        .route("/api/storage/list", web::get().to(storage_list))
        .route("/api/storage/filesystems", web::get().to(storage_filesystems))
        .route("/api/storage/remote-list", web::get().to(remote_storage_list))
        .route("/api/containers/lxc/stats", web::get().to(lxc_stats))
        .route("/api/containers/lxc/{name}/logs", web::get().to(lxc_logs))
        .route("/api/containers/lxc/{name}/config", web::get().to(lxc_config))
        .route("/api/containers/lxc/{name}/config", web::put().to(lxc_save_config))
        .route("/api/containers/lxc/{name}/action", web::post().to(lxc_action))
        .route("/api/containers/lxc/{name}/clone", web::post().to(lxc_clone))
        .route("/api/containers/lxc/{name}/mounts", web::get().to(lxc_mounts))
        .route("/api/containers/lxc/{name}/mounts", web::post().to(lxc_add_mount))
        .route("/api/containers/lxc/{name}/mounts", web::delete().to(lxc_remove_mount))
        .route("/api/containers/lxc/{name}/autostart", web::post().to(lxc_set_autostart))
        .route("/api/containers/lxc/{name}/network-link", web::post().to(lxc_set_network_link))
        .route("/api/containers/lxc/{name}/parsed-config", web::get().to(lxc_parsed_config))
        .route("/api/containers/lxc/{name}/settings", web::post().to(lxc_update_settings))
        .route("/api/containers/lxc/{name}/export", web::post().to(lxc_export_endpoint))
        .route("/api/containers/lxc/{name}/migrate", web::post().to(lxc_migrate))
        .route("/api/containers/lxc/{name}/disk", web::get().to(lxc_disk_info))
        .route("/api/containers/lxc/{name}/disk/resize", web::post().to(lxc_disk_resize))
        .route("/api/containers/lxc/{name}/disk/migrate", web::post().to(lxc_disk_migrate))
        .route("/api/containers/lxc/{name}/migrate-external", web::post().to(lxc_migrate_external))
        .route("/api/migration/{id}/status", web::get().to(migration_status))
        // Network Conflicts
        .route("/api/network/conflicts", web::get().to(network_conflicts))
        // WolfNet
        .route("/api/wolfnet/status", web::get().to(wolfnet_network_status))
        .route("/api/wolfnet/next-ip", web::get().to(wolfnet_next_ip))
        // AI Agent
        .route("/api/ai/config", web::get().to(ai_get_config))
        .route("/api/ai/config", web::post().to(ai_save_config))
        .route("/api/ai/chat", web::post().to(ai_chat))
        .route("/api/ai/status", web::get().to(ai_status))
        .route("/api/ai/alerts", web::get().to(ai_alerts))
        .route("/api/ai/models", web::get().to(ai_models))
        .route("/api/ai/exec", web::post().to(ai_exec))
        .route("/api/ai/action", web::post().to(ai_action))
        .route("/api/ai/action/command", web::get().to(ai_action_command))
        .route("/api/ai/action/exec", web::post().to(ai_action_exec))
        .route("/api/ai/config/sync", web::post().to(ai_sync_config))
        .route("/api/ai/test-email", web::post().to(ai_test_email))
        // System dependency audit
        .route("/api/system-check", web::get().to(system_check_run))
        .route("/api/system-check/ask-ai", web::post().to(system_check_ask_ai))
        // Ceph Cluster
        .route("/api/ceph/status", web::get().to(ceph_status))
        .route("/api/ceph/install-status", web::get().to(ceph_install_status))
        .route("/api/ceph/install", web::post().to(ceph_install))
        .route("/api/ceph/devices", web::get().to(ceph_devices))
        .route("/api/ceph/bootstrap", web::post().to(ceph_bootstrap))
        .route("/api/ceph/pools", web::post().to(ceph_create_pool))
        .route("/api/ceph/pools/{name}", web::delete().to(ceph_delete_pool))
        .route("/api/ceph/pools/{name}", web::put().to(ceph_set_pool_option))
        .route("/api/ceph/osds", web::post().to(ceph_add_osd))
        .route("/api/ceph/osds/{id}", web::delete().to(ceph_remove_osd))
        .route("/api/ceph/osds/{id}/action", web::post().to(ceph_osd_action))
        .route("/api/ceph/fs", web::post().to(ceph_create_fs))
        .route("/api/ceph/fs/{name}", web::delete().to(ceph_delete_fs))
        .route("/api/ceph/rbd/{pool}", web::get().to(ceph_list_rbd))
        .route("/api/ceph/rbd", web::post().to(ceph_create_rbd))
        .route("/api/ceph/rbd/{pool}/{image}", web::delete().to(ceph_delete_rbd))
        // Storage Manager
        .route("/api/storage/mounts", web::get().to(storage_list_mounts))
        .route("/api/storage/mounts", web::post().to(storage_create_mount))
        .route("/api/storage/available", web::get().to(storage_available_mounts))
        .route("/api/storage/import-rclone", web::post().to(storage_import_rclone))
        .route("/api/storage/mounts/{id}", web::put().to(storage_update_mount))
        .route("/api/storage/mounts/{id}", web::delete().to(storage_remove_mount))
        .route("/api/storage/mounts/{id}/duplicate", web::post().to(storage_duplicate_mount))
        .route("/api/storage/mounts/{id}/mount", web::post().to(storage_do_mount))
        .route("/api/storage/mounts/{id}/unmount", web::post().to(storage_do_unmount))
        .route("/api/storage/mounts/{id}/sync", web::post().to(storage_sync_mount))
        .route("/api/storage/mounts/{id}/sync-s3", web::post().to(storage_sync_s3))
        .route("/api/storage/providers", web::get().to(storage_list_providers))
        .route("/api/storage/providers/{name}/install", web::post().to(storage_install_provider))
        .route("/api/storage/providers/{name}/action", web::post().to(storage_provider_action))
        .route("/api/storage/providers/{name}/config", web::get().to(storage_provider_config))
        .route("/api/storage/providers/{name}/config", web::post().to(storage_provider_config_save))
        .route("/api/system/logs", web::get().to(system_logs))
        // Cluster-internal file operations — require cluster-secret auth.
        // Used by WolfAgent tools to read/write/delete files across the
        // cluster; never reachable via a human session token.
        .route("/api/cluster/file/read", web::post().to(cluster_file_read))
        .route("/api/cluster/file/write", web::post().to(cluster_file_write))
        .route("/api/cluster/file/delete", web::post().to(cluster_file_delete))
        // Disk partition info
        .route("/api/storage/disk-info", web::get().to(storage_disk_info))
        // Disk Partitioning & Formatting
        .route("/api/storage/disk/partition-table", web::post().to(disk_create_partition_table))
        .route("/api/storage/disk/partition", web::post().to(disk_create_partition))
        .route("/api/storage/disk/partition/delete", web::post().to(disk_delete_partition))
        .route("/api/storage/disk/format", web::post().to(disk_format_partition))
        .route("/api/storage/disk/resize", web::post().to(disk_resize_partition))
        .route("/api/storage/disk/filesystems", web::get().to(disk_supported_filesystems))
        // ZFS
        .route("/api/storage/zfs/status", web::get().to(zfs_status))
        .route("/api/storage/zfs/pools", web::get().to(zfs_pools))
        .route("/api/storage/zfs/datasets", web::get().to(zfs_datasets))
        .route("/api/storage/zfs/snapshots", web::get().to(zfs_snapshots))
        .route("/api/storage/zfs/snapshot", web::post().to(zfs_create_snapshot))
        .route("/api/storage/zfs/snapshot", web::delete().to(zfs_delete_snapshot))
        .route("/api/storage/zfs/pool/scrub", web::post().to(zfs_pool_scrub))
        .route("/api/storage/zfs/pool/status", web::get().to(zfs_pool_status))
        .route("/api/storage/zfs/pool/iostat", web::get().to(zfs_pool_iostat))
        // File Manager
        .route("/api/files/browse", web::get().to(files_browse))
        .route("/api/files/mkdir", web::post().to(files_mkdir))
        .route("/api/files/delete", web::post().to(files_delete))
        .route("/api/files/rename", web::post().to(files_rename))
        .route("/api/files/upload", web::post().to(files_upload))
        .route("/api/files/download", web::get().to(files_download))
        .route("/api/files/search", web::get().to(files_search))
        .route("/api/files/chmod", web::post().to(files_chmod))
        .route("/api/files/read", web::get().to(files_read))
        .route("/api/files/write", web::post().to(files_write))
        // Docker File Manager
        .route("/api/files/docker/browse", web::get().to(files_docker_browse))
        .route("/api/files/docker/mkdir", web::post().to(files_docker_mkdir))
        .route("/api/files/docker/delete", web::post().to(files_docker_delete))
        .route("/api/files/docker/rename", web::post().to(files_docker_rename))
        .route("/api/files/docker/download", web::get().to(files_docker_download))
        .route("/api/files/docker/upload", web::post().to(files_docker_upload))
        .route("/api/files/docker/read", web::get().to(files_docker_read))
        .route("/api/files/docker/write", web::post().to(files_docker_write))
        // LXC File Manager
        .route("/api/files/lxc/browse", web::get().to(files_lxc_browse))
        .route("/api/files/lxc/mkdir", web::post().to(files_lxc_mkdir))
        .route("/api/files/lxc/delete", web::post().to(files_lxc_delete))
        .route("/api/files/lxc/rename", web::post().to(files_lxc_rename))
        .route("/api/files/lxc/download", web::get().to(files_lxc_download))
        .route("/api/files/lxc/upload", web::post().to(files_lxc_upload))
        .route("/api/files/lxc/read", web::get().to(files_lxc_read))
        .route("/api/files/lxc/write", web::post().to(files_lxc_write))
        // Networking
        .route("/api/networking/interfaces", web::get().to(net_list_interfaces))
        .route("/api/networking/dns", web::get().to(net_get_dns))
        .route("/api/networking/dns", web::post().to(net_set_dns))
        .route("/api/networking/wolfnet", web::get().to(net_get_wolfnet))
        .route("/api/networking/wolfnet/config", web::get().to(net_get_wolfnet_config))
        .route("/api/networking/wolfnet/config", web::put().to(net_save_wolfnet_config))
        .route("/api/networking/wolfnet/peers", web::post().to(net_add_wolfnet_peer))
        .route("/api/networking/wolfnet/peers", web::delete().to(net_remove_wolfnet_peer))
        .route("/api/networking/wolfnet/local-info", web::get().to(net_get_wolfnet_local_info))
        .route("/api/networking/wolfnet/action", web::post().to(net_wolfnet_action))
        .route("/api/networking/wolfnet/invite", web::get().to(net_wolfnet_invite))
        .route("/api/networking/wolfnet/status-full", web::get().to(net_wolfnet_status_full))
        .route("/api/networking/interfaces/{name}/ip", web::post().to(net_add_ip))
        .route("/api/networking/interfaces/{name}/ip", web::delete().to(net_remove_ip))
        .route("/api/networking/interfaces/{name}/state", web::post().to(net_set_state))
        .route("/api/networking/interfaces/{name}/mtu", web::post().to(net_set_mtu))
        .route("/api/networking/vlans", web::post().to(net_create_vlan))
        .route("/api/networking/vlans/{name}", web::delete().to(net_delete_vlan))
        // IP Mappings
        .route("/api/networking/ip-mappings", web::get().to(net_list_ip_mappings))
        .route("/api/networking/ip-mappings", web::post().to(net_add_ip_mapping))
        .route("/api/networking/ip-mappings/{id}", web::delete().to(net_remove_ip_mapping))
        .route("/api/networking/ip-mappings/{id}", web::put().to(net_update_ip_mapping))
        .route("/api/networking/available-ips", web::get().to(net_available_ips))
        .route("/api/networking/listening-ports", web::get().to(net_listening_ports))
        // WireGuard bridge
        .route("/api/networking/wireguard", web::get().to(net_wireguard_list))
        .route("/api/networking/wireguard/{cluster}", web::get().to(net_wireguard_get))
        .route("/api/networking/wireguard/{cluster}/init", web::post().to(net_wireguard_init))
        .route("/api/networking/wireguard/{cluster}/toggle", web::post().to(net_wireguard_toggle))
        .route("/api/networking/wireguard/{cluster}", web::delete().to(net_wireguard_delete))
        .route("/api/networking/wireguard/{cluster}/clients", web::post().to(net_wireguard_add_client))
        .route("/api/networking/wireguard/{cluster}/clients/{id}", web::delete().to(net_wireguard_remove_client))
        .route("/api/networking/wireguard/{cluster}/clients/{id}/config", web::get().to(net_wireguard_client_config))
        // Backups
        .route("/api/backups", web::get().to(backup_list))
        .route("/api/backups", web::post().to(backup_create))
        .route("/api/backups/stream", web::post().to(backup_stream))
        .route("/api/backups/targets", web::get().to(backup_targets))
        .route("/api/backups/schedules", web::get().to(backup_schedules_list))
        .route("/api/backups/schedules", web::post().to(backup_schedule_create))
        .route("/api/backups/test-storage", web::post().to(backup_test_storage))
        .route("/api/backups/schedules/{id}", web::delete().to(backup_schedule_delete))
        .route("/api/backups/import", web::post().to(backup_import))
        // PBS (Proxmox Backup Server) — must be before {id} routes
        .route("/api/backups/pbs/status", web::get().to(pbs_status))
        .route("/api/backups/pbs/snapshots", web::get().to(pbs_snapshots))
        .route("/api/backups/pbs/restore", web::post().to(pbs_restore))
        .route("/api/backups/pbs/restore/progress", web::get().to(pbs_restore_progress))
        .route("/api/backups/pbs/config/full", web::get().to(pbs_config_get_full))
        .route("/api/backups/pbs/config", web::get().to(pbs_config_get))
        .route("/api/backups/pbs/config", web::post().to(pbs_config_save))
        // Generic backup {id} routes — after specific routes
        .route("/api/backups/{id}", web::delete().to(backup_delete))
        .route("/api/backups/{id}/restore/stream", web::post().to(backup_restore_stream))
        .route("/api/backups/{id}/restore", web::post().to(backup_restore))
        // Console WebSocket
        .route("/ws/console/{type}/{name}", web::get().to(crate::console::console_ws))
        // Remote Console WebSocket proxy (bridges browser ↔ remote node's console)
        .route("/ws/remote-console/{node_id}/{type}/{name}", web::get().to(crate::console::remote_console_ws))
        // PVE Console WebSocket proxy
        .route("/ws/pve-console/{node_id}/{vmid}", web::get().to(pve_console::pve_console_ws))
        // PVE VNC — ticket endpoint + WebSocket bridge for Proxmox VM graphical consoles
        .route("/api/pve-vnc-ticket/{vmid}", web::get().to(pve_console::pve_vnc_ticket))
        .route("/ws/pve-vnc/{vmid}", web::get().to(pve_console::pve_vnc_ws))
        // Native VM VNC — WebSocket proxy for QEMU VM graphical consoles
        .route("/ws/vm-vnc/{name}", web::get().to(pve_console::vm_vnc_ws))
        // VR Terminal — HTTP polling (avoids WebSocket port restrictions in VR headsets)
        // WolfFlow — workflow automation
        .route("/api/wolfflow/workflows", web::get().to(wolfflow_list))
        .route("/api/wolfflow/workflows", web::post().to(wolfflow_create))
        .route("/api/wolfflow/workflows/{id}", web::get().to(wolfflow_get))
        .route("/api/wolfflow/workflows/{id}", web::put().to(wolfflow_update))
        .route("/api/wolfflow/workflows/{id}", web::delete().to(wolfflow_delete))
        .route("/api/wolfflow/workflows/{id}/run", web::post().to(wolfflow_trigger))
        .route("/api/wolfflow/runs", web::get().to(wolfflow_runs_list))
        .route("/api/wolfflow/runs/{id}", web::get().to(wolfflow_run_detail))
        .route("/api/wolfflow/toolbox", web::get().to(wolfflow_toolbox))
        .route("/api/wolfflow/exec", web::post().to(wolfflow_exec))
        .route("/api/wolfflow/container-exec", web::post().to(wolfflow_container_exec))
        .route("/api/wolfflow/all-containers-exec", web::post().to(wolfflow_all_containers_exec))
        .route("/api/wolfflow/infrastructure", web::get().to(wolfflow_infrastructure))
        // User Preferences
        .route("/api/user/preferences", web::get().to(user_prefs_get))
        .route("/api/user/preferences", web::post().to(user_prefs_save))
        .route("/api/user/preferences", web::patch().to(user_prefs_patch))
        // WolfUSB — USB over IP
        .route("/api/wolfusb/status", web::get().to(wolfusb_status))
        .route("/api/wolfusb/install", web::post().to(wolfusb_install))
        .route("/api/wolfusb/config", web::get().to(wolfusb_get_config))
        .route("/api/wolfusb/config", web::post().to(wolfusb_save_config))
        .route("/api/wolfusb/devices", web::get().to(wolfusb_devices))
        .route("/api/wolfusb/cluster_devices", web::get().to(wolfusb_cluster_devices))
        .route("/api/wolfusb/assign", web::post().to(wolfusb_assign))
        .route("/api/wolfusb/unassign", web::post().to(wolfusb_unassign))
        .route("/api/wolfusb/attach", web::post().to(wolfusb_attach))
        .route("/api/wolfusb/diagnose/{busid}", web::get().to(wolfusb_diagnose))
        .route("/api/wolfusb/prepare-for-export", web::post().to(wolfusb_prepare_for_export))
        .route("/api/wolfusb/reattach/{busid}", web::post().to(wolfusb_reattach))
        .route("/api/wolfusb/sync", web::post().to(wolfusb_sync))
        // VR Terminal
        .route("/api/vr-terminal/create", web::post().to(crate::vr_terminal::vr_term_create))
        .route("/api/vr-terminal/{id}/output", web::get().to(crate::vr_terminal::vr_term_output))
        .route("/api/vr-terminal/{id}/input", web::post().to(crate::vr_terminal::vr_term_input))
        .route("/api/vr-terminal/{id}", web::delete().to(crate::vr_terminal::vr_term_close))
        // MySQL Database Editor
        .route("/api/mysql/detect", web::get().to(mysql_detect))
        .route("/api/mysql/detect-containers", web::get().to(mysql_detect_containers))
        .route("/api/mysql/connect", web::post().to(mysql_connect))
        .route("/api/mysql/databases", web::post().to(mysql_databases))
        .route("/api/mysql/tables", web::post().to(mysql_tables))
        .route("/api/mysql/structure", web::post().to(mysql_structure))
        .route("/api/mysql/data", web::post().to(mysql_data))
        .route("/api/mysql/query", web::post().to(mysql_query))
        .route("/api/mysql/dump", web::post().to(mysql_dump))
        // Agent (cluster-secret auth — inter-node communication)
        .route("/api/agent/status", web::get().to(agent_status))
        .route("/api/agent/storage/apply", web::post().to(agent_storage_apply))
        .route("/api/ports", web::get().to(get_ports))
        .route("/api/ports", web::post().to(set_ports))
        .route("/api/cluster-services", web::get().to(cluster_services_list))
        .route("/api/cluster-services/sweep", web::post().to(cluster_services_sweep))
        .route("/api/cluster-services/manual", web::post().to(cluster_services_add_manual))
        .route("/api/cluster-services/{id}", web::delete().to(cluster_services_delete))
        .route("/api/cluster-browser/sessions", web::get().to(cluster_browser_list))
        .route("/api/cluster-browser/sessions", web::post().to(cluster_browser_start))
        .route("/api/cluster-browser/sessions/start-stream", web::post().to(cluster_browser_start_stream))
        .route("/api/cluster-browser/sessions/{id}", web::delete().to(cluster_browser_stop))
        .route("/api/cluster-browser/image-status", web::get().to(cluster_browser_image_status))
        // Reverse proxy so every selkies request (HTML, assets, /websocket)
        // rides WolfStack's own port — see cluster_browser_proxy module docs.
        // Catch-all `.*` path segment forwards the rest of the URL to the
        // container untouched.
        .route(
            "/api/cluster-browser/session/{id}/{tail:.*}",
            web::to(cluster_browser_proxy::cluster_browser_proxy),
        )
        .route("/cluster-home", web::get().to(cluster_browser_homepage))
        .route("/api/agent/cluster-name", web::post().to(agent_set_cluster_name))
        .route("/api/agent/wolfnet-routes", web::post().to(agent_set_wolfnet_routes))
        .route("/api/wolfnet/used-ips", web::get().to(wolfnet_used_ips_endpoint))
        .route("/api/wolfnet/routes", web::get().to(wolfnet_routes_debug))
        // Geolocation proxy (ip-api.com is HTTP-only, browsers block mixed content on HTTPS pages)
        .route("/api/geolocate", web::get().to(geolocate))
        // Kubernetes
        .route("/api/kubernetes/detect", web::get().to(k8s_detect))
        .route("/api/kubernetes/run-script", web::post().to(k8s_run_script))
        .route("/api/kubernetes/kubeconfig", web::get().to(k8s_kubeconfig))
        .route("/api/kubernetes/join-token", web::get().to(k8s_join_token))
        .route("/api/kubernetes/uninstall", web::post().to(k8s_uninstall))
        .route("/api/kubernetes/clusters", web::get().to(k8s_list_clusters))
        .route("/api/kubernetes/clusters", web::post().to(k8s_create_cluster))
        .route("/api/kubernetes/clusters/provision", web::post().to(k8s_provision))
        .route("/api/kubernetes/clusters/prepare-provision", web::post().to(k8s_prepare_provision))
        .route("/api/kubernetes/clusters/prepare-provision-agents", web::post().to(k8s_prepare_provision_agents))
        .route("/api/kubernetes/clusters/{id}", web::delete().to(k8s_delete_cluster))
        .route("/api/kubernetes/clusters/{id}/status", web::get().to(k8s_cluster_status))
        .route("/api/kubernetes/clusters/{id}/namespaces", web::get().to(k8s_namespaces))
        .route("/api/kubernetes/clusters/{id}/namespaces", web::post().to(k8s_create_namespace))
        .route("/api/kubernetes/clusters/{id}/namespaces/{name}", web::delete().to(k8s_delete_namespace))
        .route("/api/kubernetes/clusters/{id}/pods", web::get().to(k8s_pods))
        .route("/api/kubernetes/clusters/{id}/pods/{name}", web::delete().to(k8s_delete_pod))
        .route("/api/kubernetes/clusters/{id}/pods/{name}/detail", web::get().to(k8s_pod_detail))
        .route("/api/kubernetes/clusters/{id}/pods/{name}/top", web::get().to(k8s_pod_top))
        .route("/api/kubernetes/clusters/{id}/pods/{name}/exec", web::post().to(k8s_pod_exec))
        .route("/api/kubernetes/clusters/{id}/pods/{name}/events", web::get().to(k8s_pod_events))
        .route("/api/kubernetes/clusters/{id}/deployments", web::get().to(k8s_deployments))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}", web::delete().to(k8s_delete_deployment))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/detail", web::get().to(k8s_deployment_detail))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/scale", web::patch().to(k8s_scale_deployment))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/restart", web::post().to(k8s_restart_deployment))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/image", web::patch().to(k8s_set_image))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/env", web::patch().to(k8s_set_env))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/full", web::delete().to(k8s_delete_deployment_full))
        .route("/api/kubernetes/clusters/{id}/settings", web::patch().to(k8s_cluster_settings))
        .route("/api/kubernetes/clusters/{id}/services", web::get().to(k8s_services))
        .route("/api/kubernetes/clusters/{id}/services/{name}", web::delete().to(k8s_delete_service))
        .route("/api/kubernetes/clusters/{id}/nodes", web::get().to(k8s_nodes))
        .route("/api/kubernetes/clusters/{id}/logs/{pod}", web::get().to(k8s_pod_logs))
        .route("/api/kubernetes/clusters/{id}/resource-yaml", web::get().to(k8s_resource_yaml))
        .route("/api/kubernetes/clusters/{id}/apply", web::post().to(k8s_apply))
        .route("/api/kubernetes/clusters/{id}/deploy-app", web::post().to(k8s_deploy_app))
        .route("/api/kubernetes/clusters/{id}/wolfnet", web::get().to(k8s_wolfnet_status))
        .route("/api/kubernetes/clusters/{id}/wolfnet", web::post().to(k8s_deploy_wolfnet))
        .route("/api/kubernetes/clusters/{id}/wolfnet", web::delete().to(k8s_remove_wolfnet))
        .route("/api/kubernetes/clusters/{id}/storage", web::get().to(k8s_storage_overview))
        .route("/api/kubernetes/clusters/{id}/storage/pvcs", web::post().to(k8s_create_pvc))
        .route("/api/kubernetes/clusters/{id}/storage/pvcs/{name}", web::delete().to(k8s_delete_pvc))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/volumes", web::post().to(k8s_add_volume))
        .route("/api/kubernetes/clusters/{id}/deployments/{name}/volumes/{vol_name}", web::delete().to(k8s_remove_volume))
        // App Store
        .route("/api/appstore/apps", web::get().to(appstore_list))
        .route("/api/appstore/apps/{id}", web::get().to(appstore_get))
        .route("/api/appstore/apps/{id}/install", web::post().to(appstore_install))
        .route("/api/appstore/apps/{id}/prepare-install", web::post().to(appstore_prepare_install))
        .route("/api/appstore/apps/{id}/install-stream", web::post().to(appstore_install_stream))
        .route("/api/system/prepare-install-package", web::post().to(prepare_install_package))
        .route("/api/appstore/installed", web::get().to(appstore_installed))
        .route("/api/appstore/installed/{id}", web::delete().to(appstore_uninstall))
        // System
        .route("/api/config/export", web::get().to(config_export))
        .route("/api/config/import", web::post().to(config_import))
        .route("/api/upgrade", web::post().to(system_upgrade))
        // Issues Scanner
        .route("/api/issues/scan", web::get().to(scan_issues))
        .route("/api/issues/clean", web::post().to(clean_system))
        .route("/api/alerts", web::get().to(get_alert_log))
        // File locations
        .route("/api/settings/paths", web::get().to(get_file_locations))
        .route("/api/settings/paths", web::post().to(update_file_locations))
        // Security (Fail2ban, iptables, UFW)
        .route("/api/security/status", web::get().to(security_status))
        .route("/api/security/fail2ban/install", web::post().to(security_fail2ban_install))
        .route("/api/security/fail2ban/rebuild", web::post().to(security_fail2ban_rebuild))
        .route("/api/security/fail2ban/config", web::get().to(security_fail2ban_config_get))
        .route("/api/security/fail2ban/config", web::post().to(security_fail2ban_config_save))
        .route("/api/security/fail2ban/unban", web::post().to(security_fail2ban_unban))
        .route("/api/security/ufw/install", web::post().to(security_ufw_install))
        .route("/api/security/ufw/rule", web::post().to(security_ufw_add_rule))
        .route("/api/security/ufw/rule", web::delete().to(security_ufw_delete_rule))
        .route("/api/security/ufw/toggle", web::post().to(security_ufw_toggle))
        .route("/api/security/iptables/rules", web::get().to(security_iptables_rules))
        .route("/api/security/updates/check", web::post().to(security_check_updates))
        .route("/api/security/updates/apply", web::post().to(security_apply_updates))
        // Alerting
        .route("/api/alerts/config", web::get().to(alerts_config_get))
        .route("/api/alerts/config", web::post().to(alerts_config_save))
        .route("/api/alerts/test", web::post().to(alerts_test))
        .route("/api/system/install-package", web::post().to(system_install_package))
        // WolfAgents — named AI agents with persistent memory.
        .route("/api/agents", web::get().to(agents_list))
        .route("/api/agents", web::post().to(agents_create))
        // Static /tools MUST be registered before the {id} catch-all —
        // actix matches in registration order, and the dynamic route
        // would otherwise swallow `/api/agents/tools` as `id="tools"`.
        .route("/api/agents/tools", web::get().to(agents_tool_catalogue))
        .route("/api/agents/build", web::post().to(agents_build_proposal))
        .route("/api/agents/{id}", web::get().to(agents_get))
        .route("/api/agents/{id}", web::put().to(agents_update))
        .route("/api/agents/{id}", web::delete().to(agents_delete))
        .route("/api/agents/{id}/chat", web::post().to(agents_chat))
        .route("/api/agents/{id}/memory", web::get().to(agents_memory))
        .route("/api/agents/{id}/audit", web::get().to(agents_audit))
        .route("/api/agents/{id}/pending", web::get().to(agents_pending_list))
        .route("/api/agents/{id}/pending/{seq}/approve", web::post().to(agents_pending_approve))
        .route("/api/agents/{id}/pending/{seq}/deny", web::post().to(agents_pending_deny))
        // MCP-shaped tool surface so external agent harnesses can call
        // WolfStack's read-only capabilities without reinventing each one.
        .route("/api/mcp/tools/list", web::post().to(mcp_tools_list))
        .route("/api/mcp/tools/call", web::post().to(mcp_tools_call))
        // WhatsApp inbound via Twilio — unauth, signature-validated.
        .route("/api/whatsapp/webhook", web::post().to(whatsapp_webhook))
        // Integrations (auth required)
        .route("/api/integrations/connectors", web::get().to(integrations_connectors))
        .route("/api/integrations", web::get().to(integrations_list))
        .route("/api/integrations", web::post().to(integrations_create))
        .route("/api/integrations/{id}", web::get().to(integrations_get))
        .route("/api/integrations/{id}", web::delete().to(integrations_delete))
        // WolfRun — container orchestration
        .route("/api/wolfrun/services", web::get().to(wolfrun_list))
        .route("/api/wolfrun/services", web::post().to(wolfrun_create))
        .route("/api/wolfrun/services/adopt", web::post().to(wolfrun_adopt))
        .route("/api/wolfrun/sync", web::post().to(wolfrun_sync))
        .route("/api/wolfrun/failover-events", web::get().to(wolfrun_failover_events))
        .route("/api/wolfrun/reconcile", web::post().to(wolfrun_reconcile))
        .route("/api/wolfrun/services/{id}", web::get().to(wolfrun_get))
        .route("/api/wolfrun/services/{id}", web::delete().to(wolfrun_delete))
        .route("/api/wolfrun/services/{id}/scale", web::post().to(wolfrun_scale))
        .route("/api/wolfrun/services/{id}/action", web::post().to(wolfrun_service_action))
        .route("/api/wolfrun/services/{id}/settings", web::post().to(wolfrun_settings))
        .route("/api/wolfrun/services/{id}/update", web::post().to(wolfrun_update))
        .route("/api/wolfrun/services/{id}/portforward", web::get().to(wolfrun_portforward_list))
        .route("/api/wolfrun/services/{id}/portforward", web::post().to(wolfrun_portforward_add))
        .route("/api/wolfrun/services/{id}/portforward/{rule_id}", web::delete().to(wolfrun_portforward_delete))
        // Configurators
        // Nginx (WolfProxy)
        .route("/api/configurator/nginx/sites", web::get().to(nginx_list_sites))
        .route("/api/configurator/nginx/sites", web::post().to(nginx_create_site))
        .route("/api/configurator/nginx/sites/{name}", web::get().to(nginx_read_site))
        .route("/api/configurator/nginx/sites/{name}", web::put().to(nginx_update_site))
        .route("/api/configurator/nginx/sites/{name}", web::delete().to(nginx_delete_site))
        .route("/api/configurator/nginx/sites/{name}/enable", web::post().to(nginx_enable_site))
        .route("/api/configurator/nginx/sites/{name}/disable", web::post().to(nginx_disable_site))
        .route("/api/configurator/nginx/test", web::post().to(nginx_test_config))
        .route("/api/configurator/nginx/reload", web::post().to(nginx_reload))
        .route("/api/configurator/nginx/error-log", web::get().to(nginx_error_log))
        .route("/api/configurator/nginx/generate", web::post().to(nginx_generate_config))
        .route("/api/configurator/nginx/bootstrap", web::post().to(nginx_bootstrap))
        // Apache (WolfServe)
        .route("/api/configurator/apache/sites", web::get().to(apache_list_sites))
        .route("/api/configurator/apache/sites", web::post().to(apache_create_site))
        .route("/api/configurator/apache/sites/{name}", web::get().to(apache_read_site))
        .route("/api/configurator/apache/sites/{name}", web::put().to(apache_update_site))
        .route("/api/configurator/apache/sites/{name}", web::delete().to(apache_delete_site))
        .route("/api/configurator/apache/sites/{name}/enable", web::post().to(apache_enable_site))
        .route("/api/configurator/apache/sites/{name}/disable", web::post().to(apache_disable_site))
        .route("/api/configurator/apache/modules", web::get().to(apache_list_modules))
        .route("/api/configurator/apache/modules/{name}/enable", web::post().to(apache_enable_module))
        .route("/api/configurator/apache/modules/{name}/disable", web::post().to(apache_disable_module))
        .route("/api/configurator/apache/test", web::post().to(apache_test_config))
        .route("/api/configurator/apache/reload", web::post().to(apache_reload))
        .route("/api/configurator/apache/error-log", web::get().to(apache_error_log))
        .route("/api/configurator/apache/generate", web::post().to(apache_generate_config))
        .route("/api/configurator/apache/bootstrap", web::post().to(apache_bootstrap))
        // Docker Compose
        .route("/api/compose/stacks", web::get().to(compose_list_stacks))
        .route("/api/compose/stacks", web::post().to(compose_create_stack))
        .route("/api/compose/stacks/{name}", web::delete().to(compose_delete_stack))
        .route("/api/compose/stacks/{name}/compose", web::get().to(compose_read_yaml))
        .route("/api/compose/stacks/{name}/compose", web::post().to(compose_write_yaml))
        .route("/api/compose/stacks/{name}/env", web::get().to(compose_read_env))
        .route("/api/compose/stacks/{name}/env", web::post().to(compose_write_env))
        .route("/api/compose/stacks/{name}/up", web::post().to(compose_up))
        .route("/api/compose/stacks/{name}/down", web::post().to(compose_down))
        .route("/api/compose/stacks/{name}/pull", web::post().to(compose_pull))
        .route("/api/compose/stacks/{name}/restart", web::post().to(compose_restart))
        .route("/api/compose/stacks/{name}/logs", web::get().to(compose_logs))
        .route("/api/compose/stacks/{name}/validate", web::post().to(compose_validate))
        // Secrets Manager
        // Plugins
        .route("/api/plugins", web::get().to(plugins_list))
        .route("/api/plugins/reload", web::post().to(plugins_reload))
        .route("/api/plugins/store", web::get().to(plugins_store))
        .route("/api/plugins/install", web::post().to(plugins_install))
        .route("/api/plugins/{id}", web::delete().to(plugins_uninstall))
        .route("/api/plugins/{id}/toggle", web::post().to(plugins_toggle))
        .route("/api/plugins/{id}/data/config", web::get().to(plugin_data_config_get))
        .route("/api/plugins/{id}/data/config", web::post().to(plugin_data_config_set))
        .route("/api/plugins/{id}/data/upload/{filename}", web::post().to(plugin_data_upload))
        .route("/api/plugins/{id}/data/file/{filename}", web::get().to(plugin_data_file))
        .route("/api/plugins/{id}/file/{path:.*}", web::get().to(plugins_file))
        .route("/api/plugins/{id}/api/{path:.*}", web::get().to(plugins_proxy))
        .route("/api/plugins/{id}/api/{path:.*}", web::post().to(plugins_proxy))
        .route("/api/plugins/{id}/api/{path:.*}", web::put().to(plugins_proxy))
        .route("/api/plugins/{id}/api/{path:.*}", web::delete().to(plugins_proxy))
        // Platform calibration & access tokens
        .route("/api/platform/status", web::get().to(platform_status))
        .route("/api/platform/apply", web::post().to(platform_apply))
        .route("/api/tokens", web::get().to(list_tokens))
        .route("/api/tokens", web::post().to(create_token))
        .route("/api/tokens/scopes", web::get().to(list_token_scopes))
        .route("/api/tokens/events", web::get().to(token_events))
        .route("/api/tokens/{id}", web::delete().to(revoke_token))
        // Secrets
        .route("/api/secrets", web::get().to(secrets_list))
        .route("/api/secrets", web::post().to(secrets_save))
        .route("/api/secrets/{key}", web::get().to(secrets_get))
        .route("/api/secrets/{key}", web::delete().to(secrets_delete))
        // Wolfram — memory compression daemon
        .route("/api/wolfram/status", web::get().to(wolfram_status))
        .route("/api/wolfram/install", web::post().to(wolfram_install))
        .route("/api/wolfram/uninstall", web::post().to(wolfram_uninstall))
        .route("/api/wolfram/action", web::post().to(wolfram_action))
        .route("/api/wolfram/config", web::get().to(wolfram_config_get))
        .route("/api/wolfram/config", web::post().to(wolfram_config_save))
        // TOML Editors (WolfDisk, WolfScale)
        .route("/api/configurator/toml/{component}/structured", web::get().to(toml_get_structured))
        .route("/api/configurator/toml/{component}/structured", web::post().to(toml_save_structured))
        .route("/api/configurator/toml/{component}/validate", web::post().to(toml_validate))
        .route("/api/configurator/toml/{component}/bootstrap", web::post().to(toml_bootstrap))
        // Node proxy — forward API calls to remote nodes (must be last — wildcard path)
        .route("/api/nodes/{id}/proxy/{path:.*}", web::get().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::post().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::put().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::delete().to(node_proxy))
        .route("/api/nodes/{id}/proxy/{path:.*}", web::patch().to(node_proxy))
        // Status Page (admin — auth required)
        .route("/api/statuspage/config", web::get().to(statuspage_config_get))
        .route("/api/statuspage/config", web::post().to(statuspage_config_save))
        .route("/api/statuspage/monitors", web::get().to(statuspage_monitors_list))
        .route("/api/statuspage/monitors", web::post().to(statuspage_monitor_save))
        .route("/api/statuspage/monitors/{id}", web::delete().to(statuspage_monitor_delete))
        .route("/api/statuspage/pages", web::get().to(statuspage_pages_list))
        .route("/api/statuspage/pages", web::post().to(statuspage_page_save))
        .route("/api/statuspage/pages/{id}", web::delete().to(statuspage_page_delete))
        .route("/api/statuspage/incidents", web::get().to(statuspage_incidents_list))
        .route("/api/statuspage/incidents", web::post().to(statuspage_incident_save))
        .route("/api/statuspage/incidents/{id}", web::delete().to(statuspage_incident_delete))
        .route("/api/statuspage/sync", web::post().to(statuspage_sync))
        // Patreon integration
        .route("/api/patreon/connect", web::get().to(patreon_connect))
        .route("/api/patreon/callback", web::get().to(patreon_callback))
        .route("/api/patreon/status", web::get().to(patreon_status))
        .route("/api/patreon/sync", web::post().to(patreon_sync))
        .route("/api/patreon/disconnect", web::post().to(patreon_disconnect))
        // Icon Packs
        .route("/api/icon-packs", web::get().to(icon_packs_list))
        .route("/api/icon-packs/semantic-names", web::get().to(icon_packs_semantic_names))
        .route("/api/icon-packs/install", web::post().to(icon_packs_install))
        .route("/api/icon-packs/{pack_id}", web::delete().to(icon_packs_remove))
        .route("/api/icon-packs/{pack_id}/icon/{icon_name}", web::get().to(icon_packs_serve))
        .route("/api/icon-packs/{pack_id}/preview", web::get().to(icon_packs_preview))
        // WolfNote integration
        .route("/api/wolfnote/login", web::post().to(wolfnote_login))
        .route("/api/wolfnote/disconnect", web::post().to(wolfnote_disconnect))
        .route("/api/wolfnote/config", web::get().to(wolfnote_config_get))
        .route("/api/wolfnote/config", web::post().to(wolfnote_config_save))
        .route("/api/wolfnote/folders", web::get().to(wolfnote_folders_list))
        .route("/api/wolfnote/folders", web::post().to(wolfnote_folders_create))
        .route("/api/wolfnote/notes", web::get().to(wolfnote_notes_list))
        .route("/api/wolfnote/notes", web::post().to(wolfnote_notes_create))
        // Status Page (public — NO auth)
        .route("/status", web::get().to(statuspage_public_index))
        .route("/status/{slug}", web::get().to(statuspage_public_page));
}

/// GET /status/{slug} — public status page on dedicated port 8550.
/// Uses slug-only lookup. Data integrity is guaranteed by replication filters
/// (broadcast and pull only store own-cluster data), so a node only has its own pages.
pub async fn statuspage_public_page_dedicated(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let slug = path.into_inner();
    let page = state.statuspage.find_page_by_slug(&slug);
    match page {
        Some(p) => {
            match crate::statuspage::render_public_page_inner(&state.statuspage, &p) {
                Some(html) => HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html),
                None => HttpResponse::NotFound().content_type("text/html; charset=utf-8").body(
                    r#"<!DOCTYPE html><html><head><title>Not Found</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;"><p>Status page not found.</p></body></html>"#
                ),
            }
        }
        None => HttpResponse::NotFound().content_type("text/html; charset=utf-8").body(
            r#"<!DOCTYPE html><html><head><title>Not Found</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;"><p>Status page not found.</p></body></html>"#
        ),
    }
}

/// Minimal config for the dedicated status page HTTP listener (port 8550).
pub fn configure_statuspage_only(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/", web::get().to(statuspage_public_index))
        .route("/status", web::get().to(statuspage_public_index))
        .route("/status/{slug}", web::get().to(statuspage_public_page_dedicated));
}
