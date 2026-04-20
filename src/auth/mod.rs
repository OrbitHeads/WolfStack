// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

// Authentication — Linux system user authentication via crypt(),
// with optional WolfStack user accounts and TOTP two-factor authentication.

pub mod users;
#[allow(dead_code)]
pub mod oidc;
#[allow(dead_code)]
pub mod webauthn;

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::warn;

/// Session token lifetime (8 hours)
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Maximum failed login attempts per IP before lockout
const MAX_LOGIN_ATTEMPTS: u32 = 10;
/// Lockout window — failed attempts are counted within this period
const LOGIN_LOCKOUT_WINDOW: Duration = Duration::from_secs(300); // 5 minutes

/// Built-in cluster secret shared by all WolfStack installations.
const CLUSTER_SECRET: &str = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3";

/// Get the built-in default cluster secret (always accepted as fallback)
pub fn default_cluster_secret() -> &'static str {
    CLUSTER_SECRET
}

/// Path for user-generated custom cluster secrets (via Settings → Security).
/// Note: /etc/wolfstack/cluster-secret may contain leftover per-installation
/// secrets from v11.26.3 — we deliberately use a different path to avoid loading those.
fn custom_secret_path() -> String { crate::paths::get().cluster_secret }

/// Load the active cluster secret — custom from file if present, otherwise the built-in default
pub fn load_cluster_secret() -> String {
    let path_str = custom_secret_path();
    let path = std::path::Path::new(&path_str);
    if let Ok(secret) = std::fs::read_to_string(path) {
        let secret = secret.trim().to_string();
        if !secret.is_empty() {
            return secret;
        }
    }
    CLUSTER_SECRET.to_string()
}

/// Generate a new random cluster secret (wsk_ prefix + 64 hex chars)
pub fn generate_cluster_secret() -> String {
    use std::fmt::Write;
    let mut secret = String::from("wsk_");
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    for b in &buf {
        let _ = write!(secret, "{:02x}", b);
    }
    secret
}

/// Save a cluster secret to the custom secret file. Written with mode
/// 0600 — the secret is the cluster's inter-node auth token, so any
/// non-root reader can impersonate a cluster member. Pre-v18.7.27 this
/// used `std::fs::write` which inherited the process umask (usually
/// 022 → 0644) and made the secret world-readable.
pub fn save_cluster_secret(secret: &str) -> Result<(), String> {
    let path = custom_secret_path();
    crate::paths::write_secure(&path, secret)
        .map_err(|e| format!("Cannot write custom-cluster-secret: {}", e))
}

/// Validate a cluster secret from a request header.
///
/// True constant-time comparison: the pre-v18.7.30 implementation had
/// an early-exit on length mismatch which leaked the secret's length
/// via timing. Now we fold the length difference into the accumulator
/// so the running time depends only on the longer of the two inputs.
pub fn validate_cluster_secret(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    // Mix the length difference into the accumulator by OR-ing every
    // byte of the XOR — this folds len-mismatch into the result
    // without a narrow u8 cast (which would alias 256-byte-apart
    // lengths to "equal"). Then walk both inputs in full by reading
    // zero for out-of-bounds indices.
    let len_diff_bytes = ((a.len() as u64) ^ (b.len() as u64)).to_le_bytes();
    let mut acc: u8 = len_diff_bytes.iter().fold(0u8, |x, b| x | *b);
    let max = a.len().max(b.len());
    for i in 0..max {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        acc |= x ^ y;
    }
    acc == 0
}

// Pure-Rust password hashing (replaces C libcrypt dependency)

/// Active session
struct Session {
    username: String,
    created: Instant,
}

/// Session manager
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Session>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session for a user, returns the session token
    pub fn create_session(&self, username: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(token.clone(), Session {
            username: username.to_string(),
            created: Instant::now(),
        });

        token
    }

    /// Validate a session token, returns the username if valid
    pub fn validate(&self, token: &str) -> Option<String> {
        let sessions = self.sessions.read().unwrap();
        if let Some(session) = sessions.get(token) {
            if session.created.elapsed() < SESSION_LIFETIME {
                return Some(session.username.clone());
            }
        }
        None
    }

    /// Destroy a session
    pub fn destroy(&self, token: &str) {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(_session) = sessions.remove(token) {

        }
    }

    /// Clean up expired sessions
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.created.elapsed() < SESSION_LIFETIME);
    }
}

/// Authenticate a user against the Linux system (/etc/shadow)
pub fn authenticate_user(username: &str, password: &str) -> bool {
    // Validate inputs
    if username.is_empty() || password.is_empty() {
        return false;
    }

    // Prevent path traversal and injection
    if username.contains(':') || username.contains('/') || username.contains('\0') {
        warn!("Invalid username characters in login attempt");
        return false;
    }

    // Read /etc/shadow (requires root)
    let shadow = match std::fs::read_to_string("/etc/shadow") {
        Ok(s) => s,
        Err(e) => {
            warn!("Cannot read /etc/shadow: {} — WolfStack must run as root", e);
            return false;
        }
    };

    for line in shadow.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        if parts[0] != username {
            continue;
        }

        let stored_hash = parts[1];

        // Skip locked/disabled accounts
        if stored_hash.is_empty() || stored_hash == "!" || stored_hash == "*"
            || stored_hash == "!!" || stored_hash.starts_with('!')
        {
            warn!("Login attempt for locked account '{}'", username);
            return false;
        }

        // Use crypt() to verify password
        match verify_password(password, stored_hash) {
            true => {

                return true;
            }
            false => {
                warn!("Failed login attempt for user '{}'", username);
                return false;
            }
        }
    }

    warn!("Login attempt for unknown user '{}'", username);
    false
}

/// Verify a password against a stored hash.
/// Uses native C crypt() via dlopen when available, with pure-Rust fallback
/// for yescrypt ($y$), SHA-512 ($6$), and SHA-256 ($5$).
fn verify_password(password: &str, stored_hash: &str) -> bool {
    // Try native C crypt() first — handles all formats
    if let Some(result) = native_crypt(password, stored_hash) {
        return result == stored_hash;
    }
    // Fallback: pure Rust (needed for statically-linked / musl builds)
    if stored_hash.starts_with("$y$") {
        use yescrypt::Yescrypt;
        use yescrypt::password_hash::PasswordVerifier;
        return Yescrypt::default().verify_password(password.as_bytes(), stored_hash).is_ok();
    } else if stored_hash.starts_with("$6$") {
        sha_crypt::sha512_check(password, stored_hash).is_ok()
    } else if stored_hash.starts_with("$5$") {
        sha_crypt::sha256_check(password, stored_hash).is_ok()
    } else {
        false
    }
}

/// Try to call crypt() by dynamically loading libcrypt.so at runtime.
/// Returns None if libcrypt is not available (e.g. minimal Debian ISO).
fn native_crypt(password: &str, salt: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c_password = CString::new(password).ok()?;
    let c_salt = CString::new(salt).ok()?;
    unsafe {
        // Try libcrypt.so.2 (Arch/Fedora), then libcrypt.so.1 (Debian/Ubuntu)
        let lib = libc::dlopen(b"libcrypt.so.2\0".as_ptr() as *const _, libc::RTLD_NOW);
        let lib = if lib.is_null() {
            libc::dlopen(b"libcrypt.so.1\0".as_ptr() as *const _, libc::RTLD_NOW)
        } else {
            lib
        };
        if lib.is_null() {
            return None;
        }
        let sym = libc::dlsym(lib, b"crypt\0".as_ptr() as *const _);
        if sym.is_null() {
            libc::dlclose(lib);
            return None;
        }
        let crypt_fn: extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char =
            std::mem::transmute(sym);
        let result = crypt_fn(c_password.as_ptr(), c_salt.as_ptr());
        let ret = if result.is_null() {
            None
        } else {
            Some(CStr::from_ptr(result).to_string_lossy().to_string())
        };
        libc::dlclose(lib);
        ret
    }
}

/// IP-based login rate limiter to prevent brute-force attacks
pub struct LoginRateLimiter {
    attempts: RwLock<HashMap<String, Vec<Instant>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
        }
    }

    /// Record a failed login attempt for an IP. Returns true if the IP is now locked out.
    pub fn record_failure(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        // Prune old entries outside the window
        entry.retain(|t| now.duration_since(*t) < LOGIN_LOCKOUT_WINDOW);
        entry.push(now);
        entry.len() >= MAX_LOGIN_ATTEMPTS as usize
    }

    /// Check if an IP is currently locked out (too many recent failures)
    pub fn is_locked_out(&self, ip: &str) -> bool {
        let attempts = self.attempts.read().unwrap();
        if let Some(entry) = attempts.get(ip) {
            let now = Instant::now();
            let recent = entry.iter().filter(|t| now.duration_since(**t) < LOGIN_LOCKOUT_WINDOW).count();
            recent >= MAX_LOGIN_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Clear failures for an IP (called on successful login)
    pub fn clear(&self, ip: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
    }

    /// Periodic cleanup of expired entries
    pub fn cleanup(&self) {
        let mut attempts = self.attempts.write().unwrap();
        let now = Instant::now();
        attempts.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < LOGIN_LOCKOUT_WINDOW);
            !entries.is_empty()
        });
    }
}

// ─── Password Reset Tokens ───

/// In-memory storage for password reset tokens (30-minute expiry)
pub struct PasswordResetTokens {
    tokens: RwLock<HashMap<String, ResetToken>>,
}

struct ResetToken {
    username: String,
    created: Instant,
}

const RESET_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60); // 30 minutes

impl PasswordResetTokens {
    pub fn new() -> Self {
        Self { tokens: RwLock::new(HashMap::new()) }
    }

    /// Create a reset token for a user. Returns the token string.
    pub fn create(&self, username: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().unwrap();
        // Remove any existing tokens for this user
        tokens.retain(|_, t| t.username != username);
        tokens.insert(token.clone(), ResetToken {
            username: username.to_string(),
            created: Instant::now(),
        });
        token
    }

    /// Validate and consume a reset token. Returns the username if valid.
    pub fn validate_and_consume(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some(rt) = tokens.remove(token) {
            if rt.created.elapsed() < RESET_TOKEN_LIFETIME {
                return Some(rt.username);
            }
        }
        None
    }

    /// Clean up expired tokens
    pub fn cleanup(&self) {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, t| t.created.elapsed() < RESET_TOKEN_LIFETIME);
    }
}

/// Validate a container/VM name — only allow safe characters (alphanumeric, dash, underscore, dot)
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn equal_content_equal_length_is_true() {
        assert!(validate_cluster_secret("wsk_abc123", "wsk_abc123"));
        assert!(validate_cluster_secret("x", "x"));
    }

    #[test]
    fn equal_length_different_content_is_false() {
        assert!(!validate_cluster_secret("wsk_abc123", "wsk_xyz999"));
        assert!(!validate_cluster_secret("aaaaa", "aaaab"));  // one byte off
    }

    #[test]
    fn different_length_is_false() {
        // The bug this test prevents: pre-v18.7.30 the function did an
        // early return on length mismatch, leaking expected length via
        // timing. Now len-mismatch is folded into the accumulator
        // alongside content bytes — still returns false, still const
        // time relative to the longer input.
        assert!(!validate_cluster_secret("short", "muchlongersecret"));
        assert!(!validate_cluster_secret("longerthanexpected", "short"));
        assert!(!validate_cluster_secret("a", "ab"));
        assert!(!validate_cluster_secret("", ""));  // both empty — explicit early exit
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(!validate_cluster_secret("", "real_secret"));
        assert!(!validate_cluster_secret("real_secret", ""));
    }

    #[test]
    fn long_secret_equality() {
        let s = "wsk_".to_string() + &"a".repeat(64);
        assert!(validate_cluster_secret(&s, &s));
        let mut tampered = s.clone();
        tampered.pop();
        tampered.push('b');  // flip last byte
        assert!(!validate_cluster_secret(&s, &tampered));
    }
}
