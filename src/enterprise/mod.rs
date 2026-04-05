// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Enterprise features — license verification, API key management, audit logging

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

// ─── License Verification ───

const LICENSE_FILE: &str = "/etc/wolfstack/license.key";

/// Ed25519 public key for license verification (32 bytes).
/// The private key is held exclusively by Wolf Software Systems Ltd.
/// Even with full source code access, valid licenses cannot be forged.
const LICENSE_PUBLIC_KEY: [u8; 32] = [
    0xf9, 0x7b, 0x9e, 0x05, 0x3b, 0xbe, 0x21, 0xda,
    0x08, 0xe8, 0x01, 0xf6, 0x09, 0xb4, 0xb0, 0x09,
    0x9b, 0x5b, 0x82, 0x7b, 0xed, 0x33, 0x18, 0xb3,
    0x34, 0x91, 0x63, 0x74, 0xb1, 0xda, 0x0b, 0x0c,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub customer: String,
    pub email: String,
    #[serde(default)]
    pub max_nodes: u32,
    pub expires: String,   // ISO 8601 date: "2027-12-31"
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedLicense {
    payload: String,   // base64-encoded JSON of License
    signature: String, // base64-encoded HMAC-SHA256
}

/// Check if a valid enterprise license is installed
pub fn is_enterprise() -> bool {
    load_license().is_some()
}

/// Load and validate the license file
pub fn load_license() -> Option<License> {
    let content = std::fs::read_to_string(LICENSE_FILE).ok()?;
    let signed: SignedLicense = serde_json::from_str(content.trim()).ok()?;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Decode payload and signature
    let payload_bytes = b64.decode(&signed.payload).ok()?;
    let sig_bytes = b64.decode(&signed.signature).ok()?;

    // Verify Ed25519 signature using ring
    let public_key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        &LICENSE_PUBLIC_KEY,
    );
    public_key.verify(&payload_bytes, &sig_bytes).ok()?;

    // Parse payload
    let license: License = serde_json::from_slice(&payload_bytes).ok()?;

    // Check expiry
    let today = chrono_today();
    if license.expires < today {
        return None;
    }

    Some(license)
}

/// Get license status for the API
pub fn license_status() -> serde_json::Value {
    match load_license() {
        Some(lic) => serde_json::json!({
            "valid": true,
            "customer": lic.customer,
            "email": lic.email,
            "max_nodes": lic.max_nodes,
            "expires": lic.expires,
            "features": lic.features,
        }),
        None => serde_json::json!({
            "valid": false,
            "message": "No valid enterprise license found",
        }),
    }
}

// License signing is done exclusively in the PHP admin tool (adminsys/)
// using the Ed25519 private key. The binary only verifies with the public key.

fn chrono_today() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    // Approximate year/month/day from unix days (good enough for license expiry)
    let (y, m, d) = unix_days_to_date(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn unix_days_to_date(days: u64) -> (u64, u64, u64) {
    // Civil calendar from days since epoch (Algorithm from Howard Hinnant)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─── API Key Management ───

const API_KEYS_FILE: &str = "/etc/wolfstack/api_keys.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    /// SHA-256 hash of the actual key (we never store the raw key)
    pub key_hash: String,
    /// First 8 chars of the key for display (e.g. "wsk_a1b2...")
    pub key_prefix: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires: Option<String>,  // ISO 8601 date or None for never
    pub created: String,
    #[serde(default)]
    pub last_used: Option<String>,
    #[serde(default)]
    pub last_ip: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Available API scopes
pub const SCOPES: &[(&str, &str)] = &[
    ("*", "Full access (all endpoints)"),
    ("read", "Read-only access (GET endpoints)"),
    ("containers", "Manage containers (Docker + LXC)"),
    ("vms", "Manage virtual machines"),
    ("storage", "Manage storage mounts"),
    ("networking", "Manage networking"),
    ("backup", "Manage backups"),
    ("appstore", "Install/manage applications"),
    ("statuspage", "Manage status pages"),
    ("cluster", "Cluster management"),
    ("wolfrun", "WolfRun orchestration"),
];

fn default_enabled() -> bool { true }

static API_KEYS: LazyLock<RwLock<Vec<ApiKey>>> = LazyLock::new(|| {
    RwLock::new(load_keys_from_disk())
});

fn load_keys_from_disk() -> Vec<ApiKey> {
    match std::fs::read_to_string(API_KEYS_FILE) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_keys_to_disk(keys: &[ApiKey]) -> Result<(), String> {
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    let json = serde_json::to_string_pretty(keys)
        .map_err(|e| format!("Failed to serialize API keys: {}", e))?;
    let tmp = format!("{}.tmp", API_KEYS_FILE);
    std::fs::write(&tmp, &json)
        .map_err(|e| format!("Failed to write API keys: {}", e))?;
    std::fs::rename(&tmp, API_KEYS_FILE)
        .map_err(|e| format!("Failed to rename API keys file: {}", e))?;
    // Restrict permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(API_KEYS_FILE, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn generate_key() -> String {
    // Read 24 bytes from /dev/urandom for cryptographic randomness
    let mut bytes = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    } else {
        // Fallback: hash of high-resolution time + process ID (not ideal but functional)
        use sha2::Digest;
        let seed = format!("{}_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(), std::process::id());
        let hash = sha2::Sha256::digest(seed.as_bytes());
        bytes.copy_from_slice(&hash[..24]);
    }
    format!("wsk_{}", hex::encode(bytes)) // wsk_ + 48 hex chars = 52 chars
}

fn hash_key(raw_key: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(raw_key.as_bytes());
    hex::encode(hash)
}

/// Create a new API key. Returns (ApiKey metadata, raw key string).
/// The raw key is only returned once — we store only the hash.
pub fn create_key(name: &str, scopes: Vec<String>, expires: Option<String>) -> Result<(ApiKey, String), String> {
    if !is_enterprise() {
        return Err("Enterprise license required for API key management".into());
    }

    let raw_key = generate_key();
    let key_hash = hash_key(&raw_key);
    let prefix = format!("{}...", &raw_key[..12.min(raw_key.len())]);

    let api_key = ApiKey {
        id: format!("key_{}", now_timestamp_nanos()),
        name: name.to_string(),
        key_hash,
        key_prefix: prefix,
        scopes,
        expires,
        created: chrono_today(),
        last_used: None,
        last_ip: None,
        enabled: true,
    };

    let mut keys = API_KEYS.write().unwrap();
    keys.push(api_key.clone());
    save_keys_to_disk(&keys)?;

    Ok((api_key, raw_key))
}

/// List all API keys (metadata only, no raw keys)
pub fn list_keys() -> Vec<ApiKey> {
    API_KEYS.read().unwrap().clone()
}

/// Delete/revoke an API key by ID
pub fn delete_key(id: &str) -> Result<(), String> {
    let mut keys = API_KEYS.write().unwrap();
    let before = keys.len();
    keys.retain(|k| k.id != id);
    if keys.len() == before {
        return Err(format!("API key '{}' not found", id));
    }
    save_keys_to_disk(&keys)?;
    Ok(())
}

/// Validate a raw API key. Returns the ApiKey if valid.
/// Also updates last_used timestamp and IP.
pub fn validate_key(raw_key: &str, ip: Option<&str>) -> Option<ApiKey> {
    let key_hash = hash_key(raw_key);

    // Read lock for lookup — doesn't block other auth requests
    let result = {
        let keys = API_KEYS.read().unwrap();
        let found = keys.iter().find(|k| k.key_hash == key_hash && k.enabled)?;

        // Check expiry
        if let Some(ref exp) = found.expires {
            let today = chrono_today();
            if *exp < today {
                return None;
            }
        }
        found.clone()
    };

    // Write lock only to update usage tracking (best-effort)
    if let Ok(mut keys) = API_KEYS.write() {
        if let Some(found) = keys.iter_mut().find(|k| k.id == result.id) {
            let now = now_iso8601();
            found.last_used = Some(now);
            if let Some(ip) = ip {
                found.last_ip = Some(ip.to_string());
            }
            let _ = save_keys_to_disk(&keys);
        }
    }

    Some(result)
}

/// Check if an API key's scopes allow access to a given endpoint
pub fn scope_allows(key: &ApiKey, method: &str, path: &str) -> bool {
    // Full access
    if key.scopes.contains(&"*".to_string()) {
        return true;
    }

    // Read-only scope allows all GET requests
    if method == "GET" && key.scopes.contains(&"read".to_string()) {
        return true;
    }

    // Match path-based scopes
    for scope in &key.scopes {
        let allowed = match scope.as_str() {
            "containers" => path.starts_with("/api/containers") || path.starts_with("/api/docker") || path.starts_with("/api/lxc"),
            "vms" => path.starts_with("/api/vms"),
            "storage" => path.starts_with("/api/storage"),
            "networking" => path.starts_with("/api/networking") || path.starts_with("/api/dns") || path.starts_with("/api/firewall"),
            "backup" => path.starts_with("/api/backup"),
            "appstore" => path.starts_with("/api/appstore"),
            "statuspage" => path.starts_with("/api/statuspage"),
            "cluster" => path.starts_with("/api/cluster") || path.starts_with("/api/nodes"),
            "wolfrun" => path.starts_with("/api/wolfrun"),
            _ => false,
        };
        if allowed { return true; }
    }

    false
}

fn now_timestamp_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()
}

fn now_iso8601() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, m, d) = unix_days_to_date(secs / 86400);
    let rem = secs % 86400;
    let h = rem / 3600;
    let min = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, min, s)
}

// ─── Audit Logging ───

const AUDIT_LOG_FILE: &str = "/etc/wolfstack/api_audit.log";
const MAX_AUDIT_ENTRIES: usize = 10000;

static AUDIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub key_name: String,
    pub key_id: String,
    pub method: String,
    pub path: String,
    pub ip: String,
    pub status: u16,
}

/// Append an audit log entry, rotating if the file exceeds MAX_AUDIT_ENTRIES lines.
pub fn audit_log(entry: &AuditEntry) {
    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    // Serialize all audit file access through a mutex
    let _guard = match AUDIT_LOCK.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    maybe_rotate_audit_log();

    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_FILE)
    {
        let _ = writeln!(f, "{}", line);
    }
}

/// Rotate the audit log if it exceeds MAX_AUDIT_ENTRIES lines.
/// Keeps the most recent half of entries and discards the rest.
fn maybe_rotate_audit_log() {
    let meta = match std::fs::metadata(AUDIT_LOG_FILE) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Quick size check first — each JSON line is ~200 bytes, so skip if file is small
    if meta.len() < (MAX_AUDIT_ENTRIES as u64 * 150) {
        return;
    }

    let content = match std::fs::read_to_string(AUDIT_LOG_FILE) {
        Ok(c) => c,
        Err(_) => return,
    };

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() <= MAX_AUDIT_ENTRIES {
        return;
    }

    // Keep the most recent half
    let keep = MAX_AUDIT_ENTRIES / 2;
    let trimmed: String = lines[lines.len() - keep..]
        .iter()
        .map(|l| format!("{}\n", l))
        .collect();

    let _ = std::fs::write(AUDIT_LOG_FILE, trimmed);
}

/// Read recent audit log entries
pub fn read_audit_log(limit: usize) -> Vec<AuditEntry> {
    let content = match std::fs::read_to_string(AUDIT_LOG_FILE) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let entries: Vec<AuditEntry> = content.lines()
        .rev()
        .take(limit)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    entries
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_ed25519_verify() {
        // This payload+signature was generated by openssl with the matching private key
        let payload_json = r#"{"customer":"Test","email":"test@test.com","max_nodes":0,"expires":"2099-12-31","features":["api_keys"]}"#;
        let sig_b64 = "bv5ETiSJy4WRAfU2hD2zw+/lm5WIdC5k6hFliMEuZdW3QiKHEU89gKb33kzaqogU2TN5yJsltckjKYlMF1x7Cg==";

        let b64 = base64::engine::general_purpose::STANDARD;
        let sig_bytes = b64.decode(sig_b64).unwrap();
        assert_eq!(sig_bytes.len(), 64); // Ed25519 signature is 64 bytes

        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &LICENSE_PUBLIC_KEY,
        );
        assert!(public_key.verify(payload_json.as_bytes(), &sig_bytes).is_ok());

        // Verify a tampered payload fails
        let tampered = payload_json.replace("Test", "Fake");
        assert!(public_key.verify(tampered.as_bytes(), &sig_bytes).is_err());
    }

    #[test]
    fn test_unix_days_to_date() {
        // 2024-01-01 = day 19723
        let (y, m, d) = unix_days_to_date(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_scope_allows() {
        let key = ApiKey {
            id: "test".into(),
            name: "test".into(),
            key_hash: "".into(),
            key_prefix: "".into(),
            scopes: vec!["read".into(), "containers".into()],
            expires: None,
            created: "".into(),
            last_used: None,
            last_ip: None,
            enabled: true,
        };

        // Read scope allows GET on anything
        assert!(scope_allows(&key, "GET", "/api/vms"));
        // Containers scope allows POST on containers
        assert!(scope_allows(&key, "POST", "/api/containers/create"));
        // But not POST on VMs
        assert!(!scope_allows(&key, "POST", "/api/vms/create"));
    }

    #[test]
    fn test_wildcard_scope() {
        let key = ApiKey {
            id: "test".into(),
            name: "test".into(),
            key_hash: "".into(),
            key_prefix: "".into(),
            scopes: vec!["*".into()],
            expires: None,
            created: "".into(),
            last_used: None,
            last_ip: None,
            enabled: true,
        };

        assert!(scope_allows(&key, "POST", "/api/anything"));
        assert!(scope_allows(&key, "DELETE", "/api/vms/123"));
    }
}
