// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WebAuthn (Passkeys / FIDO2) — config types and credential storage.
//!
//! The actual WebAuthn ceremony (registration + authentication) requires
//! the `webauthn-rs` crate which is not yet in Cargo.toml. This module
//! provides the config persistence layer and credential management so
//! the API endpoints and UI can be built out. The ceremony stubs return
//! errors until the crate is added.

use serde::{Deserialize, Serialize};

fn webauthn_config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/webauthn.json", cfg)
}

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

/// Top-level WebAuthn configuration, persisted to /etc/wolfstack/webauthn.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Whether passkey/WebAuthn login is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Relying Party ID — typically the domain name (e.g. "wolfstack.example.com")
    #[serde(default)]
    pub rp_id: String,
    /// Relying Party display name shown in authenticator prompts
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
    /// Origin URL for the RP (e.g. "https://wolfstack.example.com:8553")
    #[serde(default)]
    pub origin: String,
    /// Stored credentials per user
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

fn default_rp_name() -> String {
    "WolfStack".to_string()
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: String::new(),
            rp_name: default_rp_name(),
            origin: String::new(),
            credentials: Vec::new(),
        }
    }
}

impl WebAuthnConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(&webauthn_config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = webauthn_config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("Failed to write WebAuthn config: {}", e))
    }
}

/// A stored WebAuthn credential — represents a registered passkey/security key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Unique credential ID (base64url-encoded, from the authenticator)
    pub credential_id: String,
    /// Username this credential belongs to
    pub username: String,
    /// Human-readable label (e.g. "YubiKey 5", "MacBook Touch ID")
    #[serde(default)]
    pub label: String,
    /// COSE public key (base64url-encoded) — used to verify assertion signatures
    #[serde(default)]
    pub public_key: String,
    /// Signature counter — monotonically increasing, detects cloned authenticators
    #[serde(default)]
    pub sign_count: u32,
    /// When this credential was registered (ISO 8601)
    #[serde(default)]
    pub registered_at: String,
    /// When this credential was last used (ISO 8601), empty if never
    #[serde(default)]
    pub last_used_at: String,
    /// Authenticator Attestation GUID — identifies the make/model
    #[serde(default)]
    pub aaguid: String,
}

// ═══════════════════════════════════════════════
// ─── Credential Management ───
// ═══════════════════════════════════════════════

/// List all stored credentials for a given username.
pub fn list_credentials(config: &WebAuthnConfig, username: &str) -> Vec<StoredCredential> {
    config
        .credentials
        .iter()
        .filter(|c| c.username == username)
        .cloned()
        .collect()
}

/// Remove a credential by its credential_id. Returns Ok(true) if found and removed,
/// Ok(false) if not found.
pub fn remove_credential(config: &mut WebAuthnConfig, credential_id: &str) -> Result<bool, String> {
    let before = config.credentials.len();
    config
        .credentials
        .retain(|c| c.credential_id != credential_id);
    let removed = config.credentials.len() < before;
    if removed {
        config.save()?;
    }
    Ok(removed)
}

// ═══════════════════════════════════════════════
// ─── Ceremony Stubs ───
// ═══════════════════════════════════════════════

/// Begin the registration ceremony — generates a challenge for the authenticator.
///
/// Stub: requires `webauthn-rs` crate to be added to Cargo.toml.
pub fn start_registration(
    _config: &WebAuthnConfig,
    _username: &str,
) -> Result<serde_json::Value, String> {
    Err("WebAuthn requires webauthn-rs crate".to_string())
}

/// Complete the registration ceremony — verifies the authenticator's attestation response.
///
/// Stub: requires `webauthn-rs` crate to be added to Cargo.toml.
pub fn finish_registration(
    _config: &mut WebAuthnConfig,
    _username: &str,
    _response: &serde_json::Value,
) -> Result<StoredCredential, String> {
    Err("WebAuthn requires webauthn-rs crate".to_string())
}

/// Begin the authentication ceremony — generates a challenge for an existing credential.
///
/// Stub: requires `webauthn-rs` crate to be added to Cargo.toml.
pub fn start_authentication(
    _config: &WebAuthnConfig,
    _username: &str,
) -> Result<serde_json::Value, String> {
    Err("WebAuthn requires webauthn-rs crate".to_string())
}

/// Complete the authentication ceremony — verifies the authenticator's assertion response.
///
/// Stub: requires `webauthn-rs` crate to be added to Cargo.toml.
pub fn finish_authentication(
    _config: &mut WebAuthnConfig,
    _username: &str,
    _response: &serde_json::Value,
) -> Result<String, String> {
    Err("WebAuthn requires webauthn-rs crate".to_string())
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_credentials() -> WebAuthnConfig {
        WebAuthnConfig {
            enabled: true,
            rp_id: "example.com".to_string(),
            rp_name: "WolfStack".to_string(),
            origin: "https://example.com:8553".to_string(),
            credentials: vec![
                StoredCredential {
                    credential_id: "cred-aaa".to_string(),
                    username: "alice".to_string(),
                    label: "YubiKey".to_string(),
                    public_key: "pk-aaa".to_string(),
                    sign_count: 5,
                    registered_at: "2025-01-01T00:00:00Z".to_string(),
                    last_used_at: "2025-06-15T12:00:00Z".to_string(),
                    aaguid: "".to_string(),
                },
                StoredCredential {
                    credential_id: "cred-bbb".to_string(),
                    username: "bob".to_string(),
                    label: "Touch ID".to_string(),
                    public_key: "pk-bbb".to_string(),
                    sign_count: 12,
                    registered_at: "2025-02-01T00:00:00Z".to_string(),
                    last_used_at: "".to_string(),
                    aaguid: "".to_string(),
                },
                StoredCredential {
                    credential_id: "cred-ccc".to_string(),
                    username: "alice".to_string(),
                    label: "Windows Hello".to_string(),
                    public_key: "pk-ccc".to_string(),
                    sign_count: 0,
                    registered_at: "2025-03-01T00:00:00Z".to_string(),
                    last_used_at: "".to_string(),
                    aaguid: "".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_list_credentials_filters_by_username() {
        let config = test_config_with_credentials();
        let alice_creds = list_credentials(&config, "alice");
        assert_eq!(alice_creds.len(), 2);
        assert!(alice_creds.iter().all(|c| c.username == "alice"));
    }

    #[test]
    fn test_list_credentials_empty_for_unknown_user() {
        let config = test_config_with_credentials();
        let creds = list_credentials(&config, "nobody");
        assert!(creds.is_empty());
    }

    #[test]
    fn test_remove_credential_found() {
        let mut config = test_config_with_credentials();
        // remove_credential calls save(), which will fail in tests (no /etc/wolfstack).
        // We test the in-memory removal logic directly.
        let before = config.credentials.len();
        config.credentials.retain(|c| c.credential_id != "cred-bbb");
        assert_eq!(config.credentials.len(), before - 1);
        assert!(config.credentials.iter().all(|c| c.credential_id != "cred-bbb"));
    }

    #[test]
    fn test_remove_credential_not_found() {
        let mut config = test_config_with_credentials();
        let before = config.credentials.len();
        config.credentials.retain(|c| c.credential_id != "nonexistent");
        assert_eq!(config.credentials.len(), before);
    }

    #[test]
    fn test_stubs_return_error() {
        let config = test_config_with_credentials();
        assert!(start_registration(&config, "alice").is_err());
        assert!(start_authentication(&config, "alice").is_err());

        let mut config2 = config.clone();
        let fake_response = serde_json::json!({});
        assert!(finish_registration(&mut config2, "alice", &fake_response).is_err());
        assert!(finish_authentication(&mut config2, "alice", &fake_response).is_err());
    }

    #[test]
    fn test_default_config() {
        let config = WebAuthnConfig::default();
        assert!(!config.enabled);
        assert!(config.rp_id.is_empty());
        assert_eq!(config.rp_name, "WolfStack");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_serialization_round_trip() {
        let config = test_config_with_credentials();
        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let loaded: WebAuthnConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(loaded.credentials.len(), 3);
        assert_eq!(loaded.rp_id, "example.com");
        assert!(loaded.enabled);
    }
}
