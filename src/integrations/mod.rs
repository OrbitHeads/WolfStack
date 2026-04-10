// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Integration framework — connect WolfStack to third-party services
//!
//! Provides a pluggable `Connector` trait that each integration implements.
//! Credentials are stored AES-256-GCM encrypted (keyed from the cluster secret).
//! Instances and vault are persisted as JSON under `/etc/wolfstack/integrations/`.

pub mod connectors;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::RwLock;
use tracing::{info, warn, error};

// ═══════════════════════════════════════════════
// ─── Config file paths ───
// ═══════════════════════════════════════════════

const INTEGRATIONS_DIR: &str = "/etc/wolfstack/integrations";

fn instances_file() -> String {
    format!("{}/instances.json", INTEGRATIONS_DIR)
}

fn vault_file() -> String {
    format!("{}/vault.json", INTEGRATIONS_DIR)
}

// ═══════════════════════════════════════════════
// ─── Connector trait ───
// ═══════════════════════════════════════════════

/// Pluggable integration connector. Each third-party service (NetBird, TrueNAS,
/// Unifi, etc.) implements this trait.
///
/// Async methods return boxed futures for dyn-compatibility.
pub trait Connector: Send + Sync {
    /// Static metadata about this connector.
    fn info(&self) -> ConnectorInfo;

    /// What dashboard panels / data views this connector can provide.
    fn capabilities(&self) -> Vec<ConnectorCapability>;

    /// Check whether the remote service is reachable and healthy.
    fn health_check<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + 'a>>;

    /// Execute a named operation (e.g. "list_peers", "create_snapshot").
    fn execute<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        operation: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>>;

    /// Fetch data for a specific dashboard capability panel.
    fn dashboard_data<'a>(
        &'a self,
        instance: &'a IntegrationInstance,
        credentials: &'a serde_json::Value,
        capability_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>>;
}

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInfo {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub description: String,
    pub auth_methods: Vec<AuthMethod>,
    pub config_schema: Vec<ConfigField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorCapability {
    pub id: String,
    pub label: String,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Bearer,
    ApiKey,
    BasicAuth,
    OAuth2,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigField {
    pub name: String,
    pub label: String,
    pub field_type: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationInstance {
    pub id: String,
    pub connector_id: String,
    pub name: String,
    pub base_url: String,
    pub auth_method: AuthMethod,
    #[serde(default)]
    pub config: HashMap<String, String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: ServiceStatus,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub last_checked: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Online,
    Degraded,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub instance_id: String,
    pub auth_method: AuthMethod,
    /// Base64-encoded encrypted data: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub encrypted_data: String,
}

// ═══════════════════════════════════════════════
// ─── Integration State ───
// ═══════════════════════════════════════════════

pub struct IntegrationState {
    pub instances: RwLock<Vec<IntegrationInstance>>,
    pub health_cache: RwLock<HashMap<String, HealthStatus>>,
    pub vault: RwLock<Vec<StoredCredential>>,
    pub connectors: HashMap<String, Box<dyn Connector>>,
    encryption_key: Vec<u8>,
}

impl IntegrationState {
    /// Create a new IntegrationState, deriving the encryption key from the
    /// cluster secret via HKDF-SHA256.
    pub fn new(cluster_secret: &str) -> Self {
        // Derive a 32-byte AES-256 key from the cluster secret
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"wolfstack-integrations-v1");
        let prk = salt.extract(cluster_secret.as_bytes());
        let okm = prk.expand(&[b"credential-encryption"], &ring::aead::AES_256_GCM)
            .expect("HKDF expand failed");
        let mut key_bytes = vec![0u8; 32];
        okm.fill(&mut key_bytes).expect("HKDF fill failed");

        // Register built-in connectors
        let mut connector_map: HashMap<String, Box<dyn Connector>> = HashMap::new();
        connectors::register_all(&mut connector_map);

        // Load persisted instances
        let instances = Self::load_json::<Vec<IntegrationInstance>>(&instances_file())
            .unwrap_or_default();

        // Load persisted vault
        let vault = Self::load_json::<Vec<StoredCredential>>(&vault_file())
            .unwrap_or_default();

        info!(
            "Integrations: loaded {} instances, {} credentials, {} connectors",
            instances.len(),
            vault.len(),
            connector_map.len()
        );

        Self {
            instances: RwLock::new(instances),
            health_cache: RwLock::new(HashMap::new()),
            vault: RwLock::new(vault),
            connectors: connector_map,
            encryption_key: key_bytes,
        }
    }

    // ─── Instance CRUD ───────────────────────────

    pub fn list_instances(&self) -> Vec<IntegrationInstance> {
        self.instances.read().unwrap().clone()
    }

    pub fn get_instance(&self, id: &str) -> Option<IntegrationInstance> {
        self.instances.read().unwrap().iter().find(|i| i.id == id).cloned()
    }

    pub fn create_instance(&self, mut instance: IntegrationInstance) -> Result<IntegrationInstance, String> {
        let now = chrono::Utc::now().to_rfc3339();
        if instance.id.is_empty() {
            instance.id = uuid::Uuid::new_v4().to_string();
        }
        instance.created_at = now.clone();
        instance.updated_at = now;

        // Verify the connector_id is known
        if !self.connectors.contains_key(&instance.connector_id) {
            return Err(format!("Unknown connector: {}", instance.connector_id));
        }

        let mut instances = self.instances.write().unwrap();
        instances.push(instance.clone());
        drop(instances);
        self.save_instances();
        info!("Integration created: {} ({})", instance.name, instance.id);
        Ok(instance)
    }

    pub fn update_instance(&self, id: &str, mut updated: IntegrationInstance) -> Result<IntegrationInstance, String> {
        let mut instances = self.instances.write().unwrap();
        let pos = instances.iter().position(|i| i.id == id)
            .ok_or_else(|| format!("Instance not found: {}", id))?;

        updated.id = id.to_string();
        updated.created_at = instances[pos].created_at.clone();
        updated.updated_at = chrono::Utc::now().to_rfc3339();
        instances[pos] = updated.clone();
        drop(instances);
        self.save_instances();
        info!("Integration updated: {} ({})", updated.name, id);
        Ok(updated)
    }

    pub fn delete_instance(&self, id: &str) -> Result<(), String> {
        let mut instances = self.instances.write().unwrap();
        let before = instances.len();
        instances.retain(|i| i.id != id);
        if instances.len() == before {
            return Err(format!("Instance not found: {}", id));
        }
        drop(instances);
        self.save_instances();

        // Also remove credentials and cached health
        self.delete_credential(id);
        self.health_cache.write().unwrap().remove(id);

        info!("Integration deleted: {}", id);
        Ok(())
    }

    // ─── Credential vault (AES-256-GCM) ─────────

    /// Encrypt and store a credential for the given instance.
    pub fn store_credential(
        &self,
        instance_id: &str,
        auth_method: AuthMethod,
        plaintext: &serde_json::Value,
    ) -> Result<(), String> {
        let plaintext_bytes = serde_json::to_vec(plaintext)
            .map_err(|e| format!("Failed to serialize credential: {}", e))?;

        let encrypted = self.encrypt(&plaintext_bytes)?;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        );

        let cred = StoredCredential {
            instance_id: instance_id.to_string(),
            auth_method,
            encrypted_data: encoded,
        };

        let mut vault = self.vault.write().unwrap();
        vault.retain(|c| c.instance_id != instance_id);
        vault.push(cred);
        drop(vault);
        self.save_vault();
        Ok(())
    }

    /// Decrypt and return the credential for the given instance.
    pub fn get_credential(&self, instance_id: &str) -> Result<serde_json::Value, String> {
        let vault = self.vault.read().unwrap();
        let cred = vault.iter().find(|c| c.instance_id == instance_id)
            .ok_or_else(|| format!("No credential for instance: {}", instance_id))?;

        let encrypted = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &cred.encrypted_data,
        ).map_err(|e| format!("Base64 decode failed: {}", e))?;

        let plaintext = self.decrypt(&encrypted)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to deserialize credential: {}", e))
    }

    /// Remove the credential for the given instance.
    pub fn delete_credential(&self, instance_id: &str) {
        let mut vault = self.vault.write().unwrap();
        vault.retain(|c| c.instance_id != instance_id);
        drop(vault);
        self.save_vault();
    }

    // ─── Health checking ─────────────────────────

    /// Run health checks on all enabled instances, updating the cache.
    pub async fn check_all_health(&self) {
        let instances = self.instances.read().unwrap().clone();
        for instance in &instances {
            if !instance.enabled {
                continue;
            }
            let connector = match self.connectors.get(&instance.connector_id) {
                Some(c) => c,
                None => {
                    warn!("No connector for instance {} ({})", instance.name, instance.connector_id);
                    continue;
                }
            };
            let credentials = self.get_credential(&instance.id).unwrap_or_default();
            let status = connector.health_check(instance, &credentials).await;
            self.health_cache.write().unwrap().insert(instance.id.clone(), status);
        }
    }

    /// Get the cached health status for an instance.
    pub fn get_health(&self, instance_id: &str) -> Option<HealthStatus> {
        self.health_cache.read().unwrap().get(instance_id).cloned()
    }

    // ─── Action execution ────────────────────────

    /// Execute an operation on a specific integration instance.
    pub async fn execute_action(
        &self,
        instance_id: &str,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let instance = self.get_instance(instance_id)
            .ok_or_else(|| format!("Instance not found: {}", instance_id))?;

        if !instance.enabled {
            return Err("Integration instance is disabled".to_string());
        }

        let connector = self.connectors.get(&instance.connector_id)
            .ok_or_else(|| format!("No connector for: {}", instance.connector_id))?;

        let credentials = self.get_credential(instance_id)
            .map_err(|e| format!("Credential error: {}", e))?;

        connector.execute(&instance, &credentials, operation, params).await
    }

    /// Fetch dashboard data for a capability panel.
    pub async fn get_dashboard_data(
        &self,
        instance_id: &str,
        capability_id: &str,
    ) -> Result<serde_json::Value, String> {
        let instance = self.get_instance(instance_id)
            .ok_or_else(|| format!("Instance not found: {}", instance_id))?;

        let connector = self.connectors.get(&instance.connector_id)
            .ok_or_else(|| format!("No connector for: {}", instance.connector_id))?;

        let credentials = self.get_credential(instance_id)
            .map_err(|e| format!("Credential error: {}", e))?;

        connector.dashboard_data(&instance, &credentials, capability_id).await
    }

    // ─── Encryption helpers (AES-256-GCM) ────────

    /// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext || tag.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use ring::aead;
        use ring::rand::{SystemRandom, SecureRandom};

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.encryption_key)
            .map_err(|_| "Failed to create AES key".to_string())?;
        let key = aead::LessSafeKey::new(key);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| "Failed to generate nonce".to_string())?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| "Encryption failed".to_string())?;

        // Prepend nonce: nonce (12) || ciphertext || tag (16)
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    /// Decrypt nonce || ciphertext || tag back to plaintext.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use ring::aead;

        if data.len() < 12 + 16 {
            return Err("Encrypted data too short".to_string());
        }

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.encryption_key)
            .map_err(|_| "Failed to create AES key".to_string())?;
        let key = aead::LessSafeKey::new(key);

        let (nonce_bytes, ciphertext_and_tag) = data.split_at(12);
        let nonce = aead::Nonce::assume_unique_for_key(
            nonce_bytes.try_into().map_err(|_| "Invalid nonce length".to_string())?
        );

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| "Decryption failed — wrong key or corrupted data".to_string())?;

        Ok(plaintext.to_vec())
    }

    // ─── JSON persistence helpers ────────────────

    fn load_json<T: serde::de::DeserializeOwned>(path: &str) -> Option<T> {
        match std::fs::read_to_string(path) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(val) => Some(val),
                Err(e) => {
                    warn!("Failed to parse {}: {}", path, e);
                    None
                }
            },
            Err(_) => None,
        }
    }

    fn save_instances(&self) {
        let instances = self.instances.read().unwrap();
        Self::save_json(&instances_file(), &*instances);
    }

    fn save_vault(&self) {
        let vault = self.vault.read().unwrap();
        Self::save_json(&vault_file(), &*vault);
    }

    fn save_json<T: Serialize>(path: &str, data: &T) {
        if let Err(e) = std::fs::create_dir_all(INTEGRATIONS_DIR) {
            error!("Failed to create integrations dir: {}", e);
            return;
        }
        match serde_json::to_string_pretty(data) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    error!("Failed to write {}: {}", path, e);
                }
            }
            Err(e) => error!("Failed to serialize for {}: {}", path, e),
        }
    }
}
