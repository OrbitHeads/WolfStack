// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Docker image update watcher — checks whether container images have newer
//! versions available in their upstream registries and optionally auto-updates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{error, warn};

const CONFIG_FILE: &str = "/etc/wolfstack/image-watcher.json";

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageWatcherConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
    #[serde(default)]
    pub default_policy: UpdatePolicy,
    #[serde(default)]
    pub container_policies: HashMap<String, ContainerUpdatePolicy>,
    #[serde(default)]
    pub update_history: Vec<ImageUpdateEvent>,
}

fn default_check_interval() -> u64 { 3600 }

impl Default for ImageWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_secs: default_check_interval(),
            default_policy: UpdatePolicy::default(),
            container_policies: HashMap::new(),
            update_history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePolicy {
    NotifyOnly,
    AutoUpdate,
    Ignore,
}

impl Default for UpdatePolicy {
    fn default() -> Self { Self::NotifyOnly }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerUpdatePolicy {
    #[serde(default = "default_notify_only")]
    pub policy: UpdatePolicy,
    #[serde(default = "default_true")]
    pub backup_before_update: bool,
    #[serde(default = "default_true")]
    pub health_check: bool,
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub auto_rollback: bool,
}

fn default_notify_only() -> UpdatePolicy { UpdatePolicy::NotifyOnly }
fn default_true() -> bool { true }
fn default_health_check_timeout() -> u64 { 60 }

impl Default for ContainerUpdatePolicy {
    fn default() -> Self {
        Self {
            policy: UpdatePolicy::NotifyOnly,
            backup_before_update: true,
            health_check: true,
            health_check_timeout_secs: default_health_check_timeout(),
            auto_rollback: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUpdateEvent {
    pub id: String,
    pub container_name: String,
    pub image: String,
    pub old_digest: String,
    pub new_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(default)]
    pub status: ImageUpdateStatus,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImageUpdateStatus {
    UpdateAvailable,
    BackingUp,
    Pulling,
    Recreating,
    HealthChecking,
    Completed,
    RolledBack,
    Failed,
}

impl Default for ImageUpdateStatus {
    fn default() -> Self { Self::UpdateAvailable }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCheckResult {
    pub container_name: String,
    pub image: String,
    pub local_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_digest: Option<String>,
    pub update_available: bool,
    pub last_checked: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════
// ─── Image Reference Parsing ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    pub registry: String,
    pub repo: String,
    pub tag: String,
}

impl ImageRef {
    /// Parse a Docker image reference into registry, repo, and tag components.
    ///
    /// Examples:
    /// - `nginx`            → registry-1.docker.io / library/nginx : latest
    /// - `user/repo:v2`     → registry-1.docker.io / user/repo    : v2
    /// - `ghcr.io/org/app:latest` → ghcr.io / org/app : latest
    pub fn parse(image: &str) -> Self {
        let (name, tag) = match image.rsplit_once(':') {
            // Guard against treating a port number as a tag, e.g. "host:5000/repo"
            Some((n, t)) if !t.contains('/') => (n, t.to_string()),
            _ => (image, "latest".to_string()),
        };

        // Determine if the first component is a registry hostname.
        // A hostname contains a dot or a colon (port), or is "localhost".
        let parts: Vec<&str> = name.splitn(2, '/').collect();

        if parts.len() == 1 {
            // Official image: "nginx"
            Self {
                registry: "registry-1.docker.io".into(),
                repo: format!("library/{}", parts[0]),
                tag,
            }
        } else {
            let first = parts[0];
            let rest = parts[1];

            if first.contains('.') || first.contains(':') || first == "localhost" {
                // Custom registry: "ghcr.io/org/app" or "localhost:5000/myimg"
                Self {
                    registry: first.into(),
                    repo: rest.into(),
                    tag,
                }
            } else {
                // Docker Hub user image: "user/repo"
                Self {
                    registry: "registry-1.docker.io".into(),
                    repo: name.into(),
                    tag,
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Config Persistence ───
// ═══════════════════════════════════════════════

impl ImageWatcherConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_FILE) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(dir) = std::path::Path::new(CONFIG_FILE).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_FILE, json).map_err(|e| e.to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── Local Digest ───
// ═══════════════════════════════════════════════

/// Get the image digest for a running container by inspecting Docker locally.
/// Returns the repo-digest string (e.g. `nginx@sha256:abc123...`).
pub fn get_local_digest(container_name: &str) -> Result<String, String> {
    // First, get the image name from the container
    let image_out = Command::new("docker")
        .args(["inspect", "--format", "{{.Config.Image}}", container_name])
        .output()
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;

    if !image_out.status.success() {
        return Err(format!(
            "docker inspect failed for container '{}': {}",
            container_name,
            String::from_utf8_lossy(&image_out.stderr).trim()
        ));
    }

    let image = String::from_utf8_lossy(&image_out.stdout).trim().to_string();
    if image.is_empty() {
        return Err(format!("No image found for container '{}'", container_name));
    }

    // Get the repo digest for the image
    let digest_out = Command::new("docker")
        .args(["image", "inspect", "--format", "{{index .RepoDigests 0}}", &image])
        .output()
        .map_err(|e| format!("Failed to inspect image '{}': {}", image, e))?;

    if !digest_out.status.success() {
        return Err(format!(
            "docker image inspect failed for '{}': {}",
            image,
            String::from_utf8_lossy(&digest_out.stderr).trim()
        ));
    }

    let digest = String::from_utf8_lossy(&digest_out.stdout).trim().to_string();
    if digest.is_empty() {
        return Err(format!("No repo digest available for image '{}' (locally built?)", image));
    }

    Ok(digest)
}

// ═══════════════════════════════════════════════
// ─── Registry Authentication ───
// ═══════════════════════════════════════════════

/// Token response from a registry's auth endpoint.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

/// Obtain a bearer token for pulling manifest metadata from a registry.
pub async fn get_registry_token(registry: &str, repo: &str) -> Result<String, String> {
    let url = match registry {
        "registry-1.docker.io" => format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            repo
        ),
        "ghcr.io" => format!(
            "https://ghcr.io/token?service=ghcr.io&scope=repository:{}:pull",
            repo
        ),
        other => {
            // Generic OCI token endpoint — try the standard path
            format!(
                "https://{}/token?service={}&scope=repository:{}:pull",
                other, other, repo
            )
        }
    };

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Token request to {} failed: {}", url, e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Token endpoint returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    let body: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    Ok(body.token)
}

// ═══════════════════════════════════════════════
// ─── Remote Digest ───
// ═══════════════════════════════════════════════

/// Fetch the digest of an image tag from its upstream registry via the V2 manifest API.
pub async fn get_remote_digest(image_ref: &ImageRef) -> Result<String, String> {
    let token = get_registry_token(&image_ref.registry, &image_ref.repo).await?;

    let url = format!(
        "https://{}/v2/{}/manifests/{}",
        image_ref.registry, image_ref.repo, image_ref.tag
    );

    let client = reqwest::Client::new();
    let resp = client
        .head(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json",
        )
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .send()
        .await
        .map_err(|e| format!("Manifest HEAD request to {} failed: {}", url, e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Registry returned {} for {}: {}",
            resp.status(),
            url,
            resp.text().await.unwrap_or_default()
        ));
    }

    resp.headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No Docker-Content-Digest header in response from {}", url))
}

// ═══════════════════════════════════════════════
// ─── Container Update Checking ───
// ═══════════════════════════════════════════════

/// Check a single container for available image updates.
pub async fn check_container_update(container_name: &str) -> Result<ImageCheckResult, String> {
    let now = chrono::Utc::now().to_rfc3339();

    // Get the image name from the container
    let image_out = Command::new("docker")
        .args(["inspect", "--format", "{{.Config.Image}}", container_name])
        .output()
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;

    if !image_out.status.success() {
        return Err(format!(
            "docker inspect failed for container '{}': {}",
            container_name,
            String::from_utf8_lossy(&image_out.stderr).trim()
        ));
    }

    let image = String::from_utf8_lossy(&image_out.stdout).trim().to_string();
    if image.is_empty() {
        return Err(format!("No image found for container '{}'", container_name));
    }

    // Get local digest
    let local_digest = match get_local_digest(container_name) {
        Ok(d) => d,
        Err(e) => {
            return Ok(ImageCheckResult {
                container_name: container_name.into(),
                image: image.clone(),
                local_digest: String::new(),
                remote_digest: None,
                update_available: false,
                last_checked: now,
                error: Some(format!("Could not get local digest: {}", e)),
            });
        }
    };

    // Parse the image reference and fetch the remote digest
    let image_ref = ImageRef::parse(&image);
    match get_remote_digest(&image_ref).await {
        Ok(remote) => {
            // Extract just the digest portion from the local repo-digest (after '@')
            let local_hash = local_digest
                .rsplit_once('@')
                .map(|(_, h)| h)
                .unwrap_or(&local_digest);
            let update_available = local_hash != remote;

            Ok(ImageCheckResult {
                container_name: container_name.into(),
                image,
                local_digest,
                remote_digest: Some(remote),
                update_available,
                last_checked: now,
                error: None,
            })
        }
        Err(e) => {
            warn!("Failed to check remote digest for {}: {}", image, e);
            Ok(ImageCheckResult {
                container_name: container_name.into(),
                image,
                local_digest,
                remote_digest: None,
                update_available: false,
                last_checked: now,
                error: Some(e),
            })
        }
    }
}

/// Check all running Docker containers for available image updates.
/// Containers with an `Ignore` policy are skipped.
pub async fn check_all_containers(config: &ImageWatcherConfig) -> Vec<ImageCheckResult> {
    // List all running container names
    let output = match Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            error!(
                "docker ps failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return Vec::new();
        }
        Err(e) => {
            error!("Failed to run docker ps: {}", e);
            return Vec::new();
        }
    };

    let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut results = Vec::new();

    for name in &names {
        // Determine effective policy for this container
        let policy = config
            .container_policies
            .get(name)
            .map(|cp| &cp.policy)
            .unwrap_or(&config.default_policy);

        if *policy == UpdatePolicy::Ignore {
            continue;
        }

        match check_container_update(name).await {
            Ok(result) => results.push(result),
            Err(e) => {
                warn!("Failed to check container '{}': {}", name, e);
                results.push(ImageCheckResult {
                    container_name: name.clone(),
                    image: String::new(),
                    local_digest: String::new(),
                    remote_digest: None,
                    update_available: false,
                    last_checked: chrono::Utc::now().to_rfc3339(),
                    error: Some(e),
                });
            }
        }
    }

    results
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_official_image() {
        let r = ImageRef::parse("nginx");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_official_image_with_tag() {
        let r = ImageRef::parse("redis:7-alpine");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/redis");
        assert_eq!(r.tag, "7-alpine");
    }

    #[test]
    fn parse_user_image() {
        let r = ImageRef::parse("user/repo:v2");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "user/repo");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn parse_user_image_no_tag() {
        let r = ImageRef::parse("myuser/myapp");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "myuser/myapp");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_custom_registry() {
        let r = ImageRef::parse("ghcr.io/org/app:latest");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repo, "org/app");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_custom_registry_with_port() {
        let r = ImageRef::parse("localhost:5000/myimage:dev");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repo, "myimage");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn parse_custom_registry_nested_repo() {
        let r = ImageRef::parse("registry.example.com/team/project/app:1.0");
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.repo, "team/project/app");
        assert_eq!(r.tag, "1.0");
    }

    #[test]
    fn config_serialization_roundtrip() {
        let mut config = ImageWatcherConfig::default();
        config.enabled = true;
        config.check_interval_secs = 1800;
        config.default_policy = UpdatePolicy::AutoUpdate;
        config.container_policies.insert(
            "my-app".into(),
            ContainerUpdatePolicy {
                policy: UpdatePolicy::AutoUpdate,
                backup_before_update: true,
                health_check: true,
                health_check_timeout_secs: 120,
                auto_rollback: false,
            },
        );
        config.update_history.push(ImageUpdateEvent {
            id: "evt-1".into(),
            container_name: "my-app".into(),
            image: "myuser/myapp:latest".into(),
            old_digest: "sha256:aaa".into(),
            new_digest: "sha256:bbb".into(),
            backup_id: Some("bk-123".into()),
            status: ImageUpdateStatus::Completed,
            timestamp: "2026-04-09T12:00:00Z".into(),
            error: None,
        });

        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let deserialized: ImageWatcherConfig =
            serde_json::from_str(&json).expect("deserialize");

        assert!(deserialized.enabled);
        assert_eq!(deserialized.check_interval_secs, 1800);
        assert_eq!(deserialized.default_policy, UpdatePolicy::AutoUpdate);
        assert_eq!(deserialized.container_policies.len(), 1);
        assert_eq!(deserialized.update_history.len(), 1);
        assert_eq!(deserialized.update_history[0].status, ImageUpdateStatus::Completed);
    }

    #[test]
    fn config_defaults_from_empty_json() {
        let config: ImageWatcherConfig = serde_json::from_str("{}").expect("deserialize");
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.default_policy, UpdatePolicy::NotifyOnly);
        assert!(config.container_policies.is_empty());
        assert!(config.update_history.is_empty());
    }

    #[test]
    fn update_policy_serde_snake_case() {
        let json = serde_json::to_string(&UpdatePolicy::NotifyOnly).unwrap();
        assert_eq!(json, "\"notify_only\"");

        let json = serde_json::to_string(&UpdatePolicy::AutoUpdate).unwrap();
        assert_eq!(json, "\"auto_update\"");

        let json = serde_json::to_string(&UpdatePolicy::Ignore).unwrap();
        assert_eq!(json, "\"ignore\"");

        // Round-trip
        let parsed: UpdatePolicy = serde_json::from_str("\"auto_update\"").unwrap();
        assert_eq!(parsed, UpdatePolicy::AutoUpdate);
    }

    #[test]
    fn image_update_status_serde_snake_case() {
        let json = serde_json::to_string(&ImageUpdateStatus::UpdateAvailable).unwrap();
        assert_eq!(json, "\"update_available\"");

        let json = serde_json::to_string(&ImageUpdateStatus::HealthChecking).unwrap();
        assert_eq!(json, "\"health_checking\"");

        let json = serde_json::to_string(&ImageUpdateStatus::RolledBack).unwrap();
        assert_eq!(json, "\"rolled_back\"");

        let parsed: ImageUpdateStatus = serde_json::from_str("\"rolled_back\"").unwrap();
        assert_eq!(parsed, ImageUpdateStatus::RolledBack);
    }
}
