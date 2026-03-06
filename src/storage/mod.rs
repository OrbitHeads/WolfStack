// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Storage Manager — mount and manage S3, NFS, directory, and WolfDisk storage
//!
//! Supports:
//! - S3 storage via rust-s3 (pure Rust, native, works on IBM Power/ppc64le)
//! - S3 storage via s3fs-fuse (fallback)
//! - SSHFS mounts via sshfs
//! - NFS storage via mount -t nfs
//! - Local directory bind mounts
//! - WolfDisk mounts via wolfdiskctl
//! - Global mounts replicated across the cluster
//! - Import of S3 configs from rclone.conf

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{warn, error};
use chrono::Utc;

const CONFIG_PATH: &str = "/etc/wolfstack/storage.json";
const MOUNT_BASE: &str = "/mnt/wolfstack";

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    S3,
    Nfs,
    Directory,
    Wolfdisk,
    Sshfs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_s3_provider")]
    pub provider: String,
    #[serde(default)]
    pub bucket: String,
}

fn default_s3_provider() -> String { "AWS".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMount {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub mount_type: MountType,
    pub source: String,          // NFS: server:/path, Directory: /local/path, WolfDisk: path
    pub mount_point: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub global: bool,            // replicate to cluster nodes
    #[serde(default)]
    pub auto_mount: bool,        // mount on boot
    #[serde(default)]
    pub s3_config: Option<S3Config>,
    #[serde(default)]
    pub nfs_options: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub error_message: Option<String>,
    pub created_at: String,
}

fn default_status() -> String { "unmounted".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub mounts: Vec<StorageMount>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig { mounts: Vec::new() }
    }
}

// ─── Config Persistence ───

pub fn load_config() -> StorageConfig {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(content) => {
            serde_json::from_str(&content).unwrap_or_else(|e| {
                error!("Failed to parse storage config: {}", e);
                StorageConfig::default()
            })
        }
        Err(_) => StorageConfig::default(),
    }
}

pub fn save_config(config: &StorageConfig) -> Result<(), String> {
    // Ensure directory exists
    let dir = Path::new(CONFIG_PATH).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(CONFIG_PATH, json)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

// ─── Mount ID Generation ───

pub fn generate_id(name: &str) -> String {
    let slug: String = name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let short_uuid = &uuid::Uuid::new_v4().to_string()[..8];
    format!("{}-{}", slug, short_uuid)
}

// ─── Status Check ───

pub fn check_mounted(mount_point: &str) -> bool {
    Command::new("mountpoint")
        .arg("-q")
        .arg(mount_point)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get the status of all mounts (refreshes live status)
pub fn list_mounts() -> Vec<StorageMount> {
    let mut config = load_config();
    for mount in &mut config.mounts {
        if check_mounted(&mount.mount_point) {
            mount.status = "mounted".to_string();
            mount.error_message = None;
        } else if mount.status == "mounted" {
            // Was mounted but no longer — mark as unmounted
            mount.status = "unmounted".to_string();
        }
        // Preserve "error" status with error_message intact
    }
    config.mounts
}

// ─── Mount Operations ───

/// Mount a storage entry by ID
pub fn mount_storage(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.mounts.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    // Already mounted?
    if check_mounted(&config.mounts[idx].mount_point) {
        config.mounts[idx].status = "mounted".to_string();
        save_config(&config)?;
        return Ok("Already mounted".to_string());
    }
    
    // Create mount point directory
    fs::create_dir_all(&config.mounts[idx].mount_point)
        .map_err(|e| format!("Failed to create mount point: {}", e))?;
    
    let result = match config.mounts[idx].mount_type {
        MountType::S3 => mount_s3(&config.mounts[idx]),
        MountType::Nfs => mount_nfs(&config.mounts[idx]),
        MountType::Directory => mount_directory(&config.mounts[idx]),
        MountType::Wolfdisk => mount_wolfdisk(&config.mounts[idx]),
        MountType::Sshfs => mount_sshfs(&config.mounts[idx]),
    };
    
    match result {
        Ok(msg) => {
            config.mounts[idx].status = "mounted".to_string();
            config.mounts[idx].error_message = None;
            config.mounts[idx].enabled = true;
            save_config(&config)?;

            Ok(msg)
        }
        Err(e) => {
            config.mounts[idx].status = "error".to_string();
            config.mounts[idx].error_message = Some(e.clone());
            save_config(&config)?;
            Err(e)
        }
    }
}

/// Unmount a storage entry by ID
pub fn unmount_storage(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.mounts.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    if !check_mounted(&config.mounts[idx].mount_point) {
        config.mounts[idx].status = "unmounted".to_string();
        save_config(&config)?;
        return Ok("Not mounted".to_string());
    }
    
    // For S3 mounts, try fusermount first (for s3fs), then regular umount (for rust-s3 bind mounts)
    let output = if config.mounts[idx].mount_type == MountType::S3 {
        // Try fusermount first (s3fs), fall back to regular umount (rust-s3 bind mount)
        let fuse_result = Command::new("fusermount")
            .args(["-u", &config.mounts[idx].mount_point])
            .output();
        match &fuse_result {
            Ok(o) if o.status.success() => fuse_result,
            _ => Command::new("umount")
                .arg(&config.mounts[idx].mount_point)
                .output(),
        }
    } else {
        Command::new("umount")
            .arg(&config.mounts[idx].mount_point)
            .output()
    };
    
    match output {
        Ok(o) if o.status.success() => {
            config.mounts[idx].status = "unmounted".to_string();
            config.mounts[idx].error_message = None;
            save_config(&config)?;

            Ok("Unmounted successfully".to_string())
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            // Try lazy unmount as fallback
            let _ = Command::new("umount").args(["-l", &config.mounts[idx].mount_point]).output();
            config.mounts[idx].status = "unmounted".to_string();
            save_config(&config)?;
            Ok(format!("Unmounted (lazy): {}", err))
        }
        Err(e) => Err(format!("Failed to unmount: {}", e)),
    }
}

/// Create a new mount entry and optionally mount it
pub fn create_mount(mut mount: StorageMount, do_mount: bool) -> Result<StorageMount, String> {
    let mut config = load_config();
    
    // Generate ID if empty
    if mount.id.is_empty() {
        mount.id = generate_id(&mount.name);
    }
    
    // Default mount point
    if mount.mount_point.is_empty() {
        mount.mount_point = format!("{}/{}", MOUNT_BASE, mount.id);
    }
    
    // Set created_at
    if mount.created_at.is_empty() {
        mount.created_at = Utc::now().to_rfc3339();
    }
    
    mount.status = "unmounted".to_string();
    
    // Check for duplicate mount points
    if config.mounts.iter().any(|m| m.mount_point == mount.mount_point) {
        return Err(format!("Mount point '{}' already in use", mount.mount_point));
    }
    
    // Check for duplicate names (prevents double-adding the same storage)
    if config.mounts.iter().any(|m| m.name == mount.name) {
        return Err(format!("A mount named '{}' already exists", mount.name));
    }
    
    config.mounts.push(mount.clone());
    save_config(&config)?;
    
    if do_mount {
        mount_storage(&mount.id)?;
        // Refresh status
        let config = load_config();
        if let Some(m) = config.mounts.iter().find(|m| m.id == mount.id) {
            return Ok(m.clone());
        }
    }
    
    Ok(mount)
}

/// Remove a mount entry (unmount first if needed)
pub fn remove_mount(id: &str) -> Result<String, String> {
    let mut config = load_config();
    
    if let Some(mount) = config.mounts.iter().find(|m| m.id == id) {
        // Unmount if currently mounted
        if check_mounted(&mount.mount_point) {
            let _ = unmount_storage(id);
        }
    }
    
    // Reload after potential unmount
    config = load_config();
    let len_before = config.mounts.len();
    config.mounts.retain(|m| m.id != id);
    
    if config.mounts.len() == len_before {
        return Err(format!("Mount '{}' not found", id));
    }
    
    save_config(&config)?;
    Ok("Mount removed".to_string())
}

/// Duplicate a mount entry — clone with new ID and "(copy)" name
pub fn duplicate_mount(id: &str) -> Result<StorageMount, String> {
    let mut config = load_config();
    let original = config.mounts.iter().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?
        .clone();
    
    let new_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let mut dup = original.clone();
    dup.id = new_id.clone();
    dup.name = format!("{} (copy)", original.name);
    dup.mount_point = format!("{}/{}", MOUNT_BASE, new_id);
    dup.status = "unmounted".to_string();
    dup.error_message = None;
    dup.created_at = Utc::now().to_rfc3339();
    
    config.mounts.push(dup.clone());
    save_config(&config)?;
    Ok(dup)
}

/// Update a mount entry
pub fn update_mount(id: &str, updates: serde_json::Value) -> Result<StorageMount, String> {
    let mut config = load_config();
    let mount = config.mounts.iter_mut().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;
    
    // Apply updates — basic fields
    if let Some(name) = updates.get("name").and_then(|v| v.as_str()) {
        mount.name = name.to_string();
    }
    if let Some(global) = updates.get("global").and_then(|v| v.as_bool()) {
        mount.global = global;
    }
    if let Some(auto_mount) = updates.get("auto_mount").and_then(|v| v.as_bool()) {
        mount.auto_mount = auto_mount;
    }
    if let Some(enabled) = updates.get("enabled").and_then(|v| v.as_bool()) {
        mount.enabled = enabled;
    }
    if let Some(mount_point) = updates.get("mount_point").and_then(|v| v.as_str()) {
        if !mount_point.is_empty() {
            mount.mount_point = mount_point.to_string();
        }
    }
    if let Some(source) = updates.get("source").and_then(|v| v.as_str()) {
        mount.source = source.to_string();
    }
    if let Some(nfs_opts) = updates.get("nfs_options").and_then(|v| v.as_str()) {
        mount.nfs_options = if nfs_opts.is_empty() { None } else { Some(nfs_opts.to_string()) };
    }
    
    // Apply S3 config updates
    if let Some(s3_updates) = updates.get("s3_config") {
        let s3 = mount.s3_config.get_or_insert_with(|| S3Config {
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: String::new(),
            endpoint: String::new(),
            provider: default_s3_provider(),
            bucket: String::new(),
        });
        if let Some(v) = s3_updates.get("bucket").and_then(|v| v.as_str()) {
            s3.bucket = v.to_string();
        }
        if let Some(v) = s3_updates.get("access_key_id").and_then(|v| v.as_str()) {
            s3.access_key_id = v.to_string();
        }
        if let Some(v) = s3_updates.get("secret_access_key").and_then(|v| v.as_str()) {
            // Only update if not the placeholder
            if v != "••••••••" {
                s3.secret_access_key = v.to_string();
            }
        }
        if let Some(v) = s3_updates.get("region").and_then(|v| v.as_str()) {
            s3.region = v.to_string();
        }
        if let Some(v) = s3_updates.get("endpoint").and_then(|v| v.as_str()) {
            s3.endpoint = v.to_string();
        }
        if let Some(v) = s3_updates.get("provider").and_then(|v| v.as_str()) {
            s3.provider = v.to_string();
        }
        // Update source to reflect bucket
        if !s3.bucket.is_empty() {
            mount.source = format!("s3:{}", s3.bucket);
        }
    }
    
    let result = mount.clone();
    save_config(&config)?;
    Ok(result)
}

// ─── Type-specific mount implementations ───

fn mount_s3(mount: &StorageMount) -> Result<String, String> {
    let s3 = mount.s3_config.as_ref()
        .ok_or("S3 config is required for S3 mounts")?;
    
    if s3.bucket.is_empty() {
        return Err("Bucket name is required for S3 mounts".to_string());
    }
    
    // Strategy:
    // 1. Try rust-s3 native sync (pure Rust, works on IBM Power/ppc64le)
    // 2. Fall back to s3fs-fuse if available
    // 3. Try installing s3fs as last resort
    match mount_s3_via_rust_s3(mount, s3) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            warn!("rust-s3 mount failed ({}), trying s3fs fallback", e);
            if has_s3fs() {
                mount_s3_via_s3fs(mount, s3)
            } else {
                install_s3fs().ok();
                if has_s3fs() {
                    mount_s3_via_s3fs(mount, s3)
                } else {
                    Err(format!("S3 mount failed: rust-s3 error: {}", e))
                }
            }
        }
    }
}

/// Mount S3 using s3fs-fuse — fast, native, handles offline endpoints gracefully
fn mount_s3_via_s3fs(mount: &StorageMount, s3: &S3Config) -> Result<String, String> {
    // Write credentials file: access_key:secret_key
    let creds_dir = "/etc/wolfstack/s3";
    fs::create_dir_all(creds_dir)
        .map_err(|e| format!("Failed to create credentials dir: {}", e))?;
    
    let creds_path = format!("{}/{}.passwd", creds_dir, mount.id);
    fs::write(&creds_path, format!("{}:{}", s3.access_key_id, s3.secret_access_key))
        .map_err(|e| format!("Failed to write credentials: {}", e))?;
    
    // Set restrictive permissions (s3fs requires 600)
    Command::new("chmod").args(["600", &creds_path]).output().ok();
    
    // Build s3fs arguments
    let mut args = vec![
        s3.bucket.clone(),
        mount.mount_point.clone(),
        "-o".to_string(), format!("passwd_file={}", creds_path),
        "-o".to_string(), "allow_other".to_string(),
        "-o".to_string(), "mp_umask=022".to_string(),
        "-o".to_string(), "use_cache=/tmp/wolfstack-s3cache".to_string(),
        "-o".to_string(), "ensure_diskfree=1024".to_string(),  // keep 1GB free
        "-o".to_string(), "connect_timeout=10".to_string(),
        "-o".to_string(), "retries=3".to_string(),
    ];
    
    // Custom endpoint for non-AWS providers (R2, MinIO, Wasabi, etc.)
    if !s3.endpoint.is_empty() {
        let endpoint = if !s3.endpoint.starts_with("http://") && !s3.endpoint.starts_with("https://") {
            format!("https://{}", s3.endpoint)
        } else {
            s3.endpoint.clone()
        };
        args.push("-o".to_string());
        args.push(format!("url={}", endpoint));
        args.push("-o".to_string());
        args.push("use_path_request_style".to_string());
    }
    
    // Region
    if !s3.region.is_empty() {
        args.push("-o".to_string());
        args.push(format!("endpoint={}", s3.region));
    }
    
    let output = Command::new("s3fs")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run s3fs: {}", e))?;
    
    if output.status.success() {
        // Verify mount — s3fs launches as daemon, may take a moment
        for attempt in 0..4 {
            std::thread::sleep(std::time::Duration::from_millis(500 * (attempt + 1)));
            if check_mounted(&mount.mount_point) {
                return Ok("S3 storage mounted via s3fs".to_string());
            }
        }
        // Mount point still not detected but s3fs started OK
        // Trust the exit code — it may just be slow
        warn!("s3fs started but mount point detection slow for {}", mount.mount_point);
        Ok("S3 storage mounted via s3fs (mount may still be initializing)".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(format!("s3fs mount failed: {}", stderr))
    }
}

/// Mount S3 using rust-s3 — pure Rust, native, works on IBM Power/ppc64le
/// Syncs bucket contents to a local cache directory and bind-mounts it
fn mount_s3_via_rust_s3(mount: &StorageMount, s3: &S3Config) -> Result<String, String> {
    use s3::bucket::Bucket;
    use s3::creds::Credentials;
    use s3::region::Region;

    // Build credentials
    let credentials = Credentials::new(
        Some(&s3.access_key_id),
        Some(&s3.secret_access_key),
        None, None, None,
    ).map_err(|e| format!("Invalid S3 credentials: {}", e))?;

    // Build region
    let region = if !s3.endpoint.is_empty() {
        // Ensure endpoint has a scheme
        let endpoint = if !s3.endpoint.starts_with("http://") && !s3.endpoint.starts_with("https://") {
            format!("https://{}", s3.endpoint)
        } else {
            s3.endpoint.clone()
        };

        Region::Custom {
            region: if s3.region.is_empty() { "us-east-1".to_string() } else { s3.region.clone() },
            endpoint,
        }
    } else {
        let region = s3.region.parse::<Region>()
            .unwrap_or(Region::UsEast1);

        region
    };

    // Create bucket handle
    let bucket = Bucket::new(&s3.bucket, region, credentials)
        .map_err(|e| format!("Failed to create S3 bucket handle: {}", e))?
        .with_path_style();

    // Create local cache directory for this mount
    let cache_dir = format!("/var/cache/wolfstack/s3/{}", mount.id);
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create S3 cache dir: {}", e))?;

    // Use tokio runtime to sync bucket contents
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;

    let sync_result = rt.block_on(async {
        // Wrap the entire S3 operation in a timeout
        let timeout_duration = std::time::Duration::from_secs(30);
        match tokio::time::timeout(timeout_duration, async {
            // List objects in bucket (top-level, first 1000)
            let list = bucket.list("".to_string(), None).await
                .map_err(|e| format!("Failed to list S3 bucket '{}': {}", s3.bucket, e))?;

            let mut synced = 0usize;
            for item in &list {
                for obj in &item.contents {
                    let key = &obj.key;
                    // Skip directory markers
                    if key.ends_with('/') {
                        let dir_path = format!("{}/{}", cache_dir, key);
                        fs::create_dir_all(&dir_path).ok();
                        continue;
                    }

                    let local_path = format!("{}/{}", cache_dir, key);

                    // Create parent directories
                    if let Some(parent) = Path::new(&local_path).parent() {
                        fs::create_dir_all(parent).ok();
                    }

                    // Check if local file exists and matches size
                    let needs_download = match fs::metadata(&local_path) {
                        Ok(meta) => meta.len() != obj.size,
                        Err(_) => true,
                    };

                    if needs_download {
                        match bucket.get_object(key).await {
                            Ok(response) => {
                                if let Err(e) = fs::write(&local_path, response.bytes()) {
                                    error!("Failed to write {}: {}", local_path, e);
                                } else {
                                    synced += 1;
                                }
                            }
                            Err(e) => {
                                error!("Failed to download s3://{}/{}: {}", s3.bucket, key, e);
                            }
                        }
                    }
                }
            }

            Ok::<usize, String>(synced)
        }).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "S3 connection timed out after 30s — check endpoint '{}', credentials, and bucket '{}'",
                s3.endpoint, s3.bucket
            )),
        }
    })?;

    // Bind-mount the cache directory to the mount point
    fs::create_dir_all(&mount.mount_point)
        .map_err(|e| format!("Failed to create mount point: {}", e))?;

    let output = Command::new("mount")
        .args(["--bind", &cache_dir, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to bind mount: {}", e))?;

    if output.status.success() {

        Ok(format!("S3 storage mounted via rust-s3 ({} objects synced)", sync_result))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Bind mount failed after S3 sync: {}", stderr))
    }
}

fn mount_nfs(mount: &StorageMount) -> Result<String, String> {
    // Ensure nfs-common is installed
    if !Path::new("/sbin/mount.nfs").exists() && !Path::new("/usr/sbin/mount.nfs").exists() {

        let distro = crate::installer::detect_distro();
        let (pkg_mgr, pkg_name) = match distro {
            crate::installer::DistroFamily::Debian => ("apt-get", "nfs-common"),
            crate::installer::DistroFamily::RedHat => ("dnf", "nfs-utils"),
            crate::installer::DistroFamily::Suse => ("zypper", "nfs-client"),
            crate::installer::DistroFamily::Unknown => ("apt-get", "nfs-common"),
        };
        let install = Command::new(pkg_mgr)
            .args(["install", "-y", pkg_name])
            .output()
            .map_err(|e| format!("Failed to install {}: {}", pkg_name, e))?;
        if !install.status.success() {
            return Err(format!("Failed to install {}: {}",
                pkg_name, String::from_utf8_lossy(&install.stderr)));
        }
    }
    
    let options = mount.nfs_options.as_deref().unwrap_or("rw,soft,timeo=50");
    
    let output = Command::new("mount")
        .args(["-t", "nfs", "-o", options, &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    
    if output.status.success() {
        Ok("NFS storage mounted".to_string())
    } else {
        Err(format!("NFS mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn mount_directory(mount: &StorageMount) -> Result<String, String> {
    if !Path::new(&mount.source).exists() {
        return Err(format!("Source directory '{}' does not exist", mount.source));
    }
    
    let output = Command::new("mount")
        .args(["--bind", &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    
    if output.status.success() {
        Ok("Directory bind-mounted".to_string())
    } else {
        Err(format!("Bind mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn mount_wolfdisk(mount: &StorageMount) -> Result<String, String> {
    // Check if wolfdiskctl exists
    if !Path::new("/usr/local/bin/wolfdiskctl").exists() 
        && !Path::new("/opt/wolfdisk/wolfdiskctl").exists() {
        return Err("WolfDisk is not installed. Install it first via Components.".to_string());
    }
    
    let output = Command::new("wolfdiskctl")
        .args(["mount", &mount.source, &mount.mount_point])
        .output()
        .map_err(|e| format!("Failed to run wolfdiskctl: {}", e))?;
    
    if output.status.success() {
        Ok("WolfDisk storage mounted".to_string())
    } else {
        Err(format!("WolfDisk mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn mount_sshfs(mount: &StorageMount) -> Result<String, String> {
    // Ensure sshfs is installed
    if !has_sshfs() {

        install_sshfs().map_err(|e| format!("Failed to install sshfs: {}", e))?;
        if !has_sshfs() {
            return Err("sshfs is not installed and could not be auto-installed".to_string());
        }
    }

    if mount.source.is_empty() {
        return Err("SSHFS source is required (e.g. user@host:/remote/path)".to_string());
    }

    let mut args = vec![
        mount.source.clone(),
        mount.mount_point.clone(),
        "-o".to_string(), "allow_other".to_string(),
        "-o".to_string(), "reconnect".to_string(),
        "-o".to_string(), "ServerAliveInterval=15".to_string(),
        "-o".to_string(), "ServerAliveCountMax=3".to_string(),
        "-o".to_string(), "StrictHostKeyChecking=no".to_string(),
    ];

    // If nfs_options is set, treat it as the SSH key path
    if let Some(ref key_path) = mount.nfs_options {
        if !key_path.is_empty() {
            args.push("-o".to_string());
            args.push(format!("IdentityFile={}", key_path));
        }
    }

    let output = Command::new("sshfs")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run sshfs: {}", e))?;

    if output.status.success() {
        Ok("SSHFS storage mounted".to_string())
    } else {
        Err(format!("SSHFS mount failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── Helpers ───

fn has_s3fs() -> bool {
    Command::new("s3fs").arg("--version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn has_sshfs() -> bool {
    Command::new("which").arg("sshfs").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn install_sshfs() -> Result<(), String> {

    let distro = crate::installer::detect_distro();
    let (pkg_mgr, pkg_name) = match distro {
        crate::installer::DistroFamily::Debian => ("apt-get", "sshfs"),
        crate::installer::DistroFamily::RedHat => ("dnf", "fuse-sshfs"),
        crate::installer::DistroFamily::Suse => ("zypper", "sshfs"),
        crate::installer::DistroFamily::Unknown => ("apt-get", "sshfs"),
    };
    let output = Command::new(pkg_mgr)
        .args(["install", "-y", pkg_name])
        .output()
        .map_err(|e| format!("Failed to install {}: {}", pkg_name, e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} installation failed: {}", pkg_name, String::from_utf8_lossy(&output.stderr)))
    }
}

fn has_nfs() -> bool {
    Path::new("/sbin/mount.nfs").exists() || Path::new("/usr/sbin/mount.nfs").exists()
}

fn has_wolfdisk() -> bool {
    Path::new("/usr/local/bin/wolfdiskctl").exists()
        || Path::new("/opt/wolfdisk/wolfdiskctl").exists()
        || Command::new("which").arg("wolfdiskctl").output().map(|o| o.status.success()).unwrap_or(false)
}

fn install_s3fs() -> Result<(), String> {

    let distro = crate::installer::detect_distro();
    let (pkg_mgr, pkg_name) = match distro {
        crate::installer::DistroFamily::Debian => ("apt-get", "s3fs"),
        crate::installer::DistroFamily::RedHat => ("dnf", "s3fs-fuse"),
        crate::installer::DistroFamily::Suse => ("zypper", "s3fs"),
        crate::installer::DistroFamily::Unknown => ("apt-get", "s3fs"),
    };
    // RHEL/CentOS may need EPEL for s3fs-fuse
    if distro == crate::installer::DistroFamily::RedHat {
        let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();
    }
    let output = Command::new(pkg_mgr)
        .args(["install", "-y", pkg_name])
        .output()
        .map_err(|e| format!("Failed to install {}: {}", pkg_name, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} installation failed: {}",
            pkg_name, String::from_utf8_lossy(&output.stderr)))
    }
}

/// Sync local changes back to S3 bucket (called on unmount or periodic sync)
pub fn sync_to_s3(id: &str) -> Result<String, String> {
    use s3::bucket::Bucket;
    use s3::creds::Credentials;
    use s3::region::Region;

    let config = load_config();
    let mount = config.mounts.iter().find(|m| m.id == id)
        .ok_or_else(|| format!("Mount '{}' not found", id))?;

    let s3 = mount.s3_config.as_ref()
        .ok_or("Not an S3 mount")?;

    let credentials = Credentials::new(
        Some(&s3.access_key_id),
        Some(&s3.secret_access_key),
        None, None, None,
    ).map_err(|e| format!("Invalid credentials: {}", e))?;

    let region = if !s3.endpoint.is_empty() {
        Region::Custom {
            region: if s3.region.is_empty() { "us-east-1".to_string() } else { s3.region.clone() },
            endpoint: s3.endpoint.clone(),
        }
    } else {
        s3.region.parse::<Region>().unwrap_or(Region::UsEast1)
    };

    let bucket = Bucket::new(&s3.bucket, region, credentials)
        .map_err(|e| format!("Failed to create bucket handle: {}", e))?
        .with_path_style();

    let cache_dir = format!("/var/cache/wolfstack/s3/{}", mount.id);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;

    let uploaded = rt.block_on(async {
        let mut count = 0usize;
        sync_dir_to_s3(&bucket, &cache_dir, &cache_dir, &mut count).await?;
        Ok::<usize, String>(count)
    })?;

    Ok(format!("Synced {} files to S3", uploaded))
}

/// Recursively sync a local directory to S3
async fn sync_dir_to_s3(
    bucket: &s3::bucket::Bucket,
    base_dir: &str,
    current_dir: &str,
    count: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(current_dir)
        .map_err(|e| format!("Failed to read dir {}: {}", current_dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            Box::pin(sync_dir_to_s3(bucket, base_dir, path.to_str().unwrap_or(""), count)).await?;
        } else if path.is_file() {
            let key = path.strip_prefix(base_dir)
                .map_err(|e| format!("Path error: {}", e))?
                .to_str()
                .unwrap_or("")
                .to_string();

            if key.is_empty() { continue; }

            let content = fs::read(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

            bucket.put_object(&key, &content).await
                .map_err(|e| format!("Failed to upload {}: {}", key, e))?;

            *count += 1;
        }
    }

    Ok(())
}

// ─── Rclone Config Import ───

/// Parse an rclone.conf file contents and extract S3 remotes as StorageMount definitions
pub fn import_rclone_config(rclone_conf: &str) -> Result<Vec<StorageMount>, String> {
    let mut mounts = Vec::new();
    let mut current_section: Option<String> = None;
    let mut current_props: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    
    for line in rclone_conf.lines() {
        let trimmed = line.trim();
        
        // New section
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Save previous section
            if let Some(ref name) = current_section {
                if let Some(mount) = rclone_section_to_mount(name, &current_props) {
                    mounts.push(mount);
                }
            }
            current_section = Some(trimmed[1..trimmed.len()-1].to_string());
            current_props.clear();
            continue;
        }
        
        // Key = value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos+1..].trim().to_string();
            current_props.insert(key, value);
        }
    }
    
    // Don't forget the last section
    if let Some(ref name) = current_section {
        if let Some(mount) = rclone_section_to_mount(name, &current_props) {
            mounts.push(mount);
        }
    }
    
    if mounts.is_empty() {
        return Err("No S3-compatible remotes found in rclone.conf".to_string());
    }
    
    Ok(mounts)
}

fn rclone_section_to_mount(
    name: &str, 
    props: &std::collections::HashMap<String, String>
) -> Option<StorageMount> {
    let rtype = props.get("type").map(|s| s.as_str()).unwrap_or("");
    
    // Only import S3-compatible types
    if rtype != "s3" && rtype != "b2" && rtype != "gcs" && rtype != "r2" {
        return None;
    }
    
    let s3_config = S3Config {
        access_key_id: props.get("access_key_id").cloned().unwrap_or_default(),
        secret_access_key: props.get("secret_access_key").cloned().unwrap_or_default(),
        region: props.get("region").cloned().unwrap_or_default(),
        endpoint: props.get("endpoint").cloned().unwrap_or_default(),
        provider: props.get("provider").cloned().unwrap_or_else(|| "AWS".to_string()),
        bucket: String::new(),
    };
    
    let id = generate_id(name);
    Some(StorageMount {
        id: id.clone(),
        name: name.to_string(),
        mount_type: MountType::S3,
        source: format!("{}:", name),
        mount_point: format!("{}/{}", MOUNT_BASE, id),
        enabled: false,
        global: false,
        auto_mount: false,
        s3_config: Some(s3_config),
        nfs_options: None,
        status: "unmounted".to_string(),
        error_message: None,
        created_at: Utc::now().to_rfc3339(),
    })
}

// ─── Auto-mount on boot ───

/// Mount all entries that have auto_mount: true — called at startup
pub fn auto_mount_all() {
    let config = load_config();
    let auto_mounts: Vec<_> = config.mounts.iter()
        .filter(|m| m.auto_mount && m.enabled)
        .map(|m| (m.id.clone(), m.name.clone()))
        .collect();
    
    if auto_mounts.is_empty() {
        return;
    }
    

    for (id, name) in auto_mounts {
        std::thread::spawn(move || {
            match mount_storage(&id) {
                Ok(_msg) => {}
                Err(e) => error!("  ✗ Failed to auto-mount {}: {}", name, e),
            }
        });
    }
}

// ─── Container Mount Integration ───

/// Get all mounted storage entries that can be attached to containers
pub fn available_mounts() -> Vec<StorageMount> {
    load_config().mounts.into_iter()
        .filter(|m| m.status == "mounted" || check_mounted(&m.mount_point))
        .collect()
}

// ─── Storage Provider Detection ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProvider {
    pub name: String,
    pub label: String,
    pub icon: String,
    pub installed: bool,
    pub description: String,
    pub package: String,
    /// systemd service name (if applicable)
    pub service: Option<String>,
    /// Service status: "running", "stopped", "not-installed", "no-service"
    pub status: String,
    /// Path to config file (if applicable)
    pub config_path: Option<String>,
}

fn service_status(service_name: &str) -> String {
    match Command::new("systemctl").args(["is-active", service_name]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match s.as_str() {
                "active" => "running".to_string(),
                "inactive" => "stopped".to_string(),
                "failed" => "failed".to_string(),
                _ => s,
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

/// List all available storage providers with their install status
pub fn list_providers() -> Vec<StorageProvider> {
    vec![
        {
            let installed = has_nfs();
            let svc = if installed { Some("nfs-server".to_string()) } else { None };
            let status = if !installed { "not-installed".to_string() }
                else { service_status("nfs-server") };
            StorageProvider {
                name: "nfs".to_string(),
                label: "NFS".to_string(),
                icon: "\u{1f5c4}\u{fe0f}".to_string(),
                installed,
                description: "Network File System \u{2014} mount remote directories over the network".to_string(),
                package: "nfs-common".to_string(),
                service: svc,
                status,
                config_path: Some("/etc/exports".to_string()),
            }
        },
        {
            let installed = has_sshfs();
            StorageProvider {
                name: "sshfs".to_string(),
                label: "SSHFS".to_string(),
                icon: "\u{1f511}".to_string(),
                installed,
                description: "SSH Filesystem \u{2014} mount remote directories over SSH".to_string(),
                package: "sshfs".to_string(),
                service: None,
                status: if installed { "no-service".to_string() } else { "not-installed".to_string() },
                config_path: Some("/etc/fuse.conf".to_string()),
            }
        },
        {
            let installed = has_s3fs();
            StorageProvider {
                name: "s3fs".to_string(),
                label: "S3 (s3fs-fuse)".to_string(),
                icon: "\u{2601}\u{fe0f}".to_string(),
                installed,
                description: "S3-compatible object storage via FUSE".to_string(),
                package: "s3fs".to_string(),
                service: None,
                status: if installed { "no-service".to_string() } else { "not-installed".to_string() },
                config_path: Some("/etc/passwd-s3fs".to_string()),
            }
        },
        {
            let installed = has_wolfdisk();
            let svc = if installed { Some("wolfdisk".to_string()) } else { None };
            let status = if !installed { "not-installed".to_string() }
                else { service_status("wolfdisk") };
            StorageProvider {
                name: "wolfdisk".to_string(),
                label: "WolfDisk".to_string(),
                icon: "\u{1f43a}".to_string(),
                installed,
                description: "Distributed file system with replicated and shared storage".to_string(),
                package: "wolfdisk".to_string(),
                service: svc,
                status,
                config_path: Some("/etc/wolfdisk/config.toml".to_string()),
            }
        },
    ]
}

/// Perform an action on a storage provider service (start/stop/restart)
pub fn provider_action(name: &str, action: &str) -> Result<String, String> {
    let service_name = match name {
        "nfs" => "nfs-server",
        "wolfdisk" => "wolfdisk",
        _ => return Err(format!("Provider '{}' has no manageable service", name)),
    };

    match action {
        "start" | "stop" | "restart" | "enable" | "disable" => {
            let output = Command::new("systemctl")
                .args([action, service_name])
                .output()
                .map_err(|e| format!("Failed to {} {}: {}", action, service_name, e))?;
            if output.status.success() {
                Ok(format!("{} {} successful", service_name, action))
            } else {
                Err(format!("{} failed: {}", action, String::from_utf8_lossy(&output.stderr)))
            }
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

/// Read a provider's config file contents
pub fn provider_config(name: &str) -> Result<String, String> {
    let path = match name {
        "nfs" => "/etc/exports",
        "sshfs" => "/etc/fuse.conf",
        "s3fs" => "/etc/passwd-s3fs",
        "wolfdisk" => "/etc/wolfdisk/config.toml",
        _ => return Err(format!("Unknown provider: {}", name)),
    };
    std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path, e))
}

/// Write a provider's config file contents
pub fn save_provider_config(name: &str, content: &str) -> Result<String, String> {
    let path = match name {
        "nfs" => "/etc/exports",
        "sshfs" => "/etc/fuse.conf",
        "s3fs" => "/etc/passwd-s3fs",
        "wolfdisk" => "/etc/wolfdisk/config.toml",
        _ => return Err(format!("Unknown provider: {}", name)),
    };
    std::fs::write(path, content)
        .map_err(|e| format!("Cannot write {}: {}", path, e))?;
    // If NFS, reload exports
    if name == "nfs" {
        let _ = Command::new("exportfs").arg("-ra").output();
    }
    Ok(format!("Config saved to {}", path))
}

/// Install a storage provider by name
pub fn install_provider(name: &str) -> Result<String, String> {
    let distro = crate::installer::detect_distro();
    let (pkg_mgr, pkg_name) = match name {
        "nfs" => match distro {
            crate::installer::DistroFamily::RedHat => ("dnf", "nfs-utils"),
            crate::installer::DistroFamily::Suse => ("zypper", "nfs-client"),
            _ => ("apt-get", "nfs-common"),
        },
        "sshfs" => match distro {
            crate::installer::DistroFamily::RedHat => ("dnf", "fuse-sshfs"),
            _ => ("apt-get", "sshfs"),
        },
        "s3fs" => match distro {
            crate::installer::DistroFamily::RedHat => {
                let _ = Command::new("dnf").args(["install", "-y", "epel-release"]).output();
                ("dnf", "s3fs-fuse")
            },
            _ => ("apt-get", "s3fs"),
        },
        "wolfdisk" => {
            return Err("WolfDisk must be installed separately. See https://wolf.uk.com/wolfdisk".to_string());
        },
        _ => return Err(format!("Unknown provider: {}", name)),
    };


    let output = Command::new(pkg_mgr)
        .args(["install", "-y", pkg_name])
        .output()
        .map_err(|e| format!("Failed to run {}: {}", pkg_mgr, e))?;

    if output.status.success() {
        Ok(format!("{} installed successfully", pkg_name))
    } else {
        Err(format!("Installation failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

// ─── System Logs ───

/// Read system logs from journalctl
pub fn read_system_logs(lines: usize, search: Option<&str>, unit: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_string(),
        "-n".to_string(), lines.to_string(),
        "--output".to_string(), "short-iso".to_string(),
    ];
    if let Some(u) = unit {
        if !u.is_empty() {
            args.push("-u".to_string());
            args.push(u.to_string());
        }
    }
    if let Some(s) = search {
        if !s.is_empty() {
            args.push("-g".to_string());
            args.push(s.to_string());
        }
    }

    match Command::new("journalctl").args(&args).output() {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines().map(|l| l.to_string()).collect()
        }
        Err(e) => vec![format!("Error reading logs: {}", e)],
    }
}

// ─── Disk Partitioning & Formatting ───

/// Protected device prefixes and mount points that must never be modified
const PROTECTED_MOUNTS: &[&str] = &["/", "/boot", "/boot/efi", "/home"];

/// Supported filesystem types for formatting
pub const SUPPORTED_FILESYSTEMS: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "fat32", "ntfs", "swap",
];

/// Validate that a device path is a real block device and not protected
fn validate_device(device: &str) -> Result<(), String> {
    // Must be an absolute path starting with /dev/
    if !device.starts_with("/dev/") {
        return Err("Device path must start with /dev/".into());
    }
    // Reject path traversal
    if device.contains("..") {
        return Err("Invalid device path".into());
    }
    // Must actually exist as a block device
    let p = Path::new(device);
    if !p.exists() {
        return Err(format!("{} does not exist", device));
    }
    // Use lsblk to verify it's a real block device
    let output = Command::new("lsblk")
        .args(["-no", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk failed: {}", e))?;
    if !output.status.success() {
        return Err(format!("{} is not a block device", device));
    }
    Ok(())
}

/// Check if a device or any of its children are mounted at a protected mount point
fn is_protected_device(device: &str) -> Result<bool, String> {
    let output = Command::new("lsblk")
        .args(["-Jno", "NAME,MOUNTPOINTS,TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
        fn check_nodes(nodes: &[serde_json::Value]) -> bool {
            for node in nodes {
                if let Some(mounts) = node.get("mountpoints").and_then(|m| m.as_array()) {
                    for mp in mounts {
                        if let Some(s) = mp.as_str() {
                            for protected in PROTECTED_MOUNTS {
                                if s == *protected {
                                    return true;
                                }
                            }
                        }
                    }
                }
                if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                    if check_nodes(children) { return true; }
                }
            }
            false
        }
        if let Some(devs) = val.get("blockdevices").and_then(|b| b.as_array()) {
            return Ok(check_nodes(devs));
        }
    }
    Ok(false)
}

/// Check if a specific device is currently mounted
fn is_mounted(device: &str) -> bool {
    Command::new("findmnt")
        .args(["-n", "-S", device])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get partition table type for a disk (gpt, dos/mbr, or empty)
pub fn get_partition_table(disk: &str) -> Result<String, String> {
    let output = Command::new("blkid")
        .args(["-p", "-o", "value", "-s", "PTTYPE", disk])
        .output()
        .map_err(|e| format!("blkid: {}", e))?;
    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if result.is_empty() { "none".to_string() } else { result })
}

/// Create a new partition table on a disk (gpt or msdos)
pub fn create_partition_table(disk: &str, table_type: &str) -> Result<String, String> {
    validate_device(disk)?;

    // Only allow on whole disks
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", disk])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "disk" {
        return Err(format!("{} is not a whole disk (type: {})", disk, dev_type_str));
    }

    if is_protected_device(disk)? {
        return Err(format!("{} has partitions mounted at protected locations — refusing", disk));
    }

    let label = match table_type {
        "gpt" => "gpt",
        "msdos" | "mbr" => "msdos",
        _ => return Err(format!("Unsupported partition table type: {}. Use 'gpt' or 'msdos'.", table_type)),
    };

    let output = Command::new("parted")
        .args(["-s", disk, "mklabel", label])
        .output()
        .map_err(|e| format!("parted: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted mklabel failed: {}", stderr.trim()));
    }
    tracing::info!("Created {} partition table on {}", label, disk);
    Ok(format!("Created {} partition table on {}", label, disk))
}

/// Create a new partition on a disk
pub fn create_partition(disk: &str, size_mb: Option<u64>, fs_type_hint: Option<&str>) -> Result<String, String> {
    validate_device(disk)?;

    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", disk])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "disk" {
        return Err(format!("{} is not a whole disk", disk));
    }

    if is_protected_device(disk)? {
        return Err(format!("{} has partitions at protected mount points — refusing", disk));
    }

    // Check the disk has a partition table
    let pt = get_partition_table(disk)?;
    if pt == "none" {
        return Err(format!("{} has no partition table. Create one first (GPT or MBR).", disk));
    }

    // Find the end of the last partition to know where to start
    let output = Command::new("parted")
        .args(["-s", "-m", disk, "unit", "MiB", "print", "free"])
        .output()
        .map_err(|e| format!("parted print: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the last free space block
    let mut free_start: Option<f64> = None;
    let mut free_end: Option<f64> = None;
    for line in stdout.lines() {
        // Machine-parseable lines: "1:1.00MiB:500MiB:499MiB:ext4::;"  or "1:500MiB:1000MiB:500MiB:free;"
        if line.contains(":free;") || line.contains(":free:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let start = parts[1].trim_end_matches("MiB").parse::<f64>().unwrap_or(0.0);
                let end = parts[2].trim_end_matches("MiB").parse::<f64>().unwrap_or(0.0);
                if end - start > 1.0 {
                    free_start = Some(start);
                    free_end = Some(end);
                }
            }
        }
    }

    let start = free_start.ok_or_else(|| "No free space available on the disk".to_string())?;
    let max_end = free_end.unwrap_or(start);

    let end = if let Some(sz) = size_mb {
        let proposed = start + sz as f64;
        if proposed > max_end {
            return Err(format!("Requested {}MiB but only {:.0}MiB free", sz, max_end - start));
        }
        proposed
    } else {
        max_end // Use all remaining space
    };

    let fs_hint = fs_type_hint.unwrap_or("");
    let part_type = match fs_hint {
        "swap" => "linux-swap",
        "vfat" | "fat32" => "fat32",
        "ntfs" => "ntfs",
        _ => "ext2", // parted type hint, actual filesystem is created by mkfs later
    };

    let start_str = format!("{:.2}MiB", start);
    let end_str = format!("{:.2}MiB", end);

    let output = Command::new("parted")
        .args(["-s", "-a", "optimal", disk, "mkpart", "primary", part_type, &start_str, &end_str])
        .output()
        .map_err(|e| format!("parted mkpart: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted mkpart failed: {}", stderr.trim()));
    }

    // Inform kernel of partition changes
    let _ = Command::new("partprobe").arg(disk).output();
    // Small delay for udev to settle
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    tracing::info!("Created partition on {}: {}-{}", disk, start_str, end_str);
    Ok(format!("Partition created on {} ({} - {})", disk, start_str, end_str))
}

/// Delete a partition
pub fn delete_partition(device: &str) -> Result<String, String> {
    validate_device(device)?;

    // Must be a partition, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "part" {
        return Err(format!("{} is not a partition (type: {})", device, dev_type_str));
    }

    // Check it's not mounted at a protected location
    if is_protected_device(device)? {
        return Err(format!("{} is mounted at a protected location — refusing", device));
    }

    // Unmount if currently mounted
    if is_mounted(device) {
        let output = Command::new("umount").arg(device).output()
            .map_err(|e| format!("umount: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Cannot unmount {}: {}", device, stderr.trim()));
        }
    }

    // Extract disk and partition number
    // /dev/sda1 -> disk=/dev/sda, num=1
    // /dev/nvme0n1p2 -> disk=/dev/nvme0n1, num=2
    let name = device.trim_start_matches("/dev/");
    let (disk, part_num) = if name.contains("nvme") || name.contains("mmcblk") || name.contains("loop") {
        // NVMe style: nvme0n1p2
        if let Some(idx) = name.rfind('p') {
            let num = &name[idx+1..];
            let disk_name = &name[..idx];
            (format!("/dev/{}", disk_name), num.to_string())
        } else {
            return Err(format!("Cannot parse partition number from {}", device));
        }
    } else {
        // SCSI style: sda1
        let split_pos = name.len() - name.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        if split_pos == name.len() {
            return Err(format!("Cannot parse partition number from {}", device));
        }
        let disk_name = &name[..split_pos];
        let num = &name[split_pos..];
        (format!("/dev/{}", disk_name), num.to_string())
    };

    let output = Command::new("parted")
        .args(["-s", &disk, "rm", &part_num])
        .output()
        .map_err(|e| format!("parted rm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("parted rm failed: {}", stderr.trim()));
    }

    let _ = Command::new("partprobe").arg(&disk).output();
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    tracing::info!("Deleted partition {}", device);
    Ok(format!("Partition {} deleted", device))
}

/// Format a partition with a given filesystem type
pub fn format_partition(device: &str, fstype: &str, label: Option<&str>) -> Result<String, String> {
    validate_device(device)?;

    if !SUPPORTED_FILESYSTEMS.contains(&fstype) {
        return Err(format!("Unsupported filesystem type: {}. Supported: {}", fstype, SUPPORTED_FILESYSTEMS.join(", ")));
    }

    // Must be a partition or LVM, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str == "disk" {
        return Err("Cannot format a whole disk — format individual partitions instead".into());
    }

    // Check it's not mounted at a protected location
    if is_protected_device(device)? {
        return Err(format!("{} is mounted at a protected location — refusing", device));
    }

    // Unmount if currently mounted
    if is_mounted(device) {
        let output = Command::new("umount").arg(device).output()
            .map_err(|e| format!("umount: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Cannot unmount {}: {}", device, stderr.trim()));
        }
    }

    // Build mkfs command
    let cmd;
    let mut args: Vec<&str> = Vec::new();

    match fstype {
        "ext4" | "ext3" | "ext2" => {
            cmd = format!("mkfs.{}", fstype);
            args.push("-F"); // Force — don't ask for confirmation
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "xfs" => {
            cmd = "mkfs.xfs".to_string();
            args.push("-f"); // Force overwrite
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "btrfs" => {
            cmd = "mkfs.btrfs".to_string();
            args.push("-f");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "vfat" | "fat32" => {
            cmd = "mkfs.vfat".to_string();
            args.push("-F"); args.push("32");
            if let Some(l) = label {
                if !l.is_empty() { args.push("-n"); args.push(l); }
            }
        }
        "ntfs" => {
            cmd = "mkfs.ntfs".to_string();
            args.push("-f"); // Quick format
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        "swap" => {
            cmd = "mkswap".to_string();
            if let Some(l) = label {
                if !l.is_empty() { args.push("-L"); args.push(l); }
            }
        }
        _ => return Err(format!("Unsupported filesystem: {}", fstype)),
    }

    args.push(device);

    let output = Command::new(&cmd)
        .args(&args)
        .output()
        .map_err(|e| format!("{} failed: {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} failed: {}", cmd, stderr.trim()));
    }

    tracing::info!("Formatted {} as {} (label: {:?})", device, fstype, label);
    Ok(format!("{} formatted as {}", device, fstype))
}

/// Resize a partition to fill its available space, then grow the filesystem.
///
/// This handles the common case where a virtual disk has been extended
/// (e.g. in a VM or cloud) and the partition + filesystem need to be grown
/// to use the new space.
///
/// Steps:
///  1. Use `growpart` (if available) or `parted resizepart` to extend the partition
///  2. Detect the filesystem type
///  3. Run the appropriate filesystem resize tool (resize2fs, xfs_growfs, btrfs resize)
pub fn resize_partition(device: &str) -> Result<String, String> {
    validate_device(device)?;

    // Must be a partition, not a whole disk
    let dev_type = Command::new("lsblk")
        .args(["-dno", "TYPE", device])
        .output()
        .map_err(|e| format!("lsblk: {}", e))?;
    let dev_type_str = String::from_utf8_lossy(&dev_type.stdout).trim().to_string();
    if dev_type_str != "part" && dev_type_str != "lvm" {
        return Err(format!("{} is not a partition (type: {}). Resize individual partitions, not whole disks.", device, dev_type_str));
    }

    // Extract parent disk and partition number
    let name = device.trim_start_matches("/dev/");
    let (disk, part_num) = if name.contains("nvme") || name.contains("mmcblk") || name.contains("loop") {
        if let Some(idx) = name.rfind('p') {
            (format!("/dev/{}", &name[..idx]), name[idx+1..].to_string())
        } else {
            return Err(format!("Cannot parse partition number from {}", device));
        }
    } else {
        let split_pos = name.len() - name.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        if split_pos == name.len() {
            return Err(format!("Cannot parse partition number from {}", device));
        }
        (format!("/dev/{}", &name[..split_pos]), name[split_pos..].to_string())
    };

    let mut messages: Vec<String> = Vec::new();

    // Step 1: Grow the partition to fill available space
    // Try growpart first (cloud-utils), then fall back to parted
    let part_grown = if Command::new("which").arg("growpart").output().map(|o| o.status.success()).unwrap_or(false) {
        let output = Command::new("growpart")
            .args([&disk, &part_num])
            .output()
            .map_err(|e| format!("growpart: {}", e))?;
        if output.status.success() {
            messages.push("Partition extended with growpart".into());
            true
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // growpart returns exit code 1 with "NOCHANGE" if already at max size
            if stderr.contains("NOCHANGE") || String::from_utf8_lossy(&output.stdout).contains("NOCHANGE") {
                messages.push("Partition already at maximum size".into());
                true
            } else {
                // Fall back to parted
                false
            }
        }
    } else {
        false
    };

    if !part_grown {
        // Try parted resizepart — grow to 100%
        let output = Command::new("parted")
            .args(["-s", &disk, "resizepart", &part_num, "100%"])
            .output()
            .map_err(|e| format!("parted resizepart: {}", e))?;
        if output.status.success() {
            messages.push("Partition extended with parted".into());
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Not fatal — the partition may already be at max, or this may be LVM
            messages.push(format!("Partition resize skipped: {}", stderr.trim()));
        }
    }

    // Inform kernel of changes
    let _ = Command::new("partprobe").arg(&disk).output();
    let _ = Command::new("udevadm").args(["settle", "--timeout=3"]).output();

    // Step 2: Detect filesystem type
    let fstype_out = Command::new("blkid")
        .args(["-o", "value", "-s", "TYPE", device])
        .output()
        .map_err(|e| format!("blkid: {}", e))?;
    let fstype = String::from_utf8_lossy(&fstype_out.stdout).trim().to_string();

    if fstype.is_empty() {
        // No filesystem — partition resize is all we can do
        messages.push("No filesystem detected — only partition was resized".into());
        tracing::info!("Resized partition {} (no filesystem): {:?}", device, messages);
        return Ok(messages.join(". "));
    }

    // Step 3: Resize the filesystem
    match fstype.as_str() {
        "ext4" | "ext3" | "ext2" => {
            // resize2fs works on mounted or unmounted ext filesystems
            let output = Command::new("resize2fs")
                .arg(device)
                .output()
                .map_err(|e| format!("resize2fs: {}", e))?;
            if output.status.success() {
                messages.push(format!("{} filesystem resized with resize2fs", fstype));
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("resize2fs failed: {}", stderr.trim()));
            }
        }
        "xfs" => {
            // xfs_growfs requires the filesystem to be mounted
            let mountpoint = get_mountpoint(device);
            if let Some(mp) = mountpoint {
                let output = Command::new("xfs_growfs")
                    .arg(&mp)
                    .output()
                    .map_err(|e| format!("xfs_growfs: {}", e))?;
                if output.status.success() {
                    messages.push("XFS filesystem resized with xfs_growfs".into());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("xfs_growfs failed: {}", stderr.trim()));
                }
            } else {
                return Err("XFS filesystem must be mounted to resize. Mount it first, then retry.".into());
            }
        }
        "btrfs" => {
            // btrfs filesystem resize requires the filesystem to be mounted
            let mountpoint = get_mountpoint(device);
            if let Some(mp) = mountpoint {
                let output = Command::new("btrfs")
                    .args(["filesystem", "resize", "max", &mp])
                    .output()
                    .map_err(|e| format!("btrfs resize: {}", e))?;
                if output.status.success() {
                    messages.push("Btrfs filesystem resized".into());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("btrfs resize failed: {}", stderr.trim()));
                }
            } else {
                return Err("Btrfs filesystem must be mounted to resize. Mount it first, then retry.".into());
            }
        }
        "swap" => {
            // Recreate swap to match new partition size
            let was_on = Command::new("swapon").args(["--show=NAME", "--noheadings"])
                .output().map(|o| String::from_utf8_lossy(&o.stdout).contains(device)).unwrap_or(false);
            if was_on {
                let _ = Command::new("swapoff").arg(device).output();
            }
            let output = Command::new("mkswap").arg(device).output()
                .map_err(|e| format!("mkswap: {}", e))?;
            if output.status.success() {
                messages.push("Swap recreated at new size".into());
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("mkswap failed: {}", stderr.trim()));
            }
            if was_on {
                let _ = Command::new("swapon").arg(device).output();
                messages.push("Swap re-enabled".into());
            }
        }
        other => {
            messages.push(format!("Filesystem '{}' does not support online resize — partition was extended but filesystem was not grown", other));
        }
    }

    tracing::info!("Resized {}: {:?}", device, messages);
    Ok(messages.join(". "))
}

/// Get the mount point for a device, if mounted
fn get_mountpoint(device: &str) -> Option<String> {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", "-S", device])
        .output()
        .ok()?;
    let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if mp.is_empty() { None } else { Some(mp) }
}
