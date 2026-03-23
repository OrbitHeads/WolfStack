// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::api::{AppState, require_auth, build_node_urls};
use super::manager::{VmConfig, StorageVolume};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/vms")
            .route("", web::get().to(list_vms))
            .route("/create", web::post().to(create_vm))
            .route("/storage", web::get().to(list_storage))
            .route("/import-external", web::post().to(vm_import_external))
            .route("/{name}/action", web::post().to(vm_action))
            .route("/{name}/logs", web::get().to(vm_logs))
            .route("/{name}/migrate", web::post().to(vm_migrate))
            .route("/{name}/migrate-external", web::post().to(vm_migrate_external))
            .route("/{name}/volumes", web::post().to(add_volume))
            .route("/{name}/volumes/{vol}", web::delete().to(remove_volume))
            .route("/{name}/volumes/{vol}/resize", web::post().to(resize_volume))
            .route("/{name}", web::put().to(update_vm))
            .route("/{name}", web::delete().to(delete_vm))
            .route("/{name}", web::get().to(get_vm))
    );
}

async fn list_vms(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    let vms = manager.list_vms();
    HttpResponse::Ok().json(vms)
}

/// List available storage locations on the host
async fn list_storage(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    let locations = manager.list_storage_locations();
    HttpResponse::Ok().json(locations)
}

#[derive(Deserialize)]
struct CreateVmDisk {
    name: String,
    size_gb: u32,
    #[serde(default = "default_storage")]
    storage_path: String,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_bus")]
    bus: String,
}

fn default_storage() -> String { "/var/lib/wolfstack/vms".to_string() }
fn default_format() -> String { "qcow2".to_string() }
fn default_bus() -> String { "virtio".to_string() }

#[derive(Deserialize)]
struct CreateVmRequest {
    name: String,
    cpus: u32,
    memory_mb: u32,
    disk_size_gb: u32,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
    /// Storage path for the OS disk
    storage_path: Option<String>,
    /// Bus type for OS disk (virtio, ide, sata) — use ide for Windows
    #[serde(default = "default_os_bus")]
    os_disk_bus: String,
    /// Network adapter model (virtio, e1000, rtl8139) — use e1000 for Windows
    #[serde(default = "default_os_bus")]
    net_model: String,
    /// Optional path to VirtIO drivers ISO (for Windows + virtio disk)
    drivers_iso: Option<String>,
    /// Import a disk image (.img, .qcow2, .vmdk, .vdi) as the OS disk instead of creating an empty one
    import_image: Option<String>,
    /// Extra disks to create with the VM (Proxmox-style)
    #[serde(default)]
    extra_disks: Vec<CreateVmDisk>,
}

fn default_os_bus() -> String { "virtio".to_string() }

async fn create_vm(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CreateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    
    let mut config = VmConfig::new(
        body.name.clone(),
        body.cpus,
        body.memory_mb,
        body.disk_size_gb
    );
    config.iso_path = body.iso_path.clone();

    // WolfNet IP: use provided value, or None if not specified
    config.wolfnet_ip = match &body.wolfnet_ip {
        Some(ip) if !ip.is_empty() => Some(ip.clone()),
        _ => None,
    };
    config.storage_path = body.storage_path.clone();
    config.os_disk_bus = body.os_disk_bus.clone();
    config.net_model = body.net_model.clone();
    config.drivers_iso = body.drivers_iso.clone();

    // If importing a disk image, set it on the config
    if let Some(ref img) = body.import_image {
        if !img.is_empty() {
            config.import_image = Some(img.clone());
        }
    }

    // Convert extra disks from request to StorageVolume structs
    for disk in &body.extra_disks {
        config.extra_disks.push(StorageVolume {
            name: format!("{}-{}", body.name, disk.name),
            size_gb: disk.size_gb,
            storage_path: disk.storage_path.clone(),
            format: disk.format.clone(),
            bus: disk.bus.clone(),
        });
    }

    match manager.create_vm(config) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct UpdateVmRequest {
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    disk_size_gb: Option<u32>,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
    os_disk_bus: Option<String>,
    net_model: Option<String>,
    drivers_iso: Option<String>,
    auto_start: Option<bool>,
}

async fn update_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.update_vm(&name, body.cpus, body.memory_mb, body.iso_path.clone(), 
                            body.wolfnet_ip.clone(), body.disk_size_gb,
                            body.os_disk_bus.clone(), body.net_model.clone(),
                            body.drivers_iso.clone(), body.auto_start) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn get_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.get_vm(&name) {
        Some(vm) => HttpResponse::Ok().json(vm),
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "VM not found" })),
    }
}

async fn delete_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    match manager.delete_vm(&name) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct VmActionRequest {
    action: String,
}

async fn vm_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<VmActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    let result = match body.action.as_str() {
        "start" => manager.start_vm(&name),
        "stop" => manager.stop_vm(&name),
        _ => Err(format!("Unknown action: {}", body.action)),
    };
    
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn vm_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();
    
    let log_path = manager.base_dir.join(format!("{}.log", name));
    let log_content = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|_| "No logs available for this VM.".to_string());
    
    HttpResponse::Ok().json(serde_json::json!({ "name": name, "logs": log_content }))
}

// ─── Storage Volume Endpoints ───

#[derive(Deserialize)]
struct AddVolumeRequest {
    name: String,
    size_gb: u32,
    storage_path: Option<String>,
    format: Option<String>,
    bus: Option<String>,
}

async fn add_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<AddVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vm_name = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.add_volume(&vm_name, &body.name, body.size_gb, 
                             body.storage_path.as_deref(), body.format.as_deref(),
                             body.bus.as_deref()) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn remove_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.remove_volume(&vm_name, &vol_name, true) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct ResizeVolumeRequest {
    size_gb: u32,
}

async fn resize_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<ResizeVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.resize_volume(&vm_name, &vol_name, body.size_gb) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── VM Migration Endpoints ───

#[derive(Deserialize)]
struct VmMigrateRequest {
    target_node: String,
    new_name: Option<String>,
    storage: Option<String>,
    #[serde(default)]
    target_address: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VmMigrateExternalRequest {
    target_url: String,
    target_token: String,
    new_name: Option<String>,
    storage: Option<String>,
    delete_source: Option<bool>, // accepted but ignored — source is never deleted
}

/// POST /api/vms/{name}/migrate — migrate VM to another cluster node
async fn vm_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmMigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name);

    // Find target node — fall back to address/port if not in local cluster state
    let node = match state.cluster.get_node(&body.target_node) {
        Some(n) => n,
        None => {
            if let Some(ref addr) = body.target_address {
                let port = body.target_port.unwrap_or(8553);
                tracing::info!("VM migrate: node '{}' not in cluster state, using fallback {}:{}", body.target_node, addr, port);
                crate::agent::Node {
                    id: body.target_node.clone(),
                    address: addr.clone(),
                    port,
                    hostname: addr.clone(),
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
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot migrate to the same node"}));
    }

    // Stop VM temporarily for a consistent export, then restart
    {
        let manager = state.vms.lock().unwrap();
        if let Err(e) = manager.stop_vm(&name) {
            tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
        }
    }

    // Export (outside of mutex — this is I/O heavy)
    let archive_path = match super::manager::export_vm(&name) {
        Ok(p) => p,
        Err(e) => {
            // Restart source on failure
            let manager = state.vms.lock().unwrap();
            let _ = manager.start_vm(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Export failed: {}", e)}));
        }
    };

    // Restart source immediately after export — source stays running
    {
        let manager = state.vms.lock().unwrap();
        let _ = manager.start_vm(&name);
    }

    // Read archive
    let archive_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read archive: {}", e)}));
        }
    };

    // Build import URLs for the target node
    let import_urls = if node.node_type == "proxmox" {
        let mut urls = build_node_urls(&node.address, 8553, "/api/vms/import-external");
        urls.extend(build_node_urls(&node.address, 8552, "/api/vms/import-external"));
        urls
    } else {
        build_node_urls(&node.address, node.port, "/api/vms/import-external")
    };

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(3600))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let mut last_err: Option<String> = None;

    let storage_val = body.storage.as_deref().unwrap_or("").to_string();

    for import_url in &import_urls {
        let form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));

        match client.post(import_url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .multipart(form)
            .send()
            .await
        {
            Ok(r) => {
                super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                if r.status().is_success() {
                    // Source stays running, destination is stopped
                    return HttpResponse::Ok().json(serde_json::json!({
                        "message": format!("VM '{}' transferred to '{}' on node '{}'. Destination is stopped — start it manually when ready.", name, new_name, body.target_node)
                    }));
                } else {
                    let err_text = r.text().await.unwrap_or_default();
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Import on target failed: {}", err_text)}));
                }
            }
            Err(e) => {
                last_err = Some(e.to_string());
                continue;
            }
        }
    }

    // All URLs failed
    super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Transfer to {} failed on all ports/protocols: {}", node.address, last_err.unwrap_or_default())
    }))
}

/// POST /api/vms/{name}/migrate-external — migrate VM to external cluster
async fn vm_migrate_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmMigrateExternalRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.as_deref().unwrap_or(&name);

    // Pre-flight: verify we can reach the destination before doing the expensive export
    let preflight_urls = crate::api::build_external_urls(&body.target_url, "/api/storage/list");
    let preflight_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut preflight_ok = false;
    let mut preflight_err = String::new();
    for url in &preflight_urls {
        match preflight_client.get(url)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .send()
            .await
        {
            Ok(_) => { preflight_ok = true; break; } // any response = reachable
            Err(e) => { preflight_err = format!("{}: {}", url, e); }
        }
    }
    if !preflight_ok {
        return HttpResponse::BadGateway().json(serde_json::json!({
            "error": format!("Pre-flight check failed — cannot reach destination: {}", preflight_err)
        }));
    }

    // Stop VM temporarily for a consistent export, then restart
    {
        let manager = state.vms.lock().unwrap();
        if let Err(e) = manager.stop_vm(&name) {
            tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
        }
    }

    // Export
    let archive_path = match super::manager::export_vm(&name) {
        Ok(p) => p,
        Err(e) => {
            let manager = state.vms.lock().unwrap();
            let _ = manager.start_vm(&name);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Export failed: {}", e)}));
        }
    };

    // Restart source immediately after export — source stays running
    {
        let manager = state.vms.lock().unwrap();
        let _ = manager.start_vm(&name);
    }

    // Read archive
    let archive_bytes = match std::fs::read(&archive_path) {
        Ok(b) => b,
        Err(e) => {
            super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Read archive: {}", e)}));
        }
    };

    // Build URLs to try — automatically tries WolfStack (8553) and Proxmox (8006) ports
    let import_urls = crate::api::build_external_urls(&body.target_url, "/api/vms/import-external");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3600))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let storage_val = body.storage.as_deref().unwrap_or("").to_string();
    let mut last_err: Option<String> = None;

    for import_url in &import_urls {
        let form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));

        match client.post(import_url)
            .header("X-Transfer-Token", &body.target_token)
            .header("X-WolfStack-Secret", state.cluster_secret.clone())
            .multipart(form)
            .send()
            .await
        {
            Ok(r) => {
                super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                if r.status().is_success() {
                    // Source stays running, destination is stopped
                    return HttpResponse::Ok().json(serde_json::json!({
                        "message": format!("VM '{}' transferred to {}. Destination is stopped — start it manually when ready.", name, body.target_url)
                    }));
                } else {
                    let err = r.text().await.unwrap_or_default();
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("External import failed: {}", err)}));
                }
            }
            Err(e) => {
                last_err = Some(e.to_string());
                continue;
            }
        }
    }

    super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
    HttpResponse::BadGateway().json(serde_json::json!({
        "error": format!("Transfer to {} failed on all ports: {}", body.target_url, last_err.unwrap_or_default())
    }))
}

/// POST /api/vms/import-external — receive a migrated VM (multipart upload)
/// Auth: X-WolfStack-Secret (intra-cluster) or X-Transfer-Token (cross-cluster)
async fn vm_import_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    // Auth: accept either cluster secret or transfer token
    let has_secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == state.cluster_secret.as_str())
        .unwrap_or(false);

    let has_token = req.headers().get("X-Transfer-Token")
        .and_then(|v| v.to_str().ok())
        .map(|v| crate::api::validate_transfer_token(v))
        .unwrap_or(false);

    if !has_secret && !has_token {
        // Fall back to session auth
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    use futures::StreamExt;

    let import_dir = std::path::PathBuf::from("/tmp/wolfstack-vm-imports");
    let _ = std::fs::create_dir_all(&import_dir);

    let mut new_name: Option<String> = None;
    let mut storage: Option<String> = None;
    let mut archive_path: Option<std::path::PathBuf> = None;

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
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { new_name = Some(val); }
            }
            "storage" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { storage = Some(val); }
            }
            "archive" => {
                let fname = format!("vm-import-{}.tar.gz", uuid::Uuid::new_v4());
                let dest = import_dir.join(&fname);
                let mut file = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create temp file: {}", e)})),
                };
                use std::io::Write;
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk {
                        if let Err(e) = file.write_all(&data) {
                            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write failed: {}", e)}));
                        }
                    }
                }
                archive_path = Some(dest);
            }
            _ => { while let Some(_) = field.next().await {} }
        }
    }

    let archive = match archive_path {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "No archive uploaded"})),
    };

    match super::manager::import_vm(
        archive.to_str().unwrap_or(""),
        new_name.as_deref(),
        storage.as_deref(),
    ) {
        Ok(msg) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::Ok().json(serde_json::json!({"message": msg}))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e}))
        }
    }
}
