// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::api::{AppState, require_auth, build_node_urls};
use super::manager::{VmConfig, StorageVolume, UsbDevice, PciDevice};
use super::passthrough;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/vms")
            .route("", web::get().to(list_vms))
            .route("/create", web::post().to(create_vm))
            .route("/storage", web::get().to(list_storage))
            .route("/host-devices", web::get().to(host_devices))
            .route("/import-external", web::post().to(vm_import_external))
            .route("/discover-libvirt", web::get().to(discover_libvirt))
            .route("/adopt-libvirt", web::post().to(adopt_libvirt))
            .route("/{name}/action", web::post().to(vm_action))
            .route("/{name}/logs", web::get().to(vm_logs))
            .route("/{name}/serial-status", web::get().to(vm_serial_status))
            .route("/{name}/add-serial", web::post().to(vm_add_serial))
            .route("/{name}/migrate", web::post().to(vm_migrate))
            .route("/{name}/migrate-external", web::post().to(vm_migrate_external))
            .route("/{name}/disk/migrate", web::post().to(vm_disk_migrate))
            .route("/{name}/volumes", web::post().to(add_volume))
            .route("/{name}/volumes/{vol}", web::delete().to(remove_volume))
            .route("/{name}/volumes/{vol}/resize", web::post().to(resize_volume))
            .route("/{name}", web::put().to(update_vm))
            .route("/{name}", web::delete().to(delete_vm))
            .route("/{name}", web::get().to(get_vm))
    );
}

/// GET /api/vms/host-devices — list USB + PCI devices on the host with IOMMU
/// info and VFIO preflight. Devices currently claimed by a VM configured in
/// WolfStack are tagged with `in_use_by` so the picker can grey them out.
async fn host_devices(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vms = {
        let manager = state.vms.lock().unwrap();
        manager.list_vms()
    };
    let ownership = passthrough::build_ownership(&vms);
    let response = passthrough::list_host_devices(&ownership);
    HttpResponse::Ok().json(response)
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
    /// Extra network interfaces (net1, net2, ...) for multi-NIC VMs
    #[serde(default)]
    extra_nics: Vec<super::manager::NicConfig>,
    /// USB devices to pass through from host
    #[serde(default)]
    usb_devices: Vec<UsbDevice>,
    /// PCI devices to pass through from host
    #[serde(default)]
    pci_devices: Vec<PciDevice>,
    /// BIOS type: "seabios" (legacy) or "ovmf" (UEFI/EFI)
    #[serde(default = "default_bios_type")]
    bios_type: String,
}

fn default_bios_type() -> String { "seabios".to_string() }

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
    config.bios_type = body.bios_type.clone();

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

    // Extra NICs (auto-generate MACs where missing)
    config.extra_nics = body.extra_nics.iter().map(|n| {
        let mut nic = n.clone();
        if nic.mac.is_none() || nic.mac.as_ref().map(|m| m.is_empty()).unwrap_or(false) {
            nic.mac = Some(super::manager::generate_mac());
        }
        nic
    }).collect();

    // USB/PCI passthrough devices
    config.usb_devices = body.usb_devices.clone();
    config.pci_devices = body.pci_devices.iter().map(|p| {
        let mut d = p.clone();
        if let Ok(norm) = passthrough::normalize_bdf(&d.bdf) {
            d.bdf = norm;
        }
        d
    }).collect();

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
    bios_type: Option<String>,
    extra_nics: Option<Vec<super::manager::NicConfig>>,
    usb_devices: Option<Vec<UsbDevice>>,
    pci_devices: Option<Vec<PciDevice>>,
}

async fn update_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.update_vm(&name, body.cpus, body.memory_mb, body.iso_path.clone(),
                            body.wolfnet_ip.clone(), body.disk_size_gb,
                            body.os_disk_bus.clone(), body.net_model.clone(),
                            body.drivers_iso.clone(), body.auto_start,
                            body.bios_type.clone(),
                            body.extra_nics.clone(),
                            body.usb_devices.clone(),
                            body.pci_devices.clone()) {
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
        // Graceful ACPI shutdown — tries to let the guest close cleanly.
        // qm / virsh / SIGTERM variants depending on backend.
        "stop" => manager.stop_vm(&name, false),
        // Power-yank — equivalent to the old `stop` behaviour. For when
        // the guest is wedged or the user needs an immediate halt.
        "force-stop" => manager.stop_vm(&name, true),
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

/// GET /api/vms/{name}/serial-status — is this VM wired up for a serial
/// console (so `qm terminal` / `virsh console` / socat-to-serial-sock
/// actually has somewhere to attach)? Frontend calls this before opening
/// the terminal window so it can pop an "add serial console?" prompt when
/// missing, instead of dropping the user into a dead WebSocket.
async fn vm_serial_status(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    let backend = if crate::containers::is_proxmox() {
        "pve"
    } else if crate::containers::is_libvirt() {
        "libvirt"
    } else {
        "standalone"
    };

    let configured: bool;
    let running: bool;
    match backend {
        "pve" => {
            let manager = state.vms.lock().unwrap();
            let vmid = manager.qm_vmid_by_name(&name);
            drop(manager);
            let Some(vmid) = vmid else {
                return HttpResponse::NotFound().json(serde_json::json!({"error": format!("VM '{}' not found", name)}));
            };
            // `qm config` lists current config; a `serial0:` line means an
            // emulated UART is wired to a socket we can attach to.
            let cfg = std::process::Command::new("qm")
                .args(["config", &vmid.to_string()])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            configured = cfg.lines().any(|l| l.trim_start().starts_with("serial0:"));
            // Running = has an associated qemu process per `qm status`.
            let status = std::process::Command::new("qm")
                .args(["status", &vmid.to_string()])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            running = status.contains("running");
        }
        "libvirt" => {
            let xml = std::process::Command::new("virsh")
                .args(["dumpxml", &name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            // `virsh console` wants a matching <serial>/<console> pair.
            // Some libvirt versions auto-mirror one from the other, but
            // the conservative answer is "both present". If either is
            // missing, vm_add_serial() will top up just the missing half.
            configured = xml.contains("<serial ") && xml.contains("<console ");
            let state = std::process::Command::new("virsh")
                .args(["domstate", &name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            running = state.trim() == "running";
        }
        _ => {
            // Standalone QEMU. Three distinct states:
            //  - not running → configured=false,running=false ("start it first")
            //  - running, new QEMU spawn (has -chardev socket) → both true
            //  - running, old QEMU spawn from before the serial-socket wiring
            //    → process up, socket missing. Report running=true so the
            //    frontend skips the "start it first" path and falls into
            //    the "add serial console?" prompt (which returns a clear
            //    "restart the VM" message for standalone).
            let sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
            let sock_exists = std::path::Path::new(&sock).exists();
            let process_running = {
                let m = state.vms.lock().unwrap();
                m.check_running(&name)
            };
            running = process_running;
            configured = sock_exists;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "backend": backend,
        "configured": configured,
        "running": running,
        "hint": "If the terminal stays blank after opening, the guest may need `console=ttyS0` on its kernel cmdline and a getty on ttyS0 — same setup as bare-metal serial consoles."
    }))
}

/// POST /api/vms/{name}/add-serial — add a serial console device to a VM
/// that doesn't have one. Takes effect on next boot for running VMs;
/// applies immediately for stopped ones. Standalone QEMU VMs already get
/// a serial socket at create time, so this endpoint only handles the
/// PVE and libvirt paths where a pre-existing VM may be missing one.
async fn vm_add_serial(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    if crate::containers::is_proxmox() {
        let vmid = {
            let m = state.vms.lock().unwrap();
            m.qm_vmid_by_name(&name)
        };
        let Some(vmid) = vmid else {
            return HttpResponse::NotFound().json(serde_json::json!({"error": format!("VM '{}' not found in Proxmox", name)}));
        };
        // Check running-ness so we can tell the user whether a reboot is
        // needed for the new device to show up in the guest.
        let running = std::process::Command::new("qm")
            .args(["status", &vmid.to_string()])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
            .contains("running");

        let output = std::process::Command::new("qm")
            .args(["set", &vmid.to_string(), "--serial0", "socket"])
            .output()
            .map_err(|e| format!("Failed to run qm set: {}", e));
        match output {
            Ok(o) if o.status.success() => {
                HttpResponse::Ok().json(serde_json::json!({
                    "ok": true,
                    "message": "serial0 added (socket)",
                    "requires_reboot": running,
                }))
            }
            Ok(o) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("qm set failed: {}", String::from_utf8_lossy(&o.stderr).trim())
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        }
    } else if crate::containers::is_libvirt() {
        // libvirt: a working serial setup wants a matching <serial>/<console>
        // pair — some libvirt versions auto-mirror, others reject a console
        // without an associated serial. We probe what's already there and
        // attach each missing half separately. Console devices aren't
        // hot-pluggable so we always write to the persisted XML (`--config`)
        // and tell the caller to reboot if the domain is currently up.
        let running = std::process::Command::new("virsh")
            .args(["domstate", &name])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
            .trim()
            .to_string() == "running";

        let xml_dump = std::process::Command::new("virsh")
            .args(["dumpxml", &name])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let has_serial = xml_dump.contains("<serial ");
        let has_console = xml_dump.contains("<console ");

        // Build a list of (label, xml) pieces to attach. Skip anything
        // that's already present to avoid "device already exists" errors.
        let mut pieces: Vec<(&str, &str)> = Vec::new();
        if !has_serial {
            pieces.push(("serial",  "<serial type='pty'><target port='0'/></serial>"));
        }
        if !has_console {
            pieces.push(("console", "<console type='pty'><target type='serial' port='0'/></console>"));
        }

        // Shouldn't happen (caller checks configured=false before calling)
        // but handle gracefully if everything's already wired.
        if pieces.is_empty() {
            return HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "message": "serial + console already configured",
                "requires_reboot": false,
            }));
        }

        let mut errors: Vec<String> = Vec::new();
        let mut attached: Vec<&str> = Vec::new();
        for (label, xml) in &pieces {
            let xml_path = format!("/tmp/wolfstack-{}-{}.xml", label, uuid::Uuid::new_v4());
            if let Err(e) = std::fs::write(&xml_path, xml) {
                errors.push(format!("write {} xml: {}", label, e));
                continue;
            }
            let out = std::process::Command::new("virsh")
                .args(["attach-device", &name, &xml_path, "--config"])
                .output();
            let _ = std::fs::remove_file(&xml_path);
            match out {
                Ok(o) if o.status.success() => attached.push(label),
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    // libvirt uses varying wording for "this device already
                    // exists in the config" — treat any such response as a
                    // no-op success rather than a hard failure.
                    let lower = stderr.to_lowercase();
                    if lower.contains("already exist") || lower.contains("duplicate") {
                        attached.push(label);
                    } else {
                        errors.push(format!("{}: {}", label, stderr.trim()));
                    }
                }
                Err(e) => errors.push(format!("{}: {}", label, e)),
            }
        }

        if !errors.is_empty() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("virsh attach-device failed: {}", errors.join("; "))
            }));
        }
        HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "message": format!("attached: {}", attached.join(", ")),
            "requires_reboot": running,
        }))
    } else {
        // Standalone QEMU wires the serial socket at start time (since the
        // change that added `-chardev socket ... -serial chardev:serial0`
        // to the spawn args). A running VM without a socket is one that
        // was started by an older WolfStack — stop and start it to pick
        // up the new args.
        let running = {
            let m = state.vms.lock().unwrap();
            m.check_running(&name)
        };
        if running {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "This VM was started before serial-console support was added. Stop and start it again to enable the terminal."
            }))
        } else {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Start the VM first — standalone QEMU creates its serial socket at boot time."
            }))
        }
    }
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
    /// Destination storage path / PVE storage ID on the target node
    /// — where the final qcow2(s) end up after import.
    storage: Option<String>,
    /// Staging root on the SOURCE node for the export tarball. The
    /// default `/tmp` is often a small tmpfs; operators whose VMs
    /// don't fit can point this at a big disk (e.g. /var/wolftmp).
    #[serde(default)]
    staging_dir: Option<String>,
    /// Staging root on the TARGET node used by vm_import_external
    /// to extract + stage the incoming archive. Sent to the target
    /// as a `target_staging_dir` multipart field; fell back to
    /// $TMPDIR / /tmp on the target when absent.
    #[serde(default)]
    target_staging_dir: Option<String>,
    /// When true, the target node imports the VM as a PVE-managed VM
    /// via `qm create` + `qm importdisk`. Requires the target to be
    /// a Proxmox host and `storage` to be a PVE storage id.
    #[serde(default)]
    proxmox: bool,
    #[serde(default)]
    target_address: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
}

#[derive(Deserialize)]
pub struct VmDiskMigrateRequest {
    /// Target storage path on the same node.
    pub target: String,
    /// Whether to delete source files after a successful copy.
    /// Default false — we keep the source so the operator can verify
    /// the new copy boots before reclaiming space.
    #[serde(default)]
    pub remove_source: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VmMigrateExternalRequest {
    target_url: String,
    target_token: String,
    new_name: Option<String>,
    storage: Option<String>,
    delete_source: Option<bool>, // accepted but ignored — source is never deleted
    /// Staging root on the source node — same semantics as vm_migrate.
    #[serde(default)]
    staging_dir: Option<String>,
    /// Staging root on the target — passed as target_staging_dir in the
    /// multipart upload so the target honours it during extraction.
    #[serde(default)]
    target_staging_dir: Option<String>,
    /// Request PVE-managed import on the target.
    #[serde(default)]
    proxmox: bool,
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
        if let Err(e) = manager.stop_vm(&name, true) {
            tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
        }
    }

    // Export (outside of mutex — this is I/O heavy). staging_dir lets
    // the operator point export staging at a big disk instead of /tmp.
    let archive_path = match super::manager::export_vm_with_staging(
        &name, body.staging_dir.as_deref(),
    ) {
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
    let tgt_staging_val = body.target_staging_dir.as_deref().unwrap_or("").to_string();
    let proxmox_val = if body.proxmox { "1" } else { "" }.to_string();

    for import_url in &import_urls {
        let mut form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));
        // Send the optional fields only when set so old targets
        // (pre-v18.7.18) silently ignore unknown multipart parts.
        if !tgt_staging_val.is_empty() {
            form = form.text("target_staging_dir", tgt_staging_val.clone());
        }
        if !proxmox_val.is_empty() {
            form = form.text("proxmox", proxmox_val.clone());
        }

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

/// POST /api/vms/{name}/disk/migrate — move a stopped VM's disks to a
/// different storage path on the same node. Counterpart to the
/// `/api/containers/lxc/{name}/disk/migrate` endpoint for LXC; same
/// shape (`target` path + `remove_source` flag).
async fn vm_disk_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmDiskMigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    match super::manager::migrate_storage(&name, &body.target, body.remove_source) {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "message": msg })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

/// POST /api/vms/{name}/migrate-external — migrate VM to another cluster
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
        if let Err(e) = manager.stop_vm(&name, true) {
            tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
        }
    }

    // Export
    let archive_path = match super::manager::export_vm_with_staging(
        &name, body.staging_dir.as_deref(),
    ) {
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
    let tgt_staging_val = body.target_staging_dir.as_deref().unwrap_or("").to_string();
    let proxmox_val = if body.proxmox { "1" } else { "" }.to_string();
    let mut last_err: Option<String> = None;

    for import_url in &import_urls {
        let mut form = reqwest::multipart::Form::new()
            .text("new_name", new_name.to_string())
            .text("storage", storage_val.clone())
            .part("archive", reqwest::multipart::Part::bytes(archive_bytes.clone())
                .file_name(file_name.clone()));
        if !tgt_staging_val.is_empty() {
            form = form.text("target_staging_dir", tgt_staging_val.clone());
        }
        if !proxmox_val.is_empty() {
            form = form.text("proxmox", proxmox_val.clone());
        }

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

    // Respect TMPDIR so operators whose target `/tmp` is a small tmpfs
    // can point upload staging at a roomy disk via the wolfstack
    // systemd unit's `Environment=TMPDIR=/big/tmp` line. Guard against
    // an empty-string TMPDIR (systemd `Environment=TMPDIR=` to clear)
    // so we don't land on a relative path that makes create_dir_all
    // silently succeed against CWD.
    let import_dir = std::env::var("TMPDIR").ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("wolfstack-vm-imports");
    if let Err(e) = std::fs::create_dir_all(&import_dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!(
                "Failed to create upload staging directory {} (check TMPDIR or service permissions): {}",
                import_dir.display(), e
            )
        }));
    }

    let mut new_name: Option<String> = None;
    let mut storage: Option<String> = None;
    let mut archive_path: Option<std::path::PathBuf> = None;
    // New multipart fields — backward compatible (old clients don't send them).
    let mut target_staging_dir: Option<String> = None;
    let mut proxmox: bool = false;

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
            "target_staging_dir" => {
                // Source sends this so the target extracts the archive
                // under the operator's chosen staging root instead of
                // $TMPDIR / /tmp. Source staging is set separately on
                // the source vm_migrate call — this is strictly the
                // target side's extraction/upload directory.
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { target_staging_dir = Some(val); }
            }
            "proxmox" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_ascii_lowercase();
                proxmox = matches!(val.as_str(), "1" | "true" | "yes" | "on");
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

    // Choose the import path. `proxmox=true` routes to import_vm_proxmox
    // which creates a PVE-managed VM via qm create + qm importdisk.
    // Fall back to native import if the operator asked for PVE but
    // this host isn't Proxmox — surface the error instead of silently
    // creating a WolfStack-style VM.
    let result = if proxmox {
        if !crate::containers::is_proxmox() {
            Err("proxmox=true was requested but this host does not have Proxmox installed (`qm` not found)".to_string())
        } else {
            let sid = storage.as_deref().unwrap_or("").trim();
            if sid.is_empty() {
                Err("PVE storage id is required when proxmox=true (e.g. 'local-lvm')".to_string())
            } else {
                super::manager::import_vm_proxmox(
                    archive.to_str().unwrap_or(""),
                    new_name.as_deref(),
                    sid,
                    target_staging_dir.as_deref(),
                )
            }
        }
    } else {
        super::manager::import_vm_with_staging(
            archive.to_str().unwrap_or(""),
            new_name.as_deref(),
            storage.as_deref(),
            target_staging_dir.as_deref(),
        )
    };

    match result {
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

// ─── Libvirt VM Discovery & Adoption ───

/// GET /api/vms/discover-libvirt — discover VMs managed by libvirt
async fn discover_libvirt(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    HttpResponse::Ok().json(manager.discover_libvirt_vms())
}

#[derive(Deserialize)]
struct AdoptLibvirtRequest {
    name: String,
}

/// POST /api/vms/adopt-libvirt — adopt a libvirt VM into WolfStack
async fn adopt_libvirt(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AdoptLibvirtRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    match manager.adopt_libvirt_vm(&body.name) {
        Ok(config) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("VM '{}' adopted successfully", config.name),
            "vm": config,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}
