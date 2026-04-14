// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, warn, info};
use rand::Rng;
use crate::containers;
use crate::networking;
use super::passthrough::{parse_libvirt_hostdevs, parse_proxmox_passthrough, find_conflicts};

/// A storage volume that can be attached to a VM
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageVolume {
    /// Volume name (used for filename)
    pub name: String,
    /// Size in GB
    pub size_gb: u32,
    /// Storage path (directory where the volume file lives)
    pub storage_path: String,
    /// Disk format (qcow2, raw)
    #[serde(default = "default_format")]
    pub format: String,
    /// Bus type (virtio, scsi, ide)
    #[serde(default = "default_bus")]
    pub bus: String,
}

fn default_format() -> String { "qcow2".to_string() }
fn default_bus() -> String { "virtio".to_string() }

/// Summary of a storage location available on the host
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageLocation {
    pub path: String,
    pub total_gb: u64,
    pub available_gb: u64,
    pub fs_type: String,
}

impl StorageVolume {
    /// Full path to the volume file
    pub fn file_path(&self) -> PathBuf {
        Path::new(&self.storage_path).join(format!("{}.{}", self.name, self.format))
    }
}

/// Additional network interface configuration for multi-NIC VMs (e.g. OPNsense WAN+LAN)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NicConfig {
    /// NIC model: "virtio", "e1000", "e1000e", "rtl8139"
    #[serde(default = "default_net_model")]
    pub model: String,
    /// MAC address (auto-generated if empty)
    #[serde(default)]
    pub mac: Option<String>,
    /// Bridge name for this NIC (e.g. "br0", "vmbr1"). Empty = user-mode networking.
    #[serde(default)]
    pub bridge: Option<String>,
    /// Physical NIC passthrough: specify a host interface (e.g. "enp2s0") and WolfStack
    /// will auto-create a dedicated bridge for it. Used for OPNsense WAN, Starlink, etc.
    #[serde(default)]
    pub passthrough_interface: Option<String>,
}

/// USB device passthrough configuration. The device is matched on the host by
/// vendor:product ID — simple, stable across reboots, but if multiple identical
/// devices are plugged in QEMU grabs the first one. For pinning to a specific
/// physical port, use host_bus instead (format: "bus-port", e.g. "1-4").
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    /// USB vendor ID in hex, without 0x prefix (e.g. "046d")
    #[serde(default)]
    pub vendor_id: String,
    /// USB product ID in hex, without 0x prefix (e.g. "c52b")
    #[serde(default)]
    pub product_id: String,
    /// Optional: pin to a specific bus-port (e.g. "1-4") instead of vendor:product.
    /// When set, vendor_id/product_id are ignored by the builder.
    #[serde(default)]
    pub host_bus: Option<String>,
    /// Human-readable label for the UI (from lsusb). Not used by QEMU.
    #[serde(default)]
    pub label: Option<String>,
}

impl UsbDevice {
    /// Stable identifier used for conflict detection across VMs.
    pub fn match_key(&self) -> String {
        if let Some(ref hb) = self.host_bus {
            if !hb.is_empty() {
                return format!("usb-bus:{}", hb);
            }
        }
        format!("usb:{}:{}", self.vendor_id.to_lowercase(), self.product_id.to_lowercase())
    }
}

/// PCI device passthrough configuration. Identified by BDF (bus:device.function)
/// in the canonical format "DDDD:BB:DD.F" (e.g. "0000:01:00.0"). At runtime
/// WolfStack binds the device to vfio-pci (or lets libvirt/Proxmox handle it).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PciDevice {
    /// Canonical BDF: DDDD:BB:DD.F (e.g. "0000:01:00.0")
    #[serde(default)]
    pub bdf: String,
    /// Enable PCIe capability (hostpci pcie=1 on Proxmox, pcie bus on native). Default: true.
    #[serde(default = "default_true")]
    pub pcie: bool,
    /// Pass through as primary GPU (x-vga=1 / rombar tweaks). Default: false.
    #[serde(default)]
    pub primary_gpu: bool,
    /// Human-readable label for the UI (from lspci). Not used by QEMU.
    #[serde(default)]
    pub label: Option<String>,
}

fn default_true() -> bool { true }

impl PciDevice {
    /// Stable identifier used for conflict detection across VMs.
    pub fn match_key(&self) -> String {
        format!("pci:{}", self.bdf.to_lowercase())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmConfig {
    pub name: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub disk_size_gb: u32,
    pub iso_path: Option<String>,
    pub running: bool,
    pub vnc_port: Option<u16>,
    #[serde(default)]
    pub vnc_ws_port: Option<u16>,
    pub mac_address: Option<String>,
    pub auto_start: bool,
    #[serde(default)]
    pub wolfnet_ip: Option<String>,
    /// Storage path for the OS disk (defaults to /var/lib/wolfstack/vms)
    #[serde(default)]
    pub storage_path: Option<String>,
    /// Bus type for the OS disk (virtio, ide, sata) — use ide/sata for Windows
    #[serde(default = "default_bus")]
    pub os_disk_bus: String,
    /// Network adapter model (virtio, e1000, rtl8139) — use e1000 for Windows
    #[serde(default = "default_net_model")]
    pub net_model: String,
    /// Optional secondary ISO for VirtIO drivers (needed if OS disk is virtio on Windows)
    #[serde(default)]
    pub drivers_iso: Option<String>,
    /// Import a disk image as the OS disk (not persisted — used only during creation)
    #[serde(skip)]
    pub import_image: Option<String>,
    /// Extra disks attached to this VM
    #[serde(default)]
    pub extra_disks: Vec<StorageVolume>,
    /// Extra network interfaces (net1, net2, ...) — e.g. OPNsense WAN+LAN
    #[serde(default)]
    pub extra_nics: Vec<NicConfig>,
    /// USB devices passed through from host to guest (e.g. security dongles, cameras)
    #[serde(default)]
    pub usb_devices: Vec<UsbDevice>,
    /// PCI devices passed through from host to guest (e.g. GPUs, HBAs, NVMe)
    #[serde(default)]
    pub pci_devices: Vec<PciDevice>,
    /// Proxmox VMID (only set when running on Proxmox VE)
    #[serde(default)]
    pub vmid: Option<u32>,
    /// BIOS type: "seabios" (legacy) or "ovmf" (UEFI/EFI)
    #[serde(default = "default_bios_type")]
    pub bios_type: String,
}

fn default_net_model() -> String { "virtio".to_string() }
fn default_bios_type() -> String { "seabios".to_string() }

impl VmConfig {
    pub fn new(name: String, cpus: u32, memory_mb: u32, disk_size_gb: u32) -> Self {
        VmConfig {
            name,
            cpus,
            memory_mb,
            disk_size_gb,
            iso_path: None,
            running: false,
            vnc_port: None,
            vnc_ws_port: None,
            mac_address: Some(generate_mac()),
            auto_start: false,
            wolfnet_ip: None,
            storage_path: None,
            os_disk_bus: "virtio".to_string(),
            net_model: "virtio".to_string(),
            drivers_iso: None,
            import_image: None,
            extra_disks: Vec::new(),
            extra_nics: Vec::new(),
            usb_devices: Vec::new(),
            pci_devices: Vec::new(),
            vmid: None,
            bios_type: "seabios".to_string(),
        }
    }
}

/// Detect disk image format from file extension
fn detect_image_format(path: &str) -> &str {
    let lower = path.to_lowercase();
    if lower.ends_with(".qcow2") { "qcow2" }
    else if lower.ends_with(".vmdk") { "vmdk" }
    else if lower.ends_with(".vdi") { "vdi" }
    else if lower.ends_with(".vhd") || lower.ends_with(".vhdx") { "vpc" }
    else { "raw" } // .img and anything else treated as raw
}

pub(crate) fn generate_mac() -> String {
    let mut rng = rand::thread_rng();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.r#gen::<u8>())
}

pub struct VmManager {
    pub base_dir: PathBuf,
}

impl VmManager {
    pub fn new() -> Self {
        let base_dir = PathBuf::from("/var/lib/wolfstack/vms");
        if let Err(e) = fs::create_dir_all(&base_dir) {
            error!("Failed to create VM directory: {}", e);
        }
        VmManager { base_dir }
    }

    pub fn list_vms(&self) -> Vec<VmConfig> {
        // On Proxmox, discover VMs via qm list
        if containers::is_proxmox() {
            return self.qm_list_all();
        }
        // On libvirt, discover VMs via virsh
        if containers::is_libvirt() {
            return self.virsh_list_all();
        }

        // Standalone: scan local config files
        let mut vms = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                 let path = entry.path();
                 if path.extension().and_then(|e| e.to_str()) == Some("json") {
                     if let Ok(content) = fs::read_to_string(&path) {
                         if let Ok(mut vm) = serde_json::from_str::<VmConfig>(&content) {
                             vm.running = self.check_running(&vm.name);
                             if vm.running {
                                 vm.vnc_port = self.read_runtime_vnc_port(&vm.name);
                                 vm.vnc_ws_port = self.read_runtime_ws_port(&vm.name);
                             } else {
                                 vm.vnc_port = None;
                                 vm.vnc_ws_port = None;
                             }
                             vms.push(vm);
                         }
                     }
                 }
            }
        }
        vms
    }

    /// Discover all VMs from Proxmox via `qm list` + `qm config`
    fn qm_list_all(&self) -> Vec<VmConfig> {
        let output = match Command::new("qm").arg("list").output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        output.lines()
            .skip(1) // Skip header: VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let vmid: u32 = parts.first()?.parse().ok()?;
                let name = parts.get(1).unwrap_or(&"").to_string();
                let mem_mb: u32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                let disk_gb: u32 = parts.get(4).and_then(|s| s.parse::<f64>().ok()).map(|f| f as u32).unwrap_or(0);
                // Use `qm status {vmid}` for reliable status (qm list column parsing
                // can break on ARM/PiMox or when VM names contain spaces)
                let running = Command::new("qm").args(["status", &vmid.to_string()]).output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("running"))
                    .unwrap_or(false);

                // Read detailed config from qm config {vmid}
                let mut cpus: u32 = 1;
                let mut memory_mb = mem_mb;
                let mut disk_size_gb = disk_gb;
                let mut auto_start = false;
                let mut mac_address: Option<String> = None;
                let mut iso_path: Option<String> = None;
                let mut storage_path: Option<String> = None;

                // Capture the raw qm config text so we can parse passthrough lines too
                let qm_config_text = Command::new("qm").args(["config", &vmid.to_string()]).output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                if !qm_config_text.is_empty() {
                    let cfg_text = qm_config_text.as_str();
                    for cline in cfg_text.lines() {
                        let cline = cline.trim();
                        if cline.starts_with("cores:") {
                            cpus = cline.split(':').nth(1).unwrap_or("1").trim().parse().unwrap_or(1);
                        } else if cline.starts_with("memory:") {
                            memory_mb = cline.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(mem_mb);
                        } else if cline.starts_with("onboot:") {
                            auto_start = cline.split(':').nth(1).unwrap_or("0").trim() == "1";
                        } else if cline.starts_with("net0:") {
                            // Extract MAC from net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
                            if let Some(val) = cline.splitn(2, ':').nth(1) {
                                for part in val.split(',') {
                                    let part = part.trim();
                                    if part.starts_with("virtio=") || part.starts_with("e1000=") || part.starts_with("rtl8139=") {
                                        mac_address = part.split('=').nth(1).map(|s| s.to_string());
                                    }
                                }
                            }
                        } else if (cline.starts_with("ide2:") || cline.starts_with("cdrom:")) && cline.contains("media=cdrom") {
                            // Extract ISO path
                            if let Some(val) = cline.splitn(2, ':').nth(1) {
                                let iso = val.split(',').next().unwrap_or("").trim().to_string();
                                if !iso.is_empty() {
                                    iso_path = Some(iso);
                                }
                            }
                        } else if cline.starts_with("scsi0:") || cline.starts_with("virtio0:") || cline.starts_with("ide0:") || cline.starts_with("sata0:") {
                            // Extract storage and disk size from primary disk
                            if let Some(val) = cline.splitn(2, ':').nth(1) {
                                // e.g. "local-lvm:vm-100-disk-0,size=32G"
                                let disk_spec = val.trim();
                                if let Some(store) = disk_spec.split(':').next() {
                                    storage_path = Some(store.trim().to_string());
                                }
                                for part in disk_spec.split(',') {
                                    let part = part.trim();
                                    if part.starts_with("size=") {
                                        let size_str = part.trim_start_matches("size=").trim_end_matches('G').trim_end_matches('g');
                                        if let Ok(s) = size_str.parse::<f64>() {
                                            disk_size_gb = s as u32;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Parse usbN= and hostpciN= lines so device state round-trips through edits
                let (usb_devices, pci_devices) = parse_proxmox_passthrough(&qm_config_text);

                Some(VmConfig {
                    name,
                    cpus,
                    memory_mb,
                    disk_size_gb,
                    iso_path,
                    running,
                    vnc_port: None,
                    vnc_ws_port: None,
                    mac_address,
                    auto_start,
                    wolfnet_ip: None,
                    storage_path,
                    os_disk_bus: "virtio".to_string(),
                    net_model: "virtio".to_string(),
                    drivers_iso: None,
                    import_image: None,
                    extra_disks: Vec::new(),
                    extra_nics: Vec::new(),
                    usb_devices,
                    pci_devices,
                    vmid: Some(vmid),
                    bios_type: "seabios".to_string(),
                })
            })
            .collect()
    }

    /// Look up a Proxmox VMID by VM name via `qm list`
    fn qm_vmid_by_name(&self, name: &str) -> Option<u32> {
        let output = Command::new("qm").arg("list").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.get(1).map(|n| *n == name).unwrap_or(false) {
                return parts.first()?.parse().ok();
            }
        }
        None
    }

    fn vm_config_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }
    
    fn vm_disk_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.qcow2", name))
    }

    /// Get the OS disk path, respecting custom storage_path if set
    fn vm_os_disk_path(&self, config: &VmConfig) -> PathBuf {
        if let Some(ref sp) = config.storage_path {
            Path::new(sp).join(format!("{}.qcow2", config.name))
        } else {
            self.vm_disk_path(&config.name)
        }
    }

    /// Get the per-VM EFI variables file path (for OVMF boot)
    fn vm_efivars_path(&self, config: &VmConfig) -> PathBuf {
        if let Some(ref sp) = config.storage_path {
            Path::new(sp).join(format!("{}_VARS.fd", config.name))
        } else {
            self.base_dir.join(format!("{}_VARS.fd", config.name))
        }
    }

    /// TAP interface name for a VM
    fn tap_name(name: &str) -> String {
        // TAP names limited to 15 chars
        let short = if name.len() > 11 { &name[..11] } else { name };
        format!("tap-{}", short)
    }

    pub fn create_vm(&self, mut config: VmConfig) -> Result<(), String> {
        // Validation
        if config.cpus == 0 { config.cpus = 1; }
        if config.memory_mb == 0 { config.memory_mb = 1024; }
        if config.disk_size_gb == 0 { config.disk_size_gb = 10; }

        // Validate WolfNet IP if provided
        if let Some(ref ip) = config.wolfnet_ip {
            let ip = ip.trim();
            if !ip.is_empty() {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}' — must be a valid IPv4 address", ip));
                }
                config.wolfnet_ip = Some(ip.to_string());
            } else {
                config.wolfnet_ip = None;
            }
        }

        // On Proxmox, delegate to qm create
        if containers::is_proxmox() {
            return self.qm_create(&config);
        }
        // On libvirt, delegate to virt-install
        if containers::is_libvirt() {
            return self.virsh_create(&config);
        }

        // Standalone: use QEMU directly
        if self.vm_config_path(&config.name).exists() {
            return Err("VM already exists".to_string());
        }

        // Ensure storage path exists
        if let Some(ref sp) = config.storage_path {
            fs::create_dir_all(sp).map_err(|e| format!("Failed to create storage path: {}", e))?;
        }

        let disk_path = self.vm_os_disk_path(&config);

        if let Some(ref import_src) = config.import_image {
            // Import a disk image (.img, .qcow2, .vmdk, .vdi) — convert to qcow2
            if !std::path::Path::new(import_src).exists() {
                return Err(format!("Import image not found: {}", import_src));
            }
            info!("Importing disk image: {} -> {}", import_src, disk_path.display());
            let output = Command::new("qemu-img")
                .arg("convert")
                .arg("-f").arg(detect_image_format(import_src))
                .arg("-O").arg("qcow2")
                .arg(import_src)
                .arg(&disk_path)
                .output()
                .map_err(|e| format!("qemu-img convert failed: {}", e))?;
            if !output.status.success() {
                return Err(format!("Failed to import image: {}", String::from_utf8_lossy(&output.stderr)));
            }
            // Resize if the imported image is smaller than requested
            let _ = Command::new("qemu-img")
                .arg("resize").arg(&disk_path).arg(format!("{}G", config.disk_size_gb))
                .output();
        } else {
            // Create empty OS disk
            let output = Command::new("qemu-img")
                .arg("create")
                .arg("-f")
                .arg("qcow2")
                .arg(&disk_path)
                .arg(format!("{}G", config.disk_size_gb))
                .output()
                .map_err(|e| e.to_string())?;

            if !output.status.success() {
                 return Err(String::from_utf8_lossy(&output.stderr).to_string());
            }
        }

        // Create any extra disks specified at creation time
        for vol in &config.extra_disks {
            self.create_volume_file(vol)?;
        }

        // For OVMF (EFI) boot, create a per-VM copy of the EFI vars file
        if config.bios_type == "ovmf" {
            let vars_dest = self.vm_efivars_path(&config);
            if !vars_dest.exists() {
                let vars_sources = [
                    "/usr/share/OVMF/OVMF_VARS_4M.fd",
                    "/usr/share/OVMF/OVMF_VARS.fd",
                    "/usr/share/edk2/x64/OVMF_VARS.fd",
                    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                    "/usr/share/qemu/OVMF_VARS.fd",
                    "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                ];
                if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists()) {
                    fs::copy(src, &vars_dest)
                        .map_err(|e| format!("Failed to copy EFI vars: {}", e))?;
                } else {
                    return Err("OVMF EFI firmware not found. Install OVMF: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)".to_string());
                }
            }
        }

        // Save config
        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(self.vm_config_path(&config.name), json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Create a VM via Proxmox's qm command
    fn qm_create(&self, config: &VmConfig) -> Result<(), String> {
        // Get next available VMID
        let vmid_output = Command::new("pvesh").args(["get", "/cluster/nextid"]).output()
            .map_err(|e| format!("Failed to get next VMID: {}", e))?;
        if !vmid_output.status.success() {
            return Err("pvesh get /cluster/nextid failed".to_string());
        }
        let vmid_text = String::from_utf8_lossy(&vmid_output.stdout).trim().trim_matches('"').to_string();
        let vmid: u32 = vmid_text.parse().map_err(|e| format!("Invalid VMID '{}': {}", vmid_text, e))?;

        // Determine storage ID (use Proxmox storage name, default to "local-lvm")
        let storage = config.storage_path.as_deref().unwrap_or("local-lvm");



        let mut args = vec![
            "create".to_string(),
            vmid.to_string(),
            "--name".to_string(), config.name.clone(),
            "--cores".to_string(), config.cpus.to_string(),
            "--memory".to_string(), config.memory_mb.to_string(),
            "--scsi0".to_string(), format!("{}:{}", storage, config.disk_size_gb),
            "--scsihw".to_string(), "virtio-scsi-single".to_string(),
            "--net0".to_string(), format!("virtio,bridge=vmbr0"),
            "--ostype".to_string(), "l26".to_string(), // Linux 2.6+ kernel
            "--serial0".to_string(), "socket".to_string(), // Serial console for qm terminal
        ];

        // Boot media (ISO as CD-ROM, .img not supported as USB on Proxmox)
        if let Some(ref iso) = config.iso_path {
            if !iso.is_empty() {
                let lower = iso.to_lowercase();
                if lower.ends_with(".img") || lower.ends_with(".raw") {
                    return Err("Proxmox does not support booting from .img files directly. Use 'Import Image' to import it as the OS disk instead.".to_string());
                }
                // On Proxmox, ISOs are referred to as storage:iso/filename.iso
                args.push("--ide2".to_string());
                args.push(format!("{},media=cdrom", iso));
                args.push("--boot".to_string());
                args.push("order=ide2;scsi0".to_string());
            }
        }

        // Extra disks — PVE allocates them from the same storage pool as scsi0.
        // scsi0 is taken, so numbering starts at scsi1.
        for (i, vol) in config.extra_disks.iter().enumerate() {
            let slot = i + 1;
            args.push(format!("--scsi{}", slot));
            args.push(format!("{}:{}", storage, vol.size_gb));
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("qm")
            .args(&args_ref)
            .output()
            .map_err(|e| format!("Failed to run qm create: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!("qm create failed: {} {}", stderr.trim(), stdout.trim()));
        }

        // Import disk image if provided (convert and import via qm importdisk)
        if let Some(ref import_src) = config.import_image {
            if !import_src.is_empty() {
                if !std::path::Path::new(import_src).exists() {
                    return Err(format!("Import image not found: {}", import_src));
                }
                info!("Proxmox: importing disk image {} into VM {}", import_src, vmid);

                // Convert to raw first if needed, then importdisk
                // qm importdisk accepts raw and qcow2 directly
                let fmt = detect_image_format(import_src);
                let import_path = if fmt != "raw" && fmt != "qcow2" {
                    // Convert to qcow2 in /tmp first
                    let tmp = format!("/tmp/wolfstack-import-{}.qcow2", vmid);
                    let conv = Command::new("qemu-img")
                        .arg("convert").arg("-f").arg(fmt).arg("-O").arg("qcow2")
                        .arg(import_src).arg(&tmp)
                        .output()
                        .map_err(|e| format!("qemu-img convert failed: {}", e))?;
                    if !conv.status.success() {
                        return Err(format!("Failed to convert image: {}", String::from_utf8_lossy(&conv.stderr)));
                    }
                    tmp
                } else {
                    import_src.clone()
                };

                // Import the disk — replaces the empty scsi0 disk
                let import_output = Command::new("qm")
                    .args(["importdisk", &vmid.to_string(), &import_path, storage])
                    .output()
                    .map_err(|e| format!("qm importdisk failed: {}", e))?;
                if !import_output.status.success() {
                    return Err(format!("qm importdisk failed: {}", String::from_utf8_lossy(&import_output.stderr)));
                }

                // The imported disk shows as unused0 — attach it as scsi0
                // First detach the empty disk, then attach the imported one
                let _ = Command::new("qm").args(["set", &vmid.to_string(), "--delete", "scsi0"]).output();
                let _ = Command::new("qm").args(["set", &vmid.to_string(), "--scsi0", &format!("{}:vm-{}-disk-1", storage, vmid)]).output();

                // Resize to requested size
                let _ = Command::new("qm")
                    .args(["resize", &vmid.to_string(), "scsi0", &format!("{}G", config.disk_size_gb)])
                    .output();

                // Clean up temp file
                if import_path.starts_with("/tmp/wolfstack-import-") {
                    let _ = std::fs::remove_file(&import_path);
                }
            }
        }

        // Apply USB/PCI passthrough via qm set if the user configured any
        if !config.usb_devices.is_empty() || !config.pci_devices.is_empty() {
            if let Err(e) = super::passthrough::apply_proxmox_passthrough(vmid, config) {
                warn!("Failed to apply passthrough devices to Proxmox VM {}: {}", vmid, e);
            }
        }

        // Save a WolfStack config for tracking
        let mut tracked = config.clone();
        tracked.storage_path = Some(storage.to_string());
        let json = serde_json::to_string_pretty(&tracked).map_err(|e| e.to_string())?;
        let _ = fs::write(self.vm_config_path(&config.name), json);

        Ok(())
    }

    /// Create a volume's disk file
    fn create_volume_file(&self, vol: &StorageVolume) -> Result<(), String> {
        fs::create_dir_all(&vol.storage_path)
            .map_err(|e| format!("Failed to create storage dir {}: {}", vol.storage_path, e))?;

        let path = vol.file_path();
        if path.exists() {
            return Err(format!("Volume file already exists: {}", path.display()));
        }

        let output = Command::new("qemu-img")
            .args(["create", "-f", &vol.format, &path.to_string_lossy(), &format!("{}G", vol.size_gb)])
            .output()
            .map_err(|e| format!("qemu-img create failed: {}", e))?;

        if !output.status.success() {
            return Err(format!("Failed to create volume: {}", String::from_utf8_lossy(&output.stderr)));
        }


        Ok(())
    }

    /// Add a new storage volume to an existing VM (must be stopped)
    pub fn add_volume(&self, vm_name: &str, vol_name: &str, size_gb: u32, 
                      storage_path: Option<&str>, format: Option<&str>,
                      bus: Option<&str>) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot add volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        // Check for duplicate volume name
        if config.extra_disks.iter().any(|d| d.name == vol_name) {
            return Err(format!("Volume '{}' already exists on VM '{}'", vol_name, vm_name));
        }

        // Default storage path: same dir as the VM base
        let sp = storage_path
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.base_dir.to_string_lossy().to_string());

        let vol = StorageVolume {
            name: format!("{}-{}", vm_name, vol_name),
            size_gb,
            storage_path: sp,
            format: format.unwrap_or("qcow2").to_string(),
            bus: bus.unwrap_or("virtio").to_string(),
        };

        self.create_volume_file(&vol)?;
        config.extra_disks.push(vol);

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Remove a storage volume from a VM (must be stopped)
    pub fn remove_volume(&self, vm_name: &str, vol_name: &str, delete_file: bool) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot remove volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        let full_name = format!("{}-{}", vm_name, vol_name);
        let idx = config.extra_disks.iter().position(|d| d.name == full_name || d.name == vol_name)
            .ok_or_else(|| format!("Volume '{}' not found on VM '{}'", vol_name, vm_name))?;

        let vol = config.extra_disks.remove(idx);

        if delete_file {
            let path = vol.file_path();
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| format!("Failed to delete volume file: {}", e))?;

            }
        }

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Resize a storage volume (grow only, must be stopped)
    pub fn resize_volume(&self, vm_name: &str, vol_name: &str, new_size_gb: u32) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot resize volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        let full_name = format!("{}-{}", vm_name, vol_name);
        let vol = config.extra_disks.iter_mut()
            .find(|d| d.name == full_name || d.name == vol_name)
            .ok_or_else(|| format!("Volume '{}' not found", vol_name))?;

        if new_size_gb <= vol.size_gb {
            return Err(format!("New size must be larger than current size ({}G)", vol.size_gb));
        }

        let path = vol.file_path();
        let output = Command::new("qemu-img")
            .args(["resize", &path.to_string_lossy(), &format!("{}G", new_size_gb)])
            .output()
            .map_err(|e| format!("qemu-img resize failed: {}", e))?;

        if !output.status.success() {
            return Err(format!("Resize failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        vol.size_gb = new_size_gb;

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// List available storage locations (Proxmox-aware)
    pub fn list_storage_locations(&self) -> Vec<StorageLocation> {
        // On Proxmox, use pvesm for storage IDs
        if containers::is_proxmox() {
            let pve_storages = containers::pvesm_list_storage();
            return pve_storages.iter()
                .filter(|s| s.status == "active")
                .filter(|s| s.content.iter().any(|c| c == "images" || c == "rootdir"))
                .map(|s| StorageLocation {
                    path: s.id.clone(), // PVE storage ID as "path"
                    total_gb: s.total_bytes / 1073741824,
                    available_gb: s.available_bytes / 1073741824,
                    fs_type: s.storage_type.clone(),
                })
                .collect();
        }

        // Standalone: filesystem-based storage
        let mut locations = Vec::new();
        if let Ok(output) = Command::new("df").args(["-BG", "--output=target,size,avail,fstype"]).output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let mount = parts[0];
                        let total = parts[1].trim_end_matches('G').parse::<u64>().unwrap_or(0);
                        let avail = parts[2].trim_end_matches('G').parse::<u64>().unwrap_or(0);
                        let fstype = parts[3];
                        // Skip pseudo-filesystems
                        if mount.starts_with('/') && !mount.starts_with("/snap") 
                           && !mount.starts_with("/sys") && !mount.starts_with("/proc")
                           && !mount.starts_with("/dev") && !mount.starts_with("/run")
                           && total > 0 {
                            locations.push(StorageLocation {
                                path: mount.to_string(),
                                total_gb: total,
                                available_gb: avail,
                                fs_type: fstype.to_string(),
                            });
                        }
                    }
                }
            }
        }
        locations
    }

    /// Update VM settings (must be stopped)
    #[allow(clippy::too_many_arguments)]
    pub fn update_vm(&self, name: &str, cpus: Option<u32>, memory_mb: Option<u32>,
                     iso_path: Option<String>, wolfnet_ip: Option<String>,
                     disk_size_gb: Option<u32>,
                     os_disk_bus: Option<String>, net_model: Option<String>,
                     drivers_iso: Option<String>, auto_start: Option<bool>,
                     bios_type: Option<String>,
                     extra_nics: Option<Vec<NicConfig>>,
                     usb_devices: Option<Vec<UsbDevice>>,
                     pci_devices: Option<Vec<PciDevice>>) -> Result<(), String> {
        // On Proxmox, delegate to qm set
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            let vmid_str = vmid.to_string();
            let mut args = vec!["set", &vmid_str];
            let cores_str;
            let mem_str;
            let onboot_str;
            if let Some(c) = cpus { if c > 0 { cores_str = c.to_string(); args.extend(["--cores", &cores_str]); } }
            if let Some(m) = memory_mb { if m >= 256 { mem_str = m.to_string(); args.extend(["--memory", &mem_str]); } }
            if let Some(a) = auto_start { onboot_str = if a { "1".to_string() } else { "0".to_string() }; args.extend(["--onboot", &onboot_str]); }
            if args.len() > 2 {
                let output = Command::new("qm").args(&args).output()
                    .map_err(|e| format!("Failed to run qm set: {}", e))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("qm set failed: {}", stderr.trim()));
                }
            }
            // Disk resize on Proxmox
            if let Some(new_size) = disk_size_gb {
                let size_arg = format!("{}G", new_size);
                let _ = Command::new("qm").args(["resize", &vmid_str, "scsi0", &size_arg]).output();
            }
            // Extra NICs on Proxmox: net1=virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1
            if let Some(ref nics) = extra_nics {
                for (i, nic) in nics.iter().enumerate() {
                    let key = format!("--net{}", i + 1);
                    let model = match nic.model.as_str() {
                        "e1000" | "e1000e" | "rtl8139" => nic.model.as_str(),
                        _ => "virtio",
                    };
                    let mac = nic.mac.clone().unwrap_or_else(generate_mac);
                    // Resolve bridge — passthrough_interface auto-creates a vmbr, or use manual bridge
                    let bridge = self.resolve_nic_bridge(nic)
                        .unwrap_or_else(|| "vmbr0".to_string());
                    let val = format!("{}={},bridge={}", model, mac, bridge);
                    let _ = Command::new("qm").args(["set", &vmid_str, &key, &val]).output();
                }
                // Remove higher-numbered NICs that may have been deleted.
                // Only try deleting net{N} if qm config shows it exists (avoid spurious errors).
                if let Ok(cfg_out) = Command::new("qm").args(["config", &vmid_str]).output() {
                    let cfg_text = String::from_utf8_lossy(&cfg_out.stdout);
                    for i in nics.len()..8 {
                        let net_key = format!("net{}", i + 1);
                        if cfg_text.contains(&format!("{}: ", net_key)) {
                            let _ = Command::new("qm").args(["set", &vmid_str, "--delete", &net_key]).output();
                        }
                    }
                }
            }
            // USB/PCI passthrough — build a temporary VmConfig-like holder since
            // apply_proxmox_passthrough operates on a VmConfig. We only need the
            // usb/pci fields populated for that call.
            if usb_devices.is_some() || pci_devices.is_some() {
                let mut tmp = VmConfig::new(name.to_string(), 1, 512, 1);
                tmp.usb_devices = usb_devices.clone().unwrap_or_default();
                tmp.pci_devices = pci_devices.clone().unwrap_or_default();
                super::passthrough::apply_proxmox_passthrough(vmid, &tmp)?;
            }
            return Ok(());
        }
        // On libvirt, delegate to virsh (VM must be stopped for CPU/memory changes)
        if containers::is_libvirt() {
            if let Some(c) = cpus {
                if c > 0 {
                    let cs = c.to_string();
                    let out = Command::new("virsh").args(["setvcpus", name, &cs, "--config", "--maximum"]).output()
                        .map_err(|e| format!("virsh setvcpus failed: {}", e))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!("Failed to set CPUs: {}", stderr.trim()));
                    }
                    let _ = Command::new("virsh").args(["setvcpus", name, &cs, "--config"]).output();
                }
            }
            if let Some(m) = memory_mb {
                if m >= 256 {
                    let kb = format!("{}k", (m as u64) * 1024);
                    let out = Command::new("virsh").args(["setmaxmem", name, &kb, "--config"]).output()
                        .map_err(|e| format!("virsh setmaxmem failed: {}", e))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!("Failed to set memory: {}", stderr.trim()));
                    }
                    let _ = Command::new("virsh").args(["setmem", name, &kb, "--config"]).output();
                }
            }
            if let Some(a) = auto_start {
                let val = if a { "--enable" } else { "--disable" };
                let _ = Command::new("virsh").args(["autostart", name, val]).output();
            }
            // USB/PCI passthrough via virsh attach-device / detach-device
            if usb_devices.is_some() || pci_devices.is_some() {
                let mut tmp = VmConfig::new(name.to_string(), 1, 512, 1);
                tmp.usb_devices = usb_devices.clone().unwrap_or_default();
                tmp.pci_devices = pci_devices.clone().unwrap_or_default();
                super::passthrough::apply_libvirt_passthrough(name, &tmp)?;
            }
            return Ok(());
        }

        if self.check_running(name) {
            return Err("Cannot edit VM while it is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        // Capture old network state for OVMF boot entry reset detection
        let old_wolfnet_ip = config.wolfnet_ip.clone();
        let old_net_model = config.net_model.clone();
        let old_nics_count = config.extra_nics.len();

        if let Some(c) = cpus { if c > 0 { config.cpus = c; } }
        if let Some(m) = memory_mb { if m >= 256 { config.memory_mb = m; } }
        if let Some(a) = auto_start { config.auto_start = a; }
        
        // ISO: accept empty string to clear, or a path to set
        if let Some(ref iso) = iso_path {
            if iso.is_empty() {
                config.iso_path = None;
            } else {
                config.iso_path = Some(iso.clone());
            }
        }

        // WolfNet IP: accept empty string to clear
        if let Some(ref ip) = wolfnet_ip {
            if ip.is_empty() {
                config.wolfnet_ip = None;
            } else {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}'", ip));
                }
                config.wolfnet_ip = Some(ip.clone());
            }
        }

        // Hardware settings
        if let Some(ref bus) = os_disk_bus {
            if !bus.is_empty() { config.os_disk_bus = bus.clone(); }
        }
        if let Some(ref model) = net_model {
            if !model.is_empty() { config.net_model = model.clone(); }
        }
        if let Some(ref drv) = drivers_iso {
            if drv.is_empty() {
                config.drivers_iso = None;
            } else {
                config.drivers_iso = Some(drv.clone());
            }
        }
        if let Some(ref bt) = bios_type {
            if !bt.is_empty() { config.bios_type = bt.clone(); }
        }
        if let Some(nics) = extra_nics {
            // Auto-generate MACs for any NICs that don't have one
            config.extra_nics = nics.into_iter().map(|mut n| {
                if n.mac.is_none() || n.mac.as_ref().map(|m| m.is_empty()).unwrap_or(false) {
                    n.mac = Some(generate_mac());
                }
                n
            }).collect();
        }

        // USB/PCI passthrough
        if let Some(usbs) = usb_devices {
            config.usb_devices = usbs;
        }
        if let Some(pcis) = pci_devices {
            // Normalize BDFs on write so we store canonical form
            config.pci_devices = pcis.into_iter().map(|mut p| {
                if let Ok(norm) = super::passthrough::normalize_bdf(&p.bdf) {
                    p.bdf = norm;
                }
                p
            }).collect();
        }

        // OVMF boot entry fix: when network topology changes on a UEFI VM, the OVMF
        // boot entries reference device paths that are no longer valid. Reset the EFI
        // vars file so OVMF re-discovers the boot device on next start.
        if config.bios_type == "ovmf" {
            let net_changed = config.wolfnet_ip != old_wolfnet_ip;
            let nics_changed = config.extra_nics.len() != old_nics_count;
            let model_changed = config.net_model != old_net_model;
            if net_changed || nics_changed || model_changed {
                let vars_path = self.vm_efivars_path(&config);
                if vars_path.exists() {
                    let vars_sources = [
                        "/usr/share/OVMF/OVMF_VARS_4M.fd",
                        "/usr/share/OVMF/OVMF_VARS.fd",
                        "/usr/share/edk2/x64/OVMF_VARS.fd",
                        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                        "/usr/share/qemu/OVMF_VARS.fd",
                        "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                    ];
                    if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists()) {
                        if fs::copy(src, &vars_path).is_ok() {
                            info!("Reset OVMF EFI vars for VM '{}' due to network topology change", name);
                        }
                    }
                }
            }
        }

        // Disk resize (grow only)
        if let Some(new_size) = disk_size_gb {
            if new_size > config.disk_size_gb {
                let disk_path = self.vm_os_disk_path(&config);
                let output = Command::new("qemu-img")
                    .args(["resize", &disk_path.to_string_lossy(), &format!("{}G", new_size)])
                    .output()
                    .map_err(|e| format!("Disk resize failed: {}", e))?;
                if !output.status.success() {
                    return Err(format!("Disk resize failed: {}", String::from_utf8_lossy(&output.stderr)));
                }
                config.disk_size_gb = new_size;

            }
        }

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;
        

        Ok(())
    }

    pub fn start_vm(&self, name: &str) -> Result<(), String> {
        // Start-time conflict guard: check no running VM on this host has already
        // claimed any USB/PCI device configured on the target VM. Applies to all
        // three backends (native, Proxmox, libvirt) because list_vms() pulls from
        // the active backend's authoritative state.
        let all_vms = self.list_vms();
        if let Some(target) = all_vms.iter().find(|v| v.name == name) {
            let conflicts = find_conflicts(target, &all_vms);
            if !conflicts.is_empty() {
                return Err(format!(
                    "Cannot start VM '{}': passthrough device conflict — {}",
                    name, conflicts.join("; ")
                ));
            }
        }

        // On Proxmox, delegate to qm start
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;

            // Pre-flight the config before calling qm start. PVE silently
            // tolerates a missing `memory:` field on create/edit, then spams
            // 'Use of uninitialized value in multiplication' from pvestatd
            // and fails to boot the VM with no useful error. Catch the
            // common broken configs here with a clear message instead.
            if let Err(e) = validate_pve_config(vmid) {
                return Err(format!("VM '{}' (vmid {}) config is invalid: {}", name, vmid, e));
            }

            let output = Command::new("qm").args(["start", &vmid.to_string()]).output()
                .map_err(|e| format!("Failed to run qm start: {}", e))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("qm start failed: {}", stderr.trim()));
        }
        // On libvirt, delegate to virsh start
        if containers::is_libvirt() {
            let output = Command::new("virsh").args(["start", name]).output()
                .map_err(|e| format!("Failed to run virsh start: {}", e))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("virsh start failed: {}", stderr.trim()));
        }

        if self.check_running(name) {
             return Err("VM already running".to_string());
        }

        let config_path = self.vm_config_path(name);
        let log_path = self.base_dir.join(format!("{}.log", name));

        // Helper: append to log file
        let write_log = |msg: &str| {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
            }
        };

        write_log(&format!("=== Starting VM '{}' ===", name));

        let content = fs::read_to_string(&config_path)
            .map_err(|e| { 
                let msg = format!("VM config not found: {}", e);
                write_log(&msg); msg
            })?;
        let config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| {
                let msg = format!("Invalid VM config: {}", e);
                write_log(&msg); msg
            })?;

        write_log(&format!("Config: cpus={}, memory={}MB, disk={}GB, iso={:?}, wolfnet_ip={:?}", 
                  config.cpus, config.memory_mb, config.disk_size_gb, config.iso_path, config.wolfnet_ip));

        // Detect host architecture and select the right QEMU binary
        let is_arm64 = std::env::consts::ARCH == "aarch64";
        let qemu_bin = if is_arm64 { "qemu-system-aarch64" } else { "qemu-system-x86_64" };
        let qemu_check = Command::new("which").arg(qemu_bin).output();
        let qemu_path = match &qemu_check {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                let pkg = if is_arm64 { "qemu-system-arm" } else { "qemu-system-x86" };
                let msg = format!("{} not found. Install QEMU: apt install {} qemu-utils", qemu_bin, pkg);
                write_log(&msg);
                return Err(msg);
            }
        };
        write_log(&format!("QEMU binary: {} (arch: {})", qemu_path, std::env::consts::ARCH));

        let mut rng = rand::thread_rng();
        let vnc_num: u16 = rng.gen_range(10..99); 
        let vnc_port: u16 = 5900 + vnc_num;
        let ws_port: u16 = 6080 + vnc_num;  // WebSocket port for noVNC
        let vnc_arg = format!("0.0.0.0:{},websocket={}", vnc_num, ws_port);
        
        write_log(&format!("VNC display :{} (port {}), WebSocket port {}", vnc_num, vnc_port, ws_port));

        // Check if KVM is available
        let kvm_available = std::path::Path::new("/dev/kvm").exists();
        write_log(&format!("KVM available: {}", kvm_available));
        if !kvm_available {

        }

        let disk_path = self.vm_os_disk_path(&config);
        if !disk_path.exists() {
            // Fall back to default path for backwards compat
            let fallback = self.vm_disk_path(name);
            if !fallback.exists() {
                let msg = format!("Disk image not found: {}", disk_path.display());
                write_log(&msg);
                return Err(msg);
            }
            warn!("OS disk not at configured path, using fallback: {}", fallback.display());
        }
        let actual_disk = if disk_path.exists() { &disk_path } else { &self.vm_disk_path(name) };
        write_log(&format!("OS Disk: {} (exists)", actual_disk.display()));

        let mut cmd = Command::new(qemu_bin);
        
        // OS disk: use configured bus type (virtio by default, ide/sata for Windows)
        let os_disk_if = match config.os_disk_bus.as_str() {
            "ide" => "ide",
            "sata" | "ahci" => "ide",  // QEMU uses ide for SATA in -drive syntax
            _ => "virtio",
        };
        write_log(&format!("OS disk bus: {} (if={})", config.os_disk_bus, os_disk_if));
        
        // QMP (QEMU Monitor Protocol) socket — lets wolfstack hot-plug/unplug
        // USB devices on a running VM without a restart. Path is unique per
        // VM name so we can find it later. Unix socket in a world-writable
        // spot with filename that only root writes.
        let qmp_path = format!("/run/wolfstack-qmp-{}.sock", name);
        // Remove any stale socket from a previous run.
        let _ = std::fs::remove_file(&qmp_path);

        // USB controller setup:
        //   - qemu-xhci = USB 3.0 xHCI, handles full/low/high/super-speed.
        //     Windows 10/11 has native xHCI drivers so this Just Works™.
        //   - The default `-usb` line only provides a USB 1.1 UHCI hub, which
        //     can't enumerate USB 2.0 High-Speed (480 Mb/s) devices like
        //     webcams — they appear to QEMU but never reach the guest.
        // usb-tablet is attached to xHCI so cursor sync works out of the box.
        cmd.arg("-name").arg(name)
           .arg("-m").arg(format!("{}M", config.memory_mb))
           .arg("-smp").arg(format!("{}", config.cpus))
           .arg("-drive").arg(format!("file={},format=qcow2,if={},index=0", actual_disk.display(), os_disk_if))
           .arg("-vnc").arg(&vnc_arg)
           .arg("-device").arg("qemu-xhci,id=xhci")
           .arg("-device").arg("usb-tablet,bus=xhci.0")
           .arg("-vga").arg("std")
           .arg("-qmp").arg(format!("unix:{},server,nowait", qmp_path))
           .arg("-daemonize");

        // ARM64 requires the 'virt' machine type and UEFI firmware (no legacy BIOS)
        if is_arm64 {
            cmd.arg("-M").arg("virt");
            // Look for UEFI firmware in common distribution paths
            let fw_paths = [
                "/usr/share/AAVMF/AAVMF_CODE.fd",
                "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            ];
            if let Some(fw) = fw_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                cmd.arg("-bios").arg(*fw);
                write_log(&format!("ARM64 UEFI firmware: {}", fw));
            } else {
                write_log("WARNING: No UEFI firmware found for ARM64. Install qemu-efi-aarch64 (apt install qemu-efi-aarch64)");
            }
        } else if config.bios_type == "ovmf" {
            // x86_64 UEFI boot via OVMF — use q35 machine type for full UEFI compatibility
            cmd.arg("-machine").arg("q35");
            write_log("BIOS: OVMF (UEFI) with q35 machine type");

            // OVMF firmware code (read-only)
            let code_paths = [
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/edk2/x64/OVMF_CODE.fd",
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
                "/usr/share/qemu/OVMF_CODE.fd",
                "/usr/share/OVMF/OVMF_CODE.pure-efi.fd",
            ];
            if let Some(code) = code_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                cmd.arg("-drive").arg(format!("if=pflash,format=raw,readonly=on,file={}", code));
                write_log(&format!("OVMF CODE: {}", code));
            } else {
                let msg = "OVMF firmware not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                write_log(msg);
                return Err(msg.to_string());
            }

            // Per-VM EFI vars file (writable — stores boot entries, secure boot state, etc.)
            let vars_path = self.vm_efivars_path(&config);
            if !vars_path.exists() {
                // Create vars file on first boot if it wasn't created during VM creation
                let vars_sources = [
                    "/usr/share/OVMF/OVMF_VARS_4M.fd",
                    "/usr/share/OVMF/OVMF_VARS.fd",
                    "/usr/share/edk2/x64/OVMF_VARS.fd",
                    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                    "/usr/share/qemu/OVMF_VARS.fd",
                    "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                ];
                if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists()) {
                    fs::copy(src, &vars_path).map_err(|e| {
                        let msg = format!("Failed to copy EFI vars: {}", e);
                        write_log(&msg); msg
                    })?;
                    write_log(&format!("Created EFI vars from {}", src));
                } else {
                    let msg = "OVMF_VARS.fd not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                    write_log(msg);
                    return Err(msg.to_string());
                }
            }
            cmd.arg("-drive").arg(format!("if=pflash,format=raw,file={}", vars_path.display()));
            write_log(&format!("OVMF VARS: {}", vars_path.display()));
        }

        // Attach extra storage volumes
        for (i, vol) in config.extra_disks.iter().enumerate() {
            let vol_path = vol.file_path();
            if !vol_path.exists() {
                write_log(&format!("WARNING: Volume '{}' not found at {}, skipping", vol.name, vol_path.display()));
                warn!("Volume file not found: {}", vol_path.display());
                continue;
            }
            let idx = i + 1; // OS disk is index 0
            let drive_arg = match vol.bus.as_str() {
                "scsi" => format!("file={},format={},if=none,id=disk{}", vol_path.display(), vol.format, idx),
                "ide" => format!("file={},format={},if=ide,index={}", vol_path.display(), vol.format, idx),
                _ => format!("file={},format={},if=virtio,index={}", vol_path.display(), vol.format, idx),
            };
            cmd.arg("-drive").arg(&drive_arg);
            // For SCSI, also add the device
            if vol.bus == "scsi" {
                cmd.arg("-device").arg(format!("scsi-hd,drive=disk{}", idx));
            }
            write_log(&format!("Extra disk {}: {} ({}G, {})", idx, vol.name, vol.size_gb, vol.bus));
        }

        // KVM or software emulation
        if kvm_available {
            cmd.arg("-enable-kvm").arg("-cpu").arg("host");
        } else {
            let fallback_cpu = if is_arm64 { "max" } else { "qemu64" };
            cmd.arg("-cpu").arg(fallback_cpu);
        }

        // Determine NIC model: virtio-net-pci (Linux), e1000/e1000e (Windows), rtl8139
        let nic_device = match config.net_model.as_str() {
            "e1000" => "e1000",
            "e1000e" => "e1000e",
            "rtl8139" => "rtl8139",
            _ => "virtio-net-pci",
        };
        // Build NIC device string with MAC address if available
        let nic_arg = if let Some(ref mac) = config.mac_address {
            format!("{},netdev=net0,mac={}", nic_device, mac)
        } else {
            format!("{},netdev=net0", nic_device)
        };
        write_log(&format!("NIC model: {} (mac: {})", nic_device, config.mac_address.as_deref().unwrap_or("auto")));

        // Networking: VMs configure their own IP inside the guest OS.
        // If WolfNet IP is set, try TAP networking for direct L2 access.
        // Otherwise (or if TAP fails), use user-mode networking which always works.
        let mut using_tap = false;
        if let Some(ref wolfnet_ip) = config.wolfnet_ip {
            let tap = Self::tap_name(name);
            write_log(&format!("Attempting TAP networking for WolfNet IP {} (configure this IP inside the guest OS)", wolfnet_ip));
            
            match self.setup_tap(&tap) {
                Ok(_) => {
                    write_log(&format!("TAP '{}' created successfully", tap));
                    cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
                       .arg("-device").arg(&nic_arg);
                    
                    if let Err(e) = self.setup_wolfnet_routing(&tap, wolfnet_ip) {
                        write_log(&format!("WolfNet routing warning: {} (VM will still start)", e));
                    } else {
                        write_log(&format!("WolfNet routing configured for {} via {}", wolfnet_ip, tap));
                    }
                    using_tap = true;

                }
                Err(e) => {
                    write_log(&format!("TAP setup failed: {} — falling back to user-mode networking", e));
                    write_log("Note: You can still configure the WolfNet IP inside the guest OS manually");

                }
            }
        }
        
        if !using_tap {
            write_log("Networking: user-mode (NAT, VM can access host network)");
            cmd.arg("-netdev").arg("user,id=net0")
               .arg("-device").arg(&nic_arg);
        }

        // Extra NICs (net1, net2, ...) — e.g. OPNsense WAN+LAN, multi-homed servers
        for (i, nic) in config.extra_nics.iter().enumerate() {
            let idx = i + 1; // net1, net2, ...
            let net_id = format!("net{}", idx);
            let dev = match nic.model.as_str() {
                "e1000" => "e1000",
                "e1000e" => "e1000e",
                "rtl8139" => "rtl8139",
                _ => "virtio-net-pci",
            };
            let mac = nic.mac.clone().unwrap_or_else(generate_mac);
            let dev_arg = format!("{},netdev={},mac={}", dev, net_id, mac);

            // Resolve bridge — passthrough_interface auto-creates a bridge, or use manual bridge
            if let Some(bridge) = self.resolve_nic_bridge(nic) {
                // Bridge mode — create a TAP on the resolved bridge
                let tap = format!("tap-{}-{}", &name[..name.len().min(8)], idx);
                // Clean up any stale TAP
                let _ = Command::new("ip").args(["link", "set", &tap, "down"]).output();
                let _ = Command::new("ip").args(["tuntap", "del", "dev", &tap, "mode", "tap"]).output();
                if let Ok(o) = Command::new("ip").args(["tuntap", "add", "dev", &tap, "mode", "tap"]).output() {
                    if o.status.success() {
                        let master_out = Command::new("ip").args(["link", "set", &tap, "master", &bridge]).output();
                        if let Ok(ref mo) = master_out {
                            if !mo.status.success() {
                                write_log(&format!("WARNING: bridge '{}' not found or cannot attach TAP — NIC {} may have no connectivity", bridge, net_id));
                            }
                        }
                        let _ = Command::new("ip").args(["link", "set", &tap, "up"]).output();
                        cmd.arg("-netdev").arg(format!("tap,id={},ifname={},script=no,downscript=no", net_id, tap))
                           .arg("-device").arg(&dev_arg);
                        write_log(&format!("Extra NIC {}: {} on bridge {} (mac: {}, tap: {})", net_id, dev, bridge, mac, tap));
                        continue;
                    }
                }
                write_log(&format!("Extra NIC {}: bridge TAP failed for '{}', falling back to user-mode", net_id, bridge));
            }
            // Fallback: user-mode networking
            cmd.arg("-netdev").arg(format!("user,id={}", net_id))
               .arg("-device").arg(&dev_arg);
            write_log(&format!("Extra NIC {}: {} user-mode (mac: {})", net_id, dev, mac));
        }

        // Boot media: ISO (CD-ROM) or .img (USB drive)
        let mut has_boot_media = false;
        if let Some(iso) = &config.iso_path {
             if !iso.is_empty() {
                 if !std::path::Path::new(iso).exists() {
                     let msg = format!("Boot media not found: {}", iso);
                     write_log(&msg);
                     return Err(msg);
                 }
                 let lower = iso.to_lowercase();
                 if lower.ends_with(".img") || lower.ends_with(".raw") {
                     // Raw disk image — attach as USB drive for installation
                     write_log(&format!("Boot image (USB): {} (exists)", iso));
                     cmd.arg("-drive").arg(format!("file={},format=raw,if=none,id=usbdisk,readonly=on", iso))
                        .arg("-device").arg("usb-storage,drive=usbdisk");
                 } else {
                     // ISO — attach as CD-ROM
                     write_log(&format!("ISO: {} (exists)", iso));
                     cmd.arg("-cdrom").arg(iso);
                 }
                 has_boot_media = true;
             }
        }

        // Secondary CD-ROM: VirtIO drivers (for Windows with virtio disk)
        if let Some(ref drivers) = config.drivers_iso {
            if !drivers.is_empty() {
                if std::path::Path::new(drivers).exists() {
                    write_log(&format!("VirtIO drivers ISO: {}", drivers));
                    cmd.arg("-drive").arg(format!("file={},media=cdrom,index=1", drivers));
                } else {
                    write_log(&format!("WARNING: Drivers ISO not found: {}", drivers));
                }
            }
        }

        // Boot order: always explicit so OVMF (UEFI) doesn't default to PXE
        if has_boot_media {
            cmd.arg("-boot").arg("order=dc");  // CD/USB first, then disk (installation)
        } else {
            cmd.arg("-boot").arg("order=c");   // Disk first (normal boot)
        }

        // USB/PCI passthrough — append -device usb-host,... and -device vfio-pci,...
        // for each configured device. The native path already has `-usb` on the
        // command line, so usb-host can attach.
        if !config.usb_devices.is_empty() || !config.pci_devices.is_empty() {
            write_log(&format!("Passthrough: {} USB, {} PCI", config.usb_devices.len(), config.pci_devices.len()));
            if let Err(e) = super::passthrough::append_qemu_passthrough_args(&mut cmd, &config) {
                write_log(&format!("Passthrough configuration error: {}", e));
                return Err(format!("Passthrough configuration error: {}", e));
            }
            for u in &config.usb_devices {
                write_log(&format!("  USB: {}:{} {}", u.vendor_id, u.product_id,
                    u.label.clone().unwrap_or_default()));
            }
            for p in &config.pci_devices {
                write_log(&format!("  PCI: {} {} (pcie={})", p.bdf,
                    p.label.clone().unwrap_or_default(), p.pcie));
            }
        }

        write_log(&format!("Launching QEMU: VNC :{} (port {}), KVM: {}", vnc_num, vnc_port, kvm_available));


        // Redirect QEMU stderr to log file (append mode, don't overwrite diagnostics)
        if let Ok(log_file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            cmd.stderr(std::process::Stdio::from(log_file));
        }

        let output = cmd.output().map_err(|e| {
            let msg = format!("Failed to execute QEMU: {}", e);
            write_log(&msg); msg
        })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let err_msg = if !stderr.is_empty() { stderr } else { log_content.clone() };
            write_log(&format!("QEMU exit with error: {}", err_msg));
            error!("QEMU failed for VM {}: {}", name, err_msg);
            
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
            return Err(format!("QEMU failed to start: {}", err_msg));
        }

        // -daemonize makes QEMU fork, so output.status may be 0 even if the child crashes.
        std::thread::sleep(std::time::Duration::from_secs(1));

        if !self.check_running(name) {
            let log_content = fs::read_to_string(&log_path).unwrap_or_else(|_| "no log available".to_string());
            write_log("VM exited immediately after daemonize — check QEMU errors above");
            error!("VM {} exited immediately after daemonize. Log: {}", name, log_content);

            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
            return Err(format!("VM crashed immediately after starting. QEMU log:\n{}", log_content));
        }

        write_log(&format!("VM started successfully. VNC :{} (port {}), noVNC WS :{}", vnc_num, vnc_port, ws_port));

        // Save runtime port info so frontend can connect
        let runtime = serde_json::json!({
            "vnc_port": vnc_port,
            "vnc_ws_port": ws_port,
            "vnc_display": vnc_num,
            "kvm": kvm_available,
        });
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let _ = fs::write(&runtime_path, runtime.to_string());
        

        Ok(())
    }

    pub fn autostart_vms(&self) {

        for vm in self.list_vms() {
            if vm.auto_start && !vm.running {

                if let Err(e) = self.start_vm(&vm.name) {
                    error!("Failed to autostart VM {}: {}", vm.name, e);
                }
            }
        }
    }

    /// Create and configure a TAP interface
    fn setup_tap(&self, tap: &str) -> Result<(), String> {
        // Clean up any stale TAP from a previous crash or host restart first,
        // otherwise `ip tuntap add` can fail with EBUSY if the interface exists
        // in a half-dead state (e.g. after unclean shutdown / reboot).
        let _ = Command::new("ip").args(["link", "set", tap, "down"]).output();
        let _ = Command::new("ip").args(["tuntap", "del", "dev", tap, "mode", "tap"]).output();

        // Create TAP device
        let output = Command::new("ip")
            .args(["tuntap", "add", "dev", tap, "mode", "tap"])
            .output()
            .map_err(|e| format!("Failed to create TAP {}: {}", tap, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("EEXIST") && !stderr.contains("File exists") {
                return Err(format!("TAP creation failed: {}", stderr));
            }
        }

        // Bring TAP up
        let output = Command::new("ip")
            .args(["link", "set", tap, "up"])
            .output()
            .map_err(|e| format!("Failed to bring up TAP {}: {}", tap, e))?;

        if !output.status.success() {
            return Err(format!("TAP up failed: {}", String::from_utf8_lossy(&output.stderr)));
        }


        Ok(())
    }

    /// Set up host-side routing and forwarding for WolfNet IP through a TAP
    fn setup_wolfnet_routing(&self, tap: &str, wolfnet_ip: &str) -> Result<(), String> {
        let wn_iface = networking::detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

        // Enable per-interface forwarding on TAP + WolfNet
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", wn_iface)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", wn_iface)]).output();

        // Proxy ARP on both sides so the host answers ARP on behalf of routed IPs
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", wn_iface)]).output();

        // Disable reverse-path filtering — packets arrive from tunnel/TAP with
        // source IPs that don't match the directly-connected subnet
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", wn_iface)]).output();

        // Suppress ICMP redirects — we handle routing ourselves
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", tap)]).output();

        // Add route: wolfnet_ip/32 via TAP
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let route_result = Command::new("ip")
            .args(["route", "add", &format!("{}/32", wolfnet_ip), "dev", tap])
            .output()
            .map_err(|e| format!("Route add failed: {}", e))?;

        if !route_result.status.success() {
            let err = String::from_utf8_lossy(&route_result.stderr);
            if !err.contains("File exists") {
                warn!("Failed to add route for {}/32 dev {}: {}", wolfnet_ip, tap, err);
            }
        }

        // On firewalld systems, add TAP + WolfNet to trusted zone so firewalld's
        // nftables REJECT rule doesn't block forwarded VM traffic
        crate::containers::ensure_firewalld_trusted(&[tap, &wn_iface]);

        // iptables FORWARD: allow all traffic to/from the TAP (not just wolfnet0,
        // so the VM can also reach the internet when FORWARD chain default is DROP)
        let check_in = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        if check_in.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        }
        let check_out = Command::new("iptables")
            .args(["-C", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        if check_out.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        }

        // NAT masquerade so the VM can reach the outside world.
        // Exclude WolfNet-destined traffic so the VM appears as its own WolfNet IP,
        // not the host's IP, when communicating with other WolfNet nodes.
        // Remove old overly-broad rule if it exists, then add the correct one.
        let wn_subnet = {
            let parts: Vec<&str> = wolfnet_ip.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
            } else {
                crate::containers::wolfnet_subnet_prefix().map(|p| format!("{}.0/24", p)).unwrap_or_default()
            }
        };
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
        if !wn_subnet.is_empty() {
            let check_nat = Command::new("iptables")
                .args(["-t", "nat", "-C", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
            if check_nat.map(|o| !o.status.success()).unwrap_or(true) {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-A", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
            }
        }

        // ── DHCP server on the TAP so VMs get their WolfNet IP automatically ──
        // Assign a gateway IP to the TAP (use .254 in the same /24 as the VM's IP)
        let parts: Vec<&str> = wolfnet_ip.split('.').collect();
        if parts.len() == 4 {
            let gateway_ip = format!("{}.{}.{}.254", parts[0], parts[1], parts[2]);
            // Assign gateway IP to the TAP interface
            let _ = Command::new("ip").args(["addr", "flush", "dev", tap]).output();
            let _ = Command::new("ip")
                .args(["addr", "add", &format!("{}/24", gateway_ip), "dev", tap])
                .output();
            info!("TAP gateway: {} on {}", gateway_ip, tap);

            // Kill any existing dnsmasq on this TAP
            let _ = Command::new("pkill")
                .args(["-f", &format!("dnsmasq.*--interface={}", tap)])
                .output();

            // Start dnsmasq as DHCP server — offers exactly one IP (the VM's WolfNet IP).
            //
            // Each TAP gets its own lease file at /run/dnsmasq-<tap>.leases.
            // Without this every wolfstack dnsmasq instance on the host shared
            // the default /var/lib/misc/dnsmasq.leases, so a lease written by
            // an old (now-deleted) VM for the same IP would persist and the
            // new instance would refuse to hand that IP to a fresh MAC —
            // making recycled WolfNet IPs silently fail to DHCP.
            // We wipe the per-TAP lease file at start so there's never a
            // cross-VM ghost: each VM's dnsmasq begins with a clean slate.
            let lease_file = format!("/run/dnsmasq-{}.leases", tap);
            let _ = std::fs::remove_file(&lease_file);
            let dns_server = "8.8.8.8";
            let dnsmasq_result = Command::new("dnsmasq")
                .args([
                    &format!("--interface={}", tap),
                    "--bind-interfaces",
                    "--except-interface=lo",
                    &format!("--dhcp-range={},{},12h", wolfnet_ip, wolfnet_ip),
                    &format!("--dhcp-option=3,{}", gateway_ip),
                    &format!("--dhcp-option=6,{}", dns_server),
                    "--no-resolv",
                    &format!("--server={}", dns_server),
                    &format!("--pid-file=/run/dnsmasq-{}.pid", tap),
                    &format!("--dhcp-leasefile={}", lease_file),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();

            match dnsmasq_result {
                Ok(_) => info!("DHCP server started on {} — offering {} to VM", tap, wolfnet_ip),
                Err(e) => warn!("Could not start DHCP on {}: {} — VM will need manual IP", tap, e),
            }
        }

        Ok(())
    }

    /// Clean up TAP interface and routes
    fn cleanup_tap(&self, tap: &str) -> Result<(), String> {
        // Kill dnsmasq for this TAP
        let _ = Command::new("pkill").args(["-f", &format!("dnsmasq.*--interface={}", tap)]).output();
        if let Ok(pid) = std::fs::read_to_string(format!("/run/dnsmasq-{}.pid", tap)) {
            let _ = Command::new("kill").arg(pid.trim()).output();
            let _ = std::fs::remove_file(format!("/run/dnsmasq-{}.pid", tap));
        }
        // Remove the per-TAP lease file so a future VM with a different MAC
        // won't be blocked by a ghost lease entry.
        let _ = std::fs::remove_file(format!("/run/dnsmasq-{}.leases", tap));

        let _ = Command::new("ip").args(["link", "set", tap, "down"]).output();
        let _ = Command::new("ip").args(["tuntap", "del", "dev", tap, "mode", "tap"]).output();
        // Clean up iptables FORWARD rules (generic form used since v11.28)
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        // Also clean up old-style wolfnet0-specific rules from before v11.28
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", "wolfnet0", "-o", tap, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-o", "wolfnet0", "-j", "ACCEPT"]).output();

        Ok(())
    }

    /// Ensure a dedicated bridge exists for a physical NIC passthrough.
    /// Returns the bridge name to use for TAP attachment.
    fn ensure_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        // Sanitise interface name — prevent path traversal and injection
        if iface.is_empty() || iface.len() > 15
            || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(format!("Invalid interface name: '{}'", iface));
        }

        // Validate interface exists
        if !Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            return Err(format!("Physical interface '{}' not found", iface));
        }

        // Check if interface is already in a bridge — reuse it
        let master_link = format!("/sys/class/net/{}/master", iface);
        if let Ok(target) = std::fs::read_link(&master_link) {
            if let Some(bridge_name) = target.file_name().and_then(|n| n.to_str()) {
                // Verify the master is actually a bridge (not a bond, etc.)
                let bridge_check = format!("/sys/class/net/{}/bridge", bridge_name);
                if Path::new(&bridge_check).exists() {
                    info!("Passthrough: {} already in bridge {}", iface, bridge_name);
                    return Ok(bridge_name.to_string());
                }
                warn!("Passthrough: {} has master '{}' but it is not a bridge — creating new bridge", iface, bridge_name);
            }
        }

        if containers::is_proxmox() {
            self.create_proxmox_passthrough_bridge(iface)
        } else {
            self.create_linux_passthrough_bridge(iface)
        }
    }

    /// Read the current IPv4 address, prefix, and default gateway from an interface
    fn read_iface_ip_config(iface: &str) -> Option<(String, u32, Option<String>)> {
        // Get IP/prefix: ip -j addr show dev {iface}
        let addr_out = Command::new("ip").args(["-j", "addr", "show", "dev", iface]).output().ok()?;
        let addr_json: Vec<serde_json::Value> = serde_json::from_slice(&addr_out.stdout).ok()?;
        let entry = addr_json.first()?;
        let addr_info = entry["addr_info"].as_array()?;
        let ipv4 = addr_info.iter().find(|a| a["family"].as_str() == Some("inet") && a["scope"].as_str() == Some("global"))?;
        let ip = ipv4["local"].as_str()?.to_string();
        let prefix = ipv4["prefixlen"].as_u64()? as u32;

        // Get default gateway: ip -j route show default dev {iface}
        let route_out = Command::new("ip").args(["-j", "route", "show", "default", "dev", iface]).output().ok()?;
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&route_out.stdout).unwrap_or_default();
        let gateway = routes.first()
            .and_then(|r| r["gateway"].as_str())
            .map(|g| g.to_string());

        Some((ip, prefix, gateway))
    }

    /// Create a Linux bridge for physical NIC passthrough (standalone QEMU/KVM).
    /// Moves the host's IP from the physical NIC to the bridge so the host stays reachable.
    fn create_linux_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        let bridge_name = format!("br-pt-{}", iface);

        // Capture the host's current IP config BEFORE bridging — we need to move it
        let ip_config = Self::read_iface_ip_config(iface);

        // Create bridge (ignore "File exists" — means it already exists)
        let out = Command::new("ip").args(["link", "add", &bridge_name, "type", "bridge"]).output()
            .map_err(|e| format!("Failed to create bridge: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("File exists") {
                return Err(format!("Failed to create bridge '{}': {}", bridge_name, stderr.trim()));
            }
        }

        // Flush IPs from physical interface (will be moved to the bridge)
        let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).output();

        // Add physical interface to bridge
        let out = Command::new("ip").args(["link", "set", iface, "master", &bridge_name]).output()
            .map_err(|e| format!("Failed to add {} to bridge: {}", iface, e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("already a member") && !stderr.contains("Device or resource busy") {
                return Err(format!("Failed to add {} to bridge {}: {}", iface, bridge_name, stderr.trim()));
            }
        }

        // Bring up both
        let _ = Command::new("ip").args(["link", "set", iface, "up"]).output();
        let _ = Command::new("ip").args(["link", "set", &bridge_name, "up"]).output();

        // Move the host's IP and gateway to the bridge so the host stays reachable
        if let Some((ip, prefix, gateway)) = ip_config {
            let cidr = format!("{}/{}", ip, prefix);
            let _ = Command::new("ip").args(["addr", "add", &cidr, "dev", &bridge_name]).output();
            if let Some(gw) = gateway {
                let _ = Command::new("ip").args(["route", "add", "default", "via", &gw, "dev", &bridge_name]).output();
            }
            info!("Passthrough: moved host IP {} to bridge {}", cidr, bridge_name);
        }

        info!("Passthrough: created bridge {} for physical NIC {}", bridge_name, iface);
        Ok(bridge_name)
    }

    /// Create a Proxmox vmbr bridge for physical NIC passthrough
    fn create_proxmox_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        // Find next available vmbr{N}
        let mut next_id = 1u32;
        let bridge_name = loop {
            let candidate = format!("vmbr{}", next_id);
            if !Path::new(&format!("/sys/class/net/{}", candidate)).exists() {
                break candidate;
            }
            next_id += 1;
            if next_id > 99 {
                return Err("No available vmbr{N} slot (checked up to vmbr99)".to_string());
            }
        };

        // Register with Proxmox for persistence across reboots
        let pve_node = Command::new("hostname").arg("-s").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());

        let pvesh_out = Command::new("pvesh").args([
            "create", &format!("/nodes/{}/network", pve_node),
            "--iface", &bridge_name,
            "--type", "bridge",
            "--bridge_ports", iface,
            "--autostart", "1",
        ]).output();

        if let Ok(ref o) = pvesh_out {
            if !o.status.success() {
                warn!("pvesh create bridge failed: {} — creating with ip commands only",
                    String::from_utf8_lossy(&o.stderr).trim());
            }
        }

        // Capture the host's current IP config BEFORE bridging
        let ip_config = Self::read_iface_ip_config(iface);

        // Create immediately with ip commands (pvesh config only takes effect on reboot/ifreload)
        let _ = Command::new("ip").args(["link", "add", &bridge_name, "type", "bridge"]).output();
        let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).output();
        let _ = Command::new("ip").args(["link", "set", iface, "master", &bridge_name]).output();
        let _ = Command::new("ip").args(["link", "set", iface, "up"]).output();
        let _ = Command::new("ip").args(["link", "set", &bridge_name, "up"]).output();

        // Move the host's IP and gateway to the bridge so the host stays reachable
        if let Some((ip, prefix, gateway)) = ip_config {
            let cidr = format!("{}/{}", ip, prefix);
            let _ = Command::new("ip").args(["addr", "add", &cidr, "dev", &bridge_name]).output();
            if let Some(gw) = gateway {
                let _ = Command::new("ip").args(["route", "add", "default", "via", &gw, "dev", &bridge_name]).output();
            }
            info!("Passthrough: moved host IP {} to bridge {}", cidr, bridge_name);
        }

        info!("Passthrough: created Proxmox bridge {} for physical NIC {}", bridge_name, iface);
        Ok(bridge_name)
    }

    /// Resolve the effective bridge for a NIC config — handles passthrough_interface
    fn resolve_nic_bridge(&self, nic: &NicConfig) -> Option<String> {
        // Passthrough takes priority over manual bridge
        if let Some(ref pt_iface) = nic.passthrough_interface {
            if !pt_iface.is_empty() {
                match self.ensure_passthrough_bridge(pt_iface) {
                    Ok(bridge) => return Some(bridge),
                    Err(e) => {
                        warn!("Passthrough bridge failed for {}: {}", pt_iface, e);
                    }
                }
            }
        }
        // Fall back to manual bridge
        nic.bridge.clone().filter(|b| !b.is_empty())
    }

    /// Clean up TAP interfaces for extra NICs
    fn cleanup_extra_nic_taps(&self, name: &str, nics: &[NicConfig]) {
        for (i, nic) in nics.iter().enumerate() {
            let has_bridge = nic.bridge.as_ref().map(|b| !b.is_empty()).unwrap_or(false);
            let has_passthrough = nic.passthrough_interface.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
            if has_bridge || has_passthrough {
                let tap = format!("tap-{}-{}", &name[..name.len().min(8)], i + 1);
                let _ = self.cleanup_tap(&tap);
            }
        }
    }

    /// Clean up WolfNet routes for a specific IP
    fn cleanup_wolfnet_routes(&self, wolfnet_ip: &str) {
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
    }

    /// Stop a VM. `force = false` asks the guest to shut down gracefully
    /// (ACPI / SIGTERM); `force = true` yanks the power (like pulling the
    /// plug). Graceful is the default for user-initiated stop actions;
    /// internal callers that need a fast, definite stop pass true.
    pub fn stop_vm(&self, name: &str, force: bool) -> Result<(), String> {
        // On Proxmox: graceful = `qm shutdown` (ACPI, waits up to 30 s);
        // force = `qm stop` (immediate)
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            let (cmd_args, label): (Vec<String>, &str) = if force {
                (vec!["stop".into(), vmid.to_string()], "qm stop")
            } else {
                (
                    vec!["shutdown".into(), vmid.to_string(), "--timeout".into(), "30".into()],
                    "qm shutdown",
                )
            };
            let output = Command::new("qm").args(&cmd_args).output()
                .map_err(|e| format!("Failed to run {}: {}", label, e))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("{} failed: {}", label, stderr.trim()));
        }
        // On libvirt: graceful = `virsh shutdown` (ACPI, fire-and-forget);
        // force = `virsh destroy` (immediate)
        if containers::is_libvirt() {
            let (action, label) = if force { ("destroy", "virsh destroy") } else { ("shutdown", "virsh shutdown") };
            let output = Command::new("virsh").args([action, name]).output()
                .map_err(|e| format!("Failed to run {}: {}", label, e))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "domain is not running" is not an error — VM is already stopped
            if stderr.contains("not running") || stderr.contains("not found") {
                return Ok(());
            }
            return Err(format!("{} failed: {}", label, stderr.trim()));
        }

        // Read config to get WolfNet IP for cleanup
        let config = self.get_vm(name);

        let signal = if force { "-9" } else { "-15" };
        let output = Command::new("pkill")
            .arg(signal)
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output()
            .map_err(|e| e.to_string())?;

        if !output.status.success() {
            return Err("Failed to stop VM (process not found?)".to_string());
        }

        // Clean up networking
        if let Some(config) = config {
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
                if let Some(ref ip) = config.wolfnet_ip {
                    self.cleanup_wolfnet_routes(ip);
                }
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
        }

        // Clean up runtime file
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));


        Ok(())
    }

    pub fn get_vm(&self, name: &str) -> Option<VmConfig> {
        // On Proxmox, find VM in the qm list output
        if containers::is_proxmox() {
            return self.qm_list_all().into_iter().find(|vm| vm.name == name);
        }
        // On libvirt, get VM details via virsh
        if containers::is_libvirt() {
            return self.virsh_vm_to_config(name);
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).ok()?;
        let mut vm: VmConfig = serde_json::from_str(&content).ok()?;
        vm.running = self.check_running(name);
        if vm.running {
            vm.vnc_port = self.read_runtime_vnc_port(name);
            vm.vnc_ws_port = self.read_runtime_ws_port(name);
        }
        Some(vm)
    }

    pub fn delete_vm(&self, name: &str) -> Result<(), String> {
        // Release the VM's WolfNet IP from the route cache so it becomes
        // available for the next allocation. Without this, the IP stays
        // in WOLFNET_ROUTES / routes.json until the next poll cycle, and
        // a VM recreated immediately afterwards would see the IP as
        // "still in use" and get empty / a different address.
        let released_ip: Option<String> =
            self.get_vm(name).and_then(|c| c.wolfnet_ip.clone());

        // On Proxmox, delegate to qm destroy
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            // Stop first if running
            let _ = Command::new("qm").args(["stop", &vmid.to_string()]).output();
            let output = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output()
                .map_err(|e| format!("Failed to run qm destroy: {}", e))?;
            if output.status.success() {
                // Also clean up any WolfStack tracking config
                let _ = fs::remove_file(self.vm_config_path(name));
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("qm destroy failed: {}", stderr.trim()));
        }
        // On libvirt, delegate to virsh undefine (keeps disk files — user can delete manually)
        if containers::is_libvirt() {
            // Stop first if running
            let _ = Command::new("virsh").args(["destroy", name]).output();
            // Undefine the VM definition (does NOT delete disk files)
            let output = Command::new("virsh").args(["undefine", name, "--nvram"]).output()
                .map_err(|e| format!("Failed to run virsh undefine: {}", e))?;
            if output.status.success() {
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                return Ok(());
            }
            // Retry without --nvram for non-UEFI VMs
            let output2 = Command::new("virsh").args(["undefine", name]).output()
                .map_err(|e| format!("Failed to run virsh undefine: {}", e))?;
            if output2.status.success() {
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output2.stderr);
            return Err(format!("virsh undefine failed: {}", stderr.trim()));
        }

        if self.check_running(name) {
            // Deleting — force stop is correct here, no point waiting for ACPI
            let _ = self.stop_vm(name, true);
        }

        // Load config to find extra disk files to clean up
        if let Some(config) = self.get_vm(name) {
            // Delete OS disk at custom path if applicable
            let os_disk = self.vm_os_disk_path(&config);
            let _ = fs::remove_file(&os_disk);

            // Delete all extra volume files
            for vol in &config.extra_disks {
                let path = vol.file_path();
                if path.exists() {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        let _ = fs::remove_file(self.vm_config_path(name));
        let _ = fs::remove_file(self.vm_disk_path(name));  // fallback default path
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));
        let _ = fs::remove_file(self.base_dir.join(format!("{}.log", name)));

        if let Some(ip) = released_ip {
            containers::release_wolfnet_ip(&ip);
        }

        Ok(())
    }

    fn check_running(&self, name: &str) -> bool {
        // Check both x86_64 and aarch64 QEMU binaries (for PiMox / ARM hosts)
        for qemu_bin in &["qemu-system-x86_64", "qemu-system-aarch64"] {
            let output = Command::new("pgrep")
                .arg("-f")
                .arg(format!("{}.*-name {}", qemu_bin, name))
                .output();
            if let Ok(o) = output {
                if o.status.success() {
                    return true;
                }
            }
        }
        false
    }

    /// Read the VNC port from runtime file
    fn read_runtime_vnc_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }

    /// Read the WebSocket port from runtime file (for noVNC)
    fn read_runtime_ws_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_ws_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }

    // ─── Libvirt VM Management (virsh) ───

    /// List all VMs from libvirt via `virsh list --all`
    fn virsh_list_all(&self) -> Vec<VmConfig> {
        let output = match Command::new("virsh").args(["list", "--all", "--name"]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        output.lines()
            .map(|l| l.trim().to_string())
            .filter(|name| !name.is_empty())
            .filter_map(|name| self.virsh_vm_to_config(&name))
            .collect()
    }

    /// Convert a libvirt VM into a VmConfig (used by list and get)
    fn virsh_vm_to_config(&self, name: &str) -> Option<VmConfig> {
        // dominfo for CPU, memory, state
        let dominfo = Command::new("virsh").args(["dominfo", name]).output().ok()?;
        let dominfo_text = String::from_utf8_lossy(&dominfo.stdout);

        let mut cpus = 1u32;
        let mut memory_kb = 1048576u64;
        let mut running = false;
        let mut auto_start = false;

        for line in dominfo_text.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "CPU(s)" => { cpus = val.parse().unwrap_or(1); }
                "Max memory" => {
                    memory_kb = val.split_whitespace().next()
                        .and_then(|v| v.parse().ok()).unwrap_or(1048576);
                }
                "State" => { running = val.contains("running"); }
                "Autostart" => { auto_start = val.contains("enable"); }
                _ => {}
            }
        }

        // Primary disk: first non-CDROM from domblklist
        let blklist = Command::new("virsh").args(["domblklist", name, "--details"]).output().ok()?;
        let blklist_text = String::from_utf8_lossy(&blklist.stdout);
        let mut disk_size_gb = 0u32;
        let mut disk_source = String::new();
        let mut iso_path: Option<String> = None;

        for line in blklist_text.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let device = parts[1]; // disk, cdrom
            let target = parts[2]; // vda, sda
            let source = parts[3..].join(" ");
            if source == "-" || source.is_empty() { continue; }

            if device == "cdrom" {
                iso_path = Some(source);
            } else if disk_source.is_empty() {
                disk_source = source;
                disk_size_gb = disk_size_from_virsh(name, target).unwrap_or(0);
            }
        }

        // MAC address from first NIC
        let iflist = Command::new("virsh").args(["domiflist", name]).output().ok()?;
        let iflist_text = String::from_utf8_lossy(&iflist.stdout);
        let mut mac_address: Option<String> = None;
        for line in iflist_text.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                mac_address = Some(parts[4].to_string());
                break;
            }
        }

        // VNC port for running VMs: virsh vncdisplay returns ":N" or "host:N"
        let vnc_port = if running {
            Command::new("virsh").args(["vncdisplay", name]).output().ok()
                .and_then(|o| {
                    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    // Parse display number after the last ':'  (handles both ":0" and "127.0.0.1:0")
                    text.rsplit(':').next()
                        .and_then(|n| n.parse::<u16>().ok())
                        .map(|n| 5900 + n)
                })
        } else {
            None
        };

        // Storage path from disk source directory
        let storage_path = Path::new(&disk_source).parent()
            .map(|p| p.to_string_lossy().to_string());

        // Detect UEFI/OVMF from dumpxml, and parse <hostdev> nodes for USB/PCI passthrough
        let dumpxml = Command::new("virsh").args(["dumpxml", name]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let bios_type = if dumpxml.contains("OVMF") || dumpxml.contains("ovmf") || dumpxml.contains("AAVMF") || dumpxml.contains("edk2") {
            "ovmf".to_string()
        } else {
            "seabios".to_string()
        };

        let (usb_devices, pci_devices) = parse_libvirt_hostdevs(&dumpxml);

        Some(VmConfig {
            name: name.to_string(),
            cpus,
            memory_mb: (memory_kb / 1024) as u32,
            disk_size_gb,
            iso_path,
            running,
            vnc_port,
            vnc_ws_port: None, // libvirt VMs don't use WebSocket VNC
            mac_address,
            auto_start,
            wolfnet_ip: None,
            storage_path,
            os_disk_bus: "virtio".to_string(),
            net_model: "virtio".to_string(),
            drivers_iso: None,
            import_image: None,
            extra_disks: Vec::new(),
            extra_nics: Vec::new(),
            usb_devices,
            pci_devices,
            vmid: None,
            bios_type,
        })
    }

    /// Create a VM via libvirt (virt-install)
    fn virsh_create(&self, config: &VmConfig) -> Result<(), String> {
        let storage_dir = config.storage_path.as_deref().unwrap_or("/var/lib/libvirt/images");
        let disk_path = format!("{}/{}.qcow2", storage_dir, config.name);

        let mut args = vec![
            "--name".to_string(), config.name.clone(),
            "--vcpus".to_string(), config.cpus.to_string(),
            "--memory".to_string(), config.memory_mb.to_string(),
            "--disk".to_string(), format!("path={},size={},format=qcow2", disk_path, config.disk_size_gb),
            "--os-variant".to_string(), "generic".to_string(),
            "--graphics".to_string(), "vnc,listen=0.0.0.0".to_string(),
            "--noautoconsole".to_string(),
        ];

        // Network: use default network
        args.extend(["--network".to_string(), "default".to_string()]);

        // Import image or ISO — one of these is required for virt-install
        if let Some(ref import) = config.import_image {
            if !import.is_empty() {
                args.push("--import".to_string());
                // Replace the disk arg with the import image
                if let Some(pos) = args.iter().position(|a| a.starts_with("path=")) {
                    args[pos] = format!("path={},format=qcow2", import);
                }
            }
        } else if let Some(ref iso) = config.iso_path {
            if !iso.is_empty() {
                args.extend(["--cdrom".to_string(), iso.clone()]);
            } else {
                return Err("An ISO or import image is required to create a VM via libvirt".to_string());
            }
        } else {
            return Err("An ISO or import image is required to create a VM via libvirt".to_string());
        }

        if config.bios_type == "ovmf" {
            args.extend(["--boot".to_string(), "uefi".to_string()]);
        }

        // Extra disks — virt-install accepts multiple --disk flags. The
        // files are created by virt-install itself when size is given.
        for vol in &config.extra_disks {
            let vol_path = vol.file_path();
            args.push("--disk".to_string());
            args.push(format!(
                "path={},size={},format={},bus={}",
                vol_path.display(), vol.size_gb, vol.format, vol.bus
            ));
        }

        let output = Command::new("virt-install").args(&args).output()
            .map_err(|e| format!("Failed to run virt-install: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("virt-install failed: {}", stderr.trim()));
        }

        // Attach USB/PCI passthrough devices to the newly-created domain
        if !config.usb_devices.is_empty() || !config.pci_devices.is_empty() {
            if let Err(e) = super::passthrough::apply_libvirt_passthrough(&config.name, config) {
                warn!("Failed to attach passthrough devices to libvirt VM {}: {}", config.name, e);
            }
        }

        Ok(())
    }

    // ─── Libvirt VM Discovery & Adoption ───

    /// Discover VMs managed by libvirt that could be adopted into WolfStack
    pub fn discover_libvirt_vms(&self) -> Vec<DiscoveredVm> {
        // Check if virsh is available
        let virsh_check = Command::new("which").arg("virsh").output();
        if !virsh_check.map(|o| o.status.success()).unwrap_or(false) {
            return vec![];
        }

        // Get all VM names
        let output = match Command::new("virsh").args(["list", "--all", "--name"]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        let existing_vms: Vec<String> = self.list_vms().iter().map(|v| v.name.clone()).collect();

        output.lines()
            .map(|l| l.trim().to_string())
            .filter(|name| !name.is_empty())
            .filter_map(|name| self.discover_single_libvirt_vm(&name, &existing_vms))
            .collect()
    }

    fn discover_single_libvirt_vm(&self, name: &str, existing: &[String]) -> Option<DiscoveredVm> {
        // Get dominfo for CPU, memory, state
        let dominfo = Command::new("virsh").args(["dominfo", name]).output().ok()?;
        let dominfo_text = String::from_utf8_lossy(&dominfo.stdout);

        let mut cpus = 1u32;
        let mut memory_kb = 1048576u64; // 1GB default
        let mut state = "unknown".to_string();

        for line in dominfo_text.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "CPU(s)" => { cpus = val.parse().unwrap_or(1); }
                "Max memory" => {
                    // Format: "2097152 KiB"
                    memory_kb = val.split_whitespace().next()
                        .and_then(|v| v.parse().ok()).unwrap_or(1048576);
                }
                "State" => { state = val.to_string(); }
                _ => {}
            }
        }

        // Get disk info via domblklist
        let blklist = Command::new("virsh").args(["domblklist", name, "--details"]).output().ok()?;
        let blklist_text = String::from_utf8_lossy(&blklist.stdout);
        let mut disks = Vec::new();

        for line in blklist_text.lines().skip(2) { // Skip header + separator
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: Type  Device  Target  Source
            if parts.len() < 4 { continue; }
            let _dev_type = parts[0]; // file, block, etc.
            let device = parts[1];   // disk, cdrom
            let target = parts[2];   // vda, sda, hda
            let source = parts[3..].join(" "); // path (may contain spaces)

            if source == "-" || source.is_empty() { continue; }

            let is_cdrom = device == "cdrom";
            // Get disk size: try virsh domblkinfo first (works on running VMs),
            // fall back to qemu-img info
            let (size_gb, format) = if !is_cdrom {
                let size = disk_size_from_virsh(name, target)
                    .unwrap_or_else(|| disk_info_from_qemu_img(&source).0);
                let fmt = Path::new(&source).extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("qcow2")
                    .to_string();
                (size, fmt)
            } else {
                (0, "raw".to_string())
            };

            disks.push(DiscoveredDisk {
                target: target.to_string(),
                source: source.to_string(),
                size_gb,
                format,
                is_cdrom,
            });
        }

        // Get NIC info via domiflist
        let iflist = Command::new("virsh").args(["domiflist", name]).output().ok()?;
        let iflist_text = String::from_utf8_lossy(&iflist.stdout);
        let mut nics = Vec::new();

        for line in iflist_text.lines().skip(2) { // Skip header + separator
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: Interface  Type  Source  Model  MAC
            if parts.len() < 5 { continue; }
            nics.push(DiscoveredNic {
                nic_type: parts[1].to_string(),
                source: parts[2].to_string(),
                model: parts[3].to_string(),
                mac: parts[4].to_string(),
            });
        }

        // Parse dumpxml for BIOS type and primary disk bus
        let (bios_type, os_disk_bus) = if let Ok(xml_out) = Command::new("virsh").args(["dumpxml", name]).output() {
            let xml = String::from_utf8_lossy(&xml_out.stdout);
            let bios = if xml.contains("OVMF") || xml.contains("ovmf") || xml.contains("AAVMF") || xml.contains("edk2") {
                "ovmf".to_string()
            } else {
                "seabios".to_string()
            };
            // Find primary disk bus: look for <target dev='vda' bus='virtio'/> in first <disk device='disk'> block
            let bus = xml.lines()
                .skip_while(|l| !l.contains("device='disk'"))
                .find(|l| l.contains("<target") && l.contains("bus="))
                .and_then(|l| {
                    l.split("bus='").nth(1).or_else(|| l.split("bus=\"").nth(1))
                        .and_then(|s| s.split(['\'', '"']).next())
                })
                .unwrap_or("virtio")
                .to_string();
            (bios, bus)
        } else {
            ("seabios".to_string(), "virtio".to_string())
        };

        Some(DiscoveredVm {
            name: name.to_string(),
            state,
            cpus,
            memory_mb: (memory_kb / 1024) as u32,
            disks,
            nics,
            bios_type,
            os_disk_bus,
            already_managed: existing.contains(&name.to_string()),
        })
    }

    /// Adopt a libvirt VM into WolfStack management.
    /// Creates a WolfStack config pointing at the existing disk files.
    /// Does NOT modify or remove anything from libvirt — the user can
    /// stop and undefine from libvirt themselves when ready to switch.
    pub fn adopt_libvirt_vm(&self, name: &str) -> Result<VmConfig, String> {
        // Validate name
        if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
            return Err("Invalid VM name".to_string());
        }

        // Check not already managed
        if self.vm_config_path(name).exists() {
            return Err(format!("VM '{}' is already managed by WolfStack", name));
        }

        // Discover VM details
        let existing = self.list_vms().iter().map(|v| v.name.clone()).collect::<Vec<_>>();
        let discovered = self.discover_single_libvirt_vm(name, &existing)
            .ok_or_else(|| format!("Could not read VM '{}' from libvirt", name))?;

        // Find primary disk (first non-CDROM disk)
        let primary_disk = discovered.disks.iter()
            .find(|d| !d.is_cdrom)
            .ok_or_else(|| format!("VM '{}' has no disk images", name))?;

        // Validate disk is a real file
        let disk_path = Path::new(&primary_disk.source);
        if !disk_path.exists() {
            return Err(format!("Disk file not found: {}", primary_disk.source));
        }
        let disk_dir = disk_path.parent()
            .ok_or_else(|| "Cannot determine disk directory".to_string())?;

        // If the disk filename doesn't match {name}.qcow2, create a symlink
        let storage_path = disk_dir.to_string_lossy().to_string();
        let expected_path = disk_dir.join(format!("{}.qcow2", name));
        if disk_path != expected_path {
            if expected_path.exists() {
                warn!("Expected disk path {} already exists — using it as-is", expected_path.display());
            } else {
                std::os::unix::fs::symlink(disk_path, &expected_path)
                    .map_err(|e| format!("Failed to create symlink for disk: {}", e))?;
                info!("Created symlink: {} -> {}", expected_path.display(), disk_path.display());
            }
        }

        // Build VmConfig
        let primary_mac = discovered.nics.first().map(|n| n.mac.clone());
        let primary_nic_model = discovered.nics.first()
            .map(|n| n.model.clone()).unwrap_or_else(|| "virtio".to_string());

        // Extra NICs (all after the first)
        let extra_nics: Vec<NicConfig> = discovered.nics.iter().skip(1).map(|n| {
            NicConfig {
                model: n.model.clone(),
                mac: Some(n.mac.clone()),
                bridge: if n.nic_type == "bridge" { Some(n.source.clone()) } else { None },
                passthrough_interface: None,
            }
        }).collect();

        // Extra disks (non-primary, non-CDROM)
        let extra_disks: Vec<StorageVolume> = discovered.disks.iter()
            .filter(|d| !d.is_cdrom && d.source != primary_disk.source)
            .enumerate()
            .map(|(i, d)| {
                let dp = Path::new(&d.source);
                StorageVolume {
                    name: format!("{}-extra{}", name, i + 1),
                    size_gb: d.size_gb,
                    storage_path: dp.parent().map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| storage_path.clone()),
                    format: d.format.clone(),
                    bus: discovered.os_disk_bus.clone(),
                }
            }).collect();

        // ISO (first CDROM with a source)
        let iso_path = discovered.disks.iter()
            .find(|d| d.is_cdrom && !d.source.is_empty())
            .map(|d| d.source.clone());

        // Parse passthrough devices from the libvirt XML so adopted VMs retain them
        let dumpxml = Command::new("virsh").args(["dumpxml", name]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let (usb_devices, pci_devices) = parse_libvirt_hostdevs(&dumpxml);

        let config = VmConfig {
            name: name.to_string(),
            cpus: discovered.cpus,
            memory_mb: discovered.memory_mb,
            disk_size_gb: primary_disk.size_gb,
            iso_path,
            running: false,
            vnc_port: None,
            vnc_ws_port: None,
            mac_address: primary_mac,
            auto_start: false,
            wolfnet_ip: None,
            storage_path: Some(storage_path),
            os_disk_bus: discovered.os_disk_bus,
            net_model: primary_nic_model,
            drivers_iso: None,
            import_image: None,
            extra_disks,
            extra_nics,
            usb_devices,
            pci_devices,
            vmid: None,
            bios_type: discovered.bios_type,
        };

        // Save config
        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(self.vm_config_path(name), json).map_err(|e| e.to_string())?;

        info!("Adopted libvirt VM '{}' into WolfStack (libvirt config left intact)", name);
        Ok(config)
    }
}

/// A VM discovered from libvirt that can be adopted
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredVm {
    pub name: String,
    pub state: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub disks: Vec<DiscoveredDisk>,
    pub nics: Vec<DiscoveredNic>,
    pub bios_type: String,
    pub os_disk_bus: String,
    pub already_managed: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredDisk {
    pub target: String,
    pub source: String,
    pub size_gb: u32,
    pub format: String,
    pub is_cdrom: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredNic {
    pub nic_type: String,
    pub source: String,
    pub model: String,
    pub mac: String,
}

/// Get disk size from virsh domblkinfo (works on running VMs)
fn disk_size_from_virsh(vm_name: &str, target: &str) -> Option<u32> {
    let output = Command::new("virsh").args(["domblkinfo", vm_name, target]).output().ok()?;
    if !output.status.success() { return None; }
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "Capacity:       21474836480" line
    for line in text.lines() {
        if let Some(val) = line.strip_prefix("Capacity:") {
            let bytes: u64 = val.trim().parse().ok()?;
            let gb = (bytes / (1024 * 1024 * 1024)) as u32;
            return Some(gb.max(1));
        }
    }
    None
}

/// Get disk size and format from qemu-img info
fn disk_info_from_qemu_img(path: &str) -> (u32, String) {
    let output = Command::new("qemu-img").args(["info", "--output=json", path]).output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&text) {
                let size_bytes = info["virtual-size"].as_u64().unwrap_or(0);
                let size_gb = (size_bytes / (1024 * 1024 * 1024)) as u32;
                let format = info["format"].as_str().unwrap_or("qcow2").to_string();
                return (size_gb.max(1), format);
            }
            (0, "qcow2".to_string())
        }
        _ => (0, "qcow2".to_string()),
    }
}

// ─── VM Migration (standalone functions — no mutex needed) ───

const VM_BASE: &str = "/var/lib/wolfstack/vms";

/// Export a VM as a tar.gz archive containing config JSON + disk images.
/// Returns the archive path. The VM must be stopped first.
pub fn export_vm(name: &str) -> Result<PathBuf, String> {
    // Validate name to prevent path traversal
    if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
        return Err("Invalid VM name".to_string());
    }

    let base = Path::new(VM_BASE);
    let config_path = base.join(format!("{}.json", name));

    if !config_path.exists() {
        return Err(format!("VM config not found: {}", config_path.display()));
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read VM config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse VM config: {}", e))?;

    // Create export staging directory
    let export_dir = PathBuf::from("/tmp/wolfstack-vm-exports");
    fs::create_dir_all(&export_dir)
        .map_err(|e| format!("Failed to create export dir: {}", e))?;

    // Stage files into a temp directory, then tar from there
    let staging = export_dir.join(format!("staging-{}-{}", name, uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging)
        .map_err(|e| format!("Failed to create staging dir: {}", e))?;

    // Copy config JSON (clear runtime fields for portability)
    let mut portable = config.clone();
    portable.running = false;
    portable.vnc_port = None;
    portable.vnc_ws_port = None;
    portable.wolfnet_ip = None;
    portable.storage_path = None; // will use target default
    portable.vmid = None; // clear Proxmox VMID
    // Passthrough devices are host-specific — they never survive a migration
    portable.usb_devices.clear();
    portable.pci_devices.clear();
    // Reset extra disk storage paths to default
    for disk in &mut portable.extra_disks {
        disk.storage_path = VM_BASE.to_string();
    }
    let portable_json = serde_json::to_string_pretty(&portable)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(staging.join(format!("{}.json", name)), &portable_json)
        .map_err(|e| format!("Failed to write staged config: {}", e))?;

    // Copy OS disk — may be in custom storage_path or default
    let os_disk = if let Some(ref sp) = config.storage_path {
        Path::new(sp).join(format!("{}.qcow2", name))
    } else {
        base.join(format!("{}.qcow2", name))
    };

    if let Some(vmid) = config.vmid.filter(|_| containers::is_proxmox()) {
        // On Proxmox, export disk via qemu-img convert
        // Get the disk path from Proxmox storage
        let pvesm = Command::new("pvesm")
            .args(["path", &format!("local-lvm:vm-{}-disk-0", vmid)])
            .output();
        let disk_source = match pvesm {
            Ok(ref o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => {
                // Fallback: try common paths
                format!("/dev/pve/vm-{}-disk-0", vmid)
            }
        };
        let dest = staging.join(format!("{}.qcow2", name));
        let output = Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2", &disk_source, &dest.to_string_lossy()])
            .output()
            .map_err(|e| format!("qemu-img convert failed to start: {}", e))?;
        if !output.status.success() {
            let _ = fs::remove_dir_all(&staging);
            return Err(format!("qemu-img convert failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
    } else if os_disk.exists() {
        fs::copy(&os_disk, staging.join(format!("{}.qcow2", name)))
            .map_err(|e| format!("Failed to copy OS disk: {}", e))?;
    } else {
        warn!("VM '{}' has no OS disk at {}", name, os_disk.display());
    }

    // Copy extra disks
    for disk in &config.extra_disks {
        let src = disk.file_path();
        if src.exists() {
            let dest_name = src.file_name().unwrap_or_default();
            fs::copy(&src, staging.join(dest_name))
                .map_err(|e| format!("Failed to copy extra disk '{}': {}", disk.name, e))?;
        }
    }

    // Create tar.gz archive
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_name = format!("vm-{}-{}.tar.gz", name, timestamp);
    let archive_path = export_dir.join(&archive_name);

    // Collect filenames in staging for tar
    let mut tar_items: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&staging) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                tar_items.push(fname.to_string());
            }
        }
    }

    let output = Command::new("tar")
        .arg("czf")
        .arg(archive_path.to_string_lossy().as_ref())
        .arg("-C")
        .arg(staging.to_string_lossy().as_ref())
        .args(&tar_items)
        .output()
        .map_err(|e| format!("Failed to create archive: {}", e))?;

    // Clean up staging
    let _ = fs::remove_dir_all(&staging);

    if !output.status.success() {
        return Err(format!("tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok(archive_path)
}

/// Import a VM from a tar.gz archive. Extracts to the VM base directory.
/// Returns a success message with the VM name.
pub fn import_vm(archive_path: &str, new_name: Option<&str>, storage: Option<&str>) -> Result<String, String> {
    // Validate new_name to prevent path traversal
    if let Some(n) = new_name {
        if n.contains('/') || n.contains("..") || n.contains('\0') || n.is_empty() {
            return Err("Invalid VM name: must not contain path separators".to_string());
        }
    }

    let base = Path::new(VM_BASE);
    fs::create_dir_all(base)
        .map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to a unique temp directory to avoid race conditions
    let tmp = PathBuf::from(format!("/tmp/wolfstack-vm-import-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp)
        .map_err(|e| format!("Failed to create import temp dir: {}", e))?;

    let output = Command::new("tar")
        .args(["xzf", archive_path, "-C"])
        .arg(tmp.to_string_lossy().as_ref())
        .output()
        .map_err(|e| format!("Failed to extract archive: {}", e))?;

    if !output.status.success() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Find the config JSON
    let config_file = fs::read_dir(&tmp)
        .map_err(|e| format!("Failed to read temp dir: {}", e))?
        .flatten()
        .find(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .ok_or_else(|| "No .json config file found in archive".to_string())?;

    let config_content = fs::read_to_string(config_file.path())
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: VmConfig = serde_json::from_str(&config_content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    let original_name = config.name.clone();
    let target_name = new_name.unwrap_or(&original_name).to_string();

    // Validate names from the archive to prevent path traversal
    if original_name.contains('/') || original_name.contains("..") || original_name.contains('\0') ||
       target_name.contains('/') || target_name.contains("..") || target_name.contains('\0') ||
       target_name.is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("Invalid VM name in archive: must not contain path separators".to_string());
    }

    // Check for name conflict
    if base.join(format!("{}.json", target_name)).exists() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("A VM named '{}' already exists on this node", target_name));
    }

    // Determine destination storage path
    let dest_storage = storage.filter(|s| !s.is_empty());

    // Update config for the new host
    config.name = target_name.clone();
    config.running = false;
    config.vnc_port = None;
    config.vnc_ws_port = None;
    config.wolfnet_ip = None;
    config.storage_path = dest_storage.map(|s| s.to_string());
    config.vmid = None;
    config.mac_address = Some(generate_mac()); // new MAC to avoid conflicts
    // Passthrough devices are host-specific; the target host may not even have
    // matching hardware, so clear them.
    config.usb_devices.clear();
    config.pci_devices.clear();
    // Reset extra disk storage paths
    let disk_storage = dest_storage.unwrap_or(VM_BASE);
    for disk in &mut config.extra_disks {
        disk.storage_path = disk_storage.to_string();
    }

    // On Proxmox, create via qm and import the disk
    if containers::is_proxmox() {
        // Get next VMID
        let nextid = Command::new("pvesh")
            .args(["get", "/cluster/nextid"])
            .output()
            .map_err(|e| format!("Failed to get next VMID: {}", e))?;
        if !nextid.status.success() {
            let _ = fs::remove_dir_all(&tmp);
            return Err("Failed to allocate Proxmox VMID".to_string());
        }
        let vmid: u32 = String::from_utf8_lossy(&nextid.stdout).trim().trim_matches('"').parse()
            .map_err(|_| "Failed to parse VMID".to_string())?;

        // Create a minimal VM shell
        let create = Command::new("qm")
            .args([
                "create", &vmid.to_string(),
                "--name", &target_name,
                "--cores", &config.cpus.to_string(),
                "--memory", &config.memory_mb.to_string(),
                "--net0", &format!("virtio={},bridge=vmbr0", config.mac_address.as_deref().unwrap_or("auto")),
            ])
            .output()
            .map_err(|e| format!("qm create failed: {}", e))?;
        if !create.status.success() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("qm create failed: {}", String::from_utf8_lossy(&create.stderr)));
        }

        // Import the disk
        let pve_storage = dest_storage.unwrap_or("local-lvm");
        let qcow2 = tmp.join(format!("{}.qcow2", original_name));
        if qcow2.exists() {
            let import = Command::new("qm")
                .args(["importdisk", &vmid.to_string(), &qcow2.to_string_lossy(), pve_storage])
                .output()
                .map_err(|e| format!("qm importdisk failed: {}", e))?;
            if !import.status.success() {
                // Clean up the VM shell we created since disk import failed
                let _ = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output();
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("qm importdisk failed: {}", String::from_utf8_lossy(&import.stderr)));
            }
            // Attach the imported disk
            let attach = Command::new("qm")
                .args(["set", &vmid.to_string(), "--scsi0", &format!("{}:vm-{}-disk-0", pve_storage, vmid)])
                .output()
                .map_err(|e| format!("qm set disk failed: {}", e))?;
            if !attach.status.success() {
                let _ = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output();
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("qm set disk failed: {}", String::from_utf8_lossy(&attach.stderr)));
            }
            let boot = Command::new("qm")
                .args(["set", &vmid.to_string(), "--boot", "order=scsi0"])
                .output()
                .map_err(|e| format!("qm set boot failed: {}", e))?;
            if !boot.status.success() {
                warn!("qm set boot order failed: {}", String::from_utf8_lossy(&boot.stderr));
            }
        }

        config.vmid = Some(vmid);
        // Save WolfStack tracking config
        let json = serde_json::to_string_pretty(&config).unwrap_or_default();
        let _ = fs::write(base.join(format!("{}.json", target_name)), &json);

        let _ = fs::remove_dir_all(&tmp);
        return Ok(format!("VM '{}' imported as Proxmox VMID {} ({})", original_name, vmid, target_name));
    }

    // Standalone: move files to destination storage directory
    let disk_dest = if let Some(sp) = dest_storage {
        let p = Path::new(sp);
        fs::create_dir_all(p).map_err(|e| format!("Failed to create storage dir '{}': {}", sp, e))?;
        p.to_path_buf()
    } else {
        base.to_path_buf()
    };

    // Move the qcow2 disk
    let src_disk = tmp.join(format!("{}.qcow2", original_name));
    if src_disk.exists() {
        let dest_disk = disk_dest.join(format!("{}.qcow2", target_name));
        fs::rename(&src_disk, &dest_disk)
            .or_else(|_| fs::copy(&src_disk, &dest_disk).map(|_| ()))
            .map_err(|e| format!("Failed to move OS disk: {}", e))?;
    }

    // Move extra disk files (rename if target_name differs)
    for disk in &mut config.extra_disks {
        let old_filename = format!("{}.{}", disk.name, disk.format);
        let src = tmp.join(&old_filename);
        if src.exists() {
            // Update disk name if VM was renamed
            if target_name != original_name && disk.name.starts_with(&original_name) {
                disk.name = disk.name.replacen(&original_name, &target_name, 1);
            }
            let new_filename = format!("{}.{}", disk.name, disk.format);
            let dest = disk_dest.join(&new_filename);
            fs::rename(&src, &dest)
                .or_else(|_| fs::copy(&src, &dest).map(|_| ()))
                .map_err(|e| format!("Failed to move extra disk '{}': {}", disk.name, e))?;
        }
    }

    // Write the updated config
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(base.join(format!("{}.json", target_name)), &json)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Clean up
    let _ = fs::remove_dir_all(&tmp);

    Ok(format!("VM '{}' imported successfully as '{}'", original_name, target_name))
}

/// Clean up an export archive
pub fn export_cleanup(archive_path: &str) {
    let _ = fs::remove_file(archive_path);
}

/// Pre-flight a Proxmox VM config before `qm start`.
///
/// Reads `/etc/pve/qemu-server/<vmid>.conf` and confirms the fields that PVE
/// silently blank-tolerates but can't actually boot without. Returns the
/// problem in plain English so the UI/CLI can surface it instead of the
/// generic pvestatd warning.
pub fn validate_pve_config(vmid: u32) -> Result<(), String> {
    let path = format!("/etc/pve/qemu-server/{}.conf", vmid);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path, e))?;

    // Walk the top-level section only — snapshots appear as [snap-name]
    // headers and carry their own memory/cores which we do not validate.
    let mut memory: Option<i64> = None;
    let mut cores: Option<i64> = None;
    let mut has_boot_target = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.starts_with('[') { break; } // start of snapshot section
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "memory" => memory = val.parse::<i64>().ok(),
                "cores" => cores = val.parse::<i64>().ok(),
                _ => {
                    // Any scsi/virtio/ide/sata block device counts as a
                    // bootable target. efidisk0 is just EFI vars, not boot.
                    let is_disk = ["scsi", "virtio", "ide", "sata"].iter().any(|prefix| {
                        key.starts_with(prefix)
                            && key.len() > prefix.len()
                            && key[prefix.len()..].chars().all(|c| c.is_ascii_digit())
                    });
                    if is_disk && !val.is_empty() { has_boot_target = true; }
                }
            }
        }
    }

    match memory {
        None => return Err("missing `memory:` line (e.g. `memory: 512`)".into()),
        Some(m) if m <= 0 => return Err(format!("`memory: {}` must be greater than 0", m)),
        _ => {}
    }
    match cores {
        // PVE defaults `cores` to 1 when absent, so only reject explicitly-
        // blank or zero values.
        Some(c) if c <= 0 => return Err(format!("`cores: {}` must be greater than 0", c)),
        _ => {}
    }
    if !has_boot_target {
        return Err("no disk attached (need at least one of scsi0/virtio0/ide0/sata0)".into());
    }
    Ok(())
}
