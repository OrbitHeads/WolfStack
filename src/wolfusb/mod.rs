// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfUSB Integration — USB-over-IP device sharing
//!
//! Manages WolfUSB servers on cluster nodes, allowing USB devices to be
//! shared across the network and assigned to Docker containers, LXC
//! containers, and VMs.

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn};

fn config_path() -> String { format!("{}/wolfusb.json", crate::paths::get().config_dir) }

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfUsbConfig {
    /// Whether the WolfUSB server is enabled on this node
    #[serde(default)]
    pub enabled: bool,
    /// Bind address for the WolfUSB server
    #[serde(default = "default_bind")]
    pub bind_address: String,
    /// TCP port for the WolfUSB server
    #[serde(default = "default_port")]
    pub port: u16,
    /// Pre-shared authentication key (optional)
    #[serde(default)]
    pub auth_key: String,
    /// USB devices currently assigned to containers/VMs
    #[serde(default)]
    pub assignments: Vec<UsbAssignment>,
}

fn default_bind() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 3240 }

fn generate_auth_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let hostname = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
    let raw = format!("{:x}{}{:x}", seed, hostname, seed.wrapping_mul(0x517cc1b727220a95));
    // Take 32 hex chars
    raw.chars().filter(|c| c.is_ascii_hexdigit()).take(32).collect()
}

impl Default for WolfUsbConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: default_bind(),
            port: default_port(),
            auth_key: generate_auth_key(),
            assignments: Vec::new(),
        }
    }
}

impl WolfUsbConfig {
    pub fn load() -> Self {
        let mut config: Self = match std::fs::read_to_string(&config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => {
                // First run — save defaults (with generated auth key)
                let c = Self::default();
                let _ = c.save();
                return c;
            }
        };
        // Backfill auth key if config exists but key is empty
        if config.auth_key.is_empty() {
            config.auth_key = generate_auth_key();
            let _ = config.save();
        }
        config
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        let dir = std::path::Path::new(&path).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }
}

/// Assignment of a USB device to a container/VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbAssignment {
    /// Bus number of the USB device
    pub bus: u8,
    /// Device address on the bus
    pub address: u8,
    /// Friendly label (e.g. "Logitech Webcam")
    #[serde(default)]
    pub label: String,
    /// Target type: "docker", "lxc", "vm"
    pub target_type: String,
    /// Target name (container/VM name)
    pub target_name: String,
    /// Whether this assignment is currently active
    #[serde(default)]
    pub active: bool,
    /// WolfUSB session ID (set when attached)
    #[serde(default)]
    pub session_id: Option<u64>,
}

// ─── USB Device Info ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub bus: u8,
    pub address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    #[serde(default)]
    pub device_class: u8,
    #[serde(default)]
    pub speed: String,
    /// Whether this device is currently assigned to something
    #[serde(default)]
    pub assigned_to: Option<String>,
}

// ─── Installation ───

/// Check if WolfUSB binary is installed
pub fn is_installed() -> bool {
    Command::new("which").arg("wolfusb").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get the installed version
pub fn installed_version() -> Option<String> {
    let output = Command::new("wolfusb").arg("--version").output().ok()?;
    if !output.status.success() { return None; }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Output is "wolfusb X.Y.Z" — extract version
    text.split_whitespace().last().map(|s| s.to_string())
}

/// Install WolfUSB from the official setup script
pub async fn install() -> Result<String, String> {
    info!("WolfUSB: installing from setup.sh");
    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg("curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfusb/main/setup.sh | bash")
        .output()
        .await
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}\n{}", stdout, stderr);

    // Check if the binary actually exists (installer may exit non-zero due to
    // harmless shell issues like unbound variables even when install succeeded)
    if is_installed() {
        info!("WolfUSB: installed successfully");
        Ok(combined)
    } else if output.status.success() {
        info!("WolfUSB: installed successfully");
        Ok(combined)
    } else {
        warn!("WolfUSB: installation failed");
        Err(format!("Installation failed:\n{}", combined))
    }
}

// ─── Service Management ───

/// Check if the WolfUSB systemd service is running
pub fn is_running() -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", "wolfusb"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Start the WolfUSB service with current config
pub fn start_service(config: &WolfUsbConfig) -> Result<(), String> {
    // Write env file for systemd
    let env_content = format!(
        "WOLFUSB_BIND={}\nWOLFUSB_PORT={}\n{}",
        config.bind_address,
        config.port,
        if config.auth_key.is_empty() { String::new() } else { format!("WOLFUSB_KEY={}", config.auth_key) }
    );
    std::fs::create_dir_all("/etc/wolfusb").map_err(|e| e.to_string())?;
    std::fs::write("/etc/wolfusb/wolfusb.env", &env_content).map_err(|e| e.to_string())?;

    // Install systemd service if not present
    if !std::path::Path::new("/etc/systemd/system/wolfusb.service").exists() {
        let service = format!(
            "[Unit]\nDescription=WolfUSB — USB over IP\nAfter=network.target\n\n\
             [Service]\nType=simple\nEnvironmentFile=/etc/wolfusb/wolfusb.env\n\
             ExecStart=/usr/local/bin/wolfusb server --bind ${{WOLFUSB_BIND}} --port ${{WOLFUSB_PORT}} {}\n\
             Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target",
            if config.auth_key.is_empty() { "" } else { "--key ${WOLFUSB_KEY}" }
        );
        std::fs::write("/etc/systemd/system/wolfusb.service", &service).map_err(|e| e.to_string())?;
        Command::new("systemctl").args(["daemon-reload"]).output().ok();
    }

    Command::new("systemctl").args(["enable", "--now", "wolfusb"])
        .output()
        .map_err(|e| format!("Failed to start WolfUSB: {}", e))?;
    Ok(())
}

/// Stop the WolfUSB service
pub fn stop_service() -> Result<(), String> {
    Command::new("systemctl").args(["stop", "wolfusb"])
        .output()
        .map_err(|e| format!("Failed to stop WolfUSB: {}", e))?;
    Ok(())
}

// ─── Device Operations ───

/// List USB devices on the local machine (uses lsusb for reliability)
pub fn list_local_devices(config: &WolfUsbConfig) -> Vec<UsbDevice> {
    // Try wolfusb list first if server is running
    if is_running() {
        let key_arg = if config.auth_key.is_empty() {
            String::new()
        } else {
            format!(" --key '{}'", config.auth_key)
        };
        let cmd = format!("wolfusb list --server 127.0.0.1:{}{}", config.port, key_arg);
        if let Ok(output) = Command::new("bash").arg("-c").arg(&cmd).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let devices = parse_wolfusb_list(&text, config);
                if !devices.is_empty() {
                    return devices;
                }
            }
        }
    }

    // Fallback: parse lsusb output
    parse_lsusb(config)
}

/// List USB devices on a remote WolfUSB server
pub async fn list_remote_devices(host: &str, port: u16, key: &str) -> Result<Vec<UsbDevice>, String> {
    let mut cmd = format!("wolfusb list --server {}:{}", host, port);
    if !key.is_empty() {
        cmd.push_str(&format!(" --key '{}'", key));
    }

    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .map_err(|e| format!("Failed to list devices: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("WolfUSB list failed: {}", stderr));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_wolfusb_list(&text, &WolfUsbConfig::default()))
}

/// Parse wolfusb list output into UsbDevice structs
fn parse_wolfusb_list(text: &str, config: &WolfUsbConfig) -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Expected format: "Bus XXX Device YYY: ID VVVV:PPPP Manufacturer Product"
        if !line.starts_with("Bus ") { continue; }
        let parts: Vec<&str> = line.splitn(2, ": ").collect();
        if parts.len() < 2 { continue; }

        // Parse "Bus XXX Device YYY"
        let bus_dev: Vec<&str> = parts[0].split_whitespace().collect();
        let bus = bus_dev.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
        let address = bus_dev.get(3).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);

        // Parse "ID VVVV:PPPP Description"
        let id_desc = parts[1];
        let (vendor_id, product_id, product) = if id_desc.starts_with("ID ") {
            let rest = &id_desc[3..];
            let id_parts: Vec<&str> = rest.splitn(2, ' ').collect();
            let ids: Vec<&str> = id_parts[0].split(':').collect();
            let vid = ids.get(0).and_then(|s| u16::from_str_radix(s, 16).ok()).unwrap_or(0);
            let pid = ids.get(1).and_then(|s| u16::from_str_radix(s, 16).ok()).unwrap_or(0);
            let desc = id_parts.get(1).unwrap_or(&"").to_string();
            (vid, pid, desc)
        } else {
            (0, 0, id_desc.to_string())
        };

        let assigned = config.assignments.iter()
            .find(|a| a.bus == bus && a.address == address)
            .map(|a| format!("{}:{}", a.target_type, a.target_name));

        devices.push(UsbDevice {
            bus,
            address,
            vendor_id,
            product_id,
            manufacturer: String::new(),
            product,
            serial: String::new(),
            device_class: 0,
            speed: String::new(),
            assigned_to: assigned,
        });
    }
    devices
}

/// Parse lsusb output as fallback
fn parse_lsusb(config: &WolfUsbConfig) -> Vec<UsbDevice> {
    let output = match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    let mut devices = Vec::new();
    for line in output.lines() {
        // Format: "Bus 001 Device 002: ID 1a2b:3c4d Manufacturer Product"
        let parts: Vec<&str> = line.splitn(2, ": ").collect();
        if parts.len() < 2 { continue; }

        let bus_dev: Vec<&str> = parts[0].split_whitespace().collect();
        let bus = bus_dev.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
        let address = bus_dev.get(3).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);

        let id_desc = parts[1];
        let (vendor_id, product_id, product) = if id_desc.starts_with("ID ") {
            let rest = &id_desc[3..];
            let id_parts: Vec<&str> = rest.splitn(2, ' ').collect();
            let ids: Vec<&str> = id_parts[0].split(':').collect();
            let vid = ids.get(0).and_then(|s| u16::from_str_radix(s, 16).ok()).unwrap_or(0);
            let pid = ids.get(1).and_then(|s| u16::from_str_radix(s, 16).ok()).unwrap_or(0);
            let desc = id_parts.get(1).unwrap_or(&"").trim().to_string();
            (vid, pid, desc)
        } else {
            (0, 0, id_desc.to_string())
        };

        let assigned = config.assignments.iter()
            .find(|a| a.bus == bus && a.address == address)
            .map(|a| format!("{}:{}", a.target_type, a.target_name));

        devices.push(UsbDevice {
            bus,
            address,
            vendor_id,
            product_id,
            manufacturer: String::new(),
            product,
            serial: String::new(),
            device_class: 0,
            speed: String::new(),
            assigned_to: assigned,
        });
    }
    devices
}

// ─── Device Assignment ───

/// Assign a USB device to a Docker container, LXC container, or VM.
/// For Docker: uses --device flag (requires container restart).
/// For LXC: modifies LXC config to pass through the device.
/// For VMs: uses WolfStack's existing USB passthrough system.
pub fn assign_device(
    config: &mut WolfUsbConfig,
    bus: u8,
    address: u8,
    label: &str,
    target_type: &str,
    target_name: &str,
) -> Result<String, String> {
    // Validate target type
    if !["docker", "lxc", "vm"].contains(&target_type) {
        return Err(format!("Invalid target type: {}. Must be docker, lxc, or vm", target_type));
    }

    // Remove any existing assignment for this device
    config.assignments.retain(|a| !(a.bus == bus && a.address == address));

    // Find the device path
    let dev_bus_path = format!("/dev/bus/usb/{:03}/{:03}", bus, address);

    let result = match target_type {
        "docker" => {
            // Docker: we'll store the assignment — the user needs to restart the container
            // with --device flag, or we can update the compose/run config
            info!("WolfUSB: assigning USB {}:{} to docker:{}", bus, address, target_name);
            Ok(format!(
                "USB device assigned to Docker container '{}'. \
                 The container needs to be recreated with --device {}. \
                 If using docker-compose, add:\n  devices:\n    - \"{}:{}\"",
                target_name, dev_bus_path, dev_bus_path, dev_bus_path
            ))
        }
        "lxc" => {
            // LXC: add cgroup device permission + mount entry
            info!("WolfUSB: assigning USB {}:{} to lxc:{}", bus, address, target_name);
            let lxc_config_path = format!("/var/lib/lxc/{}/config", target_name);
            if std::path::Path::new(&lxc_config_path).exists() {
                // Add device access to LXC config
                let entry = format!(
                    "\n# WolfUSB: USB device bus={} addr={} ({})\n\
                     lxc.cgroup2.devices.allow = c 189:* rwm\n\
                     lxc.mount.entry = {} dev/bus/usb/{:03}/{:03} none bind,optional,create=file 0 0\n",
                    bus, address, label, dev_bus_path, bus, address
                );
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&lxc_config_path)
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(entry.as_bytes())
                    })
                    .map_err(|e| format!("Failed to update LXC config: {}", e))?;
                Ok(format!("USB device assigned to LXC container '{}'. Restart the container to apply.", target_name))
            } else {
                Ok(format!("USB device assigned to LXC '{}'. Config will be applied on next start.", target_name))
            }
        }
        "vm" => {
            // VMs: use WolfStack's existing USB passthrough (VmConfig.usb_devices)
            info!("WolfUSB: assigning USB {}:{} to vm:{}", bus, address, target_name);
            Ok(format!(
                "USB device assigned to VM '{}'. \
                 Use the VM's USB Passthrough tab to complete the assignment, \
                 or the device will be passed through on next VM start.",
                target_name
            ))
        }
        _ => Err("Invalid target type".to_string()),
    };

    // Store the assignment in config
    config.assignments.push(UsbAssignment {
        bus,
        address,
        label: label.to_string(),
        target_type: target_type.to_string(),
        target_name: target_name.to_string(),
        active: true,
        session_id: None,
    });
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    result
}

/// Remove a USB device assignment
pub fn unassign_device(config: &mut WolfUsbConfig, bus: u8, address: u8) -> Result<String, String> {
    let removed = config.assignments.iter()
        .find(|a| a.bus == bus && a.address == address)
        .map(|a| format!("{}:{}", a.target_type, a.target_name));

    config.assignments.retain(|a| !(a.bus == bus && a.address == address));
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    match removed {
        Some(target) => Ok(format!("USB device {}:{} unassigned from {}", bus, address, target)),
        None => Err("Device was not assigned".to_string()),
    }
}
