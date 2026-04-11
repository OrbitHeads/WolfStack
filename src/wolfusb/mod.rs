// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfUSB Integration — USB device sharing across the cluster
//!
//! Uses the standalone `wolfusb` binary (https://github.com/wolfsoftwaresystemsltd/wolfusb)
//! which provides USB-over-IP via libusb with its own authenticated protocol.
//!
//! Architecture:
//! - Each node runs `wolfusb server` (managed via systemd or direct spawn)
//! - WolfStack queries the local wolfusb server for device discovery
//! - Assignments are stored in WolfStack config and synced across the cluster
//! - Local passthrough uses /dev/bus/usb directly (Docker --device, LXC mount, QEMU)
//! - Remote access uses the wolfusb protocol with cluster secret as the auth key

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::OnceLock;
use tracing::{info, warn};

fn config_path() -> String { format!("{}/wolfusb.json", crate::paths::get().config_dir) }

/// Cluster secret stored at init time, used as the wolfusb auth key
static CLUSTER_SECRET: OnceLock<String> = OnceLock::new();

/// Initialize the WolfUSB module with the cluster secret (call from main.rs)
pub fn init(cluster_secret: &str) {
    let _ = CLUSTER_SECRET.set(cluster_secret.to_string());
}

fn get_secret() -> &'static str {
    CLUSTER_SECRET.get().map(|s| s.as_str()).unwrap_or("")
}

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfUsbConfig {
    /// Whether WolfUSB sharing is enabled on this node
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// USB devices currently assigned to containers/VMs (local or remote)
    #[serde(default)]
    pub assignments: Vec<UsbAssignment>,
}

fn default_true() -> bool { true }

impl Default for WolfUsbConfig {
    fn default() -> Self {
        Self { enabled: true, assignments: Vec::new() }
    }
}

impl WolfUsbConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(&config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => {
                let c = Self::default();
                let _ = c.save();
                c
            }
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        let dir = std::path::Path::new(&path).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }
}

/// Assignment of a USB device to a container/VM (possibly on another node)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbAssignment {
    /// USB bus ID string (e.g. "wolfusb-1-2")
    pub busid: String,
    /// Friendly label (e.g. "Logitech Webcam")
    #[serde(default)]
    pub label: String,
    /// Vendor:Product ID string (e.g. "046d:0825")
    #[serde(default)]
    pub usb_id: String,
    /// Node ID where the physical USB device is connected (source)
    pub source_node_id: String,
    /// Source node hostname (for display)
    #[serde(default)]
    pub source_hostname: String,
    /// Source node address (IP/hostname for wolfusb connection)
    pub source_address: String,
    /// Target type: "docker", "lxc", "vm"
    pub target_type: String,
    /// Target name (container/VM name)
    pub target_name: String,
    /// Node ID where the target container/VM runs
    pub target_node_id: String,
    /// Target node hostname (for display)
    #[serde(default)]
    pub target_hostname: String,
    /// Whether this assignment is currently active
    #[serde(default)]
    pub active: bool,
    /// WolfUSB session ID (returned by wolfusb attach, needed for detach)
    #[serde(default)]
    pub session_id: Option<u64>,
    /// Legacy field — kept for config compat
    #[serde(default)]
    pub virtual_busid: Option<String>,
}

// ─── USB Device Info ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    /// Bus ID (e.g. "wolfusb-1-2")
    pub busid: String,
    pub vendor_id: String,
    pub product_id: String,
    pub product: String,
    #[serde(default)]
    pub assigned_to: Option<String>,
}

// ─── WolfUSB Binary Management ───

/// Find the wolfusb binary
fn find_wolfusb_binary() -> Option<String> {
    // Check PATH
    if Command::new("sh").args(["-c", "command -v wolfusb"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
    {
        return Some("wolfusb".to_string());
    }
    // Common locations
    for path in &["/usr/local/bin/wolfusb", "/usr/bin/wolfusb", "/opt/wolfusb/wolfusb"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Check if the wolfusb binary is available
pub fn is_wolfusb_available() -> bool {
    find_wolfusb_binary().is_some()
}

/// Get the installed wolfusb version string
pub fn get_wolfusb_version() -> Option<String> {
    let binary = find_wolfusb_binary()?;
    let output = Command::new(&binary).arg("--version").output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Run a wolfusb command with the cluster secret as auth key
fn run_wolfusb(args: &[&str]) -> Result<String, String> {
    let binary = find_wolfusb_binary()
        .ok_or_else(|| "wolfusb binary not found".to_string())?;

    let secret = get_secret();
    let mut cmd = Command::new(&binary);
    cmd.args(args);
    if !secret.is_empty() {
        cmd.arg("--key").arg(secret);
    }

    let output = cmd.output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("wolfusb failed: {}", stderr))
    }
}

/// Run a wolfusb command — try with key first, fall back to without key
fn run_wolfusb_with_fallback(args: &[&str]) -> Result<String, String> {
    let binary = find_wolfusb_binary()
        .ok_or_else(|| "wolfusb binary not found".to_string())?;

    let secret = get_secret();

    // Try with key if we have one
    if !secret.is_empty() {
        let output = Command::new(&binary).args(args).arg("--key").arg(secret)
            .output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try without key (server may not require auth)
    let output = Command::new(&binary).args(args)
        .output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("wolfusb failed: {}", stderr))
    }
}

/// Ensure the wolfusb server is running on this node
pub fn ensure_wolfusb_server() {
    // Check if already running via systemctl
    if let Ok(o) = Command::new("systemctl").args(["is-active", "--quiet", "wolfusb"]).status() {
        if o.success() { return; } // Already running
    }

    // Check if port 3240 is already in use
    if let Ok(o) = Command::new("sh")
        .args(["-c", "ss -tlnp 2>/dev/null | grep -q ':3240 '"])
        .status()
    {
        if o.success() { return; } // Something already listening
    }

    // Write the cluster secret to the wolfusb env file so systemd picks it up
    let secret = get_secret();
    if !secret.is_empty() {
        let _ = std::fs::create_dir_all("/etc/wolfusb");
        let env_content = format!("WOLFUSB_BIND=0.0.0.0\nWOLFUSB_PORT=3240\nWOLFUSB_KEY={}\n", secret);
        let _ = std::fs::write("/etc/wolfusb/wolfusb.env", &env_content);
    }

    // Try systemctl start first
    if let Ok(o) = Command::new("systemctl").args(["start", "wolfusb"]).status() {
        if o.success() {
            info!("WolfUSB: started wolfusb server via systemctl");
            return;
        }
    }

    // Fallback: spawn directly
    if let Some(binary) = find_wolfusb_binary() {
        let mut cmd = Command::new(&binary);
        cmd.args(["server", "--port", "3240"]);
        if !secret.is_empty() {
            cmd.arg("--key").arg(secret);
        }
        match cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => info!("WolfUSB: spawned wolfusb server directly on port 3240"),
            Err(e) => warn!("WolfUSB: failed to start wolfusb server: {}", e),
        }
    } else {
        warn!("WolfUSB: wolfusb binary not found — USB sharing unavailable");
    }
}

// ─── Device Operations ───

/// JSON structure returned by `wolfusb list --json`
#[derive(Debug, Deserialize)]
struct WolfUsbDeviceJson {
    device_id: WolfUsbDeviceIdJson,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    #[allow(dead_code)]
    serial_number: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WolfUsbDeviceIdJson {
    bus_number: u8,
    address: u8,
}

/// List USB devices on this node. Returns (devices, wolfusb_working).
pub fn list_local_devices_with_status(config: &WolfUsbConfig) -> (Vec<UsbDevice>, bool) {
    // Try with key first, fall back to without key
    match run_wolfusb_with_fallback(&["list", "--server", "127.0.0.1:3240", "--json"]) {
        Ok(json_str) => {
            match serde_json::from_str::<Vec<WolfUsbDeviceJson>>(&json_str) {
                Ok(raw_devices) => {
                    let devices = raw_devices.into_iter()
                        .filter(|d| d.vendor_id != 0x1d6b) // Filter root hubs
                        .map(|d| {
                            let busid = format!("wolfusb-{}-{}", d.device_id.bus_number, d.device_id.address);
                            let usb_id = format!("{:04x}:{:04x}", d.vendor_id, d.product_id);
                            let product = match (&d.manufacturer, &d.product) {
                                (Some(m), Some(p)) => format!("{} : {} ({usb_id})", m, p),
                                (None, Some(p)) => format!("{} ({usb_id})", p),
                                (Some(m), None) => format!("{} ({usb_id})", m),
                                (None, None) => format!("USB Device ({usb_id})"),
                            };
                            let assigned = config.assignments.iter()
                                .find(|a| a.busid == busid || a.usb_id == usb_id)
                                .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));
                            UsbDevice {
                                busid,
                                vendor_id: format!("{:04x}", d.vendor_id),
                                product_id: format!("{:04x}", d.product_id),
                                product,
                                assigned_to: assigned,
                            }
                        })
                        .collect();
                    (devices, true)
                }
                Err(e) => {
                    warn!("WolfUSB: failed to parse device list JSON: {}", e);
                    (Vec::new(), false)
                }
            }
        }
        Err(e) => {
            warn!("WolfUSB: wolfusb list failed: {}", e);
            (Vec::new(), false)
        }
    }
}

/// Parse "wolfusb-BUS-ADDR" into (bus, addr)
fn parse_busid(busid: &str) -> Result<(u8, u8), String> {
    let stripped = busid.strip_prefix("wolfusb-").unwrap_or(busid);
    let parts: Vec<&str> = stripped.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid busid format: {}", busid));
    }
    let bus: u8 = parts[0].parse().map_err(|_| format!("Invalid bus number in {}", busid))?;
    let addr: u8 = parts[1].parse().map_err(|_| format!("Invalid address in {}", busid))?;
    Ok((bus, addr))
}

/// Find the /dev/bus/usb path for a device by bus:addr
fn find_dev_path(busid: &str) -> Option<String> {
    let (bus, addr) = parse_busid(busid).ok()?;
    let path = format!("/dev/bus/usb/{:03}/{:03}", bus, addr);
    if std::path::Path::new(&path).exists() {
        Some(path)
    } else {
        None
    }
}

/// Attach to a remote USB device via the wolfusb protocol
fn wolfusb_attach_device(source_address: &str, busid: &str) -> Result<u64, String> {
    let (bus, addr) = parse_busid(busid)?;
    let server = format!("{}:3240", source_address);

    let output = run_wolfusb(&[
        "attach",
        "--server", &server,
        "--bus", &bus.to_string(),
        "--addr", &addr.to_string(),
    ])?;

    // Parse session_id from output: "Attached to X:Y, session_id = NNN"
    if let Some(sid_str) = output.split("session_id = ").nth(1) {
        if let Ok(sid) = sid_str.trim().parse::<u64>() {
            return Ok(sid);
        }
    }
    // If we can't parse the session_id, the attach still succeeded
    warn!("WolfUSB: attached but could not parse session_id from: {}", output.trim());
    Ok(0)
}

/// Detach from a remote USB device
fn wolfusb_detach_device(source_address: &str, busid: &str, session_id: u64) -> Result<(), String> {
    let (bus, addr) = parse_busid(busid)?;
    let server = format!("{}:3240", source_address);

    run_wolfusb(&[
        "detach",
        "--server", &server,
        "--bus", &bus.to_string(),
        "--addr", &addr.to_string(),
        "--session-id", &session_id.to_string(),
    ])?;
    Ok(())
}

// ─── Install ───

/// Install or upgrade the wolfusb binary and set up the systemd service
pub async fn install_wolfusb() -> Result<String, String> {
    info!("WolfUSB: installing/upgrading wolfusb");
    let script = r#"
set -e

# ─── Install libusb (required by wolfusb) ───
if command -v pacman >/dev/null 2>&1; then
    echo "Installing libusb via pacman..."
    pacman -S --noconfirm libusb 2>/dev/null || true
elif command -v apt-get >/dev/null 2>&1; then
    echo "Installing libusb via apt..."
    apt-get update -qq && apt-get install -y libusb-1.0-0 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
    echo "Installing libusb via dnf..."
    dnf install -y libusbx 2>/dev/null || dnf install -y libusb1 2>/dev/null || true
elif command -v zypper >/dev/null 2>&1; then
    echo "Installing libusb via zypper..."
    zypper install -y libusb-1_0-0 2>/dev/null || true
fi

# ─── Stop existing service before upgrade ───
if systemctl is-active --quiet wolfusb 2>/dev/null; then
    echo "Stopping wolfusb service for upgrade..."
    systemctl stop wolfusb
fi

# ─── Show old version if upgrading ───
if command -v wolfusb >/dev/null 2>&1; then
    OLD_VER=$(wolfusb --version 2>/dev/null || echo "unknown")
    echo "Current version: $OLD_VER"
fi

# ─── Download and install latest wolfusb ───
echo "Downloading latest wolfusb..."
curl -fsSL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfusb/main/setup.sh | bash

# ─── Show new version ───
if command -v wolfusb >/dev/null 2>&1; then
    NEW_VER=$(wolfusb --version 2>/dev/null || echo "unknown")
    echo "Installed version: $NEW_VER"
fi

# ─── Set up udev rules for USB access ───
mkdir -p /etc/udev/rules.d
echo 'SUBSYSTEM=="usb", MODE="0666", GROUP="plugdev"' > /etc/udev/rules.d/99-wolfusb.rules
udevadm control --reload-rules 2>/dev/null || true

# ─── Install systemd service ───
if [ ! -f /etc/systemd/system/wolfusb.service ]; then
    cat > /etc/systemd/system/wolfusb.service << 'UNIT'
[Unit]
Description=WolfUSB Server
After=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/wolfusb/wolfusb.env
ExecStart=/usr/local/bin/wolfusb server --bind ${WOLFUSB_BIND:-0.0.0.0} --port ${WOLFUSB_PORT:-3240}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
fi

# ─── Enable and start ───
systemctl enable wolfusb 2>/dev/null || true
systemctl start wolfusb 2>/dev/null || true

echo "OK: wolfusb installation complete"
    "#;

    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if is_wolfusb_available() {
        Ok(combined)
    } else {
        Err(format!("Installation may have partially succeeded:\n{}", combined))
    }
}

// ─── Assignment Operations ───

/// Assign a USB device to a container/VM, potentially on a different node.
pub fn assign_device(
    config: &mut WolfUsbConfig,
    busid: &str,
    label: &str,
    usb_id: &str,
    source_node_id: &str,
    source_hostname: &str,
    source_address: &str,
    target_type: &str,
    target_name: &str,
    target_node_id: &str,
    target_hostname: &str,
    is_local_source: bool,
) -> Result<String, String> {
    if !["docker", "lxc", "vm"].contains(&target_type) {
        return Err(format!("Invalid target type: {}", target_type));
    }

    // Remove any existing assignment for this device
    config.assignments.retain(|a| a.busid != busid || a.source_node_id != source_node_id);

    // For local same-node assignments, passthrough directly
    let is_local_target = target_node_id == source_node_id
        || (target_node_id.is_empty() && is_local_source);

    let msg = if is_local_source && is_local_target {
        match local_passthrough(busid, target_type, target_name) {
            Ok(m) => format!("USB device {} assigned to {}:{} (local)\n{}", busid, target_type, target_name, m),
            Err(e) => {
                warn!("WolfUSB: local passthrough failed: {}", e);
                format!("USB device {} assigned to {}:{} (passthrough pending: {})", busid, target_type, target_name, e)
            }
        }
    } else {
        format!("USB device {} from {} assigned to {}:{} on {}", busid, source_hostname, target_type, target_name, target_hostname)
    };

    // Store the assignment
    config.assignments.push(UsbAssignment {
        busid: busid.to_string(),
        label: label.to_string(),
        usb_id: usb_id.to_string(),
        source_node_id: source_node_id.to_string(),
        source_hostname: source_hostname.to_string(),
        source_address: source_address.to_string(),
        target_type: target_type.to_string(),
        target_name: target_name.to_string(),
        target_node_id: target_node_id.to_string(),
        target_hostname: target_hostname.to_string(),
        active: true,
        session_id: None,
        virtual_busid: None,
    });
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    info!("WolfUSB: {}", msg);
    Ok(msg)
}

/// Remove a USB device assignment and clean up
pub fn unassign_device(config: &mut WolfUsbConfig, busid: &str, source_node_id: &str) -> Result<String, String> {
    let assignment = config.assignments.iter()
        .find(|a| a.busid == busid && a.source_node_id == source_node_id)
        .cloned();

    config.assignments.retain(|a| !(a.busid == busid && a.source_node_id == source_node_id));
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    match assignment {
        Some(a) => {
            // Release the device if we have a session
            if let Some(sid) = a.session_id {
                if let Err(e) = wolfusb_detach_device(&a.source_address, &a.busid, sid) {
                    warn!("WolfUSB: detach failed (non-fatal): {}", e);
                }
            }
            Ok(format!("USB device {} unassigned from {}:{}", a.busid, a.target_type, a.target_name))
        }
        None => Err("Device was not assigned".to_string()),
    }
}

/// Attach a remote USB device and passthrough to a container.
/// Called on the TARGET node (where the container/VM lives).
pub fn attach_and_passthrough(
    source_address: &str,
    busid: &str,
    target_type: &str,
    target_name: &str,
) -> Result<String, String> {
    // Attach via wolfusb protocol
    let session_id = wolfusb_attach_device(source_address, busid)?;

    // Update the assignment with the session_id
    let mut config = WolfUsbConfig::load();
    if let Some(a) = config.assignments.iter_mut().find(|a| a.busid == busid) {
        a.session_id = Some(session_id);
        a.active = true;
        let _ = config.save();
    }

    let mut result = format!("Attached to {} via wolfusb (session {})", busid, session_id);

    // For local passthrough (device is on this same node), pass through to container
    if let Some(dev_path) = find_dev_path(busid) {
        match target_type {
            "docker" => match passthrough_to_docker(target_name, &dev_path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nDocker passthrough: {}", e)),
            },
            "lxc" => match passthrough_to_lxc(target_name, busid, &dev_path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nLXC passthrough: {}", e)),
            },
            "vm" => match passthrough_to_vm(target_name, busid, &dev_path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nVM passthrough: {}", e)),
            },
            _ => {}
        }
    } else {
        result.push_str(&format!("\nDevice claimed via wolfusb protocol on {}:3240", source_address));
    }

    Ok(result)
}

// ─── Local Device Passthrough ───

/// Pass a USB device into a local container/VM directly (same node)
pub fn local_passthrough(
    busid: &str,
    target_type: &str,
    target_name: &str,
) -> Result<String, String> {
    let dev_path = find_dev_path(busid)
        .ok_or_else(|| format!("Could not find device path for {}", busid))?;

    match target_type {
        "docker" => passthrough_to_docker(target_name, &dev_path),
        "lxc" => passthrough_to_lxc(target_name, busid, &dev_path),
        "vm" => passthrough_to_vm(target_name, busid, &dev_path),
        _ => Err(format!("Unknown target type: {}", target_type)),
    }
}

/// Passthrough a USB device into a Docker container by recreating it with --device
fn passthrough_to_docker(container_name: &str, dev_path: &str) -> Result<String, String> {
    let inspect = Command::new("docker").args(["inspect", "--format", "{{.State.Running}}", container_name])
        .output().map_err(|e| format!("docker inspect failed: {}", e))?;
    if !inspect.status.success() {
        return Err(format!("Container '{}' not found", container_name));
    }
    let was_running = String::from_utf8_lossy(&inspect.stdout).trim() == "true";

    // Check if device is already attached
    let inspect_json = Command::new("docker").args(["inspect", container_name])
        .output().map_err(|e| format!("docker inspect failed: {}", e))?;
    if inspect_json.status.success() {
        let text = String::from_utf8_lossy(&inspect_json.stdout);
        if text.contains(dev_path) {
            return Ok(format!("Device {} already attached to container {}", dev_path, container_name));
        }
    }

    if was_running {
        info!("WolfUSB: stopping {} to add USB device {}", container_name, dev_path);
        let _ = Command::new("docker").args(["stop", container_name]).output();
    }

    let backup_name = format!("{}_wolfusb_old", container_name);
    let _ = Command::new("docker").args(["rm", "-f", &backup_name]).output();

    let rename = Command::new("docker").args(["rename", container_name, &backup_name]).output()
        .map_err(|e| format!("Failed to rename container: {}", e))?;
    if !rename.status.success() {
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to rename container: {}", String::from_utf8_lossy(&rename.stderr)));
    }

    let insp = Command::new("docker").args(["inspect", &backup_name]).output()
        .map_err(|e| format!("Failed to inspect: {}", e))?;
    if !insp.status.success() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Failed to inspect container".to_string());
    }
    let insp_text = String::from_utf8_lossy(&insp.stdout);
    let inspect_arr: Vec<serde_json::Value> = serde_json::from_str(&insp_text).unwrap_or_default();
    let v = inspect_arr.first().cloned().unwrap_or(serde_json::Value::Null);

    let mut args = vec!["create".to_string(), "--name".to_string(), container_name.to_string()];

    let image = v.pointer("/Config/Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if image.is_empty() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Cannot determine container image".to_string());
    }

    // Restart policy
    let restart = v.pointer("/HostConfig/RestartPolicy/Name").and_then(|v| v.as_str()).unwrap_or("no");
    let rc = v.pointer("/HostConfig/RestartPolicy/MaximumRetryCount").and_then(|v| v.as_i64()).unwrap_or(0);
    args.push("--restart".to_string());
    args.push(if restart == "on-failure" && rc > 0 { format!("on-failure:{}", rc) } else { restart.to_string() });

    if v.pointer("/Config/Tty").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-t".to_string()); }
    if v.pointer("/Config/OpenStdin").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-i".to_string()); }
    if v.pointer("/HostConfig/Privileged").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("--privileged".to_string()); }

    let net = v.pointer("/HostConfig/NetworkMode").and_then(|v| v.as_str()).unwrap_or("default");
    if net != "default" && net != "bridge" { args.push("--network".to_string()); args.push(net.to_string()); }

    if let Some(m) = v.pointer("/HostConfig/Memory").and_then(|v| v.as_i64()).filter(|m| *m > 0) {
        args.push("--memory".to_string()); args.push(format!("{}m", m / 1048576));
    }
    if let Some(c) = v.pointer("/HostConfig/NanoCpus").and_then(|v| v.as_i64()).filter(|c| *c > 0) {
        args.push("--cpus".to_string()); args.push(format!("{:.1}", c as f64 / 1e9));
    }
    if let Some(shm) = v.pointer("/HostConfig/ShmSize").and_then(|v| v.as_i64()).filter(|s| *s > 0 && *s != 67108864) {
        args.push("--shm-size".to_string()); args.push(format!("{}", shm));
    }

    let user = v.pointer("/Config/User").and_then(|v| v.as_str()).unwrap_or("");
    if !user.is_empty() { args.push("--user".to_string()); args.push(user.to_string()); }
    let workdir = v.pointer("/Config/WorkingDir").and_then(|v| v.as_str()).unwrap_or("");
    if !workdir.is_empty() { args.push("--workdir".to_string()); args.push(workdir.to_string()); }

    if let Some(caps) = v.pointer("/HostConfig/CapAdd").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-add".to_string()); args.push(s.to_string()); } }
    }
    if let Some(caps) = v.pointer("/HostConfig/CapDrop").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-drop".to_string()); args.push(s.to_string()); } }
    }

    // Existing devices + new USB device
    let mut has_device = false;
    if let Some(devs) = v.pointer("/HostConfig/Devices").and_then(|v| v.as_array()) {
        for d in devs {
            let host = d.get("PathOnHost").and_then(|v| v.as_str()).unwrap_or("");
            let ctr = d.get("PathInContainer").and_then(|v| v.as_str()).unwrap_or("");
            if !host.is_empty() {
                args.push("--device".to_string());
                args.push(format!("{}:{}", host, ctr));
                if host == dev_path { has_device = true; }
            }
        }
    }
    if !has_device {
        args.push("--device".to_string());
        args.push(format!("{}:{}", dev_path, dev_path));
    }

    // Volumes
    let binds: Vec<String> = v.pointer("/HostConfig/Binds")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    for b in &binds { args.push("-v".to_string()); args.push(b.clone()); }

    if let Some(mounts) = v.pointer("/Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            if mount.get("Type").and_then(|v| v.as_str()) != Some("volume") { continue; }
            let vol_name = mount.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let destination = mount.get("Destination").and_then(|v| v.as_str()).unwrap_or("");
            let rw = mount.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            if vol_name.is_empty() || destination.is_empty() { continue; }
            if binds.iter().any(|b| b.starts_with(&format!("{}:", vol_name))) { continue; }
            let mode = if rw { "" } else { ":ro" };
            args.push("-v".to_string());
            args.push(format!("{}:{}{}", vol_name, destination, mode));
        }
    }

    if let Some(bindings) = v.pointer("/HostConfig/PortBindings").and_then(|v| v.as_object()) {
        for (container_port, host_list) in bindings {
            if let Some(arr) = host_list.as_array() {
                for binding in arr {
                    let host_ip = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("");
                    let host_port = binding.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                    if !host_port.is_empty() {
                        args.push("-p".to_string());
                        if host_ip.is_empty() || host_ip == "0.0.0.0" {
                            args.push(format!("{}:{}", host_port, container_port));
                        } else {
                            args.push(format!("{}:{}:{}", host_ip, host_port, container_port));
                        }
                    }
                }
            }
        }
    }

    if let Some(envs) = v.pointer("/Config/Env").and_then(|v| v.as_array()) {
        for e in envs { if let Some(s) = e.as_str() { args.push("-e".to_string()); args.push(s.to_string()); } }
    }
    if let Some(labels) = v.pointer("/Config/Labels").and_then(|v| v.as_object()) {
        for (k, lv) in labels { args.push("--label".to_string()); args.push(format!("{}={}", k, lv.as_str().unwrap_or(""))); }
    }

    let entrypoint: Vec<String> = v.pointer("/Config/Entrypoint")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !entrypoint.is_empty() {
        args.push("--entrypoint".to_string());
        args.push(entrypoint[0].clone());
    }

    args.push(image);
    for ep_arg in entrypoint.iter().skip(1) { args.push(ep_arg.clone()); }
    if entrypoint.len() <= 1 {
        if let Some(cmds) = v.pointer("/Config/Cmd").and_then(|v| v.as_array()) {
            for c in cmds { if let Some(s) = c.as_str() { args.push(s.to_string()); } }
        }
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let create = Command::new("docker").args(&args_ref).output()
        .map_err(|e| format!("docker create failed: {}", e))?;

    if !create.status.success() {
        let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
        warn!("WolfUSB: Docker recreate failed, rolling back: {}", stderr);
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to recreate container: {}", stderr));
    }

    let _ = Command::new("docker").args(["rm", &backup_name]).output();
    if was_running {
        let _ = Command::new("docker").args(["start", container_name]).output();
    }

    info!("WolfUSB: Docker container {} recreated with USB device {}", container_name, dev_path);
    Ok(format!("Container '{}' recreated with USB device {}{}", container_name, dev_path,
        if was_running { " and started" } else { "" }))
}

/// Passthrough a USB device into an LXC container
fn passthrough_to_lxc(container_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    let config_path = if crate::containers::is_proxmox() {
        let output = Command::new("pct").args(["set", container_name, "--dev0",
            &format!("{},mode=0660", dev_path)]).output()
            .map_err(|e| format!("pct set failed: {}", e))?;
        if output.status.success() {
            info!("WolfUSB: LXC {} configured with USB device {} via pct", container_name, dev_path);
            let _ = Command::new("pct").args(["reboot", container_name]).output();
            return Ok(format!("LXC '{}' configured with USB device {} and restarted", container_name, dev_path));
        }
        format!("/etc/pve/lxc/{}.conf", container_name)
    } else {
        format!("/var/lib/lxc/{}/config", container_name)
    };

    if !std::path::Path::new(&config_path).exists() {
        return Err(format!("LXC config not found at {}", config_path));
    }

    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    if existing.contains(dev_path) {
        return Ok(format!("Device {} already configured in LXC {}", dev_path, container_name));
    }

    let entry = format!(
        "\n# WolfUSB: USB device {}\nlxc.cgroup2.devices.allow = c 189:* rwm\nlxc.mount.entry = {} {} none bind,optional,create=file 0 0\n",
        busid, dev_path, dev_path.trim_start_matches('/')
    );

    std::fs::OpenOptions::new().append(true).open(&config_path)
        .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) })
        .map_err(|e| format!("Failed to update LXC config: {}", e))?;

    info!("WolfUSB: restarting LXC {} to apply USB device {}", container_name, dev_path);
    if crate::containers::is_proxmox() {
        let _ = Command::new("pct").args(["reboot", container_name]).output();
    } else {
        let _ = Command::new("lxc-stop").args(["-n", container_name]).output();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = Command::new("lxc-start").args(["-n", container_name]).output();
    }

    Ok(format!("LXC '{}' configured with USB device {} and restarted", container_name, dev_path))
}

/// Note USB device availability for a VM
fn passthrough_to_vm(vm_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    info!("WolfUSB: USB device {} ({}) available for VM {}", dev_path, busid, vm_name);
    Ok(format!("USB device {} available for VM '{}'. Add it in the VM's Passthrough settings and restart the VM.", dev_path, vm_name))
}

// ─── Startup Restore & Container Event Hooks ───

/// Called on WolfStack startup. Re-establishes all assignments.
pub fn restore_assignments(self_node_id: &str) {
    let config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }
    if !is_wolfusb_available() { return; }

    info!("WolfUSB: restoring {} assignments on startup", config.assignments.len());
    ensure_wolfusb_server();

    for a in &config.assignments {
        // Target side: re-attach remote devices for containers on this node
        if a.target_node_id == self_node_id && a.source_node_id != self_node_id {
            match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name) {
                Ok(msg) => info!("WolfUSB: restored {} — {}", a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to restore {}: {}", a.busid, e),
            }
        }
    }
}

/// Called when a container starts or restarts on this node.
pub fn on_container_started(container_name: &str, container_type: &str, self_node_id: &str) {
    let mut config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }

    let mut changed = false;

    for a in &mut config.assignments {
        if a.target_name != container_name || a.target_type != container_type { continue; }

        if a.target_node_id != self_node_id {
            info!("WolfUSB: container {} migrated to this node — re-routing USB {}", container_name, a.busid);
            a.target_node_id = self_node_id.to_string();
            a.target_hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| self_node_id.to_string());
            changed = true;
        }

        if a.source_node_id != self_node_id {
            if !a.source_address.is_empty() {
                match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name) {
                    Ok(msg) => info!("WolfUSB: restored {} for {} — {}", a.busid, container_name, msg),
                    Err(e) => warn!("WolfUSB: failed to restore {} for {}: {}", a.busid, container_name, e),
                }
            }
        } else {
            match local_passthrough(&a.busid, &a.target_type, &a.target_name) {
                Ok(msg) => info!("WolfUSB: local passthrough {} for {} — {}", a.busid, container_name, msg),
                Err(e) => warn!("WolfUSB: local passthrough {} for {} failed: {}", a.busid, container_name, e),
            }
        }
    }

    if changed { let _ = config.save(); }
}

/// Merge assignments from a remote node's config into ours.
pub fn merge_remote_assignments(remote_assignments: &[UsbAssignment]) {
    let mut config = WolfUsbConfig::load();
    let mut changed = false;

    for ra in remote_assignments {
        let exists = config.assignments.iter().any(|a|
            a.busid == ra.busid && a.source_node_id == ra.source_node_id
        );
        if !exists {
            config.assignments.push(ra.clone());
            changed = true;
        } else {
            if let Some(existing) = config.assignments.iter_mut().find(|a|
                a.busid == ra.busid && a.source_node_id == ra.source_node_id
            ) {
                if existing.target_node_id != ra.target_node_id
                    || existing.target_name != ra.target_name
                {
                    *existing = ra.clone();
                    changed = true;
                }
            }
        }
    }

    let self_id = crate::agent::self_node_id();
    let remote_busids: Vec<(&str, &str)> = remote_assignments.iter()
        .map(|a| (a.busid.as_str(), a.source_node_id.as_str()))
        .collect();
    let before = config.assignments.len();
    config.assignments.retain(|a| {
        if a.source_node_id == self_id { return true; }
        remote_busids.iter().any(|(b, s)| *b == a.busid && *s == a.source_node_id)
    });
    if config.assignments.len() != before { changed = true; }

    if changed { let _ = config.save(); }
}
