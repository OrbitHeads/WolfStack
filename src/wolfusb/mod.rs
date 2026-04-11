// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! WolfUSB Integration — USB-over-IP device sharing across the cluster
//!
//! Uses the Linux kernel's built-in `usbip` module to share USB devices across
//! nodes. WolfStack manages discovery, assignment, and auto-reconnection.
//! Devices appear as real USB in `lsusb` inside containers and VMs.
//!
//! Architecture:
//! - Source node: runs `usbip bind` to export the physical USB device
//! - Target node: runs `usbip attach` to create a virtual USB device locally
//! - The virtual device is then passed into the container/VM via standard mechanisms
//!   (Docker --device, LXC cgroup+mount, QEMU USB passthrough)

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn};

fn config_path() -> String { format!("{}/wolfusb.json", crate::paths::get().config_dir) }

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
        Self {
            enabled: true,
            assignments: Vec::new(),
        }
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
    /// USB bus ID string for usbip (e.g. "1-2")
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
    /// Source node address (IP/hostname for usbip connection)
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
    /// Whether this assignment is currently active (usbip attached)
    #[serde(default)]
    pub active: bool,
    /// The virtual USB bus path on the target node (set after usbip attach)
    #[serde(default)]
    pub virtual_busid: Option<String>,
}

// ─── USB Device Info ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    /// usbip bus ID (e.g. "1-2", "2-1.3")
    pub busid: String,
    pub vendor_id: String,
    pub product_id: String,
    pub product: String,
    #[serde(default)]
    pub assigned_to: Option<String>,
}

// ─── usbip Kernel Module Management ───

/// Ensure the usbip kernel modules are loaded
pub fn ensure_usbip_modules() -> Result<(), String> {
    // Load usbip-host (for exporting devices) and vhci-hcd (for importing)
    for module in &["usbip-core", "usbip-host", "vhci-hcd"] {
        let status = Command::new("modprobe").arg(module).status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                // Not fatal — the module might already be built-in
                warn!("WolfUSB: modprobe {} exited with {}", module, s);
            }
            Err(e) => {
                warn!("WolfUSB: failed to load module {}: {}", module, e);
            }
        }
    }
    Ok(())
}

/// Check if usbip is available (binary in PATH or kernel modules loaded)
pub fn is_usbip_available() -> bool {
    // Check for binary via shell (more reliable than `which` across distros)
    if Command::new("sh").args(["-c", "command -v usbip"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
    {
        return true;
    }
    // Check common paths directly
    if std::path::Path::new("/usr/local/bin/usbip").exists()
        || std::path::Path::new("/usr/sbin/usbip").exists()
    {
        return true;
    }
    // Check if kernel module is loaded
    std::path::Path::new("/sys/module/usbip_host").exists()
}

/// Ensure the usbipd daemon is running (required for remote nodes to attach/list devices)
pub fn ensure_usbipd_running() -> Result<(), String> {
    // Check if usbipd is already listening on port 3240
    let check = Command::new("sh")
        .args(["-c", "ss -tlnp 2>/dev/null | grep ':3240 ' || netstat -tlnp 2>/dev/null | grep ':3240 '"])
        .output();
    if let Ok(o) = &check {
        if o.status.success() && !o.stdout.is_empty() {
            return Ok(()); // Already running
        }
    }

    // Find the usbipd binary
    let usbipd = find_usbipd_binary();
    let binary = match &usbipd {
        Some(b) => b.as_str(),
        None => {
            warn!("WolfUSB: usbipd binary not found — remote USB sharing will not work");
            return Err("usbipd binary not found".to_string());
        }
    };

    info!("WolfUSB: starting usbipd daemon on port 3240");
    let result = Command::new(binary).args(["-D"]).status();
    match result {
        Ok(s) if s.success() => {
            info!("WolfUSB: usbipd daemon started");
            Ok(())
        }
        Ok(s) => {
            let msg = format!("usbipd exited with {}", s);
            warn!("WolfUSB: {}", msg);
            Err(msg)
        }
        Err(e) => {
            let msg = format!("Failed to start usbipd: {}", e);
            warn!("WolfUSB: {}", msg);
            Err(msg)
        }
    }
}

/// Find the usbipd binary (may be in different locations across distros)
fn find_usbipd_binary() -> Option<String> {
    // Check PATH first
    if Command::new("sh").args(["-c", "command -v usbipd"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
    {
        return Some("usbipd".to_string());
    }
    // Common locations
    for path in &["/usr/sbin/usbipd", "/usr/local/bin/usbipd", "/usr/lib/linux-tools/usbipd"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    // On some distros, usbipd is part of the usbip package under linux-tools
    if let Ok(o) = Command::new("sh").args(["-c", "find /usr/lib/linux-tools/ -name usbipd 2>/dev/null | head -1"]).output() {
        let path = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !path.is_empty() && std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}

/// Install usbip tools — handles Arch, Debian, Ubuntu, Proxmox, Fedora, RHEL, openSUSE
pub async fn install_usbip() -> Result<String, String> {
    info!("WolfUSB: installing usbip tools");
    let script = r#"
KERNEL="$(uname -r)"
echo "Kernel: $KERNEL"

# ─── Arch / CachyOS / Manjaro ───
if command -v pacman >/dev/null 2>&1; then
    echo "Detected: Arch-based (pacman)"
    pacman -S --noconfirm usbip 2>/dev/null || true

# ─── Debian / Ubuntu / Proxmox VE ───
elif command -v apt-get >/dev/null 2>&1; then
    echo "Detected: Debian/Ubuntu-based (apt)"
    apt-get update -y || true
    # Debian, Proxmox: package is simply "usbip"
    # Ubuntu: "usbip" or "linux-tools-generic" + "linux-tools-$KERNEL"
    apt-get install -y usbip 2>/dev/null \
        || apt-get install -y linux-tools-generic "linux-tools-$KERNEL" 2>/dev/null \
        || apt-get install -y linux-tools-common 2>/dev/null \
        || true

# ─── Fedora / RHEL / Rocky / AlmaLinux ───
elif command -v dnf >/dev/null 2>&1; then
    echo "Detected: Fedora/RHEL-based (dnf)"
    dnf install -y usbip-utils 2>/dev/null || true

# ─── openSUSE ───
elif command -v zypper >/dev/null 2>&1; then
    echo "Detected: openSUSE (zypper)"
    zypper install -y usbip-utils 2>/dev/null || zypper install -y usbip 2>/dev/null || true

else
    echo "ERROR: No supported package manager found"
fi

# ─── Load kernel modules ───
modprobe usbip-core 2>/dev/null || true
modprobe usbip-host 2>/dev/null || true
modprobe vhci-hcd 2>/dev/null || true

# ─── Persist modules across reboots ───
mkdir -p /etc/modules-load.d
printf 'usbip-core\nusbip-host\nvhci-hcd\n' > /etc/modules-load.d/wolfusb.conf 2>/dev/null || true

# ─── Find binary if not in PATH (Ubuntu puts it under /usr/lib/linux-tools/) ───
if ! command -v usbip >/dev/null 2>&1; then
    for p in /usr/lib/linux-tools/"$KERNEL"/usbip /usr/lib/linux-tools/*/usbip /usr/sbin/usbip; do
        if [ -x "$p" ]; then
            echo "Found usbip at $p — creating symlink to /usr/local/bin/usbip"
            ln -sf "$p" /usr/local/bin/usbip
            break
        fi
    done
fi

# ─── Start usbipd daemon ───
if command -v usbipd >/dev/null 2>&1; then
    # Kill any existing instance and restart
    killall usbipd 2>/dev/null || true
    usbipd -D 2>/dev/null && echo "OK: usbipd daemon started on port 3240" || echo "WARNING: failed to start usbipd"
elif [ -x /usr/sbin/usbipd ]; then
    killall usbipd 2>/dev/null || true
    /usr/sbin/usbipd -D 2>/dev/null && echo "OK: usbipd daemon started on port 3240" || echo "WARNING: failed to start usbipd"
else
    echo "WARNING: usbipd binary not found — remote USB sharing requires usbipd"
fi

# ─── Verify ───
if command -v usbip >/dev/null 2>&1; then
    echo "OK: usbip installed at $(command -v usbip)"
    usbip version 2>/dev/null || true
elif [ -d /sys/module/usbip_host ]; then
    echo "OK: usbip kernel modules loaded but binary not found in PATH"
else
    echo "WARNING: usbip installation may be incomplete"
    echo "Modules in /lib/modules/$KERNEL/kernel/drivers/usb/usbip/:"
    ls /lib/modules/"$KERNEL"/kernel/drivers/usb/usbip/ 2>/dev/null || echo "  (none)"
fi
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

    // Try loading modules after install
    let _ = ensure_usbip_modules();

    if is_usbip_available() {
        Ok(combined)
    } else {
        // Even if the check fails, the script output tells the user what happened
        Err(format!("Installation may have partially succeeded. Check output:\n{}", combined))
    }
}

// ─── Device Operations ───

/// List USB devices available for sharing on this node via usbip
pub fn list_local_devices(config: &WolfUsbConfig) -> Vec<UsbDevice> {
    let _ = ensure_usbip_modules();

    // Use usbip list -l to show locally available devices
    let output = match Command::new("usbip").args(["list", "-l"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            // Fallback to lsusb
            return parse_lsusb(config);
        }
    };

    parse_usbip_list_local(&output, config)
}

/// Parse `usbip list -l` output
fn parse_usbip_list_local(text: &str, config: &WolfUsbConfig) -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let mut current_busid = String::new();
    let mut current_desc = String::new();
    let mut current_vid = String::new();
    let mut current_pid = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        // Lines like: " - busid 1-2 (046d:0825)"
        if trimmed.starts_with("- busid ") {
            // Save previous device (skip root hubs)
            if !current_busid.is_empty() && current_vid != "1d6b" {
                let usb_id = format!("{}:{}", current_vid, current_pid);
                let assigned = config.assignments.iter()
                    .find(|a| a.busid == current_busid && a.usb_id == usb_id)
                    .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));
                devices.push(UsbDevice {
                    busid: current_busid.clone(),
                    vendor_id: current_vid.clone(),
                    product_id: current_pid.clone(),
                    product: current_desc.clone(),
                    assigned_to: assigned,
                });
            }

            // Parse busid and vendor:product
            let rest = &trimmed[8..]; // after "- busid "
            let parts: Vec<&str> = rest.split_whitespace().collect();
            current_busid = parts.first().unwrap_or(&"").to_string();
            // Extract (VVVV:PPPP) from parentheses
            if let Some(ids) = rest.split('(').nth(1).and_then(|s| s.split(')').next()) {
                let id_parts: Vec<&str> = ids.split(':').collect();
                current_vid = id_parts.first().unwrap_or(&"").to_string();
                current_pid = id_parts.get(1).unwrap_or(&"").to_string();
            }
            current_desc = String::new();
        } else if !current_busid.is_empty() && !trimmed.is_empty() && current_desc.is_empty() {
            // Description line follows the busid line
            current_desc = trimmed.trim_start_matches(':').trim().to_string();
        }
    }

    // Don't forget the last device
    if !current_busid.is_empty() && current_vid != "1d6b" {
        let usb_id = format!("{}:{}", current_vid, current_pid);
        let assigned = config.assignments.iter()
            .find(|a| a.busid == current_busid && a.usb_id == usb_id)
            .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));
        devices.push(UsbDevice {
            busid: current_busid,
            vendor_id: current_vid,
            product_id: current_pid,
            product: current_desc,
            assigned_to: assigned,
        });
    }

    // Filter out root hubs from usbip list too
    devices.retain(|d| d.vendor_id != "1d6b");

    // If usbip list was empty, fallback to lsusb
    if devices.is_empty() {
        return parse_lsusb(config);
    }

    devices
}

/// Parse lsusb output as fallback. Uses bus:device as the unique ID.
/// Filters out root hubs (vendor 1d6b = Linux Foundation virtual devices).
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
        let bus: u32 = bus_dev.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let addr: u32 = bus_dev.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        if bus == 0 || addr == 0 { continue; }

        let id_desc = parts[1];
        let (vid, pid, product) = if id_desc.starts_with("ID ") {
            let rest = &id_desc[3..];
            let id_parts: Vec<&str> = rest.splitn(2, ' ').collect();
            let ids: Vec<&str> = id_parts[0].split(':').collect();
            (
                ids.first().unwrap_or(&"0000").to_string(),
                ids.get(1).unwrap_or(&"0000").to_string(),
                id_parts.get(1).unwrap_or(&"").trim().to_string(),
            )
        } else {
            ("0000".to_string(), "0000".to_string(), id_desc.to_string())
        };

        // Skip root hubs and virtual USB devices (Linux Foundation = 1d6b)
        if vid == "1d6b" { continue; }

        // Use wolfusb-bus-device as unique ID (e.g. "wolfusb-1-2" for bus 1 device 2)
        let busid = format!("wolfusb-{}-{}", bus, addr);

        // Match assignment by BOTH busid AND usb_id (must match both to avoid cross-matching)
        let usb_id = format!("{}:{}", vid, pid);
        let assigned = config.assignments.iter()
            .find(|a| a.busid == busid && a.usb_id == usb_id)
            .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));

        devices.push(UsbDevice {
            busid,
            vendor_id: vid,
            product_id: pid,
            product,
            assigned_to: assigned,
        });
    }
    devices
}

// ─── usbip Export/Import (the actual sharing) ───

/// Strip the "wolfusb-" prefix to get the real kernel busid for usbip commands
fn real_busid(busid: &str) -> String {
    busid.strip_prefix("wolfusb-").unwrap_or(busid).to_string()
}

/// Validate a real kernel busid format (digits, hyphens, dots only)
fn validate_busid(busid: &str) -> Result<(), String> {
    let real = real_busid(busid);
    if real.is_empty() || !real.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.') {
        Err("Invalid bus ID format".to_string())
    } else {
        Ok(())
    }
}

/// Export (bind) a USB device on this node so remote nodes can attach to it
pub fn export_device(busid: &str) -> Result<String, String> {
    let _ = ensure_usbip_modules();
    validate_busid(busid)?;
    let real = real_busid(busid);

    // Ensure usbipd is running so remote nodes can connect
    if let Err(e) = ensure_usbipd_running() {
        warn!("WolfUSB: usbipd not running ({}), remote sharing may not work", e);
    }

    // Bind the device for sharing
    let output = Command::new("usbip").args(["bind", "--busid", &real]).output()
        .map_err(|e| format!("Failed to run usbip bind: {}", e))?;

    if output.status.success() {
        info!("WolfUSB: exported device {}", busid);
        Ok(format!("Device {} exported for sharing", busid))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("already bound") {
            Ok(format!("Device {} already exported", real))
        } else {
            Err(format!("Failed to export device {}: {}", busid, stderr))
        }
    }
}

/// Unexport (unbind) a USB device on this node
pub fn unexport_device(busid: &str) -> Result<String, String> {
    validate_busid(busid)?;
    let real = real_busid(busid);

    let output = Command::new("usbip").args(["unbind", "--busid", &real]).output()
        .map_err(|e| format!("Failed to run usbip unbind: {}", e))?;

    if output.status.success() {
        info!("WolfUSB: unexported device {}", busid);
        Ok(format!("Device {} unexported", busid))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to unexport device {}: {}", busid, stderr))
    }
}

/// Attach a remote USB device to this node (creates a virtual USB device locally)
pub fn attach_remote_device(remote_host: &str, busid: &str) -> Result<String, String> {
    let _ = ensure_usbip_modules();
    validate_busid(busid)?;
    let real = real_busid(busid);

    if !remote_host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '-') {
        return Err("Invalid remote host".to_string());
    }

    let output = Command::new("usbip").args(["attach", "--remote", remote_host, "--busid", &real]).output()
        .map_err(|e| format!("Failed to run usbip attach: {}", e))?;

    if output.status.success() {
        info!("WolfUSB: attached {}:{} locally", remote_host, busid);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(format!("Device {} attached from {}\n{}", busid, remote_host, stdout))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to attach {}:{}: {}", remote_host, busid, stderr))
    }
}

/// Detach a virtual USB device from this node
#[allow(dead_code)]
pub fn detach_device(port: &str) -> Result<String, String> {
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid port number".to_string());
    }

    let output = Command::new("usbip").args(["detach", "--port", port]).output()
        .map_err(|e| format!("Failed to run usbip detach: {}", e))?;

    if output.status.success() {
        info!("WolfUSB: detached port {}", port);
        Ok(format!("Device detached from port {}", port))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to detach port {}: {}", port, stderr))
    }
}

/// List currently attached (imported) virtual USB devices on this node
pub fn list_attached() -> Vec<(String, String, String)> {
    // Returns Vec<(port, busid, description)>
    let output = match Command::new("usbip").args(["port"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    let mut result = Vec::new();
    let mut current_port = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        // Lines like: "Port 00: <Port in Use> at Full Speed(12Mbps)"
        if trimmed.starts_with("Port ") {
            if let Some(port_num) = trimmed.split(':').next().and_then(|s| s.strip_prefix("Port ")) {
                current_port = port_num.trim().to_string();
            }
        }
        // Lines like: "    1-1 -> usbip://192.168.1.100:3240/1-2"
        // Or: "    vendor:product (class/subclass/protocol)"
        if !current_port.is_empty() && trimmed.contains("->") {
            let desc = trimmed.to_string();
            result.push((current_port.clone(), String::new(), desc));
            current_port.clear();
        }
    }

    result
}

// ─── Cross-Node Assignment ───

/// Assign a USB device to a container/VM, potentially on a different node.
///
/// Flow:
/// 1. On the source node: `usbip bind` to export the device
/// 2. On the target node: `usbip attach` to create virtual device
/// 3. Pass the virtual device into the container/VM
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

    // If the source device is on THIS node, bind it for sharing
    if is_local_source {
        export_device(busid)?;
    }

    let is_local_target = target_node_id == source_node_id
        || (target_node_id.is_empty() && is_local_source);

    let msg = if is_local_source && is_local_target {
        // Same node — passthrough directly (no usbip needed)
        match local_passthrough(busid, target_type, target_name) {
            Ok(m) => format!("USB device {} assigned to {}:{} (local)\n{}", busid, target_type, target_name, m),
            Err(e) => {
                warn!("WolfUSB: local passthrough failed: {}", e);
                format!("USB device {} assigned to {}:{} (local passthrough pending: {})", busid, target_type, target_name, e)
            }
        }
    } else {
        format!(
            "USB device {} from {} assigned to {}:{} on {}",
            busid, source_hostname, target_type, target_name, target_hostname
        )
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
            // Try to unbind on source if local
            let _ = unexport_device(&a.busid);
            Ok(format!("USB device {} unassigned from {}:{}", a.busid, a.target_type, a.target_name))
        }
        None => Err("Device was not assigned".to_string()),
    }
}

/// Find the /dev/bus/usb path for a given busid
fn find_dev_path(busid: &str) -> Option<String> {
    let real = real_busid(busid);
    // Parse bus number from busid (e.g. "1-2" -> bus 1)
    let bus: u32 = real.split('-').next()?.parse().ok()?;
    // Find the device address using sysfs
    let sysfs_path = format!("/sys/bus/usb/devices/{}/devnum", real);
    let addr: u32 = std::fs::read_to_string(&sysfs_path).ok()?.trim().parse().ok()?;
    Some(format!("/dev/bus/usb/{:03}/{:03}", bus, addr))
}

/// Execute the usbip attach on the target node and pass device into container.
/// Called on the TARGET node (where the container/VM lives).
pub fn attach_and_passthrough(
    source_address: &str,
    busid: &str,
    target_type: &str,
    target_name: &str,
) -> Result<String, String> {
    // Snapshot lsusb before attach so we can diff to find the new virtual device
    let before = lsusb_device_paths();

    // Step 1: Attach the remote device via usbip
    let attach_result = attach_remote_device(source_address, busid)?;

    // Step 2: Find the newly created virtual device by diffing lsusb
    std::thread::sleep(std::time::Duration::from_millis(500));
    let dev_path = find_new_device_path(&before);

    let mut result = attach_result;

    // Step 3: Pass into container/VM
    match (target_type, &dev_path) {
        ("docker", Some(path)) => {
            match passthrough_to_docker(target_name, path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nDocker passthrough failed: {}", e)),
            }
        }
        ("lxc", Some(path)) => {
            match passthrough_to_lxc(target_name, busid, path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nLXC passthrough failed: {}", e)),
            }
        }
        ("vm", Some(path)) => {
            match passthrough_to_vm(target_name, busid, path) {
                Ok(msg) => result.push_str(&format!("\n{}", msg)),
                Err(e) => result.push_str(&format!("\nVM passthrough note: {}", e)),
            }
        }
        _ => {
            result.push_str("\nNote: virtual device path not yet available. It may take a moment to appear.");
        }
    }

    Ok(result)
}

/// Pass a USB device into a local container/VM directly (same node, no usbip needed).
/// Called when source and target are on the same node.
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
    // Check if container exists
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

    // Stop container if running
    if was_running {
        info!("WolfUSB: stopping {} to add USB device {}", container_name, dev_path);
        let _ = Command::new("docker").args(["stop", container_name]).output();
    }

    // Get current config and recreate with the device added
    // Use docker commit + run approach for safety
    let backup_name = format!("{}_wolfusb_old", container_name);
    let _ = Command::new("docker").args(["rm", "-f", &backup_name]).output();

    // Rename current container
    let rename = Command::new("docker").args(["rename", container_name, &backup_name]).output()
        .map_err(|e| format!("Failed to rename container: {}", e))?;
    if !rename.status.success() {
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to rename container: {}", String::from_utf8_lossy(&rename.stderr)));
    }

    // Get full inspect config of the backup
    let insp = Command::new("docker").args(["inspect", &backup_name]).output()
        .map_err(|e| format!("Failed to inspect: {}", e))?;
    if !insp.status.success() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Failed to inspect container".to_string());
    }
    let insp_text = String::from_utf8_lossy(&insp.stdout);
    let inspect_arr: Vec<serde_json::Value> = serde_json::from_str(&insp_text).unwrap_or_default();
    let inspect_val = inspect_arr.first().cloned().unwrap_or(serde_json::Value::Null);

    // Build docker create args from the inspected config
    let mut args = vec!["create".to_string(), "--name".to_string(), container_name.to_string()];

    // Image
    let image = inspect_val.pointer("/Config/Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if image.is_empty() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Cannot determine container image".to_string());
    }

    // Restart policy
    let restart = inspect_val.pointer("/HostConfig/RestartPolicy/Name").and_then(|v| v.as_str()).unwrap_or("no");
    let restart_count = inspect_val.pointer("/HostConfig/RestartPolicy/MaximumRetryCount").and_then(|v| v.as_i64()).unwrap_or(0);
    args.push("--restart".to_string());
    args.push(if restart == "on-failure" && restart_count > 0 { format!("on-failure:{}", restart_count) } else { restart.to_string() });

    // TTY/stdin
    if inspect_val.pointer("/Config/Tty").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-t".to_string()); }
    if inspect_val.pointer("/Config/OpenStdin").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-i".to_string()); }

    // Privileged
    if inspect_val.pointer("/HostConfig/Privileged").and_then(|v| v.as_bool()).unwrap_or(false) {
        args.push("--privileged".to_string());
    }

    // Network mode
    let net = inspect_val.pointer("/HostConfig/NetworkMode").and_then(|v| v.as_str()).unwrap_or("default");
    if net != "default" && net != "bridge" {
        args.push("--network".to_string()); args.push(net.to_string());
    }

    // Memory/CPU
    if let Some(m) = inspect_val.pointer("/HostConfig/Memory").and_then(|v| v.as_i64()).filter(|m| *m > 0) {
        args.push("--memory".to_string()); args.push(format!("{}m", m / 1048576));
    }
    if let Some(c) = inspect_val.pointer("/HostConfig/NanoCpus").and_then(|v| v.as_i64()).filter(|c| *c > 0) {
        args.push("--cpus".to_string()); args.push(format!("{:.1}", c as f64 / 1e9));
    }

    // SHM size (64MB = 67108864 is Docker default, skip if default)
    if let Some(shm) = inspect_val.pointer("/HostConfig/ShmSize").and_then(|v| v.as_i64()).filter(|s| *s > 0 && *s != 67108864) {
        args.push("--shm-size".to_string()); args.push(format!("{}", shm));
    }

    // User/workdir
    let user = inspect_val.pointer("/Config/User").and_then(|v| v.as_str()).unwrap_or("");
    if !user.is_empty() { args.push("--user".to_string()); args.push(user.to_string()); }
    let workdir = inspect_val.pointer("/Config/WorkingDir").and_then(|v| v.as_str()).unwrap_or("");
    if !workdir.is_empty() { args.push("--workdir".to_string()); args.push(workdir.to_string()); }

    // Capabilities
    if let Some(caps) = inspect_val.pointer("/HostConfig/CapAdd").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-add".to_string()); args.push(s.to_string()); } }
    }
    if let Some(caps) = inspect_val.pointer("/HostConfig/CapDrop").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-drop".to_string()); args.push(s.to_string()); } }
    }

    // Existing devices + new USB device
    let mut has_device = false;
    if let Some(devs) = inspect_val.pointer("/HostConfig/Devices").and_then(|v| v.as_array()) {
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
    // Add the WolfUSB device
    if !has_device {
        args.push("--device".to_string());
        args.push(format!("{}:{}", dev_path, dev_path));
    }

    // Bind-mount volumes
    let binds: Vec<String> = inspect_val.pointer("/HostConfig/Binds")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    for b in &binds { args.push("-v".to_string()); args.push(b.clone()); }

    // Named volumes from Mounts (type=volume, skip if already in Binds)
    if let Some(mounts) = inspect_val.pointer("/Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            if mount.get("Type").and_then(|v| v.as_str()) != Some("volume") { continue; }
            let vol_name = mount.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let destination = mount.get("Destination").and_then(|v| v.as_str()).unwrap_or("");
            let rw = mount.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            if vol_name.is_empty() || destination.is_empty() { continue; }
            // Skip if already covered by a Binds entry
            if binds.iter().any(|b| b.starts_with(&format!("{}:", vol_name))) { continue; }
            let mode = if rw { "" } else { ":ro" };
            args.push("-v".to_string());
            args.push(format!("{}:{}{}", vol_name, destination, mode));
        }
    }

    // Port bindings
    if let Some(bindings) = inspect_val.pointer("/HostConfig/PortBindings").and_then(|v| v.as_object()) {
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

    // Env vars
    if let Some(envs) = inspect_val.pointer("/Config/Env").and_then(|v| v.as_array()) {
        for e in envs { if let Some(s) = e.as_str() { args.push("-e".to_string()); args.push(s.to_string()); } }
    }

    // Labels
    if let Some(labels) = inspect_val.pointer("/Config/Labels").and_then(|v| v.as_object()) {
        for (k, v) in labels { args.push("--label".to_string()); args.push(format!("{}={}", k, v.as_str().unwrap_or(""))); }
    }

    // Entrypoint (only set --entrypoint if one was explicitly configured)
    let entrypoint: Vec<String> = inspect_val.pointer("/Config/Entrypoint")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !entrypoint.is_empty() {
        args.push("--entrypoint".to_string());
        args.push(entrypoint[0].clone());
    }

    args.push(image);

    // Entrypoint args beyond [0] — these go after the image
    for ep_arg in entrypoint.iter().skip(1) { args.push(ep_arg.clone()); }

    // Cmd (only if no multi-part entrypoint, to avoid duplication)
    if entrypoint.len() <= 1 {
        if let Some(cmds) = inspect_val.pointer("/Config/Cmd").and_then(|v| v.as_array()) {
            for c in cmds { if let Some(s) = c.as_str() { args.push(s.to_string()); } }
        }
    }

    // Create the new container
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let create = Command::new("docker").args(&args_ref).output()
        .map_err(|e| format!("docker create failed: {}", e))?;

    if !create.status.success() {
        let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
        warn!("WolfUSB: Docker recreate failed, rolling back: {}", stderr);
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to recreate container with USB device: {}", stderr));
    }

    // Remove the old container
    let _ = Command::new("docker").args(["rm", &backup_name]).output();

    // Start if it was running
    if was_running {
        let _ = Command::new("docker").args(["start", container_name]).output();
    }

    info!("WolfUSB: Docker container {} recreated with USB device {}", container_name, dev_path);
    Ok(format!("Container '{}' recreated with USB device {}{}", container_name, dev_path,
        if was_running { " and started" } else { "" }))
}

/// Passthrough a USB device into an LXC container by updating config and restarting
fn passthrough_to_lxc(container_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    // Find the LXC config file
    let config_path = if crate::containers::is_proxmox() {
        // Proxmox uses pct set for device passthrough
        let output = Command::new("pct").args(["set", container_name, "--dev0",
            &format!("{},mode=0660", dev_path)]).output()
            .map_err(|e| format!("pct set failed: {}", e))?;
        if output.status.success() {
            info!("WolfUSB: LXC {} configured with USB device {} via pct", container_name, dev_path);
            // Restart LXC to apply
            let _ = Command::new("pct").args(["reboot", container_name]).output();
            return Ok(format!("LXC '{}' configured with USB device {} and restarted", container_name, dev_path));
        }
        // Fall through to manual config
        format!("/etc/pve/lxc/{}.conf", container_name)
    } else {
        format!("/var/lib/lxc/{}/config", container_name)
    };

    if !std::path::Path::new(&config_path).exists() {
        return Err(format!("LXC config not found at {}", config_path));
    }

    // Check if device entry already exists
    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    if existing.contains(dev_path) {
        return Ok(format!("Device {} already configured in LXC {}", dev_path, container_name));
    }

    // Append device config
    let entry = format!(
        "\n# WolfUSB: USB device {} via usbip\n\
         lxc.cgroup2.devices.allow = c 189:* rwm\n\
         lxc.mount.entry = {} {} none bind,optional,create=file 0 0\n",
        busid, dev_path, dev_path.trim_start_matches('/')
    );

    std::fs::OpenOptions::new().append(true).open(&config_path)
        .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) })
        .map_err(|e| format!("Failed to update LXC config: {}", e))?;

    // Restart the container to apply
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

/// Note USB device availability for a VM — VMs need manual config or will pick it up on next start
fn passthrough_to_vm(vm_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    // For VMs, USB passthrough is configured via vendor:product ID in the VM config
    // The device is available at dev_path for the VM to use on next start
    // We can't hotplug USB into a running QEMU VM safely without QMP, so we note it
    info!("WolfUSB: USB device {} ({}) available for VM {}", dev_path, busid, vm_name);
    Ok(format!("USB device {} available for VM '{}'. Add it in the VM's Passthrough settings and restart the VM to apply.", dev_path, vm_name))
}

// ─── Startup Restore & Container Event Hooks ───

/// Called on WolfStack startup. Re-establishes all usbip binds and attaches
/// for assignments where this node is the source or target.
pub fn restore_assignments(self_node_id: &str) {
    let config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }
    if !is_usbip_available() { return; }
    let _ = ensure_usbip_modules();

    info!("WolfUSB: restoring {} assignments on startup", config.assignments.len());

    // Start usbipd if this node is a source for any assignments
    let has_source_assignments = config.assignments.iter().any(|a| a.source_node_id == self_node_id);
    if has_source_assignments {
        if let Err(e) = ensure_usbipd_running() {
            warn!("WolfUSB: failed to start usbipd on startup: {}", e);
        }
    }

    for a in &config.assignments {
        // Source side: re-export devices that are physically on this node
        if a.source_node_id == self_node_id {
            match export_device(&a.busid) {
                Ok(msg) => info!("WolfUSB: re-exported {} — {}", a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to re-export {}: {}", a.busid, e),
            }
        }

        // Target side: re-attach remote devices and passthrough to containers on this node
        if a.target_node_id == self_node_id && a.source_node_id != self_node_id {
            match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name) {
                Ok(msg) => info!("WolfUSB: restored {}:{} — {}", a.source_address, a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to restore {}:{}: {}", a.source_address, a.busid, e),
            }
        }
    }
}

/// Called when a container starts or restarts on this node.
/// Checks if any WolfUSB assignments target this container and re-establishes
/// the usbip connection if needed (handles container migration automatically).
pub fn on_container_started(container_name: &str, container_type: &str, self_node_id: &str) {
    let mut config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }

    let mut changed = false;

    for a in &mut config.assignments {
        // Find assignments targeting this container
        if a.target_name != container_name || a.target_type != container_type {
            continue;
        }

        // If the container is now on this node but the assignment says a different target node,
        // the container has migrated — update the target and re-attach
        if a.target_node_id != self_node_id {
            info!(
                "WolfUSB: container {} migrated from {} to this node — re-routing USB {}",
                container_name, a.target_hostname, a.busid
            );
            a.target_node_id = self_node_id.to_string();
            // Get hostname for display
            a.target_hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| self_node_id.to_string());
            changed = true;
        }

        // Re-attach the device and passthrough to the container
        if a.source_node_id != self_node_id {
            if !a.source_address.is_empty() {
                match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name) {
                    Ok(msg) => info!("WolfUSB: restored {} for container {} — {}", a.busid, container_name, msg),
                    Err(e) => warn!("WolfUSB: failed to restore {} for {}: {}", a.busid, container_name, e),
                }
            }
        } else {
            // Local device — passthrough directly
            match local_passthrough(&a.busid, &a.target_type, &a.target_name) {
                Ok(msg) => info!("WolfUSB: local passthrough {} for {} — {}", a.busid, container_name, msg),
                Err(e) => warn!("WolfUSB: local passthrough {} for {} failed: {}", a.busid, container_name, e),
            }
        }
    }

    if changed {
        let _ = config.save();
    }
}

/// Merge assignments from a remote node's config into ours.
/// Called during cluster config sync so every node has the full assignment list.
pub fn merge_remote_assignments(remote_assignments: &[UsbAssignment]) {
    let mut config = WolfUsbConfig::load();
    let mut changed = false;

    for ra in remote_assignments {
        // Check if we already have this assignment
        let exists = config.assignments.iter().any(|a|
            a.busid == ra.busid && a.source_node_id == ra.source_node_id
        );
        if !exists {
            config.assignments.push(ra.clone());
            changed = true;
        } else {
            // Update if the remote version is newer (target might have changed)
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

    // Remove assignments that no longer exist on any remote node
    // (Only remove if the source node is NOT us — we're authoritative for our own devices)
    let self_id = crate::agent::self_node_id();
    let remote_busids: Vec<(&str, &str)> = remote_assignments.iter()
        .map(|a| (a.busid.as_str(), a.source_node_id.as_str()))
        .collect();
    let before = config.assignments.len();
    config.assignments.retain(|a| {
        // Keep our own source assignments
        if a.source_node_id == self_id { return true; }
        // Keep assignments that exist in the remote set
        remote_busids.iter().any(|(b, s)| *b == a.busid && *s == a.source_node_id)
    });
    if config.assignments.len() != before { changed = true; }

    if changed {
        let _ = config.save();
    }
}

/// Get all current /dev/bus/usb paths from lsusb (used for before/after diffing)
fn lsusb_device_paths() -> Vec<String> {
    let output = match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut paths = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let bus: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let addr: u32 = parts.get(3).and_then(|s| s.trim_end_matches(':').parse().ok()).unwrap_or(0);
            if bus > 0 && addr > 0 {
                paths.push(format!("/dev/bus/usb/{:03}/{:03}", bus, addr));
            }
        }
    }
    paths
}

/// Find newly appeared device path by comparing lsusb before and after an attach
fn find_new_device_path(before: &[String]) -> Option<String> {
    let after = lsusb_device_paths();
    // Return the first path that wasn't in the before snapshot
    for path in &after {
        if !before.contains(path) {
            return Some(path.clone());
        }
    }
    // If no new device found (race or delay), try the highest-numbered one
    after.last().cloned()
}
