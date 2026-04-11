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
use tracing::{info, warn, error};

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
            // Save previous device
            if !current_busid.is_empty() {
                let assigned = config.assignments.iter()
                    .find(|a| a.busid == current_busid)
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
    if !current_busid.is_empty() {
        let assigned = config.assignments.iter()
            .find(|a| a.busid == current_busid)
            .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));
        devices.push(UsbDevice {
            busid: current_busid,
            vendor_id: current_vid,
            product_id: current_pid,
            product: current_desc,
            assigned_to: assigned,
        });
    }

    // If usbip list was empty, fallback to lsusb
    if devices.is_empty() {
        return parse_lsusb(config);
    }

    devices
}

/// Parse lsusb output as fallback (convert to busid format)
fn parse_lsusb(config: &WolfUsbConfig) -> Vec<UsbDevice> {
    let output = match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };

    let mut devices = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(2, ": ").collect();
        if parts.len() < 2 { continue; }

        let bus_dev: Vec<&str> = parts[0].split_whitespace().collect();
        let bus: u32 = bus_dev.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let _addr: u32 = bus_dev.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);

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

        // Approximate busid from bus number (lsusb doesn't give the usbip busid directly)
        let busid = format!("{}-1", bus);

        let assigned = config.assignments.iter()
            .find(|a| a.busid == busid || (a.usb_id == format!("{}:{}", vid, pid)))
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

/// Export (bind) a USB device on this node so remote nodes can attach to it
pub fn export_device(busid: &str) -> Result<String, String> {
    let _ = ensure_usbip_modules();

    // Validate busid format (e.g. "1-2", "2-1.3")
    if !busid.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.') {
        return Err("Invalid bus ID format".to_string());
    }

    // Bind the device for sharing
    let output = Command::new("usbip").args(["bind", "--busid", busid]).output()
        .map_err(|e| format!("Failed to run usbip bind: {}", e))?;

    if output.status.success() {
        info!("WolfUSB: exported device {}", busid);
        Ok(format!("Device {} exported for sharing", busid))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "already bound" is not an error
        if stderr.contains("already bound") {
            Ok(format!("Device {} already exported", busid))
        } else {
            Err(format!("Failed to export device {}: {}", busid, stderr))
        }
    }
}

/// Unexport (unbind) a USB device on this node
pub fn unexport_device(busid: &str) -> Result<String, String> {
    if !busid.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.') {
        return Err("Invalid bus ID format".to_string());
    }

    let output = Command::new("usbip").args(["unbind", "--busid", busid]).output()
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

    if !busid.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.') {
        return Err("Invalid bus ID format".to_string());
    }
    // Validate host (alphanumeric, dots, colons for IPv6, hyphens)
    if !remote_host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '-') {
        return Err("Invalid remote host".to_string());
    }

    let output = Command::new("usbip").args(["attach", "--remote", remote_host, "--busid", busid]).output()
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

    let mut msg = String::new();

    // If this is also the target node, attach locally
    let is_local_target = target_node_id == source_node_id
        || config.assignments.is_empty(); // will be set by the API layer

    if is_local_source && is_local_target {
        // Same node — just passthrough directly (no usbip needed for local)
        let dev_path = find_dev_path(busid);
        msg = format!("USB device {} assigned to {}:{} (local passthrough)", busid, target_type, target_name);
        if let Some(ref path) = dev_path {
            msg.push_str(&format!("\nDevice path: {}", path));
        }
    } else {
        msg = format!(
            "USB device {} from {} assigned to {}:{} on {}",
            busid, source_hostname, target_type, target_name, target_hostname
        );
    }

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
    // Parse bus number from busid (e.g. "1-2" -> bus 1)
    let bus: u32 = busid.split('-').next()?.parse().ok()?;
    // Find the device address using sysfs
    let sysfs_path = format!("/sys/bus/usb/devices/{}/devnum", busid);
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
    // Step 1: Attach the remote device via usbip
    let attach_result = attach_remote_device(source_address, busid)?;

    // Step 2: Find the newly created virtual device
    // Wait briefly for the device to appear
    std::thread::sleep(std::time::Duration::from_millis(500));

    let dev_path = find_virtual_dev_path(busid);

    let mut result = attach_result;

    // Step 3: Pass into container/VM
    match (target_type, &dev_path) {
        ("docker", Some(path)) => {
            result.push_str(&format!(
                "\nDevice available at {}. Recreate the container with:\n  --device {}:{}",
                path, path, path
            ));
        }
        ("lxc", Some(path)) => {
            let lxc_config_path = format!("/var/lib/lxc/{}/config", target_name);
            if std::path::Path::new(&lxc_config_path).exists() {
                let entry = format!(
                    "\n# WolfUSB: remote device {} via usbip\n\
                     lxc.cgroup2.devices.allow = c 189:* rwm\n\
                     lxc.mount.entry = {} {} none bind,optional,create=file 0 0\n",
                    busid, path, path.trim_start_matches('/')
                );
                if let Err(e) = std::fs::OpenOptions::new().append(true).open(&lxc_config_path)
                    .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) })
                {
                    result.push_str(&format!("\nWarning: could not update LXC config: {}", e));
                } else {
                    result.push_str(&format!("\nLXC config updated. Restart {} to apply.", target_name));
                }
            }
        }
        ("vm", Some(path)) => {
            result.push_str(&format!("\nDevice available at {} for VM passthrough.", path));
        }
        _ => {
            result.push_str("\nNote: virtual device path not yet available. It may take a moment to appear.");
        }
    }

    Ok(result)
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

    for a in &config.assignments {
        // Source side: re-export devices that are physically on this node
        if a.source_node_id == self_node_id {
            match export_device(&a.busid) {
                Ok(msg) => info!("WolfUSB: re-exported {} — {}", a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to re-export {}: {}", a.busid, e),
            }
        }

        // Target side: re-attach remote devices for containers on this node
        if a.target_node_id == self_node_id && a.source_node_id != self_node_id {
            match attach_remote_device(&a.source_address, &a.busid) {
                Ok(msg) => info!("WolfUSB: re-attached {}:{} — {}", a.source_address, a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to re-attach {}:{}: {}", a.source_address, a.busid, e),
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

        // Re-attach the device if it's from a remote node
        if a.source_node_id != self_node_id {
            if !a.source_address.is_empty() {
                match attach_remote_device(&a.source_address, &a.busid) {
                    Ok(_) => info!("WolfUSB: re-attached {} for container {}", a.busid, container_name),
                    Err(e) => warn!("WolfUSB: failed to re-attach {} for {}: {}", a.busid, container_name, e),
                }
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

/// Find the /dev/bus/usb path for a recently attached virtual USB device
fn find_virtual_dev_path(_busid: &str) -> Option<String> {
    // After usbip attach, the virtual device gets a new bus/addr
    // Check the last entry in /sys/devices/platform/vhci_hcd.0/
    // For now, use lsusb to find the newest device
    let output = Command::new("lsusb").output().ok()?;
    if !output.status.success() { return None; }
    let text = String::from_utf8_lossy(&output.stdout);
    // Return the last device path found (most recently added)
    let mut last_path = None;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let bus: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let addr: u32 = parts.get(3).and_then(|s| s.trim_end_matches(':').parse().ok()).unwrap_or(0);
            if bus > 0 && addr > 0 {
                last_path = Some(format!("/dev/bus/usb/{:03}/{:03}", bus, addr));
            }
        }
    }
    last_path
}
