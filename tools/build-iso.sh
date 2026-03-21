#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
#
# build-iso.sh — Build a bootable WolfStack ISO based on Debian
#
# This creates a remastered Debian netinst ISO that:
#   1. Boots to the Debian installer with WolfStack preseed
#   2. Auto-installs Debian minimal (only asks for disk + root password)
#   3. On first boot, installs WolfStack automatically
#   4. Displays the dashboard URL and cluster token on the console
#
# Usage:
#   ./tools/build-iso.sh                    # Build with latest release binary
#   ./tools/build-iso.sh --from-source      # Build binary from local source
#   ./tools/build-iso.sh --binary /path/to  # Use a specific binary
#
# Requirements: xorriso, isolinux, cpio, wget, curl, gzip
# Run on a Debian/Ubuntu system.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="/tmp/wolfstack-iso-build"
DEBIAN_ISO_URL="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso"
DEBIAN_ISO_FILE="$BUILD_DIR/debian-netinst.iso"

# Get version from Cargo.toml
VERSION=$(grep '^version' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
OUTPUT_ISO="$PROJECT_DIR/wolfstack-${VERSION}-amd64.iso"

# Parse arguments
BINARY_PATH=""
FROM_SOURCE=false
for arg in "$@"; do
    case "$arg" in
        --from-source) FROM_SOURCE=true ;;
        --binary) shift; BINARY_PATH="$1" ;;
    esac
done

echo ""
echo "  ======================================"
echo "  WolfStack ISO Builder v${VERSION}"
echo "  ======================================"
echo ""

# ── Check dependencies ──
for cmd in xorriso cpio wget gzip; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Missing dependency: $cmd"
        echo "Install with: sudo apt install xorriso cpio wget gzip"
        exit 1
    fi
done

# ── Prepare build directory ──
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/iso" "$BUILD_DIR/wolfstack"

# ── Download Debian ISO ──
if [ ! -f "$DEBIAN_ISO_FILE" ]; then
    echo "[1/6] Downloading Debian netinst ISO..."
    wget -q --show-progress -O "$DEBIAN_ISO_FILE" "$DEBIAN_ISO_URL"
else
    echo "[1/6] Using cached Debian ISO"
fi

# ── Extract ISO ──
echo "[2/6] Extracting Debian ISO..."
xorriso -osirrox on -indev "$DEBIAN_ISO_FILE" -extract / "$BUILD_DIR/iso" 2>/dev/null
chmod -R u+w "$BUILD_DIR/iso"

# ── Build or copy WolfStack binary ──
echo "[3/6] Preparing WolfStack binary..."
if [ -n "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" "$BUILD_DIR/wolfstack/wolfstack"
elif [ "$FROM_SOURCE" = true ]; then
    echo "  Building from source (this takes a few minutes)..."
    cd "$PROJECT_DIR"
    cargo build --release 2>&1 | tail -3
    cp "$PROJECT_DIR/target/release/wolfstack" "$BUILD_DIR/wolfstack/wolfstack"
else
    # Download latest release binary from GitHub
    echo "  Downloading latest release binary..."
    RELEASE_URL="https://github.com/wolfsoftwaresystemsltd/WolfStack/releases/latest/download/wolfstack-linux-amd64"
    if ! wget -q --show-progress -O "$BUILD_DIR/wolfstack/wolfstack" "$RELEASE_URL" 2>/dev/null; then
        echo "  No release binary found. Building from source..."
        cd "$PROJECT_DIR"
        cargo build --release 2>&1 | tail -3
        cp "$PROJECT_DIR/target/release/wolfstack" "$BUILD_DIR/wolfstack/wolfstack"
    fi
fi
chmod +x "$BUILD_DIR/wolfstack/wolfstack"

# Also include the setup script for dependencies
cp "$PROJECT_DIR/setup.sh" "$BUILD_DIR/wolfstack/setup.sh" 2>/dev/null || true

# ── Copy web UI ──
echo "  Bundling web UI..."
if [ -d "$PROJECT_DIR/web" ]; then
    cp -r "$PROJECT_DIR/web" "$BUILD_DIR/wolfstack/web"
fi

# Pack WolfStack files into a tarball
cd "$BUILD_DIR"
tar czf "$BUILD_DIR/iso/wolfstack-bundle.tar.gz" -C "$BUILD_DIR" wolfstack/

# ── Create preseed.cfg ──
echo "[4/6] Creating preseed configuration..."
cat > "$BUILD_DIR/iso/preseed.cfg" << 'PRESEED'
# WolfStack Debian Preseed
# Automated installation with minimal user interaction

# Locale and keyboard
d-i debian-installer/locale string en_GB.UTF-8
d-i keyboard-configuration/xkb-keymap select gb
d-i console-setup/ask_detect boolean false

# Network (DHCP, auto-detect interface)
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string wolfstack
d-i netcfg/get_domain string local

# Mirror
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

# Time
d-i clock-setup/utc boolean true
d-i time/zone string UTC
d-i clock-setup/ntp boolean true

# Partitioning — use entire disk, single partition, no LVM
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true

# Root password — will be asked during install
# (not preseeded so the user sets their own)

# Create no regular user — root only (server use)
d-i passwd/make-user boolean false

# Package selection — minimal server
tasksel tasksel/first multiselect ssh-server, standard
d-i pkgsel/include string curl wget git build-essential sudo openssh-server \
    libssl-dev pkg-config screen htop
d-i pkgsel/upgrade select full-upgrade
popularity-contest popularity-contest/participate boolean false

# Grub — install to the first disk automatically
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string default

# Post-install: extract WolfStack and set up first-boot service
d-i preseed/late_command string \
    in-target mkdir -p /opt/wolfstack; \
    cp /cdrom/wolfstack-bundle.tar.gz /target/tmp/wolfstack-bundle.tar.gz; \
    in-target tar xzf /tmp/wolfstack-bundle.tar.gz -C /opt/; \
    in-target chmod +x /opt/wolfstack/wolfstack; \
    in-target cp /opt/wolfstack/setup.sh /opt/wolfstack/setup.sh 2>/dev/null || true; \
    echo '#!/bin/bash' > /target/opt/wolfstack/first-boot.sh; \
    echo 'set -e' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# WolfStack First Boot Setup' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  ======================================"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  WolfStack First Boot Setup"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  ======================================"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Install Rust toolchain for future updates' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'if ! command -v rustc &>/dev/null; then' >> /target/opt/wolfstack/first-boot.sh; \
    echo '    echo "Installing Rust toolchain..."' >> /target/opt/wolfstack/first-boot.sh; \
    echo '    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>/dev/null' >> /target/opt/wolfstack/first-boot.sh; \
    echo '    source /root/.cargo/env 2>/dev/null || true' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'fi' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Install the pre-compiled binary' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'mkdir -p /etc/wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'cp /opt/wolfstack/wolfstack /usr/local/bin/wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'chmod +x /usr/local/bin/wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Copy web UI' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'if [ -d /opt/wolfstack/web ]; then' >> /target/opt/wolfstack/first-boot.sh; \
    echo '    mkdir -p /opt/wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo '    # web dir already in place from ISO extraction' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'fi' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Create systemd service' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'cat > /etc/systemd/system/wolfstack.service << EOF' >> /target/opt/wolfstack/first-boot.sh; \
    echo '[Unit]' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'Description=WolfStack Server Management Platform' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'After=network.target docker.service' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '[Service]' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'Type=simple' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'ExecStart=/usr/local/bin/wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'Restart=always' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'RestartSec=5' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'Environment=RUST_LOG=info' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '[Install]' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'WantedBy=multi-user.target' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'EOF' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'systemctl daemon-reload' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'systemctl enable wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'systemctl start wolfstack' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Get the IP address' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'IP=$(hostname -I | awk "{print \\$1}")' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'TOKEN=$(/usr/local/bin/wolfstack --show-token 2>/dev/null || echo "generating...")' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Display connection info' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  ======================================"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  WolfStack is running!"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  ======================================"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  Dashboard: https://${IP}:8553"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  Token:     ${TOKEN}"' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo "  Log in with your root password."' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'echo ""' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Write to /etc/issue so it shows on the console login screen' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'cat > /etc/issue << ISSUE' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '  WolfStack Server Management Platform' >> /target/opt/wolfstack/first-boot.sh; \
    echo '  ────────────────────────────────────' >> /target/opt/wolfstack/first-boot.sh; \
    echo '  Dashboard: https://${IP}:8553' >> /target/opt/wolfstack/first-boot.sh; \
    echo '  Token:     ${TOKEN}' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'ISSUE' >> /target/opt/wolfstack/first-boot.sh; \
    echo '' >> /target/opt/wolfstack/first-boot.sh; \
    echo '# Disable first-boot service' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'systemctl disable wolfstack-firstboot' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'rm -f /etc/systemd/system/wolfstack-firstboot.service' >> /target/opt/wolfstack/first-boot.sh; \
    echo 'systemctl daemon-reload' >> /target/opt/wolfstack/first-boot.sh; \
    chmod +x /target/opt/wolfstack/first-boot.sh; \
    echo '[Unit]' > /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'Description=WolfStack First Boot Setup' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'After=network-online.target' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'Wants=network-online.target' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'ConditionPathExists=/opt/wolfstack/first-boot.sh' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo '' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo '[Service]' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'Type=oneshot' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'ExecStart=/opt/wolfstack/first-boot.sh' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'RemainAfterExit=yes' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo '' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo '[Install]' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    echo 'WantedBy=multi-user.target' >> /target/etc/systemd/system/wolfstack-firstboot.service; \
    in-target systemctl enable wolfstack-firstboot; \
    rm /target/tmp/wolfstack-bundle.tar.gz

# Finish — reboot automatically
d-i finish-install/reboot_in_progress note
PRESEED

# ── Modify boot menu to use preseed ──
echo "[5/6] Configuring boot menu..."

# Modify isolinux config for BIOS boot
if [ -f "$BUILD_DIR/iso/isolinux/isolinux.cfg" ]; then
    cat > "$BUILD_DIR/iso/isolinux/isolinux.cfg" << 'ISOLINUX'
default wolfstack
timeout 50
prompt 0

label wolfstack
    menu label ^Install WolfStack
    kernel /install.amd/vmlinuz
    append auto=true priority=critical preseed/file=/cdrom/preseed.cfg initrd=/install.amd/initrd.gz --- quiet

label expert
    menu label ^Expert Install (manual Debian)
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz --- quiet
ISOLINUX
fi

# Modify GRUB config for UEFI boot
if [ -f "$BUILD_DIR/iso/boot/grub/grub.cfg" ]; then
    cat > "$BUILD_DIR/iso/boot/grub/grub.cfg" << 'GRUBCFG'
set default=0
set timeout=5

menuentry "Install WolfStack" {
    linux /install.amd/vmlinuz auto=true priority=critical preseed/file=/cdrom/preseed.cfg --- quiet
    initrd /install.amd/initrd.gz
}

menuentry "Expert Install (manual Debian)" {
    linux /install.amd/vmlinuz --- quiet
    initrd /install.amd/initrd.gz
}
GRUBCFG
fi

# ── Build the ISO ──
echo "[6/6] Building ISO..."

# Regenerate md5sum
cd "$BUILD_DIR/iso"
find . -type f ! -name md5sum.txt ! -path './isolinux/*' -exec md5sum {} \; > md5sum.txt

# Build ISO with xorriso (supports both BIOS and UEFI)
xorriso -as mkisofs \
    -o "$OUTPUT_ISO" \
    -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
    -c isolinux/boot.cat \
    -b isolinux/isolinux.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot -isohybrid-gpt-basdat \
    -V "WOLFSTACK_${VERSION}" \
    "$BUILD_DIR/iso" 2>/dev/null

# ── Cleanup ──
rm -rf "$BUILD_DIR/iso" "$BUILD_DIR/wolfstack"

ISO_SIZE=$(du -h "$OUTPUT_ISO" | cut -f1)

echo ""
echo "  ======================================"
echo "  WolfStack ISO Built Successfully!"
echo "  ======================================"
echo ""
echo "  Output:  $OUTPUT_ISO"
echo "  Size:    $ISO_SIZE"
echo "  Version: $VERSION"
echo ""
echo "  Write to USB:"
echo "    sudo dd if=$OUTPUT_ISO of=/dev/sdX bs=4M status=progress"
echo ""
echo "  Or use in a VM (VirtualBox, VMware, Proxmox, etc.)"
echo ""
