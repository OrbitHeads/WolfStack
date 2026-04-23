#!/bin/bash
# Written by Paul Clevett
# (C)Copyright Wolf Software Systems Ltd
# https://wolf.uk.com
#
#
# WolfStack Uninstall Script
# Removes WolfStack server management dashboard and optionally other Wolf suite components
#
# Usage: sudo bash uninstall.sh                         # Remove WolfStack only
#        sudo bash uninstall.sh --purge                 # Also remove config and data
#        sudo bash uninstall.sh --wolfnet               # Also remove WolfNet
#        sudo bash uninstall.sh --wolfproxy             # Also remove WolfProxy
#        sudo bash uninstall.sh --wolfserve             # Also remove WolfServe
#        sudo bash uninstall.sh --wolfdisk              # Also remove WolfDisk
#        sudo bash uninstall.sh --wolfscale             # Also remove WolfScale
#        sudo bash uninstall.sh --all                   # Remove WolfStack + every Wolf component
#        sudo bash uninstall.sh --all --purge           # Full wipe of everything
#

set -e

# ─── Parse arguments ─────────────────────────────────────────────────────────
PURGE=false
REMOVE_WOLFNET=false
REMOVE_WOLFPROXY=false
REMOVE_WOLFSERVE=false
REMOVE_WOLFDISK=false
REMOVE_WOLFSCALE=false
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --purge)     PURGE=true ;;
        --wolfnet)   REMOVE_WOLFNET=true ;;
        --wolfproxy) REMOVE_WOLFPROXY=true ;;
        --wolfserve) REMOVE_WOLFSERVE=true ;;
        --wolfdisk)  REMOVE_WOLFDISK=true ;;
        --wolfscale) REMOVE_WOLFSCALE=true ;;
        --all)
            REMOVE_WOLFNET=true
            REMOVE_WOLFPROXY=true
            REMOVE_WOLFSERVE=true
            REMOVE_WOLFDISK=true
            REMOVE_WOLFSCALE=true
            ;;
        --force)   FORCE=true ;;
    esac
done

echo ""
echo "  🐺 WolfStack Uninstaller"
echo "  ─────────────────────────────────────"
if [ "$PURGE" = true ]; then
    echo "  Mode: Full purge (config + data will be removed)"
else
    echo "  Mode: Standard (config + data preserved)"
fi
[ "$REMOVE_WOLFNET"   = true ] && echo "  WolfNet:   Will also be removed"
[ "$REMOVE_WOLFPROXY" = true ] && echo "  WolfProxy: Will also be removed"
[ "$REMOVE_WOLFSERVE" = true ] && echo "  WolfServe: Will also be removed"
[ "$REMOVE_WOLFDISK"  = true ] && echo "  WolfDisk:  Will also be removed"
[ "$REMOVE_WOLFSCALE" = true ] && echo "  WolfScale: Will also be removed"
echo ""

# ─── Must run as root ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "✗ This script must be run as root."
    echo "  Usage: sudo bash uninstall.sh"
    exit 1
fi

# ─── Confirm ─────────────────────────────────────────────────────────────────
if [ "$FORCE" != true ]; then
    echo "This will remove WolfStack from your system."
    if [ "$PURGE" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --purge will delete ALL configuration and data:"
        echo "     • /etc/wolfstack/ (config files, S3/PBS credentials)"
        echo "     • /opt/wolfstack/ (web UI)"
        echo "     • /opt/wolfstack-src/ (source code)"
        echo "     • /mnt/wolfstack/ (storage mounts)"
        echo "     • /var/cache/wolfstack/ (S3 cache)"
    fi
    if [ "$REMOVE_WOLFNET" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfnet will also remove WolfNet:"
        echo "     • wolfnet binary and systemd service"
        if [ "$PURGE" = true ]; then
            echo "     • /etc/wolfnet/ (config and keys)"
            echo "     • /opt/wolfnet-src/ (source code)"
        fi
    fi
    if [ "$REMOVE_WOLFPROXY" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfproxy will also remove WolfProxy:"
        echo "     • wolfproxy systemd service"
        if [ "$PURGE" = true ]; then
            echo "     • /opt/wolfproxy/ (binary, source, wolfproxy.toml config)"
        fi
    fi
    if [ "$REMOVE_WOLFSERVE" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfserve will also remove WolfServe:"
        echo "     • wolfserve systemd service"
        if [ "$PURGE" = true ]; then
            echo "     • /opt/wolfserve/ (binary, config, public/ docroot)"
        fi
    fi
    if [ "$REMOVE_WOLFDISK" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfdisk will also remove WolfDisk:"
        echo "     • wolfdisk binary and systemd service"
        if [ "$PURGE" = true ]; then
            echo "     • /etc/wolfdisk/ (config)"
            echo "     • /var/lib/wolfdisk/ (chunks, index, wal)"
            echo "     • /mnt/wolfdisk/ (mount point)"
            echo "     • /opt/wolfdisk-src/ (source code)"
        fi
    fi
    if [ "$REMOVE_WOLFSCALE" = true ]; then
        echo ""
        echo "  ⚠  WARNING: --wolfscale will also remove WolfScale:"
        echo "     • wolfscale + wolfscale-lb systemd services"
        echo "     • wolfctl CLI tool"
        if [ "$PURGE" = true ]; then
            echo "     • /opt/wolfscale/ (binary, wolfscale.toml config)"
            echo "     • /var/lib/wolfscale/ (data)"
            echo "     • /var/log/wolfscale/ (logs)"
            echo "     • /opt/wolfscale-src/ (source code)"
        fi
    fi
    echo ""
    echo -n "Are you sure you want to continue? [y/N]: "
    read CONFIRM < /dev/tty
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi
    echo ""
fi

# ─── Stop and disable WolfStack service ─────────────────────────────────────
echo "Stopping WolfStack..."
if systemctl is-active --quiet wolfstack 2>/dev/null; then
    systemctl stop wolfstack 2>/dev/null || true
    echo "✓ WolfStack service stopped"
else
    echo "  WolfStack service not running"
fi

if systemctl is-enabled --quiet wolfstack 2>/dev/null; then
    systemctl disable wolfstack 2>/dev/null || true
    echo "✓ WolfStack service disabled"
fi

# ─── Remove systemd service file ────────────────────────────────────────────
if [ -f "/etc/systemd/system/wolfstack.service" ]; then
    rm -f /etc/systemd/system/wolfstack.service
    systemctl daemon-reload
    echo "✓ WolfStack systemd service removed"
else
    echo "  No systemd service file found"
fi

# ─── Remove binary ──────────────────────────────────────────────────────────
if [ -f "/usr/local/bin/wolfstack" ]; then
    rm -f /usr/local/bin/wolfstack
    echo "✓ Removed /usr/local/bin/wolfstack"
else
    echo "  Binary not found at /usr/local/bin/wolfstack"
fi

# ─── Remove web UI ──────────────────────────────────────────────────────────
if [ -d "/opt/wolfstack/web" ]; then
    rm -rf /opt/wolfstack/web
    # Remove /opt/wolfstack if now empty
    rmdir /opt/wolfstack 2>/dev/null || true
    echo "✓ Removed web UI from /opt/wolfstack/web"
else
    echo "  Web UI directory not found"
fi

# ─── Remove firewall rules ──────────────────────────────────────────────────
# Read port from config if it exists
WS_PORT=$(grep "port" /etc/wolfstack/config.toml 2>/dev/null | head -1 | awk '{print $3}' || echo "8553")

if command -v ufw &> /dev/null; then
    ufw delete allow "$WS_PORT/tcp" 2>/dev/null && echo "✓ Firewall: Closed port $WS_PORT/tcp (ufw)" || true
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --remove-port="$WS_PORT/tcp" 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null && \
    echo "✓ Firewall: Closed port $WS_PORT/tcp (firewalld)" || true
fi

# ─── Purge config and data (optional) ───────────────────────────────────────
if [ "$PURGE" = true ]; then
    echo ""
    echo "Purging configuration and data..."

    if [ -d "/etc/wolfstack" ]; then
        rm -rf /etc/wolfstack
        echo "✓ Removed /etc/wolfstack/"
    fi

    if [ -d "/opt/wolfstack-src" ]; then
        rm -rf /opt/wolfstack-src
        echo "✓ Removed /opt/wolfstack-src/"
    fi

    if [ -d "/opt/wolfstack" ]; then
        rm -rf /opt/wolfstack
        echo "✓ Removed /opt/wolfstack/"
    fi

    if [ -d "/mnt/wolfstack" ]; then
        # Unmount any active mounts first
        for mnt in /mnt/wolfstack/*/; do
            if mountpoint -q "$mnt" 2>/dev/null; then
                umount -l "$mnt" 2>/dev/null || true
            fi
        done
        rm -rf /mnt/wolfstack
        echo "✓ Removed /mnt/wolfstack/"
    fi

    if [ -d "/var/cache/wolfstack" ]; then
        rm -rf /var/cache/wolfstack
        echo "✓ Removed /var/cache/wolfstack/"
    fi
else
    echo ""
    echo "  ℹ  Config preserved at /etc/wolfstack/"
    echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge"
fi

# ─── Remove WolfNet (optional) ──────────────────────────────────────────────
if [ "$REMOVE_WOLFNET" = true ]; then
    echo ""
    echo "Removing WolfNet..."

    # Stop and disable service
    if systemctl is-active --quiet wolfnet 2>/dev/null; then
        systemctl stop wolfnet 2>/dev/null || true
        echo "✓ WolfNet service stopped"
    fi

    if systemctl is-enabled --quiet wolfnet 2>/dev/null; then
        systemctl disable wolfnet 2>/dev/null || true
        echo "✓ WolfNet service disabled"
    fi

    # Remove systemd service
    if [ -f "/etc/systemd/system/wolfnet.service" ]; then
        rm -f /etc/systemd/system/wolfnet.service
        systemctl daemon-reload
        echo "✓ WolfNet systemd service removed"
    fi

    # Remove binaries
    if [ -f "/usr/local/bin/wolfnet" ]; then
        rm -f /usr/local/bin/wolfnet
        echo "✓ Removed /usr/local/bin/wolfnet"
    fi
    if [ -f "/usr/local/bin/wolfnetctl" ]; then
        rm -f /usr/local/bin/wolfnetctl
        echo "✓ Removed /usr/local/bin/wolfnetctl"
    fi

    # Remove wolfnet0 interface
    if ip link show wolfnet0 &>/dev/null; then
        ip link set wolfnet0 down 2>/dev/null || true
        ip link delete wolfnet0 2>/dev/null || true
        echo "✓ Removed wolfnet0 network interface"
    fi

    # Remove firewall rules for WolfNet
    if command -v ufw &> /dev/null; then
        ufw delete allow 9600/udp 2>/dev/null && echo "✓ Firewall: Closed port 9600/udp (ufw)" || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-port="9600/udp" 2>/dev/null && \
        firewall-cmd --reload 2>/dev/null && \
        echo "✓ Firewall: Closed port 9600/udp (firewalld)" || true
    fi

    # Purge WolfNet config and source
    if [ "$PURGE" = true ]; then
        if [ -d "/etc/wolfnet" ]; then
            rm -rf /etc/wolfnet
            echo "✓ Removed /etc/wolfnet/"
        fi

        if [ -d "/var/run/wolfnet" ]; then
            rm -rf /var/run/wolfnet
            echo "✓ Removed /var/run/wolfnet/"
        fi

        if [ -d "/opt/wolfnet-src" ]; then
            rm -rf /opt/wolfnet-src
            echo "✓ Removed /opt/wolfnet-src/"
        fi
    else
        echo "  ℹ  WolfNet config preserved at /etc/wolfnet/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfnet"
    fi
fi

# ─── Helper: stop, disable and remove a systemd unit ────────────────────────
remove_service() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        echo "✓ ${svc} service stopped"
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        systemctl disable "$svc" 2>/dev/null || true
        echo "✓ ${svc} service disabled"
    fi
    if [ -f "/etc/systemd/system/${svc}.service" ]; then
        rm -f "/etc/systemd/system/${svc}.service"
        systemctl daemon-reload
        echo "✓ ${svc} systemd unit removed"
    fi
}

# ─── Remove WolfProxy (optional) ────────────────────────────────────────────
if [ "$REMOVE_WOLFPROXY" = true ]; then
    echo ""
    echo "Removing WolfProxy..."

    remove_service wolfproxy

    if [ "$PURGE" = true ]; then
        if [ -d "/opt/wolfproxy" ]; then
            rm -rf /opt/wolfproxy
            echo "✓ Removed /opt/wolfproxy/"
        fi
    else
        echo "  ℹ  WolfProxy files preserved at /opt/wolfproxy/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfproxy"
    fi

    # WolfProxy's setup.sh stops and disables nginx on install — restore it if present
    if systemctl cat nginx &>/dev/null; then
        systemctl enable nginx 2>/dev/null || true
        systemctl start nginx 2>/dev/null || true
        if systemctl is-active --quiet nginx; then
            echo "✓ nginx re-enabled and started"
        else
            echo "  ⚠ nginx unit exists but failed to start — check: journalctl -u nginx -n 20"
        fi
    fi
fi

# ─── Remove WolfServe (optional) ────────────────────────────────────────────
if [ "$REMOVE_WOLFSERVE" = true ]; then
    echo ""
    echo "Removing WolfServe..."

    remove_service wolfserve

    if [ "$PURGE" = true ]; then
        if [ -d "/opt/wolfserve" ]; then
            rm -rf /opt/wolfserve
            echo "✓ Removed /opt/wolfserve/"
        fi
    else
        echo "  ℹ  WolfServe files preserved at /opt/wolfserve/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfserve"
    fi
fi

# ─── Remove WolfDisk (optional) ─────────────────────────────────────────────
if [ "$REMOVE_WOLFDISK" = true ]; then
    echo ""
    echo "Removing WolfDisk..."

    # Unmount any active WolfDisk mounts before tearing down the service
    if [ -d "/mnt/wolfdisk" ]; then
        if mountpoint -q /mnt/wolfdisk 2>/dev/null; then
            umount -l /mnt/wolfdisk 2>/dev/null || true
            echo "✓ Unmounted /mnt/wolfdisk"
        fi
    fi

    remove_service wolfdisk

    if [ -f "/usr/local/bin/wolfdisk" ]; then
        rm -f /usr/local/bin/wolfdisk
        echo "✓ Removed /usr/local/bin/wolfdisk"
    fi

    if [ "$PURGE" = true ]; then
        [ -d "/etc/wolfdisk"     ] && rm -rf /etc/wolfdisk     && echo "✓ Removed /etc/wolfdisk/"
        [ -d "/var/lib/wolfdisk" ] && rm -rf /var/lib/wolfdisk && echo "✓ Removed /var/lib/wolfdisk/"
        [ -d "/mnt/wolfdisk"     ] && rm -rf /mnt/wolfdisk     && echo "✓ Removed /mnt/wolfdisk/"
        [ -d "/opt/wolfdisk-src" ] && rm -rf /opt/wolfdisk-src && echo "✓ Removed /opt/wolfdisk-src/"
    else
        echo "  ℹ  WolfDisk config preserved at /etc/wolfdisk/ and data at /var/lib/wolfdisk/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfdisk"
    fi
fi

# ─── Remove WolfScale (optional) ────────────────────────────────────────────
if [ "$REMOVE_WOLFSCALE" = true ]; then
    echo ""
    echo "Removing WolfScale..."

    remove_service wolfscale
    remove_service wolfscale-lb

    if [ -f "/usr/local/bin/wolfctl" ]; then
        rm -f /usr/local/bin/wolfctl
        echo "✓ Removed /usr/local/bin/wolfctl"
    fi

    if [ "$PURGE" = true ]; then
        [ -d "/opt/wolfscale"     ] && rm -rf /opt/wolfscale     && echo "✓ Removed /opt/wolfscale/"
        [ -d "/var/lib/wolfscale" ] && rm -rf /var/lib/wolfscale && echo "✓ Removed /var/lib/wolfscale/"
        [ -d "/var/log/wolfscale" ] && rm -rf /var/log/wolfscale && echo "✓ Removed /var/log/wolfscale/"
        [ -d "/opt/wolfscale-src" ] && rm -rf /opt/wolfscale-src && echo "✓ Removed /opt/wolfscale-src/"
    else
        echo "  ℹ  WolfScale config preserved at /opt/wolfscale/ and data at /var/lib/wolfscale/"
        echo "     To remove all data, re-run with: sudo bash uninstall.sh --purge --wolfscale"
    fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "  🐺 Uninstall Complete!"
echo "  ─────────────────────────────────────"
if [ "$PURGE" != true ]; then
    echo "  Config files preserved — reinstall with setup.sh to restore."
fi
if [ "$REMOVE_WOLFNET"   != true ] && command -v wolfnet   &>/dev/null; then
    echo "  WolfNet was NOT removed. Remove with:   sudo bash uninstall.sh --wolfnet"
fi
if [ "$REMOVE_WOLFPROXY" != true ] && systemctl cat wolfproxy &>/dev/null; then
    echo "  WolfProxy was NOT removed. Remove with: sudo bash uninstall.sh --wolfproxy"
fi
if [ "$REMOVE_WOLFSERVE" != true ] && systemctl cat wolfserve &>/dev/null; then
    echo "  WolfServe was NOT removed. Remove with: sudo bash uninstall.sh --wolfserve"
fi
if [ "$REMOVE_WOLFDISK"  != true ] && command -v wolfdisk  &>/dev/null; then
    echo "  WolfDisk was NOT removed. Remove with:  sudo bash uninstall.sh --wolfdisk"
fi
if [ "$REMOVE_WOLFSCALE" != true ] && systemctl cat wolfscale &>/dev/null; then
    echo "  WolfScale was NOT removed. Remove with: sudo bash uninstall.sh --wolfscale"
fi
echo ""
echo "  Note: System packages installed by setup.sh (git, curl, Docker,"
echo "  LXC, QEMU, etc.) were NOT removed. Remove them manually if needed."
echo ""
