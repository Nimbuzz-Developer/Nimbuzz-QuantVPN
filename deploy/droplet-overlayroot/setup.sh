#!/usr/bin/env bash
# Sets up overlayroot with tmpfs on Ubuntu/Debian droplets.
# After running this and rebooting, all writes to / stay in RAM and disappear on reboot.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Error: please run as root" >&2
    exit 1
fi

echo "==> 1. Disabling swap..."
swapoff -a || true
sed -i '/swap/d' /etc/fstab
if [ -f /swapfile ]; then
    rm -f /swapfile
fi

echo "==> 2. Setting journald to volatile (RAM only)..."
mkdir -p /etc/systemd/journald.conf.d
cat << 'EOF' > /etc/systemd/journald.conf.d/00-quantvpn-volatile.conf
[Journal]
Storage=volatile
Compress=yes
RuntimeMaxUse=64M
ForwardToSyslog=no
EOF
systemctl restart systemd-journald || true

echo "==> 3. Installing overlayroot..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y overlayroot

echo "==> 4. Setting overlayroot to tmpfs..."
cat << 'EOF' > /etc/overlayroot.conf
overlayroot="tmpfs"
EOF

echo "==> 5. Updating initramfs..."
update-initramfs -u

echo ""
echo "Setup complete. The server will boot into RAM overlay on the next reboot."
echo "To test after reboot:"
echo "  1. Check mount: df -T /  (filesystem type should be overlay)"
echo "  2. Test reboot wipe: touch /root/proof.txt && reboot"
echo "  3. Reconnect: ls /root/proof.txt should say 'No such file or directory'"
echo ""
read -p "Reboot now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Rebooting..."
    reboot
fi
