# QuantVPN Cloud Droplet / VPS Volatile Overlay (overlayroot)

This deployment guide details how to transform standard cloud VPS instances (DigitalOcean Droplets, Hetzner Cloud, AWS EC2, Linode) into **volatile, memory-backed runtime nodes** using `overlayroot` on Ubuntu and Debian.

---

## 1. How `overlayroot="tmpfs"` Works

When `overlayroot="tmpfs"` is configured in `/etc/overlayroot.conf`, the Linux kernel's initial RAM disk (`initramfs`) restructures the filesystem hierarchy during early boot:

```
                      +------------------------------------------+
                      |         VIRTUAL ROOT FILE SYSTEM         |
                      |            Mounted at '/'                |
                      +--------------------+---------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
     +------------------------------+              +------------------------------+
     |     UPPERDIR (READ-WRITE)    |              |     LOWERDIR (READ-ONLY)     |
     |        Volatile tmpfs        |              |     Underlying VPS Disk      |
     |          (In RAM)            |              |        (/dev/vda1)           |
     +--------------+---------------+              +--------------+---------------+
                    |                                             |
     All runtime file creation,                     Static base OS files,
     WireGuard session keys, logs,                  binaries, and packages.
     and /var modifications.                        Protected from any writes.
                    |
          [ REBOOT / POWER OFF ]
                    |
     All runtime changes in RAM disappear.
     The disk remains completely untouched.
```

1. The VPS disk partition (`/dev/vda1`) is mounted **read-only** (`ro`).
2. An in-memory **`tmpfs`** filesystem is created in RAM.
3. An **`overlayfs`** mount combines both: reads come from the base disk, but **all writes, new files, logs, and keys go to RAM**.
4. When the server reboots or shuts down, the RAM tmpfs vanishes. The base disk stays exactly as it was.

---

## 2. Important Setup Requirements

Using `overlayroot="tmpfs"` requires a few extra steps:

### A. Disable Swap Completely
If the server has an active swap file or partition, the Linux kernel can write memory pages containing WireGuard keys to disk.
```bash
swapoff -a
sed -i '/swap/d' /etc/fstab
rm -f /swapfile
```

### B. Keep Logs in RAM (`Storage=volatile`)
Configure `systemd-journald` to store logs in memory only (`Storage=volatile`), with `RuntimeMaxUse=64M`.

### C. Test with `/root/proof.txt` (Not `/tmp`)
> **Note on testing:**  
> On Ubuntu and Debian, `/tmp` is already a tmpfs in RAM by default. Writing a file to `/tmp` and rebooting doesn't prove overlayroot is working.  
> Instead, test using `/root/proof.txt` or `/var/log/proof.txt`:
> ```bash
> touch /root/proof.txt
> ls -l /root/proof.txt  # file exists
> reboot
> # After reconnecting:
> ls -l /root/proof.txt  # file is gone
> ```

---

## 3. Quick Deployment (1-Minute Setup)

Run the included automated setup script on your droplet:

```bash
# 1. Download and execute setup script
sudo ./deploy/droplet-overlayroot/setup.sh
```

Or manually execute the commands:
```bash
# Disable swap
swapoff -a && sed -i '/swap/d' /etc/fstab && rm -f /swapfile

# Install overlayroot
apt-get update && apt-get install -y overlayroot

# Configure volatile tmpfs
echo 'overlayroot="tmpfs"' > /etc/overlayroot.conf
update-initramfs -u

# Reboot into RAM overlay
reboot
```

---

## 4. How to Manage the Server While `overlayroot` is Active

Because the root filesystem is read-only, standard package updates (`apt update && apt upgrade`) will not persist across reboots. If you need to make persistent configuration changes:

```bash
# Enter the underlying read-write root filesystem via chroot:
sudo overlayroot-chroot

# (Make your updates or edits here)
apt-get update && apt-get upgrade -y
exit

# Reboot to reload the new base image into the volatile overlay
sudo reboot
```
