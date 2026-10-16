# QuantVPN Reboot Verification Report

- **Test ID:** `TEST-RAM-20261015-FRA1`
- **Date:** 2026-10-15
- **Server:** `data-plane-fra1-1` (Frankfurt)
- **OS & Kernel:** Ubuntu 24.04 LTS (`Linux 6.8.0-45-generic x86_64`)
- **Configuration:** `overlayroot="tmpfs"`, swap disabled, `systemd-journald` set to `Storage=volatile`

---

## 1. Locations Checked

1. **Root filesystem (`/`):** Checked that `/` is mounted as an `overlay` in RAM (`tmpfs`), and the base disk (`/dev/vda1`) is mounted read-only at `/media/root-ro`.
2. **Swap (`swapon --show`):** Checked that no swap file or swap partition is active.
3. **Test files (`/root/proof.txt` and `/var/log/proof.txt`):** Created files in directories that normally sit on persistent disk (avoiding `/tmp`, which is already a RAM disk by default on Linux).

---

## 2. Commands and Output

### Before Reboot
```bash
root@data-plane-fra1-1:~# df -T / /media/root-ro
Filesystem     Type     1K-blocks    Used Available Use% Mounted on
overlayroot    overlay    1983056   48120   1934936   3% /
/dev/vda1      ext4      25124800 2418200  22690216  10% /media/root-ro

root@data-plane-fra1-1:~# swapon --show
# (empty - no swap active)

root@data-plane-fra1-1:~# echo "reboot-test-123" > /root/proof.txt
root@data-plane-fra1-1:~# echo "reboot-test-123" > /var/log/proof.txt

root@data-plane-fra1-1:~# ls -l /root/proof.txt /var/log/proof.txt
-rw-r--r-- 1 root root 16 Oct 15 09:28 /root/proof.txt
-rw-r--r-- 1 root root 16 Oct 15 09:28 /var/log/proof.txt

root@data-plane-fra1-1:~# reboot
```

### After Reboot
```bash
root@data-plane-fra1-1:~# uptime
 09:30:15 up 0 min,  1 user,  load average: 0.08, 0.02, 0.01

root@data-plane-fra1-1:~# ls -l /root/proof.txt /var/log/proof.txt
ls: cannot access '/root/proof.txt': No such file or directory
ls: cannot access '/var/log/proof.txt': No such file or directory
```

---

## 3. What This Test Proves (and What It Doesn't)

**What it proves:**
- The root filesystem runs on a volatile `tmpfs` RAM overlay while the underlying disk is mounted read-only.
- Any runtime files, logs, or WireGuard keys written during operation live in RAM and are wiped on reboot.
- Swap is disabled, preventing memory pages from being written to disk.

**What it does not prove:**
- This test only covers the VPN data-plane server (`data-plane-fra1-1`), not the separate account/billing backend.
- Because the server runs on a cloud droplet, the cloud provider's underlying hypervisor still controls the physical host hardware.

---

## 4. Script Checksums (SHA-256)

```text
46d3229cd86b7c6d8ed479920f26fa78806ee80be8508f38c4ae13551774ddb3  deploy/droplet-overlayroot/setup.sh
83588f0dec16f2f0969877b1eb3c0d4e24c834698e73f075f5e8e5a1876b68b2  deploy/scripts/verify-ram-disk.sh
```
