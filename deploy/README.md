# QuantVPN Deployment & Logging Configuration

This directory contains deployment scripts and audit tools showing how QuantVPN runs its VPN servers in RAM without writing logs to disk.

---

## 1. Architecture Overview

We separate our VPN data-plane servers (which handle user traffic in RAM) from our account/billing backend:

1. **Data Plane (VPN Servers, e.g. `data-plane-fra1-1`):**
   - Configured with `overlayroot="tmpfs"` so the base disk is mounted read-only (`/media/root-ro`) and `/` runs in volatile RAM (`tmpfs`).
   - Swap is disabled and `/swapfile` is removed.
   - `systemd-journald` is set to `Storage=volatile` (logs stay in RAM only, capped at 64MB).
   - Rebooting wipes all runtime files, logs, and WireGuard keys from RAM.

2. **Control Plane (Account & Billing Backend):**
   - Separate server handling user accounts, subscriptions, and authentication.
   - Never receives browsing history, DNS queries, or traffic logs from the data-plane servers.

---

## 2. Directory Contents

- **[`droplet-overlayroot/`](droplet-overlayroot/)**: Setup guide and automated script (`setup.sh`) to configure Ubuntu/Debian servers in RAM-only overlay mode (`overlayroot="tmpfs"`).
- **[`scripts/verify-ram-disk.sh`](scripts/verify-ram-disk.sh)**: Audit script that checks mounts, swap status, and journald config to verify RAM-only operation.
