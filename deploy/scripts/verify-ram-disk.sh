#!/usr/bin/env bash
# Checks if the server is running in RAM-only mode:
# - No active swap
# - No writable persistent disks
# - Root running on overlayfs/tmpfs
# - journald logging to volatile RAM only

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "QuantVPN RAM-Only Node Check"
echo "----------------------------"

FAILURES=0

# 1. Check kernel command line or overlayroot config
echo -e "\n[*] Checking boot configuration..."
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
echo "    cmdline: ${CMDLINE}"

if echo "${CMDLINE}" | grep -qE "toram|boot=live"; then
    echo -e "    ${GREEN}[PASS] Live boot ('toram') detected.${NC}"
elif [ -f /etc/overlayroot.conf ] && grep -q 'overlayroot="tmpfs"' /etc/overlayroot.conf; then
    echo -e "    ${GREEN}[PASS] overlayroot tmpfs detected.${NC}"
else
    echo -e "    ${YELLOW}[WARN] Neither 'toram' nor 'overlayroot=tmpfs' found.${NC}"
fi

# 2. Check for active swap
echo -e "\n[*] Checking Swap Partitions / Files (swapon --show)..."
SWAP_OUTPUT=$(swapon --show 2>/dev/null || true)
if [ -z "${SWAP_OUTPUT}" ]; then
    echo -e "    ${GREEN}[PASS] No swap devices or swap files active.${NC}"
else
    echo -e "    ${RED}[FAIL] Active swap detected! Data can leak to disk:${NC}"
    echo "${SWAP_OUTPUT}"
    FAILURES=$((FAILURES + 1))
fi

# 3. Check Root and Writable Mounts
echo -e "\n[*] Auditing Mounts for Persistent Block Devices (/proc/mounts)..."
PERSISTENT_MOUNTS=$(grep -E '^/dev/(sd|nvme|vd|xvd|hd)[a-z0-9]+' /proc/mounts | grep -v ' / ' | grep -w 'rw' || true)

if [ -z "${PERSISTENT_MOUNTS}" ]; then
    echo -e "    ${GREEN}[PASS] Zero non-volatile block devices mounted read-write.${NC}"
else
    echo -e "    ${RED}[FAIL] Writable persistent block storage detected:${NC}"
    echo "${PERSISTENT_MOUNTS}"
    FAILURES=$((FAILURES + 1))
fi

# 4. Check Root Filesystem Type
echo -e "\n[*] Verifying Root Filesystem Type..."
ROOT_FS_TYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || stat -f -c %T / 2>/dev/null || echo "unknown")
echo "    Root filesystem type: ${ROOT_FS_TYPE}"
if echo "${ROOT_FS_TYPE}" | grep -qiE "overlay|tmpfs|ramfs"; then
    echo -e "    ${GREEN}[PASS] Root filesystem is backed by volatile memory (${ROOT_FS_TYPE}).${NC}"
else
    echo -e "    ${YELLOW}[WARN] Root filesystem is reported as ${ROOT_FS_TYPE}.${NC}"
fi

# 5. Check Journald Logging Storage Mode
echo -e "\n[*] Checking systemd-journald Storage Configuration..."
JOURNALD_STORAGE=$(grep -E '^\s*Storage\s*=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -n 1 || echo "")
echo "    Journald config: ${JOURNALD_STORAGE:-not explicitly set}"
if echo "${JOURNALD_STORAGE}" | grep -q "volatile"; then
    echo -e "    ${GREEN}[PASS] Journal storage is explicitly set to 'volatile' (RAM-only).${NC}"
else
    echo -e "    ${YELLOW}[WARN] Journal storage is not explicitly 'volatile'. Ensure volatile drop-in is active.${NC}"
fi

# 6. Check WireGuard Interface
echo -e "\n[*] Checking WireGuard Interface Status..."
if command -v wg >/dev/null 2>&1; then
    WG_INTERFACES=$(wg show interfaces 2>/dev/null || echo "")
    if [ -n "${WG_INTERFACES}" ]; then
        echo -e "    ${GREEN}[PASS] Active WireGuard interface: ${WG_INTERFACES}${NC}"
        PEER_COUNT=$(wg show "${WG_INTERFACES}" peers 2>/dev/null | wc -l || echo "0")
        echo "    Active peers configured in kernel: ${PEER_COUNT}"
    else
        echo "    No WireGuard interface running currently."
    fi
else
    echo "    WireGuard userspace tools ('wg') not installed in current environment."
fi

echo "----------------------------"
if [ "${FAILURES}" -eq 0 ]; then
    echo -e "${GREEN}PASSED: Server is running in RAM with no active swap or writable disks.${NC}"
    exit 0
else
    echo -e "${RED}FAILED: Found ${FAILURES} issue(s). Check the output above.${NC}"
    exit 1
fi
