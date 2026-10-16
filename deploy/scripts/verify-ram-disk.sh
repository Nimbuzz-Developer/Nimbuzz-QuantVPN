#!/usr/bin/env bash
# Checks if the server is running in RAM-only mode:
# - No active swap partitions or files
# - No writable persistent disks (sd, nvme, vd, mapper, md, dm, nbd, etc.)
# - Root filesystem running on overlayfs, tmpfs, or ramfs
# - systemd-journald logging to volatile RAM only
#
# Returns 0 if all checks pass, or 1 if any failure is detected.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "QuantVPN RAM-Only Node Verification"
echo "-----------------------------------"

FAILURES=0

# 1. Check Boot Configuration
echo -e "\n[*] Checking boot configuration..."
CMDLINE=$(cat /proc/cmdline 2>/dev/null || echo "")
echo "    cmdline: ${CMDLINE:-none}"

if echo "${CMDLINE}" | grep -qE "toram|boot=live"; then
    echo -e "    ${GREEN}[PASS] Live boot ('toram') detected.${NC}"
elif [ -f /etc/overlayroot.conf ] && grep -q 'overlayroot="tmpfs"' /etc/overlayroot.conf 2>/dev/null; then
    echo -e "    ${GREEN}[PASS] overlayroot tmpfs configured in /etc/overlayroot.conf.${NC}"
else
    echo -e "    ${RED}[FAIL] Neither 'toram' kernel parameter nor overlayroot=\"tmpfs\" found.${NC}"
    FAILURES=$((FAILURES + 1))
fi

# 2. Check for Active Swap
echo -e "\n[*] Checking swap status..."
SWAP_OUTPUT=$(swapon --show 2>/dev/null || cat /proc/swaps 2>/dev/null | tail -n +2 || true)
if [ -z "${SWAP_OUTPUT}" ]; then
    echo -e "    ${GREEN}[PASS] No swap devices or swap files active.${NC}"
else
    echo -e "    ${RED}[FAIL] Active swap detected! Sensitive data could leak to disk:${NC}"
    echo "${SWAP_OUTPUT}"
    FAILURES=$((FAILURES + 1))
fi

# 3. Comprehensive Mount Audit (Persistent Block Devices and Writable Filesystems)
echo -e "\n[*] Auditing mounts for persistent block devices and writable storage..."
PERSISTENT_ISSUES=()

if [ -f /proc/mounts ]; then
    while read -r src target fstype opts rest; do
        # Only inspect read-write mounts
        if [[ ",${opts}," != *",rw,"* ]]; then
            continue
        fi

        # Whitelist of approved volatile and virtual kernel filesystems
        case "${fstype}" in
            tmpfs|ramfs|overlay|proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|pstore|bpf|mqueue|hugetlbfs|debugfs|tracefs|securityfs|fusectl|configfs|autofs|binfmt_misc|nsfs|efivarfs|none)
                # Volatile or in-memory virtual filesystem
                ;;
            *)
                PERSISTENT_ISSUES+=("Non-volatile filesystem mounted rw: ${src} on ${target} (${fstype}, ${opts})")
                ;;
        esac

        # Comprehensive check across all persistent block device paths:
        # Detects /dev/sd*, /dev/nvme*, /dev/vd*, /dev/xvd*, /dev/hd*,
        # device-mapper (/dev/mapper/*, /dev/dm-*), software RAID (/dev/md*),
        # network block devices (/dev/nbd*), loop devices (/dev/loop*), and eMMC (/dev/mmcblk*)
        case "${src}" in
            /dev/sd*|/dev/nvme*|/dev/vd*|/dev/xvd*|/dev/hd*|/dev/mapper/*|/dev/md*|/dev/dm-*|/dev/nbd*|/dev/loop*|/dev/mmcblk*)
                PERSISTENT_ISSUES+=("Persistent block device mounted rw: ${src} on ${target} (${fstype})")
                ;;
        esac
    done < /proc/mounts
fi

if [ ${#PERSISTENT_ISSUES[@]} -eq 0 ]; then
    echo -e "    ${GREEN}[PASS] Zero writable persistent block devices or disks mounted.${NC}"
else
    echo -e "    ${RED}[FAIL] Writable persistent storage detected:${NC}"
    for issue in "${PERSISTENT_ISSUES[@]}"; do
        echo -e "      ${RED}* ${issue}${NC}"
    done
    FAILURES=$((FAILURES + 1))
fi

# 4. Check Root Filesystem Type
echo -e "\n[*] Verifying root filesystem type..."
ROOT_FS_TYPE="unknown"
if command -v findmnt >/dev/null 2>&1; then
    ROOT_FS_TYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || echo "unknown")
fi
if [ "${ROOT_FS_TYPE}" = "unknown" ] && [ -f /proc/mounts ]; then
    ROOT_FS_TYPE=$(awk '$2=="/" {print $3}' /proc/mounts | head -n 1 || echo "unknown")
fi
if [ "${ROOT_FS_TYPE}" = "unknown" ]; then
    ROOT_FS_TYPE=$(stat -f -c %T / 2>/dev/null || echo "unknown")
fi

echo "    Root filesystem type: ${ROOT_FS_TYPE}"
if echo "${ROOT_FS_TYPE}" | grep -qiE "^(overlay|tmpfs|ramfs)$"; then
    echo -e "    ${GREEN}[PASS] Root filesystem is volatile memory (${ROOT_FS_TYPE}).${NC}"
else
    echo -e "    ${RED}[FAIL] Root filesystem is '${ROOT_FS_TYPE}', expected 'overlay', 'tmpfs', or 'ramfs'.${NC}"
    FAILURES=$((FAILURES + 1))
fi

# 5. Check Journald Logging Storage Mode
echo -e "\n[*] Checking systemd-journald storage mode..."
JOURNALD_STORAGE=$(grep -E '^\s*Storage\s*=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -n 1 || echo "")
echo "    Journald config: ${JOURNALD_STORAGE:-not explicitly set}"

# Check both configuration file and runtime journal directory
RUNTIME_DIR_VOLATILE=true
if [ -d /var/log/journal ] && [ ! -L /var/log/journal ]; then
    # If /var/log/journal exists as a real directory on disk, journald can flush logs to disk
    if [ -f /proc/mounts ]; then
        VAR_LOG_FS=$(findmnt -n -o FSTYPE /var/log/journal 2>/dev/null || awk '$2=="/var/log/journal" {print $3}' /proc/mounts || echo "")
        if [ -n "${VAR_LOG_FS}" ] && ! echo "${VAR_LOG_FS}" | grep -qiE "^(tmpfs|ramfs|overlay)$"; then
            RUNTIME_DIR_VOLATILE=false
        fi
    fi
fi

if echo "${JOURNALD_STORAGE}" | grep -q "volatile" && [ "${RUNTIME_DIR_VOLATILE}" = true ]; then
    echo -e "    ${GREEN}[PASS] Journal storage is volatile (in-memory only, no disk writes).${NC}"
else
    echo -e "    ${RED}[FAIL] Journal storage is not strictly volatile. Logs may be written to disk.${NC}"
    FAILURES=$((FAILURES + 1))
fi

# 6. Check WireGuard Interface
echo -e "\n[*] Checking WireGuard interface status..."
if command -v wg >/dev/null 2>&1; then
    WG_INTERFACES=$(wg show interfaces 2>/dev/null || echo "")
    if [ -n "${WG_INTERFACES}" ]; then
        echo -e "    ${GREEN}[PASS] Active WireGuard interface: ${WG_INTERFACES}${NC}"
        PEER_COUNT=$(wg show "${WG_INTERFACES}" peers 2>/dev/null | wc -l || echo "0")
        echo "    Active peers configured in kernel: ${PEER_COUNT}"
    else
        echo "    No active WireGuard interface running currently."
    fi
else
    echo "    WireGuard userspace tools ('wg') not installed in current environment."
fi

# Final Verification Result
echo "-----------------------------------"
if [ "${FAILURES}" -eq 0 ]; then
    echo -e "${GREEN}PASSED: Server is confirmed running in RAM-only mode with zero persistent disk writes or swap.${NC}"
    exit 0
else
    echo -e "${RED}FAILED: Found ${FAILURES} verification failure(s). Server is NOT guaranteed RAM-only.${NC}"
    exit 1
fi
