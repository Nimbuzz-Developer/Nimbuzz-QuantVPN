# QuantVPN Transparency Center
### Infrastructure, Data Handling, and Reproducible Verification
**Last Updated:** 2026-10-15  
**Jurisdiction:** Nepal (28°N 84°E Himalayas — Outside 14 Eyes, No Mandatory Data Retention)  
**Public Repository:** [github.com/Nimbuzz-Developer/Nimbuzz-QuantVPN](https://github.com/Nimbuzz-Developer/Nimbuzz-QuantVPN)

---

## 1. RAM-Only Infrastructure

QuantVPN runs its data-plane servers using an in-memory `tmpfs` overlay (`overlayroot="tmpfs"`) so session data and logs are never written to disk.

```
+--------------------------------------------------------------------------------------------------+
|                                  STATELESS RAM-ONLY GATEWAY NODE                                 |
+--------------------------------------------------------------------------------------------------+
  [ Base Disk (/dev/vda1) ] ---> Mounted strictly Read-Only at /media/root-ro
                                         |
                                         v
   +--------------------------------------------------------------------------------------------+
   |  VOLATILE SYSTEM MEMORY (tmpfs Overlay Filesystem)                                         |
   |  • Root Filesystem (/): `overlayroot` on `tmpfs` (RAM)                                     |
   |  • Config: `/etc/overlayroot.conf` -> `overlayroot="tmpfs"`                                |
   |  • /var/log: `systemd-journald` with `Storage=volatile` (RAM-only, capped at 64MB)         |
   |  • Swap: Disabled (`swapoff -a`, `/swapfile` removed)                                      |
   +--------------------------------------------------------------------------------------------+
                                         |
                             [ POWER LOSS / REBOOT ]
                                         |
                                         v
   +--------------------------------------------------------------------------------------------+
   |  RAM IS WIPED: All temporary session keys, caches, and in-memory logs are erased           |
   +--------------------------------------------------------------------------------------------+
```

### 1.1 Storage Configuration & Boot Process
- **Overlay Setup:** Configured via [`deploy/droplet-overlayroot/setup.sh`](deploy/droplet-overlayroot/setup.sh) using Ubuntu's `overlayroot` package (`overlayroot="tmpfs"`).
- **Read-Only Disk:** The base disk partition is mounted read-only (`ro`), while all runtime writes go to `tmpfs` in RAM.
- **Volatile Logs:** `systemd-journald` is set to `Storage=volatile` so logs stay in memory and are cleared on reboot.
- **Swap Disabled:** Swap is completely disabled and removed so memory pages cannot be written to disk.

### 1.2 Reboot Test Results
- **Test ID:** [`TEST-RAM-20261015-FRA1`](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.md)
- **Date:** 2026-10-15
- **Server:** `data-plane-fra1-1` (Frankfurt, Ubuntu 24.04 LTS)
- **Test Findings:** Test files created in `/root/proof.txt` and `/var/log/proof.txt` before reboot were completely gone after reboot.
- **Full Report:** Download in [Markdown](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.md) or [JSON](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.json).

---

## 2. No-Logs Policy and Verification

### 2.1 Exact Records We DO NOT Collect or Retain
We strictly differentiate between VPN browsing traffic (data plane) and account administration (control plane).

| Data Category | Retention Status | Technical Enforcement |
|:---|:---|:---|
| **Browsing History & Visited URLs** | **NEVER COLLECTED** | Not recorded by WireGuard data plane; no logging daemons |
| **Traffic Destination IPs & Ports** | **NEVER COLLECTED** | WireGuard kernel forwards packets in RAM; zero packet capture |
| **DNS Query Records** | **NEVER COLLECTED** | In-memory Unbound/CoreDNS daemon configured with zero query logging |
| **User Real Origin IP Addresses** | **NEVER STORED** | Origin IPs exist in WireGuard kernel RAM tables only while connected |
| **VPN Connection Timestamps** | **NEVER LOGGED** | No session start/stop event logging enabled on gateway nodes |
| **Bandwidth Byte Aggregates** | **Ephemeral Total Only** | Aggregated byte counters (Rx/Tx) synced to control plane for quota |

### 2.2 How the System Architecture Enforces No-Logs
1. **Volatile Journald:** `/etc/systemd/journald.conf` sets `Storage=volatile`, discarding system event logs on power down and strictly limiting in-memory logs to a 64MB rolling FIFO ring buffer.
2. **Infrastructure Decoupling:** The Data Plane (VPN gateways) has zero database access. Even if an attacker or state authority gains physical possession of a VPN gateway, the node contains only ephemeral WireGuard kernel tables in RAM and has no database credentials or subscriber logs.
3. **Reproducible Verification Script:** We publish our audit script [`deploy/scripts/verify-ram-disk.sh`](deploy/scripts/verify-ram-disk.sh) so anyone can independently audit any running node.

---

## 3. Post-Quantum Security

QuantVPN is engineered to withstand "Store Now, Decrypt Later" (SNDL) attacks by quantum adversaries wielding Cryptographically Relevant Quantum Computers (CRQCs).

```
+--------------------------------------------------------------------------------------------------+
|                               POST-QUANTUM HYBRID SECURITY MODEL                                 |
+--------------------------------------------------------------------------------------------------+

  NIST FIPS 203 ML-KEM-1024                       CLASSICAL RFC 7748 X25519
  (Lattice-based Module-LWE)                      (Elliptic Curve Diffie-Hellman)
             |                                                |
             +-----------------------+------------------------+
                                     |
                                     v
                       [ HYBRID KEY DERIVATION ]
                       HKDF-SHA256 (RFC 5869) + ChaCha20-Poly1305 AEAD (RFC 8439)
                                     |
                                     v
                       [ 256-BIT QUANTUM-RESISTANT PSK ]
                       Injected dynamically into WireGuard Noise_IKpsk2 Handshake
```

### 3.1 Cryptographic Design & Standards
- **Standardized Algorithm:** NIST FIPS 203 Module Lattice Key Encapsulation Mechanism (**ML-KEM-1024**), offering Category 5 post-quantum security (equivalent to AES-256).
- **Hybrid Construction:** Combines standard WireGuard Curve25519 ECDH (RFC 7748) with ML-KEM-1024. If either mathematical problem remains secure, the entire tunnel remains uncompromised.
- **AEAD Envelope Protection:** WireGuard pre-shared keys are encapsulated using HKDF-SHA256 and authenticated with ChaCha20-Poly1305 AEAD, authenticating the entire 1568-byte KEM ciphertext as Additional Authenticated Data (AAD) to prevent chosen-ciphertext tampering.
- **Reference Document:** Read the comprehensive [Cryptographic Design Specification](docs/CRYPTO_DESIGN.md).

### 3.2 Supported Protocols & Feature Breakdown
| Protocol | Post-Quantum Protection | Encryption Cipher | Intended Use Case |
|:---|:---|:---|:---|
| **WireGuard (Default)** | **YES (ML-KEM-1024 + X25519)** | ChaCha20-Poly1305 + Noise PSK | Primary protocol: high speed, ultra-low latency, post-quantum |
| **OpenVPN (Fallback)** | Classical Only | AES-256-GCM / TLS 1.3 | Fallback for restrictive firewalls (UDP / TCP 443) |

### 3.3 Implementation Status & Open-Source Scope
- **Core Library:** Pure Go implementation utilizing the Go standard library `crypto/mlkem` (NIST FIPS 203) and `golang.org/x/crypto/chacha20poly1305`.
- **Public Audit Repository:** [github.com/Nimbuzz-Developer/Nimbuzz-QuantVPN/crypto](crypto/crypto.go)
- **Open-Source Scope:** Auditable post-quantum cryptographic primitives, WireGuard key injection mechanism, and infrastructure verification blueprints. (Client applications and commercial backend infrastructure are proprietary).
- **Automated Tests:** Complete test suite covering round-trips, bit-tampering, KATs, and concurrency in [crypto/crypto_test.go](crypto/crypto_test.go).

---

## 4. Transparency Reports & Warrant Canary

### 4.1 Warrant Canary
**Canary Statement:**  
As of **October 15, 2026**, QuantVPN and Kuraakani Online Pvt. Ltd.:
1. Have **NOT** received any national security letters, FISA orders, or secret surveillance court orders.
2. Have **NOT** been subjected to any search warrants or equipment seizures by any government entity.
3. Have **NOT** installed any backdoors, interception hardware, or monitoring software in our infrastructure.
4. Have **NOT** altered our no-logs architecture or compromised our encryption keys.

- **Status:** Active & Verified
- **Next Scheduled Update:** November 15, 2026
- **Signed By:** QuantVPN Infrastructure Team

### 4.2 Legal Requests & Disclosure Log
Under the laws of Nepal, VPN providers are not subject to mandatory data retention directives (unlike India's CERT-In 5-year mandate or Switzerland's BÜPF 6-month telecom retention). Because our gateway nodes operate without persistent disks, we have no historical browsing records to disclose.

| Reporting Period | Subpoenas / Court Orders | Law Enforcement Inquiries | Accounts Affected | Data Disclosed |
|:---|:---:|:---:|:---:|:---|
| **2026 Q1 - Q3** | 0 | 0 | 0 | None (No logs retained) |
| **2025 Q1 - Q4** | 0 | 0 | 0 | None (No logs retained) |

### 4.3 Reporting Limitations & Scope
This Transparency Center applies to the VPN infrastructure operated by QuantVPN. Third-party payment gateways (e.g., Visa/Mastercard processors, WeChat Pay, Nimbuzz Pay) operate independently and retain billing records in accordance with their own financial regulatory requirements. QuantVPN does not have access to credit card PANs or banking credentials.

---

## 5. Verification Tools & Resources

- [Cryptographic Design Document (`docs/CRYPTO_DESIGN.md`)](docs/CRYPTO_DESIGN.md)
- [Automated Testing & Benchmark Guide (`docs/TESTING.md`)](docs/TESTING.md)
- [RAM-Only Verification Script (`deploy/scripts/verify-ram-disk.sh`)](deploy/scripts/verify-ram-disk.sh)
- [Reboot Verification Audit Report (`docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.md`)](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.md)
