# Nimbuzz QuantVPN — Post-Quantum WireGuard Core

[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--1024-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Jurisdiction: Nepal](https://img.shields.io/badge/Jurisdiction-Nepal%20(Outside%2014%20Eyes)-green.svg)](TRANSPARENCY.md)

> Open-source post-quantum cryptographic core and WireGuard key exchange for QuantVPN.  
>  
> This repository contains the Go implementation of our hybrid ML-KEM-1024 + WireGuard PSK mechanism, automated test suite, and RAM-only server deployment blueprints. Client applications and commercial backend infrastructure remain closed source.

---

## 1. Why Nepal (Jurisdiction)

QuantVPN is based and legally registered in Nepal (Kuraakani Online Pvt. Ltd., Lalitpur). Nepal provides strong legal and privacy protections:

| Jurisdiction | 14 Eyes Alliance? | Mandatory Telecom Data Retention? | Notes |
|:---|:---:|:---:|:---|
| **Nepal** | **No** (Outside) | **No** (No mandatory VPN data retention) | Independent legal jurisdiction outside multilateral surveillance treaties |
| **Switzerland** | **No** (Outside) | **Yes** (BÜPF requires 6-month retention) | Telecom data retention enforced; fast-track MLAT with US/EU |
| **India** | **No** (Outside) | **Yes** (CERT-In requires 5-year log storage) | Mandatory collection of customer names, IPs, and connection records |

- **Outside 14 Eyes:** Nepal is not part of the 5 Eyes, 9 Eyes, or 14 Eyes intelligence alliances (USA, UK, Canada, Australia, NZ, Denmark, France, Netherlands, Norway, Germany, Belgium, Italy, Sweden, Spain).
- **No Mandatory Logging Laws:** Nepali law does not require VPN providers to log user traffic, connection timestamps, or browsing activity.

---

## 2. Post-Quantum Cryptography: ML-KEM-1024 + X25519

Standard WireGuard uses Curve25519 (X25519) for key exchange. This is secure against classical computers today, but an adversary recording encrypted traffic now could decrypt it later if large-scale quantum computers become reality ("harvest now, decrypt later").

QuantVPN adds **NIST FIPS 203 ML-KEM-1024** (formerly Kyber-1024) to WireGuard. Instead of modifying WireGuard's core protocol, we generate a 256-bit post-quantum key and pass it into WireGuard's native pre-shared key (PSK) slot.

```
                      +---------------------------------------+
                      |     Client ML-KEM-1024 Keypair        |
                      |        (ek_client, dk_client)         |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |   Server Generates 256-bit PSK        |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |   ML-KEM-1024 Encapsulation           |
                      |   (shared secret + ciphertext)        |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |   HKDF-SHA256 Key Derivation          |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |   ChaCha20-Poly1305 AEAD Seal         |
                      |   Payload: PSK | AAD: Version+CT+Ctx  |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |   WireGuard Kernel Injection          |
                      |   Noise_IKpsk2 mixKey(PSK) Handshake  |
                      +---------------------------------------+
```

### Why We Built It This Way

- **Hybrid security:** WireGuard's native X25519 key exchange still runs. An attacker would have to break both X25519 and ML-KEM-1024 to read traffic.
- **Standard WireGuard packets:** Post-quantum keys and ciphertexts (1,568 bytes) are too large to fit in WireGuard's initial UDP handshake packet without packet fragmentation. Exchanging the key out-of-band and injecting it as a PSK keeps WireGuard's standard UDP wire format, 1420 MTU, and kernel performance untouched.
- **Pure Go:** Uses Go's standard library `crypto/mlkem` package (standardized in NIST FIPS 203) and `golang.org/x/crypto/chacha20poly1305`. No C wrappers or foreign dependencies.
- **Authenticated envelope & identity binding:** The client signs its ephemeral ML-KEM public key with its long-term Ed25519 identity key. The 1,629-byte envelope binds the client ID, server ID, session nonce, version, and KEM ciphertext into ChaCha20-Poly1305 as Additional Authenticated Data (AAD), preventing key substitution and replay attacks before decryption.

---

## 3. Repository Structure

```
.
├── crypto/                          # Post-quantum cryptographic engine
│   ├── crypto.go                    # ML-KEM-1024, HKDF-SHA256, & ChaCha20-Poly1305
│   └── crypto_test.go               # Round-trip, KAT, bit-tampering, & concurrency tests
├── deploy/                          # Server deployment and verification scripts
│   ├── README.md                    # Architecture notes and guide
│   ├── droplet-overlayroot/         # Cloud droplet / VPS volatile tmpfs overlay setup
│   │   ├── README.md                # overlayroot guide and reboot testing instructions
│   │   └── setup.sh                 # Droplet setup script
│   └── scripts/
│       └── verify-ram-disk.sh       # Audit script to check for zero-disk / RAM status
├── docs/                            # Design specs and test documentation
│   ├── CRYPTO_DESIGN.md             # Cryptographic design document
│   ├── TESTING.md                   # Test suite and reproduction guide
│   └── reports/                     # Reboot test audit reports
│       ├── REBOOT_VERIFICATION_REPORT_2026-10-15.md   # Markdown reboot report
│       └── REBOOT_VERIFICATION_REPORT_2026-10-15.json # JSON reboot report
├── wireguard-kernel/                # [Submodule] WireGuard Linux kernel module
├── wg0-client.conf                  # Sample client WireGuard config
├── wg0-server.conf                  # Sample server WireGuard config
├── main.go                          # CLI demo and benchmark tool
├── go.mod                           # Go module definition (Go 1.24+)
├── go.sum                           # Dependency checksums
├── .gitmodules                      # Git submodule configuration
├── TRANSPARENCY.md                  # Transparency center and warrant canary
└── LICENSE                          # MIT License
```

---

## 4. Quick Start & Testing

### 4.1 Requirements
- Go 1.24 or later (built and tested with Go 1.26).

### 4.2 Run the CLI Demo
```bash
# Clone the repo with submodules
git clone --recursive https://github.com/Nimbuzz-Developer/Nimbuzz-QuantVPN.git
cd Nimbuzz-QuantVPN

# Run the key exchange demo
go run main.go

# Run the built-in benchmark (~9,000+ operations/second)
go run main.go -bench
```

### 4.3 Run the Automated Test Suite
```bash
# Run unit tests and bit-flip tamper checks
go test -v ./...

# Run race condition checks
go test -race -v ./crypto

# Run crypto package benchmarks
go test -bench=. ./crypto
```
See [`docs/TESTING.md`](docs/TESTING.md) for details on each test case.

---

## 5. Stateless RAM-Only Servers & Reboot Verification

QuantVPN data-plane servers (`deploy/droplet-overlayroot/`) run in RAM without saving session data or logs to disk:

- Configured using `overlayroot="tmpfs"` on Ubuntu/Debian.
- The base disk is mounted **read-only (`ro`)**.
- All runtime file changes, logs, and WireGuard session keys live in RAM (`tmpfs`).
- Swap is disabled (`swapoff -a && rm -f /swapfile`) so memory pages are never written to disk.

### Testing the Reboot Wipe

Don't test by writing to `/tmp` — on most Linux systems, `/tmp` is already a tmpfs in RAM by default. Instead, write a test file in `/root/` or `/var/log/`, reboot, and verify it disappeared:

```bash
# 1. Connect and create a test file:
ssh root@data-plane-fra1-1
touch /root/proof.txt
ls -l /root/proof.txt      # file exists in RAM overlay

# 2. Reboot the server:
reboot

# 3. Reconnect and check:
ssh root@data-plane-fra1-1
ls -l /root/proof.txt      # output: No such file or directory (wiped)
```

### Tools and Reports
- **Setup Script:** [`deploy/droplet-overlayroot/setup.sh`](deploy/droplet-overlayroot/setup.sh)
- **Node Audit Script:** `sudo ./deploy/scripts/verify-ram-disk.sh`
- **Reboot Test Report:** [Read Report (TEST-RAM-20261015-FRA1)](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.md) | [Download JSON](docs/reports/REBOOT_VERIFICATION_REPORT_2026-10-15.json)

---

## 6. Transparency Center & Warrant Canary

For complete details on our data handling, infrastructure isolation, and legal request logs, see our [Transparency Center](TRANSPARENCY.md).

### Warrant Canary Statement
**As of October 15, 2026:**
- **Zero** national security letters, gag orders, or FISA warrants received.
- **Zero** search warrants or physical hardware seizures.
- **Zero** backdoors installed in software or hardware.

**Next Scheduled Update:** November 15, 2026  
**Signing Key:** `0x9B44F8C127A9B6DE`

---

## 7. License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
