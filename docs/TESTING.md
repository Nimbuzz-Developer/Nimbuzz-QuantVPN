# QuantVPN Automated Testing & Verification Guide
**Status:** CI/CD Automated Test Suite  
**Package:** `nimbuzz.com/mlkem-psk/crypto`

This document details the automated cryptographic test suite for QuantVPN, describing how each security requirement is validated and providing exact instructions to reproduce test results.

---

## 1. Test Suite Overview

The automated test suite (`crypto/crypto_test.go`) covers cryptographic correctness, IND-CCA2 security invariants, malformed input rejection, known-answer tests (KAT), and concurrency.

| Test Case | Objective | Security Property Tested |
|:---|:---|:---|
| `TestRoundTrip` | 50 iterations of keygen, encapsulation, decapsulation, and recovery | Functional completeness & correctness |
| `TestInvalidCiphertext` | Bit-flips across multiple offsets of the 1,568-byte ML-KEM ciphertext | IND-CCA2 resistance & tamper detection |
| `TestTamperedAEADCiphertext` | Bit-flips across ChaCha20 payload and Poly1305 MAC tag | Authenticated encryption integrity (RFC 8439) |
| `TestTamperedNonce` | Bit-flips across all 12 bytes of the ChaCha20 nonce | AEAD replay and nonce integrity |
| `TestTamperedVersion` | Modification of format version byte (0x02, 0xFF) | Format version negotiation & isolation |
| `TestMalformedBlobSizes` | Envelopes of sizes {0, 1, 16, 500, 1568, 1628, 1630, 2048, 65536} bytes | Size validation and truncation checks |
| `TestInvalidPublicKey` | Public keys of 32 bytes (X25519), 1184 bytes (ML-KEM-768), and nil | Input type and length validation |
| `TestKnownAnswerTest_HKDF` | Deterministic HKDF-SHA256 test with fixed vector and label | Key derivation test vector check |
| `TestKnownAnswerTest_ChaCha20Poly1305` | Deterministic AEAD seal/open with fixed key, nonce, and AAD | AEAD test vector check |
| `TestZeroization` | Scrubbing sensitive memory buffers with `Zeroize()` | Sensitive buffer cleanup in RAM |
| `TestConcurrency` | 20 parallel worker goroutines running 50 iterations each | Thread safety under concurrent load |
| `BenchmarkGenerateEncryptedPSK` | Throughput of server-side PSK encapsulation | Server encapsulation throughput |
| `BenchmarkDecryptPSK` | Throughput of client-side PSK recovery | Client decapsulation throughput |
| `BenchmarkRoundTrip` | Total end-to-end handshake setup latency | End-to-end key exchange speed |

---

## 2. Reproducing Test Results

### 2.1 Prerequisites
- **Go Compiler:** Go 1.24 or later (built with Go 1.26.0 recommended, which includes standard library `crypto/mlkem` implementing NIST FIPS 203).
- **Operating System:** Linux (x86_64, aarch64), macOS (Apple Silicon / Intel), or Windows.

### 2.2 Running All Unit & Cryptographic Tests
Execute from the repository root:

```bash
# Run all unit tests with verbose logging
go test -v ./...
```

**Expected Output:**
```
=== RUN   TestRoundTrip
--- PASS: TestRoundTrip (0.02s)
=== RUN   TestInvalidCiphertext
--- PASS: TestInvalidCiphertext (0.00s)
=== RUN   TestTamperedAEADCiphertext
--- PASS: TestTamperedAEADCiphertext (0.00s)
=== RUN   TestTamperedNonce
--- PASS: TestTamperedNonce (0.00s)
=== RUN   TestTamperedVersion
--- PASS: TestTamperedVersion (0.00s)
=== RUN   TestMalformedBlobSizes
--- PASS: TestMalformedBlobSizes (0.00s)
=== RUN   TestInvalidPublicKey
--- PASS: TestInvalidPublicKey (0.00s)
=== RUN   TestKnownAnswerTest_HKDF
    crypto_test.go:222: KAT HKDF Derived Key Vector: a4f213d02594319d72173c58fce12bb7ce0204a48f3f0a476ca42bd624289133
--- PASS: TestKnownAnswerTest_HKDF (0.00s)
=== RUN   TestKnownAnswerTest_ChaCha20Poly1305
--- PASS: TestKnownAnswerTest_ChaCha20Poly1305 (0.00s)
=== RUN   TestZeroization
--- PASS: TestZeroization (0.00s)
=== RUN   TestConcurrency
--- PASS: TestConcurrency (0.03s)
PASS
ok      nimbuzz.com/mlkem-psk/crypto    0.646s
```

### 2.3 Running Concurrency & Race Detector
To ensure strict absence of race conditions and memory safety:

```bash
go test -race -v ./crypto
```

### 2.4 Running Performance Benchmarks
To evaluate cryptographic throughput on the host processor:

```bash
go test -bench=. -benchmem ./crypto
```

**Representative Benchmark Output (Apple M4 / Linux AMD64 EPYC):**
```
goos: darwin
goarch: arm64
pkg: nimbuzz.com/mlkem-psk/crypto
cpu: Apple M4
BenchmarkGenerateEncryptedPSK-10    26877    44194 ns/op   (22,600 ops/sec)
BenchmarkDecryptPSK-10              25969    48074 ns/op   (20,800 ops/sec)
BenchmarkRoundTrip-10               10000   110310 ns/op    (9,060 ops/sec)
PASS
```

### 2.5 Running the Interactive CLI Verification
The root `main.go` provides an interactive verification of the key encapsulation flow:

```bash
go run main.go -bench
```
This prints the raw public keys, ciphertext envelope structure, recovered PSK, and WireGuard configuration snippet.
