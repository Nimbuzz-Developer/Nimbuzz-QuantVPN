# QuantVPN Cryptographic Design Specification
**Document Version:** 1.2.0  
**Status:** Approved for Implementation  
**Standard References:** NIST FIPS 203 (ML-KEM), RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF), WireGuard Protocol Paper (Jason A. Donenfeld)

---

## 1. Executive Summary & Security Objectives

QuantVPN delivers **Post-Quantum Forward Secrecy** for VPN sessions by establishing a hybrid classical/post-quantum key exchange layered atop standard WireGuard tunnels.

### 1.1 The Threat: Store Now, Decrypt Later (SNDL)
Conventional VPN tunnels (including standard WireGuard and OpenVPN) rely exclusively on classical asymmetric primitives—specifically Elliptic Curve Diffie-Hellman (**X25519**, NIST P-256) or RSA. Adversaries and nation-state intelligence agencies currently record encrypted transit traffic in mass data repositories. When Cryptographically Relevant Quantum Computers (CRQCs) emerge, Shor’s algorithm will calculate discrete logarithms in polynomial time, retroactively decrypting all recorded classical sessions.

### 1.2 Security Goals
1. **Quantum Resistance (NIST Security Level 5):** Session encryption keys cannot be derived by a quantum adversary executing Shor's or Grover's algorithms.
2. **Hybrid Composition:** Security holds as long as *either* the post-quantum lattice problem (ML-KEM-1024, Module-LWE) *or* the classical elliptic curve problem (X25519) remains intractable.
3. **Protocol Wire Compatibility:** Full compatibility with the official WireGuard kernel module and userspace engines (`wireguard-go`) without modifying WireGuard UDP wire packet formats, MTU limits, or handshake timeouts.
4. **Active Adversary Integrity (IND-CCA2):** Ciphertext tampering, malleability, or replays during the post-quantum exchange are rejected prior to state commitment.

---

## 2. Standard WireGuard Protocol Baseline

WireGuard establishes tunnels using the **Noise_IKpsk2** handshake pattern from the Noise Protocol Framework:

$$\text{Noise\_IKpsk2}: \leftarrow s \quad \dots \quad \rightarrow e, es, s, ss \quad \leftarrow e, ee, se, \mathbf{psk}$$

### 2.1 Classical Handshake Mechanics
1. **Initiator (Client)** generates ephemeral keypair $(e_{\text{priv}}, e_{\text{pub}})$ and calculates ECDH shared secrets against the responder's static public key $(s_r)$.
2. **Responder (Server)** receives the initiation packet, validates the MAC, generates ephemeral keypair $(e_{r,\text{priv}}, e_{r,\text{pub}})$, and performs DH exchanges with $e_{\text{priv}}$ and static key $s_i$.
3. **Pre-Shared Key Mixing:** In the second handshake message, WireGuard provides a 32-byte symmetric injection slot:
   $$\text{mixKey}(\mathbf{psk})$$
   This symmetric key is incorporated into the Noise chaining key $C_k$ via BLAKE2s (see `mix_psk()` in [`wireguard-kernel/src/noise.c`](../wireguard-kernel/src/noise.c#L676)).
4. **Transport Keys:** The resulting sender and receiver transport keys $(T_{\text{send}}, T_{\text{recv}})$ derive directly from the final chaining key.

> **Key Cryptographic Invariant:**  
> If an adversary breaks X25519 using Shor's algorithm, but the 32-byte `psk` is cryptographically strong and unknown to the adversary, the resulting session keys $(T_{\text{send}}, T_{\text{recv}})$ **remain uncompromised** (provably secure under the pseudo-random function assumption of BLAKE2s / HMAC).

---

## 3. QuantVPN Post-Quantum Architecture

Standard WireGuard cannot directly encapsulate post-quantum ciphertexts (such as ML-KEM-1024's 1,568-byte ciphertext) inside its initial UDP handshake packet without exceeding Ethernet MTUs (1500 bytes), causing UDP packet fragmentation, IP-level packet loss, and amplification vulnerabilities.

QuantVPN solves this with an **out-of-band Control Plane KEM encapsulation** that provisions a dynamic, post-quantum 256-bit PSK directly into the WireGuard kernel interface before the Noise_IKpsk2 handshake executes.

```
+----------------------------------------------------------------------------------------------------+
|                                    QUANTVPN ARCHITECTURE OVERVIEW                                  |
+----------------------------------------------------------------------------------------------------+

       CLIENT (iOS / macOS / Linux / Win)                             SERVER (RAM-Only Node)
  +-----------------------------------------+               +-----------------------------------------+
  | 1. Long-term Ed25519 Identity Key       |               |                                         |
  |    (client_priv, client_pub)            |               |                                         |
  | 2. Generate ML-KEM-1024 Keypair         |               |                                         |
  |    (ek_client, dk_client)               |               |                                         |
  | 3. Establish Session Context & Sign     |               |                                         |
  |    ctx = {ClientID, ServerID, Nonce, Ts}|               |                                         |
  |    sig = Sign(client_priv, ek_client,ctx|               |                                         |
  | 4. Generate WireGuard X25519 Keypair    |               |                                         |
  |    (wg_priv, wg_pub)                    |               |                                         |
  +--------------------+--------------------+               +--------------------+--------------------+
                       |                                                         |
                       |--- [HTTPS / TLS 1.3 Control Plane Session] ------------>|
                       |    POST /api/v1/peer/add                                |
                       |    Body: { wg_pub, mlkem_pub, ctx, client_pub, sig }    |
                       |                                                         |
                       |                                    +--------------------+--------------------+
                       |                                    | 5. Authenticate Client Signature:       |
                       |                                    |    Verify(client_pub, mlkem_pub, ctx,sig|
                       |                                    | 6. Generate Random 256-bit PSK          |
                       |                                    |    psk <- CPRNG(32 bytes)               |
                       |                                    | 7. ML-KEM-1024 Encapsulation            |
                       |                                    |    (ss_kem, ct_kem) <- Encaps(ek_client)|
                       |                                    | 8. HKDF-SHA256 Derivation               |
                       |                                    |    K_aead <- HKDF(ss_kem, label)        |
                       |                                    | 9. ChaCha20-Poly1305 Seal with Context: |
                       |                                    |    AAD = Version || ct_kem || ctx       |
                       |                                    |    C_psk <- Seal(K_aead, N, psk, AAD)   |
                       |                                    | 10. Commit PSK into WireGuard Kernel    |
                       |                                    |     (via UAPI socket, zeroizing memory) |
                       |                                    +--------------------+--------------------+
                       |                                                         |
                       |<-- Response: Encrypted PSK Blob (1629 bytes) -----------|
                       |    [Version | ct_kem | Nonce | C_psk]                   |
                       |                                                         |
  +--------------------+--------------------+                                    |
  | 11. Verify Header & Version (0x01)      |                                    |
  | 12. Decapsulate ML-KEM-1024:            |                                    |
  |     ss_kem <- Decaps(dk_client, ct_kem) |                                    |
  | 13. Derive K_aead via HKDF-SHA256       |                                    |
  | 14. ChaCha20-Poly1305 Open with Context |                                    |
  |     AAD = Version || ct_kem || ctx      |                                    |
  |     psk <- Open(K_aead, N, C_psk, AAD)  |                                    |
  | 15. Commit PSK into WireGuard Kernel    |                                    |
  |     (zeroizing sensitive buffers)       |                                    |
  +--------------------+--------------------+                                    |
                       |                                                         |
                       |=========================================================|
                       |   STANDARD WIREGUARD UDP HANDSHAKE (Port 51820)         |
                       |   Noise_IKpsk2 with Hybrid Post-Quantum PSK             |
                       |   -> e, es, s, ss                                       |
                       |   <- e, ee, se, psk                                     |
                       |=========================================================|
                       |   ESTABLISHED POST-QUANTUM SECURE DATA TUNNEL           |
                       +---------------------------------------------------------+
```

---

## 4. Detailed Sequence of Cryptographic Operations

### Step 1: Client Key Generation & Identity Binding
The client initializes its post-quantum and classical cryptographic contexts:
1. Generates or loads its long-term Ed25519 client identity keypair (`client_priv`, `client_pub`).
2. Generates an ephemeral ML-KEM-1024 decapsulation key $dk \in \{0,1\}^{3168}$ and encapsulation key $ek \in \{0,1\}^{1568}$ adhering to NIST FIPS 203.
3. Generates a standard Curve25519 static private key $sk_{\text{wg}} \in \{0,1\}^{32}$ and computes public key $pk_{\text{wg}} = \text{X25519}(sk_{\text{wg}}, 9)$.
4. Constructs a `ProvisionContext` containing `ClientID`, `ServerID`, `SessionNonce` (16 bytes CPRNG), and a Unix `Timestamp`.
5. Signs the ephemeral ML-KEM public key and context using Ed25519 (`SignClientKey`), preventing man-in-the-middle key substitution.

### Step 2: Key Registration & Negotiation Request
The client opens an authenticated TLS 1.3 control connection to the QuantVPN server and submits:
- Client WireGuard Public Key: $pk_{\text{wg}}$ (32 bytes)
- Client ML-KEM-1024 Encapsulation Key: $ek$ (1568 bytes)
- Client Identity Public Key: `client_pub` (32 bytes)
- Client Signature: `sig` (64 bytes)
- Provisioning Context: `ctx` (`ClientID`, `ServerID`, `SessionNonce`, `Timestamp`)

### Step 3: Server Signature Verification & KEM Encapsulation
1. **Client Identity Authentication:**
   The server verifies `sig` using `client_pub` over `ek` and `ctx`. If signature verification fails, the connection terminates immediately with `ErrClientAuthFailed`.
2. **Generate Symmetric PSK:**
   $$\text{psk} \leftarrow_{\mathcal{R}} \{0,1\}^{256}$$
3. **KEM Encapsulation:**
   $$(ss_{\text{kem}}, ct_{\text{kem}}) \leftarrow \text{ML-KEM-1024.Encaps}(ek)$$
   - Shared secret: $ss_{\text{kem}} \in \{0,1\}^{32}$ (256 bits)
   - KEM Ciphertext: $ct_{\text{kem}} \in \{0,1\}^{1568}$ (1568 bytes)
4. **Key Derivation (HKDF-SHA256):**
   $$K_{\text{aead}} = \text{HKDF-Expand}(\text{PRK}=\text{HKDF-Extract}(\text{salt}=\emptyset, ss_{\text{kem}}), \text{info}=\text{"wireguard-psk/encrypt/mlkem1024/v1"}, L=32)$$
5. **Nonce Generation:**
   $$N \leftarrow_{\mathcal{R}} \{0,1\}^{96} \quad (12 \text{ bytes})$$
6. **Authenticated Data (AAD) Construction with Session Context:**
   $$\text{AAD} = \text{Version} \, (0x01) \,\|\, ct_{\text{kem}} \,\|\, \text{len}(ClientID) \,\|\, ClientID \,\|\, \text{len}(ServerID) \,\|\, ServerID \,\|\, SessionNonce \,\|\, Timestamp$$
   This cryptographically binds the envelope to this specific client, server, and session.
7. **Authenticated Encryption (ChaCha20-Poly1305):**
   $$C_{\text{psk}} = \text{ChaCha20-Poly1305.Seal}(K_{\text{aead}}, N, \text{psk}, \text{AAD}) \quad (48 \text{ bytes})$$
   (32 bytes encrypted PSK + 16 bytes Poly1305 authentication tag).
8. **Serialized Binary Envelope (1,629 bytes total):**
   $$\text{Blob} = \underbrace{\text{Version}}_{1\text{ byte}} \,\|\, \underbrace{ct_{\text{kem}}}_{1568\text{ bytes}} \,\|\, \underbrace{N}_{12\text{ bytes}} \,\|\, \underbrace{C_{\text{psk}}}_{48\text{ bytes}}$$

### Step 4: Server Kernel State Commitment
The control-plane applies the generated `psk` directly into the running WireGuard interface for peer $pk_{\text{wg}}$ using the WireGuard UAPI or secure stream without printing keys in shell commands, terminal outputs, or process arguments:
```bash
wg set wg0 peer <pk_wg> preshared-key /dev/stdin <<< "$psk"
```
The server memory buffer containing `psk` is immediately scrubbed with `crypto.Zeroize`.

### Step 5: Client Decapsulation & Recovery
Upon receiving the 1,629-byte blob:
1. **Envelope Validation:** Verifies length equals exactly $1629$ bytes and byte 0 equals $0x01$.
2. **KEM Decapsulation:**
   $$ss_{\text{kem}} = \text{ML-KEM-1024.Decaps}(dk, ct_{\text{kem}})$$
3. **Derive Decryption Key:**
   $$K_{\text{aead}} = \text{HKDF-SHA256}(ss_{\text{kem}}, \text{"wireguard-psk/encrypt/mlkem1024/v1"}, 32)$$
4. **Context-Bound AEAD Verification & Decryption:**
   $$\text{psk} = \text{ChaCha20-Poly1305.Open}(K_{\text{aead}}, N, C_{\text{psk}}, \text{AAD})$$
   If any field of `ctx` was modified, or if the KEM ciphertext or encrypted PSK was altered, Poly1305 verification fails immediately and returns `ErrDecryptionFailed`. No unverified plaintext is released.

### Step 6: Client Kernel State Commitment
The client configures its local tunnel interface through the WireGuard API without exposing raw keys in terminal history:
```ini
[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = [REDACTED - 32 bytes provisioned via ML-KEM-1024 into kernel]
Endpoint = <SERVER_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

### Step 7: WireGuard Data Plane Tunnel Handshake
Standard WireGuard handshake initiates over UDP. Handshake message 2 mixes `psk`:
$$C_k^{(2)} = \text{BLAKE2s}(C_k^{(1)} \,\|\, \mathbf{psk})$$
All resulting session keys are quantum-secure.

---

## 5. Scope Distinction: Standard WireGuard vs. QuantVPN Additions

| Component | Standard WireGuard Functionality | QuantVPN Post-Quantum Enhancement |
|:---|:---|:---|
| **Asymmetric Key Exchange** | X25519 (ECDH over Curve25519) | Hybrid: X25519 + ML-KEM-1024 (FIPS 203) |
| **Post-Quantum Security** | None (classical only, broken by Shor's algorithm) | NIST Security Level 5 (equivalent to AES-256) |
| **PSK Mechanism** | Native `mixKey(psk)` slot in Noise_IKpsk2 | Dynamic ML-KEM out-of-band generation & injection |
| **Encapsulation Transport** | None | Authenticated control-plane TLS envelope |
| **Envelope Integrity** | N/A | ChaCha20-Poly1305 AEAD bound with AAD |
| **Wire Protocol / UDP** | Standard UDP 51820 packets (148 bytes handshake) | 100% Unmodified WireGuard kernel wire packets |
| **MTU / Fragmentation** | 1420 bytes default (no fragmentation) | Unaffected (no KEM data on UDP wire) |
| **Hardware Acceleration** | Kernel crypto (NEON / AVX2 / SSSE3) | Hardware-accelerated ChaCha20 + pure Go ML-KEM |

---

## 6. Cryptographic Primitives & Parameters

### 6.1 ML-KEM-1024 (Module Lattice Key Encapsulation Mechanism)
- **Standard:** NIST FIPS 203 (derived from CRYSTALS-Kyber).
- **Security Category:** NIST Level 5 (classical and quantum hardness matching AES-256).
- **Hardness Assumption:** Module Learning With Errors (M-LWE).
- **Key Sizes:**
  - Encapsulation Key ($ek$): 1,568 bytes.
  - Decapsulation Key ($dk$): 3,168 bytes.
  - Ciphertext ($ct$): 1,568 bytes.
  - Shared Secret ($ss$): 32 bytes (256 bits).

### 6.2 HKDF-SHA256 (Key Derivation Function)
- **Standard:** RFC 5869.
- **Hash Primitive:** SHA-256 (FIPS 180-4).
- **Context String (info):** `wireguard-psk/encrypt/mlkem1024/v1`
- **Output Key Material:** 32 bytes (256 bits).

### 6.3 ChaCha20-Poly1305 (Authenticated Encryption with Associated Data)
- **Standard:** RFC 8439.
- **Key Size:** 32 bytes (256 bits).
- **Nonce Size:** 12 bytes (96 bits) randomly generated per encapsulation.
- **Tag Size:** 16 bytes (128 bits).
- **Associated Authenticated Data (AAD):**
  - **Base Envelope:** 1,569 bytes (Version byte $0x01$ concatenated with 1,568-byte KEM ciphertext).
  - **Context-Bound Provisioning (`BuildAuthenticatedAAD`):** Version byte ($0x01$) + KEM ciphertext ($1,568$ bytes) + length-prefixed `ClientID` + length-prefixed `ServerID` + 16-byte `SessionNonce` + 8-byte `Timestamp`.

---

## 7. Security Guarantees & Threat Analysis

### 7.1 IND-CCA2 Post-Quantum Hardness
ML-KEM-1024 is an IND-CCA2 secure key encapsulation mechanism. Even if an adversary modifies bits in transit or queries the decapsulation oracle with chosen ciphertexts, the Fujisaki-Okamoto (FO) transform guarantees that decapsulation produces pseudorandom output without leaking private key coefficients.

### 7.2 Client Identity Authentication & Key Substitution Protection
ML-KEM protects confidentiality for the intended private-key holder, but does not identify who created the public key. To prevent public key substitution (where an adversary substitutes their own ML-KEM key):
1. The client signs the ephemeral ML-KEM public key and `ProvisionContext` with its long-term Ed25519 identity key (`SignClientKey`).
2. The server verifies this signature (`VerifyClientKey`) before encapsulating the PSK.
3. The server and client bind the session context into the ChaCha20-Poly1305 AAD (`BuildAuthenticatedAAD`).
If any attacker tampers with the public key, the Ed25519 signature verification fails. If any attacker tampers with the server identity, client identity, or session nonce, ChaCha20-Poly1305 AEAD decryption fails (`ErrDecryptionFailed`).

### 7.3 Freshness Window & Anti-Replay Protection
AAD binding guarantees tamper-evidence and prevents cross-session or cross-peer mixups. However, cryptographic AAD binding alone does not prevent an attacker from replaying an entire recorded `(blob, ctx)` pair.
To prevent replay attacks and PSK rollback (reinstating an expired or compromised key):
1. **Clock Skew & Window Validation:** The receiver calls `ctx.Validate(now, maxSkew)` (defaulting to 5 minutes). Timestamps outside this window are rejected with `ErrStaleTimestamp`.
2. **Session Nonce Tracking:** Receivers maintain a thread-safe `NonceCache` (or use receiver-issued challenges). If a nonce is presented more than once within the expiration window, it is rejected with `ErrReplayDetected`.
3. **Non-Zero Nonces:** Zero-value nonces are explicitly rejected with `ErrZeroNonce`.

### 7.4 Unified Entry Points & Inseparable Authentication
To eliminate integration vulnerabilities where a caller might verify one key/context but encrypt with another, or skip verification entirely:
- **Server:** `ProvisionPSK(clientEdPub, clientMLKEMPub, sig, ctx)` combines context validation, key length checks, Ed25519 signature verification, and ML-KEM encapsulation into an atomic call.
- **Client:** `ConsumeProvisionedPSK(blob, dk, ctx)` enforces context freshness validation before performing decapsulation and AEAD opening.

### 7.5 API Hardening & Deprecation of Context-less Primitives
The raw, context-less primitives (`EncryptPSK`, `DecryptPSK`, `GenerateEncryptedPSK`) are marked `// Deprecated:` and redirected to `*NoContext` variants with explicit security warnings. These lack identity binding and replay resistance and must not be used for production tunnel provisioning.

### 7.6 Memory Hygiene & Zeroization
All intermediate cryptographic secrets and wire secrets are scrubbed from RAM immediately after use:
- The ML-KEM shared secret `ss_kem` is zeroized using `defer Zeroize(sharedSecret)`.
- The derived HKDF symmetric key `K_aead` is zeroized using `defer Zeroize(key)`.
- The WireGuard pre-shared key buffers (`psk` and `recoveredPSK`) are explicitly zeroized using `defer Zeroize(psk[:])`.
- Live plaintext PSKs are never emitted to stdout, CLI logs, or process argument lists. Truncated SHA-256 fingerprints are used solely for diagnostic status verification.

---

## 8. Summary of Binary Envelope Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)|                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
|                 ML-KEM-1024 Ciphertext (1568 bytes)           |
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |          ChaCha20-Poly1305 Nonce (12 bytes)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |   Encrypted WireGuard PSK (32 bytes)          |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |       Poly1305 Authentication Tag (16 bytes)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total Envelope Length = 1 + 1568 + 12 + 32 + 16 = 1629 bytes.
```
