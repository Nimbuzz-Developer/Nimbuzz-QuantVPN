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
  | 1. Generate ML-KEM-1024 Keypair         |               |                                         |
  |    (ek_client, dk_client)               |               |                                         |
  | 2. Generate WireGuard X25519 Keypair    |               |                                         |
  |    (wg_priv, wg_pub)                    |               |                                         |
  +--------------------+--------------------+               +--------------------+--------------------+
                       |                                                         |
                       |--- [HTTPS / TLS 1.3 Control Plane Session] ------------>|
                       |    POST /api/v1/peer/add                                |
                       |    Body: { wg_pub, mlkem_pub: ek_client }               |
                       |                                                         |
                       |                                    +--------------------+--------------------+
                       |                                    | 3. Generate Random 256-bit PSK          |
                       |                                    |    psk <- CPRNG(32 bytes)               |
                       |                                    | 4. ML-KEM-1024 Encapsulation            |
                       |                                    |    (ss_kem, ct_kem) <- Encaps(ek_client)|
                       |                                    | 5. HKDF-SHA256 Derivation               |
                       |                                    |    K_aead <- HKDF(ss_kem, label)        |
                       |                                    | 6. ChaCha20-Poly1305 Seal               |
                       |                                    |    C_psk <- Seal(K_aead, N, psk, AAD)   |
                       |                                    | 7. Commit PSK to WireGuard Kernel:      |
                       |                                    |    wg set wg0 peer <wg_pub>             |
                       |                                    |           preshared-key <psk>           |
                       |                                    +--------------------+--------------------+
                       |                                                         |
                       |<-- Response: Encrypted PSK Blob (1629 bytes) -----------|
                       |    [Version | ct_kem | Nonce | C_psk]                   |
                       |                                                         |
  +--------------------+--------------------+                                    |
  | 8. Verify Header & Version (0x01)       |                                    |
  | 9. Decapsulate ML-KEM-1024:             |                                    |
  |    ss_kem <- Decaps(dk_client, ct_kem)  |                                    |
  | 10. Derive K_aead via HKDF-SHA256       |                                    |
  | 11. ChaCha20-Poly1305 Open & Verify AAD |                                    |
  |     psk <- Open(K_aead, N, C_psk, AAD)  |                                    |
  | 12. Commit PSK to WireGuard:            |                                    |
  |     wg set wg0 peer <server_pub>        |                                    |
  |            preshared-key <psk>          |                                    |
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

### Step 1: Client Key Generation
The client initializes its post-quantum and classical cryptographic contexts:
1. Generates an ML-KEM-1024 decapsulation key $dk \in \{0,1\}^{3168}$ and encapsulation key $ek \in \{0,1\}^{1568}$ adhering to NIST FIPS 203.
2. Generates a standard Curve25519 static private key $sk_{\text{wg}} \in \{0,1\}^{32}$ and computes public key $pk_{\text{wg}} = \text{X25519}(sk_{\text{wg}}, 9)$.

### Step 2: Key Registration & Negotiation Request
The client opens a TLS 1.3 control connection to the QuantVPN control plane and submits:
- Client WireGuard Public Key: $pk_{\text{wg}}$ (32 bytes, base64 encoded)
- Client ML-KEM-1024 Encapsulation Key: $ek$ (1568 bytes, base64 encoded)

### Step 3: Server Encapsulation & Envelope Construction
1. **Generate Symmetric PSK:**
   $$\text{psk} \leftarrow_{\mathcal{R}} \{0,1\}^{256}$$
2. **KEM Encapsulation:**
   $$(ss_{\text{kem}}, ct_{\text{kem}}) \leftarrow \text{ML-KEM-1024.Encaps}(ek)$$
   - Shared secret: $ss_{\text{kem}} \in \{0,1\}^{32}$ (256 bits)
   - KEM Ciphertext: $ct_{\text{kem}} \in \{0,1\}^{1568}$ (1568 bytes)
3. **Key Derivation (HKDF-SHA256):**
   $$K_{\text{aead}} = \text{HKDF-Expand}(\text{PRK}=\text{HKDF-Extract}(\text{salt}=\emptyset, ss_{\text{kem}}), \text{info}=\text{"wireguard-psk/encrypt/mlkem1024/v1"}, L=32)$$
4. **Nonce Generation:**
   $$N \leftarrow_{\mathcal{R}} \{0,1\}^{96} \quad (12 \text{ bytes})$$
5. **Authenticated Data (AAD) Construction:**
   $$\text{AAD} = \text{Version} \, (0x01) \,\|\, ct_{\text{kem}} \quad (1569 \text{ bytes})$$
6. **Authenticated Encryption (ChaCha20-Poly1305):**
   $$C_{\text{psk}} = \text{ChaCha20-Poly1305.Seal}(K_{\text{aead}}, N, \text{psk}, \text{AAD}) \quad (48 \text{ bytes})$$
   (32 bytes encrypted PSK + 16 bytes Poly1305 authentication tag).
7. **Serialized Binary Envelope (1,629 bytes total):**
   $$\text{Blob} = \underbrace{\text{Version}}_{1\text{ byte}} \,\|\, \underbrace{ct_{\text{kem}}}_{1568\text{ bytes}} \,\|\, \underbrace{N}_{12\text{ bytes}} \,\|\, \underbrace{C_{\text{psk}}}_{48\text{ bytes}}$$

### Step 4: Server Kernel State Commitment
The control-plane applies the generated `psk` to the running WireGuard interface for peer $pk_{\text{wg}}$:
```bash
wg set wg0 peer <pk_wg> preshared-key <(echo -n "$psk")
```

### Step 5: Client Decapsulation & Recovery
Upon receiving the 1,629-byte blob:
1. **Envelope Validation:** Verifies length equals exactly $1629$ bytes and byte 0 equals $0x01$.
2. **KEM Decapsulation:**
   $$ss_{\text{kem}} = \text{ML-KEM-1024.Decaps}(dk, ct_{\text{kem}})$$
3. **Derive Decryption Key:**
   $$K_{\text{aead}} = \text{HKDF-SHA256}(ss_{\text{kem}}, \text{"wireguard-psk/encrypt/mlkem1024/v1"}, 32)$$
4. **AEAD Verification & Decryption:**
   $$\text{psk} = \text{ChaCha20-Poly1305.Open}(K_{\text{aead}}, N, C_{\text{psk}}, \text{AAD})$$
   If Poly1305 authentication verification fails, the operation immediately aborts with `ErrDecryptionFailed`. No unverified plaintext is released.

### Step 6: Client Kernel State Commitment
The client configures its local tunnel interface:
```ini
[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = <RECOVERED_PSK>
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
- **AAD:** 1,569 bytes (Version byte $0x01$ concatenated with 1,568-byte KEM ciphertext).

---

## 7. Security Guarantees & Threat Analysis

### 7.1 IND-CCA2 Post-Quantum Hardness
ML-KEM-1024 is an IND-CCA2 secure key encapsulation mechanism. Even if an adversary modifies bits in transit or queries the decapsulation oracle with chosen ciphertexts, the Fujisaki-Okamoto (FO) transform guarantees that decapsulation produces pseudorandom output without leaking private key coefficients.

### 7.2 AEAD Envelope Binding & AAD Protection
To prevent cross-protocol splicing, KEM ciphertext substitution, or format truncation attacks, the entire 1,568-byte KEM ciphertext and the 1-byte envelope version are authenticated as **Additional Authenticated Data (AAD)** in ChaCha20-Poly1305. If an attacker tampers with even a single bit of the KEM ciphertext or version header, the Poly1305 MAC verification fails immediately.

### 7.3 Memory Hygiene & Zeroization
All intermediate cryptographic secrets are scrubbed from RAM immediately after use:
- The ML-KEM shared secret `ss_kem` is zeroized using `defer Zeroize(sharedSecret)`.
- The derived HKDF symmetric key `K_aead` is zeroized using `defer Zeroize(key)`.
- Ephemeral plaintext buffers are cleared prior to returning.

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
