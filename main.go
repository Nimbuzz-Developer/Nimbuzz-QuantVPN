package main

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"nimbuzz.com/mlkem-psk/crypto"
)

func main() {
	benchFlag := flag.Bool("bench", false, "Run local performance benchmark")
	flag.Parse()

	fmt.Println("QuantVPN - Authenticated ML-KEM-1024 + WireGuard PSK Demo")
	fmt.Println("---------------------------------------------------------")

	start := time.Now()

	// 0. Classical Layer: Generate native WireGuard X25519 keypairs for Client and Server
	clientWGPriv, clientWGPub, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate client wireguard key: %v\n", err)
		os.Exit(1)
	}
	serverWGPriv, serverWGPub, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate server wireguard key: %v\n", err)
		os.Exit(1)
	}

	// 1. Post-Quantum Layer: Client creates Ed25519 identity and ephemeral ML-KEM-1024 keypair
	t0 := time.Now()
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate client identity key: %v\n", err)
		os.Exit(1)
	}

	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate ML-KEM key: %v\n", err)
		os.Exit(1)
	}
	mlkemPub := dk.EncapsulationKey().Bytes()

	var sessionNonce [16]byte
	if _, err := rand.Read(sessionNonce[:]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate session nonce: %v\n", err)
		os.Exit(1)
	}

	ctx := crypto.ProvisionContext{
		ClientID:     "client-fra1-001",
		ServerID:     "data-plane-fra1-1",
		SessionNonce: sessionNonce,
		Timestamp:    time.Now().Unix(),
	}

	clientSig, err := crypto.SignClientKey(clientPriv, mlkemPub, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to sign ML-KEM key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[1] Client generated keys and signed context in %v\n", time.Since(t0))
	fmt.Printf("    Client ID:        %s\n", ctx.ClientID)
	fmt.Printf("    Ed25519 identity: %x... (%d bytes)\n", clientPub[:8], len(clientPub))
	fmt.Printf("    ML-KEM-1024 key:  %d bytes public, %d bytes private\n", len(mlkemPub), len(dk.Bytes()))
	fmt.Printf("    Session context:  server=%s, nonce=%x...\n", ctx.ServerID, sessionNonce[:6])

	// 2. Server provisions PSK via unified entry point (validates freshness, verifies Ed25519 signature, encapsulates PSK)
	t1 := time.Now()
	psk, blob, err := crypto.ProvisionPSK(clientPub, mlkemPub, clientSig, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server provisioning failed: %v\n", err)
		os.Exit(1)
	}
	defer crypto.Zeroize(psk[:])

	serverFP := sha256.Sum256(psk[:])
	fmt.Printf("\n[2] Server authenticated client and provisioned PSK in %v\n", time.Since(t1))
	fmt.Printf("    Server PSK:       [REDACTED] (SHA-256: %x...)\n", serverFP[:8])
	fmt.Printf("    Blob size:        %d bytes\n", len(blob))
	fmt.Printf("    - Version:        0x%02x (1 byte)\n", blob[0])
	fmt.Printf("    - Ciphertext:     %d bytes (ML-KEM-1024)\n", crypto.KEMCiphertextSize)
	fmt.Printf("    - Nonce:          %d bytes\n", crypto.NonceSize)
	fmt.Printf("    - Tagged PSK:     %d bytes (ChaCha20-Poly1305)\n", crypto.PSKSize+crypto.Poly1305TagSize)

	// 3. Client consumes provisioned PSK via unified entry point (validates freshness, verifies context AAD, decrypts PSK)
	t2 := time.Now()
	recoveredPSK, err := crypto.ConsumeProvisionedPSK(blob, dk, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to consume provisioned PSK: %v\n", err)
		os.Exit(1)
	}
	defer crypto.Zeroize(recoveredPSK[:])

	clientFP := sha256.Sum256(recoveredPSK[:])
	fmt.Printf("\n[3] Client verified context and decrypted PSK in %v\n", time.Since(t2))
	fmt.Printf("    Recovered PSK:    [REDACTED] (SHA-256: %x...)\n", clientFP[:8])

	// 4. Verify match in constant time
	if subtle.ConstantTimeCompare(recoveredPSK[:], psk[:]) != 1 {
		fmt.Fprintf(os.Stderr, "Error: recovered PSK does not match original PSK\n")
		os.Exit(1)
	}

	fmt.Printf("\nSuccess: Authenticated key exchange complete (total: %v)\n", time.Since(start))
	fmt.Printf("Key fingerprint matches: %x...\n", clientFP[:8])

	pskB64 := base64.StdEncoding.EncodeToString(recoveredPSK[:])

	// 5. Native WireGuard X25519 + ML-KEM Hybrid Demonstration
	fmt.Println("\n=========================================================")
	fmt.Println("WireGuard Native Hybrid Integration Demonstration")
	fmt.Println("=========================================================")
	fmt.Println("WireGuard handles classical X25519 ECDH in the OS kernel.")
	fmt.Println("QuantVPN provisions the post-quantum ML-KEM PSK out-of-band.")
	fmt.Println("The kernel mixes both primitives via BLAKE2s in Noise_IKpsk2.")

	fmt.Println("\n--- [Client] WireGuard Interface Configuration (wg0-client.conf) ---")
	fmt.Printf("[Interface]\n")
	fmt.Printf("# Layer 1: Classical Native X25519 Private Key\n")
	fmt.Printf("PrivateKey = %s\n", clientWGPriv)
	fmt.Printf("Address = 10.0.0.2/32\n\n")
	fmt.Printf("[Peer]\n")
	fmt.Printf("# Layer 1: Classical Native X25519 Server Public Key\n")
	fmt.Printf("PublicKey = %s\n", serverWGPub)
	fmt.Printf("# Layer 2: Post-Quantum WireGuard PSK (derived via ML-KEM-1024)\n")
	fmt.Printf("PresharedKey = %s\n", pskB64)
	fmt.Printf("Endpoint = 198.51.100.1:51820\n")
	fmt.Printf("AllowedIPs = 0.0.0.0/0\n")

	fmt.Println("\n--- [Server] WireGuard Peer Configuration (wg0-server.conf) ---")
	fmt.Printf("[Interface]\n")
	fmt.Printf("# Layer 1: Classical Native X25519 Server Private Key\n")
	fmt.Printf("PrivateKey = %s\n", serverWGPriv)
	fmt.Printf("ListenPort = 51820\n\n")
	fmt.Printf("[Peer]\n")
	fmt.Printf("# Layer 1: Classical Native X25519 Client Public Key\n")
	fmt.Printf("PublicKey = %s\n", clientWGPub)
	fmt.Printf("# Layer 2: Post-Quantum WireGuard PSK (derived via ML-KEM-1024)\n")
	fmt.Printf("PresharedKey = %s\n", pskB64)
	fmt.Printf("AllowedIPs = 10.0.0.2/32\n")

	fmt.Println("\n--- Dynamic Kernel UAPI Injection (Zero-Downtime Live Update) ---")
	fmt.Println("The control-plane applies the hybrid PSK directly into the running kernel:")
	fmt.Printf("$ wg set wg0 peer %s preshared-key /dev/stdin <<< \"%s\"\n", serverWGPub, pskB64)

	fmt.Println("\n--- WireGuard Kernel Handshake Mechanics (Noise_IKpsk2) ---")
	fmt.Println("1. Classical: WireGuard kernel performs 4x X25519 ECDH (es, ss, ee, se).")
	fmt.Println("2. Quantum:   Kernel executes mixKey(psk) injecting ML-KEM PSK into chaining key:")
	fmt.Println("              Ck = BLAKE2s(Ck_classical || ML-KEM_PSK)")
	fmt.Println("3. Result:    Hybrid tunnel security (unbroken unless BOTH X25519 AND ML-KEM fail).")

	if *benchFlag {
		fmt.Println("\nRunning benchmark (1,000 round-trips with ProvisionPSK + ConsumeProvisionedPSK)...")
		benchStart := time.Now()
		const iterations = 1000
		for i := 0; i < iterations; i++ {
			bPSK, bBlob, bErr := crypto.ProvisionPSK(clientPub, mlkemPub, clientSig, ctx)
			if bErr != nil {
				panic(bErr)
			}
			bRec, bErr := crypto.ConsumeProvisionedPSK(bBlob, dk, ctx)
			if bErr != nil || subtle.ConstantTimeCompare(bRec[:], bPSK[:]) != 1 {
				panic("benchmark mismatch")
			}
			crypto.Zeroize(bPSK[:])
			crypto.Zeroize(bRec[:])
		}
		elapsed := time.Since(benchStart)
		avg := elapsed / time.Duration(iterations)
		fmt.Printf("Done: 1000 round-trips in %v (avg %v/op, ~%.0f ops/sec)\n",
			elapsed, avg, float64(iterations)/elapsed.Seconds())
	}
}
