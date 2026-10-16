package main

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

	// 1. Client creates long-term Ed25519 identity and ephemeral ML-KEM-1024 keypair
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

	clientSig := crypto.SignClientKey(clientPriv, mlkemPub, ctx)

	fmt.Printf("[1] Client generated keys and signed context in %v\n", time.Since(t0))
	fmt.Printf("    Client ID:        %s\n", ctx.ClientID)
	fmt.Printf("    Ed25519 identity: %x... (%d bytes)\n", clientPub[:8], len(clientPub))
	fmt.Printf("    ML-KEM-1024 key:  %d bytes public, %d bytes private\n", len(mlkemPub), len(dk.Bytes()))
	fmt.Printf("    Session context:  server=%s, nonce=%x...\n", ctx.ServerID, sessionNonce[:6])

	// 2. Server verifies client signature before provisioning
	t1 := time.Now()
	if err := crypto.VerifyClientKey(clientPub, mlkemPub, ctx, clientSig); err != nil {
		fmt.Fprintf(os.Stderr, "server rejected client authentication: %v\n", err)
		os.Exit(1)
	}

	psk, blob, err := crypto.GenerateEncryptedPSKWithContext(mlkemPub, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt PSK: %v\n", err)
		os.Exit(1)
	}
	defer crypto.Zeroize(psk[:])

	serverFP := sha256.Sum256(psk[:])
	fmt.Printf("\n[2] Server verified client and encrypted PSK in %v\n", time.Since(t1))
	fmt.Printf("    Server PSK:       [REDACTED] (SHA-256: %x...)\n", serverFP[:8])
	fmt.Printf("    Blob size:        %d bytes\n", len(blob))
	fmt.Printf("    - Version:        0x%02x (1 byte)\n", blob[0])
	fmt.Printf("    - Ciphertext:     %d bytes (ML-KEM-1024)\n", crypto.KEMCiphertextSize)
	fmt.Printf("    - Nonce:          %d bytes\n", crypto.NonceSize)
	fmt.Printf("    - Tagged PSK:     %d bytes (ChaCha20-Poly1305)\n", crypto.PSKSize+crypto.Poly1305TagSize)

	// 3. Client decrypts and verifies the context-bound envelope
	t2 := time.Now()
	recoveredPSK, err := crypto.DecryptPSKWithContext(blob, dk, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decrypt PSK: %v\n", err)
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
	fmt.Println("\nWireGuard configuration:")
	fmt.Println("[Peer]")
	fmt.Println("PresharedKey = [REDACTED - 32 bytes provisioned via ML-KEM-1024 into kernel]")

	if *benchFlag {
		fmt.Println("\nRunning benchmark (1,000 round-trips with authenticated context)...")
		benchStart := time.Now()
		const iterations = 1000
		for i := 0; i < iterations; i++ {
			bPSK, bBlob, bErr := crypto.GenerateEncryptedPSKWithContext(mlkemPub, ctx)
			if bErr != nil {
				panic(bErr)
			}
			bRec, bErr := crypto.DecryptPSKWithContext(bBlob, dk, ctx)
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
