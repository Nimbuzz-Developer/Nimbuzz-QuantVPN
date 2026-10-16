package main

import (
	"crypto/mlkem"
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

	fmt.Println("QuantVPN - ML-KEM-1024 + WireGuard PSK Demo")
	fmt.Println("-------------------------------------------")

	start := time.Now()

	// 1. Client generates ML-KEM-1024 keypair
	t0 := time.Now()
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key: %v\n", err)
		os.Exit(1)
	}
	pub := dk.EncapsulationKey().Bytes()
	fmt.Printf("[1] Client generated ML-KEM-1024 keys in %v\n", time.Since(t0))
	fmt.Printf("    Public key:  %d bytes\n", len(pub))
	fmt.Printf("    Private key: %d bytes\n", len(dk.Bytes()))

	// 2. Server generates a random PSK and encrypts it with the client's public key
	t1 := time.Now()
	psk, blob, err := crypto.GenerateEncryptedPSK(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt PSK: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n[2] Server generated and encrypted WireGuard PSK in %v\n", time.Since(t1))
	fmt.Printf("    Server PSK:   %s\n", base64.StdEncoding.EncodeToString(psk[:]))
	fmt.Printf("    Blob size:    %d bytes\n", len(blob))
	fmt.Printf("    - Version:    0x%02x (1 byte)\n", blob[0])
	fmt.Printf("    - Ciphertext: %d bytes (ML-KEM-1024)\n", crypto.KEMCiphertextSize)
	fmt.Printf("    - Nonce:      %d bytes\n", crypto.NonceSize)
	fmt.Printf("    - Tagged PSK: %d bytes (ChaCha20-Poly1305)\n", crypto.PSKSize+crypto.Poly1305TagSize)

	// 3. Client decrypts the blob using its private key
	t2 := time.Now()
	recoveredPSK, err := crypto.DecryptPSK(blob, dk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decrypt PSK: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n[3] Client decrypted WireGuard PSK in %v\n", time.Since(t2))
	fmt.Printf("    Recovered PSK: %s\n", base64.StdEncoding.EncodeToString(recoveredPSK[:]))

	// 4. Verify both sides match
	if recoveredPSK != psk {
		fmt.Fprintf(os.Stderr, "Error: recovered PSK does not match original PSK\n")
		os.Exit(1)
	}

	fmt.Printf("\nSuccess: Both sides have the identical 256-bit PSK (total: %v)\n", time.Since(start))
	fmt.Println("\nWireGuard config snippet:")
	fmt.Println("[Peer]")
	fmt.Printf("PresharedKey = %s\n", base64.StdEncoding.EncodeToString(recoveredPSK[:]))

	if *benchFlag {
		fmt.Println("\nRunning benchmark (1,000 round-trips)...")
		benchStart := time.Now()
		const iterations = 1000
		for i := 0; i < iterations; i++ {
			bPSK, bBlob, bErr := crypto.GenerateEncryptedPSK(pub)
			if bErr != nil {
				panic(bErr)
			}
			bRec, bErr := crypto.DecryptPSK(bBlob, dk)
			if bErr != nil || bRec != bPSK {
				panic("benchmark mismatch")
			}
		}
		elapsed := time.Since(benchStart)
		avg := elapsed / time.Duration(iterations)
		fmt.Printf("Done: 1000 round-trips in %v (avg %v/op, ~%.0f ops/sec)\n",
			elapsed, avg, float64(iterations)/elapsed.Seconds())
	}
}
