package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestRoundTrip checks that encrypting and decrypting a PSK returns the original value.
func TestRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatalf("iteration %d: failed to generate key: %v", i, err)
		}
		pub := dk.EncapsulationKey().Bytes()

		psk, blob, err := GenerateEncryptedPSK(pub)
		if err != nil {
			t.Fatalf("iteration %d: GenerateEncryptedPSK failed: %v", i, err)
		}

		if len(blob) != EncryptedPSKSize {
			t.Fatalf("iteration %d: unexpected blob length: got %d, want %d", i, len(blob), EncryptedPSKSize)
		}

		recovered, err := DecryptPSK(blob, dk)
		if err != nil {
			t.Fatalf("iteration %d: DecryptPSK failed: %v", i, err)
		}

		if recovered != psk {
			t.Fatalf("iteration %d: PSK mismatch: got %x, want %x", i, recovered, psk)
		}
	}
}

// TestInvalidCiphertext checks that flipping bits in the ML-KEM ciphertext causes decryption to fail.
func TestInvalidCiphertext(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}

	_, blob, err := GenerateEncryptedPSK(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Test bit flips at various positions in the KEM ciphertext (bytes 1 through 1568).
	testOffsets := []int{1, 10, 100, 500, 1000, 1568}
	for _, offset := range testOffsets {
		corrupted := make([]byte, len(blob))
		copy(corrupted, blob)
		corrupted[offset] ^= 0x42

		_, err := DecryptPSK(corrupted, dk)
		if err == nil {
			t.Errorf("expected decryption error when tampering with KEM ciphertext at offset %d, got nil", offset)
		}
	}
}

// TestTamperedAEADCiphertext checks that corrupting the AEAD payload or auth tag causes decryption to fail.
func TestTamperedAEADCiphertext(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}

	_, blob, err := GenerateEncryptedPSK(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// AEAD ciphertext starts right after version (1B), KEM ciphertext (1568B), and nonce (12B).
	aeadStart := 1 + KEMCiphertextSize + NonceSize
	for i := aeadStart; i < len(blob); i += 8 {
		corrupted := make([]byte, len(blob))
		copy(corrupted, blob)
		corrupted[i] ^= 0x01

		_, err := DecryptPSK(corrupted, dk)
		if err == nil {
			t.Errorf("expected decryption error when tampering AEAD payload at byte %d, got nil", i)
		}
	}
}

// TestTamperedNonce checks that corrupting any byte of the nonce fails decryption.
func TestTamperedNonce(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}

	_, blob, err := GenerateEncryptedPSK(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	nonceStart := 1 + KEMCiphertextSize
	for i := 0; i < NonceSize; i++ {
		corrupted := make([]byte, len(blob))
		copy(corrupted, blob)
		corrupted[nonceStart+i] ^= 0x80

		_, err := DecryptPSK(corrupted, dk)
		if err == nil {
			t.Errorf("expected decryption failure when tampering nonce byte %d", i)
		}
	}
}

// TestTamperedVersion checks that an unrecognized version byte is rejected.
func TestTamperedVersion(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}

	_, blob, err := GenerateEncryptedPSK(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	corrupted := make([]byte, len(blob))
	copy(corrupted, blob)
	corrupted[0] = 0x02

	_, err = DecryptPSK(corrupted, dk)
	if err == nil {
		t.Fatal("expected error on unsupported version 0x02, got nil")
	}
}

// TestMalformedBlobSizes checks that blobs with incorrect lengths are rejected.
func TestMalformedBlobSizes(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}

	_, blob, err := GenerateEncryptedPSK(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	testSizes := []int{0, 1, 16, 500, 1568, 1628, 1630, 2048, 65536}
	for _, size := range testSizes {
		buf := make([]byte, size)
		if size > 0 && size <= len(blob) {
			copy(buf, blob[:size])
		}

		_, err := DecryptPSK(buf, dk)
		if err == nil {
			t.Errorf("expected error for malformed blob size %d, got nil", size)
		}
	}
}

// TestInvalidPublicKey checks that bad public key lengths are rejected before encapsulation.
func TestInvalidPublicKey(t *testing.T) {
	var dummyPSK [PSKSize]byte

	// 1. Wrong length (e.g. 32 bytes from X25519)
	x25519Key := make([]byte, 32)
	_, err := EncryptPSK(dummyPSK, x25519Key)
	if err == nil {
		t.Error("expected error for 32-byte key, got nil")
	}

	// 2. ML-KEM-768 key size (1184 bytes instead of 1568)
	kem768Key := make([]byte, 1184)
	_, err = EncryptPSK(dummyPSK, kem768Key)
	if err == nil {
		t.Error("expected error for 1184-byte key, got nil")
	}

	// 3. Nil key
	_, err = EncryptPSK(dummyPSK, nil)
	if err == nil {
		t.Error("expected error for nil key, got nil")
	}
}

// TestKnownAnswerTest_HKDF verifies key derivation against an independently computed literal vector.
func TestKnownAnswerTest_HKDF(t *testing.T) {
	// Fixed 32-byte test input (0x42 repeated)
	testSharedSecret := bytes.Repeat([]byte{0x42}, 32)
	const expectedHex = "a4f213d02594319d72173c58fce12bb7ce0204a48f3f0a476ca42bd624289133"

	key1, err := DeriveKey(testSharedSecret)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	actualHex := hex.EncodeToString(key1)
	if actualHex != expectedHex {
		t.Fatalf("HKDF KAT mismatch: got %s, want %s", actualHex, expectedHex)
	}

	// Must also produce identical key deterministically on repeated calls
	key2, err := DeriveKey(testSharedSecret)
	if err != nil {
		t.Fatalf("DeriveKey second run failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("HKDF is not deterministic: %x != %x", key1, key2)
	}
}

// TestRFC5869_HKDF_KAT tests the underlying HKDF-SHA256 primitive using RFC 5869 Test Case 1.
func TestRFC5869_HKDF_KAT(t *testing.T) {
	// RFC 5869 Section A.1 Test Case 1:
	// IKM  = 0x0b repeated 22 times
	// Salt = 0x000102030405060708090a0b0c (13 bytes)
	// Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
	// L    = 42 bytes
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	if err != nil {
		t.Fatal(err)
	}
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	if err != nil {
		t.Fatal(err)
	}
	const expectedOKMHex = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	okm, err := hkdf.Key(sha256.New, ikm, salt, string(info), 42)
	if err != nil {
		t.Fatalf("hkdf.Key failed: %v", err)
	}

	actualHex := hex.EncodeToString(okm)
	if actualHex != expectedOKMHex {
		t.Fatalf("RFC 5869 Test Case 1 KAT failed:\ngot:  %s\nwant: %s", actualHex, expectedOKMHex)
	}
}

// TestRFC8439_ChaCha20Poly1305_KAT verifies ChaCha20-Poly1305 against official RFC 8439 Section 2.8.2 test vector.
func TestRFC8439_ChaCha20Poly1305_KAT(t *testing.T) {
	// RFC 8439 Section 2.8.2 Test Vector
	keyHex := "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	nonceHex := "070000004041424344454647"
	aadHex := "50515253c0c1c2c3c4c5c6c7"
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	expectedSealedHex := "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := hex.DecodeString(aadHex)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	// 1. Verify Seal produces the RFC KAT ciphertext + tag
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	actualSealedHex := hex.EncodeToString(sealed)
	if actualSealedHex != expectedSealedHex {
		t.Fatalf("RFC 8439 Seal KAT mismatch:\ngot:  %s\nwant: %s", actualSealedHex, expectedSealedHex)
	}

	// 2. Verify Open authenticates and recovers the plaintext from the RFC KAT vector
	expectedSealedBytes, err := hex.DecodeString(expectedSealedHex)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := aead.Open(nil, nonce, expectedSealedBytes, aad)
	if err != nil {
		t.Fatalf("RFC 8439 Open KAT failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("RFC 8439 decrypted plaintext mismatch:\ngot:  %s\nwant: %s", string(decrypted), string(plaintext))
	}
}

// TestChaCha20Poly1305_RoundTrip verifies AEAD seal and open with arbitrary test inputs.
func TestChaCha20Poly1305_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	nonce := bytes.Repeat([]byte{0x02}, NonceSize)
	aad := []byte("quantvpn-kat-aad-v1")
	var psk [PSKSize]byte
	copy(psk[:], bytes.Repeat([]byte{0x03}, PSKSize))

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("New aead failed: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, psk[:], aad)
	if len(ciphertext) != PSKSize+Poly1305TagSize {
		t.Fatalf("unexpected ciphertext len: %d", len(ciphertext))
	}

	recovered, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("aead Open failed: %v", err)
	}

	if !bytes.Equal(recovered, psk[:]) {
		t.Fatalf("recovered bytes do not match original psk: %x != %x", recovered, psk)
	}
}

// TestAuthenticatedProvisioning tests the authenticated key provisioning protocol.
func TestAuthenticatedProvisioning(t *testing.T) {
	// 1. Client creates long-term Ed25519 identity and ephemeral ML-KEM-1024 keypair
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("generate mlkem key: %v", err)
	}
	mlkemPub := dk.EncapsulationKey().Bytes()

	var sessionNonce [16]byte
	if _, err := rand.Read(sessionNonce[:]); err != nil {
		t.Fatal(err)
	}

	ctx := ProvisionContext{
		ClientID:     "client-fra1-001",
		ServerID:     "data-plane-fra1-1",
		SessionNonce: sessionNonce,
		Timestamp:    time.Now().Unix(),
	}

	// 2. Client signs ephemeral ML-KEM key bound to context
	sig := SignClientKey(clientPriv, mlkemPub, ctx)

	// 3. Server verifies client signature before provisioning
	if err := VerifyClientKey(clientPub, mlkemPub, ctx, sig); err != nil {
		t.Fatalf("valid signature failed verification: %v", err)
	}

	// 4. Server generates encrypted PSK bound to context
	serverPSK, blob, err := GenerateEncryptedPSKWithContext(mlkemPub, ctx)
	if err != nil {
		t.Fatalf("GenerateEncryptedPSKWithContext failed: %v", err)
	}

	// 5. Client decrypts and verifies context binding
	recoveredPSK, err := DecryptPSKWithContext(blob, dk, ctx)
	if err != nil {
		t.Fatalf("DecryptPSKWithContext failed: %v", err)
	}
	if recoveredPSK != serverPSK {
		t.Fatal("recovered PSK does not match server PSK")
	}

	// 6. Security tests: Tampering resistance

	// 6a. Tampered ML-KEM public key fails signature verification
	tamperedPubKey := make([]byte, len(mlkemPub))
	copy(tamperedPubKey, mlkemPub)
	tamperedPubKey[10] ^= 0xff
	if err := VerifyClientKey(clientPub, tamperedPubKey, ctx, sig); err == nil {
		t.Error("expected error for tampered public key, got nil")
	}

	// 6b. Tampered signature fails verification
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xff
	if err := VerifyClientKey(clientPub, mlkemPub, ctx, tamperedSig); err == nil {
		t.Error("expected error for tampered signature, got nil")
	}

	// 6c. Context mismatch: Client decrypts with tampered ServerID -> AEAD tag verification fails
	badServerCtx := ctx
	badServerCtx.ServerID = "rogue-server-001"
	if _, err := DecryptPSKWithContext(blob, dk, badServerCtx); err == nil {
		t.Error("expected error decrypting with swapped ServerID, got nil")
	}

	// 6d. Context mismatch: Tampered SessionNonce -> AEAD tag verification fails
	badNonceCtx := ctx
	badNonceCtx.SessionNonce[0] ^= 0xaa
	if _, err := DecryptPSKWithContext(blob, dk, badNonceCtx); err == nil {
		t.Error("expected error decrypting with tampered SessionNonce, got nil")
	}

	// 6e. Context mismatch: Old/swapped Timestamp -> AEAD tag verification fails
	badTimeCtx := ctx
	badTimeCtx.Timestamp += 3600
	if _, err := DecryptPSKWithContext(blob, dk, badTimeCtx); err == nil {
		t.Error("expected error decrypting with modified Timestamp, got nil")
	}
}

// TestZeroization checks that Zeroize clears out memory.
func TestZeroization(t *testing.T) {
	buf := make([]byte, 64)
	_, _ = rand.Read(buf)

	Zeroize(buf)

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroed: %x", i, b)
		}
	}
}

// TestConcurrency runs concurrent encryptions and decryptions across goroutines to catch race conditions.
func TestConcurrency(t *testing.T) {
	const workers = 20
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				t.Errorf("worker %d: GenerateKey failed: %v", workerID, err)
				return
			}
			pub := dk.EncapsulationKey().Bytes()

			for i := 0; i < iterations; i++ {
				psk, blob, err := GenerateEncryptedPSK(pub)
				if err != nil {
					t.Errorf("worker %d: GenerateEncryptedPSK failed: %v", workerID, err)
					return
				}

				recovered, err := DecryptPSK(blob, dk)
				if err != nil {
					t.Errorf("worker %d: DecryptPSK failed: %v", workerID, err)
					return
				}

				if recovered != psk {
					t.Errorf("worker %d: PSK mismatch", workerID)
					return
				}
			}
		}(w)
	}

	wg.Wait()
}

// Benchmarks
func BenchmarkGenerateEncryptedPSK(b *testing.B) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		b.Fatal(err)
	}
	pub := dk.EncapsulationKey().Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = GenerateEncryptedPSK(pub)
	}
}

func BenchmarkDecryptPSK(b *testing.B) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		b.Fatal(err)
	}
	pub := dk.EncapsulationKey().Bytes()

	_, blob, err := GenerateEncryptedPSK(pub)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptPSK(blob, dk)
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		b.Fatal(err)
	}
	pub := dk.EncapsulationKey().Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, blob, _ := GenerateEncryptedPSK(pub)
		_, _ = DecryptPSK(blob, dk)
	}
}
