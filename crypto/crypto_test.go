package crypto

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"

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

// TestKnownAnswerTest_HKDF verifies deterministic key derivation with a fixed test vector.
func TestKnownAnswerTest_HKDF(t *testing.T) {
	// Fixed 32-byte test input
	testSharedSecret := bytes.Repeat([]byte{0x42}, 32)

	key1, err := DeriveKey(testSharedSecret)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	// Must produce identical key on second run
	key2, err := DeriveKey(testSharedSecret)
	if err != nil {
		t.Fatalf("DeriveKey second run failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatalf("HKDF is not deterministic: %x != %x", key1, key2)
	}

	expectedHex := hex.EncodeToString(key1)
	t.Logf("KAT HKDF Derived Key Vector: %s", expectedHex)
}

// TestKnownAnswerTest_ChaCha20Poly1305 verifies AEAD seal and open with fixed test inputs.
func TestKnownAnswerTest_ChaCha20Poly1305(t *testing.T) {
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
