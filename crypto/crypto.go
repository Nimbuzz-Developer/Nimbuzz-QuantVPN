// Package crypto handles post-quantum pre-shared key (PSK) exchange for WireGuard.
// It wraps WireGuard's 32-byte PSK using ML-KEM-1024 (FIPS 203) and ChaCha20-Poly1305.
package crypto

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// WireGuard expects a 32-byte pre-shared key.
	PSKSize = 32

	// FormatVersion tracks the envelope format.
	FormatVersion byte = 0x01

	// ML-KEM-1024 ciphertext is 1568 bytes.
	KEMCiphertextSize = mlkem.CiphertextSize1024

	// Standard nonce size for ChaCha20-Poly1305.
	NonceSize = 12

	// Poly1305 authentication tag length.
	Poly1305TagSize = 16

	// Total size of the encrypted envelope:
	// 1 (version) + 1568 (KEM ciphertext) + 12 (nonce) + 32 (PSK) + 16 (tag) = 1629 bytes.
	EncryptedPSKSize = 1 + KEMCiphertextSize + NonceSize + PSKSize + Poly1305TagSize

	// Domain separation string used for HKDF key derivation.
	KDFLabel = "wireguard-psk/encrypt/mlkem1024/v1"
)

var (
	ErrBadBlobSize          = errors.New("crypto: invalid encrypted PSK blob size")
	ErrUnsupportedVersion   = errors.New("crypto: unsupported blob format version")
	ErrDecryptionFailed     = errors.New("crypto: decryption failed: wrong key or corrupted blob")
	ErrInvalidDecryptedSize = errors.New("crypto: invalid decrypted PSK length")
	ErrInvalidPublicKeySize = errors.New("crypto: invalid ML-KEM-1024 public key size")
)

// Zeroize wipes byte slices so sensitive data doesn't linger in memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateEncryptedPSK generates a random 32-byte WireGuard PSK and encrypts it
// using the recipient's ML-KEM-1024 public key.
func GenerateEncryptedPSK(recipientPubKey []byte) ([PSKSize]byte, []byte, error) {
	psk, err := GeneratePSK()
	if err != nil {
		return psk, nil, fmt.Errorf("generate psk: %w", err)
	}

	encrypted, err := EncryptPSK(psk, recipientPubKey)
	if err != nil {
		Zeroize(psk[:])
		return [PSKSize]byte{}, nil, fmt.Errorf("encrypt psk: %w", err)
	}

	return psk, encrypted, nil
}

// EncryptPSK encrypts an existing 32-byte WireGuard PSK to the recipient's ML-KEM-1024 public key.
// It encapsulates a shared secret, derives a symmetric key using HKDF-SHA256, and seals the PSK with ChaCha20-Poly1305.
func EncryptPSK(psk [PSKSize]byte, recipientPubKey []byte) ([]byte, error) {
	if len(recipientPubKey) != mlkem.EncapsulationKeySize1024 {
		return nil, fmt.Errorf("%w: want %d bytes, got %d",
			ErrInvalidPublicKeySize,
			mlkem.EncapsulationKeySize1024,
			len(recipientPubKey),
		)
	}

	ek, err := mlkem.NewEncapsulationKey1024(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse encapsulation key: %w", err)
	}

	// Encapsulate gives us a 32-byte shared secret and the 1568-byte ciphertext.
	sharedSecret, kemCT := ek.Encapsulate()
	defer Zeroize(sharedSecret)

	// Derive the ChaCha20-Poly1305 key from the shared secret.
	key, err := DeriveKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	defer Zeroize(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	out := make([]byte, 0, EncryptedPSKSize)
	out = append(out, FormatVersion)
	out = append(out, kemCT...)

	// Bind the version byte and KEM ciphertext into the AEAD authenticated data.
	aad := out[:1+KEMCiphertextSize]

	ciphertext := aead.Seal(nil, nonce, psk[:], aad)

	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

// DecryptPSK unwraps an encrypted PSK blob using the recipient's ML-KEM-1024 private key.
func DecryptPSK(blob []byte, dk *mlkem.DecapsulationKey1024) ([PSKSize]byte, error) {
	var psk [PSKSize]byte

	if len(blob) != EncryptedPSKSize {
		return psk, fmt.Errorf("%w: got %d, want %d", ErrBadBlobSize, len(blob), EncryptedPSKSize)
	}

	if blob[0] != FormatVersion {
		return psk, fmt.Errorf("%w: %d", ErrUnsupportedVersion, blob[0])
	}

	kemCT := blob[1 : 1+KEMCiphertextSize]
	nonce := blob[1+KEMCiphertextSize : 1+KEMCiphertextSize+NonceSize]
	sealed := blob[1+KEMCiphertextSize+NonceSize:]

	// Recover the shared secret from the KEM ciphertext.
	sharedSecret, err := dk.Decapsulate(kemCT)
	if err != nil {
		return psk, fmt.Errorf("decapsulate kem ciphertext: %w", err)
	}
	defer Zeroize(sharedSecret)

	// Derive the same ChaCha20-Poly1305 key using HKDF.
	key, err := DeriveKey(sharedSecret)
	if err != nil {
		return psk, fmt.Errorf("derive key: %w", err)
	}
	defer Zeroize(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return psk, fmt.Errorf("create aead: %w", err)
	}

	aad := blob[:1+KEMCiphertextSize]
	plain, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return psk, ErrDecryptionFailed
	}
	defer Zeroize(plain)

	if len(plain) != PSKSize {
		return psk, ErrInvalidDecryptedSize
	}

	copy(psk[:], plain)
	return psk, nil
}

// GeneratePSK creates a random 32-byte key using crypto/rand.
func GeneratePSK() ([PSKSize]byte, error) {
	var psk [PSKSize]byte
	if _, err := io.ReadFull(rand.Reader, psk[:]); err != nil {
		return psk, fmt.Errorf("read random bytes: %w", err)
	}
	return psk, nil
}

// DeriveKey derives a 32-byte key from an ML-KEM shared secret via HKDF-SHA256.
func DeriveKey(sharedSecret []byte) ([]byte, error) {
	return hkdf.Key(
		sha256.New,
		sharedSecret,
		nil,
		KDFLabel,
		32,
	)
}
