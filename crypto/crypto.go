// Package crypto handles post-quantum pre-shared key (PSK) exchange for WireGuard.
// It wraps WireGuard's 32-byte PSK using ML-KEM-1024 (FIPS 203) and ChaCha20-Poly1305.
package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	ErrClientAuthFailed     = errors.New("crypto: client identity signature verification failed")
	ErrInvalidSignatureSize = errors.New("crypto: invalid signature size")
)

// ProvisionContext binds a PSK exchange to specific identities and a fresh session.
// This prevents man-in-the-middle key substitution, replays, and session mixups.
type ProvisionContext struct {
	ClientID     string   // Unique client identity (e.g. client ID or pubkey fingerprint)
	ServerID     string   // Designated server identity (e.g. "data-plane-fra1-1")
	SessionNonce [16]byte // Freshness nonce to guarantee per-session uniqueness
	Timestamp    int64    // Unix timestamp (seconds) for freshness validation
}

// BuildAuthenticatedAAD creates additional authenticated data (AAD) for ChaCha20-Poly1305.
// It cryptographically binds the format version, ML-KEM ciphertext, client ID, server ID,
// session nonce, and timestamp to the envelope authentication tag.
func BuildAuthenticatedAAD(ctx ProvisionContext, kemCT []byte) []byte {
	aad := make([]byte, 0, 1+len(kemCT)+2+len(ctx.ClientID)+2+len(ctx.ServerID)+16+8)
	aad = append(aad, FormatVersion)
	aad = append(aad, kemCT...)

	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(ctx.ClientID)))
	aad = append(aad, buf[:2]...)
	aad = append(aad, ctx.ClientID...)

	binary.BigEndian.PutUint16(buf[:2], uint16(len(ctx.ServerID)))
	aad = append(aad, buf[:2]...)
	aad = append(aad, ctx.ServerID...)

	aad = append(aad, ctx.SessionNonce[:]...)

	binary.BigEndian.PutUint64(buf[:8], uint64(ctx.Timestamp))
	aad = append(aad, buf[:8]...)

	return aad
}

// ClientSignaturePayload constructs the digest signed by the client's long-term identity key.
// It authenticates ownership of the ephemeral ML-KEM public key within the session context.
func ClientSignaturePayload(mlkemPubKey []byte, ctx ProvisionContext) []byte {
	h := sha256.New()
	h.Write([]byte("quantvpn-client-auth-v1\n"))
	h.Write(mlkemPubKey)

	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(ctx.ClientID)))
	h.Write(buf[:2])
	h.Write([]byte(ctx.ClientID))

	binary.BigEndian.PutUint16(buf[:2], uint16(len(ctx.ServerID)))
	h.Write(buf[:2])
	h.Write([]byte(ctx.ServerID))

	h.Write(ctx.SessionNonce[:])

	binary.BigEndian.PutUint64(buf[:8], uint64(ctx.Timestamp))
	h.Write(buf[:8])

	return h.Sum(nil)
}

// SignClientKey signs the client's ML-KEM public key and session context using an Ed25519 identity key.
func SignClientKey(priv ed25519.PrivateKey, mlkemPubKey []byte, ctx ProvisionContext) []byte {
	payload := ClientSignaturePayload(mlkemPubKey, ctx)
	return ed25519.Sign(priv, payload)
}

// VerifyClientKey validates that the ML-KEM public key was signed by clientPubKey for this context.
func VerifyClientKey(clientPubKey ed25519.PublicKey, mlkemPubKey []byte, ctx ProvisionContext, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignatureSize
	}
	payload := ClientSignaturePayload(mlkemPubKey, ctx)
	if !ed25519.Verify(clientPubKey, payload, sig) {
		return ErrClientAuthFailed
	}
	return nil
}

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

// GenerateEncryptedPSKWithContext generates a random 32-byte WireGuard PSK and encrypts it
// to the recipient's ML-KEM public key, binding the session context to the AEAD tag.
func GenerateEncryptedPSKWithContext(recipientPubKey []byte, ctx ProvisionContext) ([PSKSize]byte, []byte, error) {
	psk, err := GeneratePSK()
	if err != nil {
		return psk, nil, fmt.Errorf("generate psk: %w", err)
	}

	encrypted, err := EncryptPSKWithContext(psk, recipientPubKey, ctx)
	if err != nil {
		Zeroize(psk[:])
		return [PSKSize]byte{}, nil, fmt.Errorf("encrypt psk: %w", err)
	}

	return psk, encrypted, nil
}

// EncryptPSK encrypts an existing 32-byte WireGuard PSK to the recipient's ML-KEM-1024 public key.
// It encapsulates a shared secret, derives a symmetric key using HKDF-SHA256, and seals the PSK with ChaCha20-Poly1305.
func EncryptPSK(psk [PSKSize]byte, recipientPubKey []byte) ([]byte, error) {
	return encryptPSKInternal(psk, recipientPubKey, func(kemCT []byte) []byte {
		aad := make([]byte, 1+len(kemCT))
		aad[0] = FormatVersion
		copy(aad[1:], kemCT)
		return aad
	})
}

// EncryptPSKWithContext encrypts an existing 32-byte WireGuard PSK to the recipient's ML-KEM-1024 public key,
// cryptographically binding the session context into the ChaCha20-Poly1305 AEAD tag.
func EncryptPSKWithContext(psk [PSKSize]byte, recipientPubKey []byte, ctx ProvisionContext) ([]byte, error) {
	return encryptPSKInternal(psk, recipientPubKey, func(kemCT []byte) []byte {
		return BuildAuthenticatedAAD(ctx, kemCT)
	})
}

func encryptPSKInternal(psk [PSKSize]byte, recipientPubKey []byte, aadFn func(kemCT []byte) []byte) ([]byte, error) {
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

	aad := aadFn(kemCT)
	ciphertext := aead.Seal(nil, nonce, psk[:], aad)

	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

// DecryptPSK unwraps an encrypted PSK blob using the recipient's ML-KEM-1024 private key.
func DecryptPSK(blob []byte, dk *mlkem.DecapsulationKey1024) ([PSKSize]byte, error) {
	return decryptPSKInternal(blob, dk, func(kemCT []byte) []byte {
		aad := make([]byte, 1+len(kemCT))
		aad[0] = FormatVersion
		copy(aad[1:], kemCT)
		return aad
	})
}

// DecryptPSKWithContext unwraps an encrypted PSK blob and validates the session context in the AEAD tag.
func DecryptPSKWithContext(blob []byte, dk *mlkem.DecapsulationKey1024, ctx ProvisionContext) ([PSKSize]byte, error) {
	return decryptPSKInternal(blob, dk, func(kemCT []byte) []byte {
		return BuildAuthenticatedAAD(ctx, kemCT)
	})
}

func decryptPSKInternal(blob []byte, dk *mlkem.DecapsulationKey1024, aadFn func(kemCT []byte) []byte) ([PSKSize]byte, error) {
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

	aad := aadFn(kemCT)
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
