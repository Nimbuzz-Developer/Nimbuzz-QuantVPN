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
	"sync"
	"time"

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

	// DefaultMaxClockSkew is the maximum allowable difference between context timestamp and receiver clock.
	DefaultMaxClockSkew = 5 * time.Minute
)

var (
	ErrBadBlobSize          = errors.New("crypto: invalid encrypted PSK blob size")
	ErrUnsupportedVersion   = errors.New("crypto: unsupported blob format version")
	ErrDecryptionFailed     = errors.New("crypto: decryption failed: wrong key, corrupted blob, or context mismatch")
	ErrInvalidDecryptedSize = errors.New("crypto: invalid decrypted PSK length")
	ErrInvalidPublicKeySize = errors.New("crypto: invalid ML-KEM-1024 public key size")
	ErrClientAuthFailed     = errors.New("crypto: client identity signature verification failed")
	ErrInvalidSignatureSize = errors.New("crypto: invalid signature size")
	ErrStaleTimestamp       = errors.New("crypto: timestamp is expired or outside allowable clock skew")
	ErrZeroNonce            = errors.New("crypto: session nonce must be non-zero")
	ErrEmptyIdentity        = errors.New("crypto: client and server identity strings must not be empty")
	ErrReplayDetected       = errors.New("crypto: session nonce replay detected")
)

// ProvisionContext binds a PSK exchange to specific client and server identities.
// Binding this context into the ChaCha20-Poly1305 AAD ensures tamper-evidence and prevents
// cross-session or cross-peer mixups.
//
// NOTE ON FRESHNESS & REPLAY:
// Cryptographic AAD binding guarantees tamper-evidence and identity binding, but does NOT by itself
// enforce freshness or prevent replay if an attacker replays a valid (blob, ctx) pair.
// To guarantee freshness and prevent replay (e.g. PSK rollback), the receiver must:
//  1. Validate timestamp freshness via ctx.Validate(now, maxSkew).
//  2. Enforce session nonce uniqueness via NonceCache or a receiver-issued challenge nonce.
type ProvisionContext struct {
	ClientID     string   // Unique client identity (e.g. client ID or pubkey fingerprint)
	ServerID     string   // Designated server identity (e.g. "data-plane-fra1-1")
	SessionNonce [16]byte // Freshness nonce (must be non-zero and unique per session)
	Timestamp    int64    // Unix timestamp (seconds)
}

// Validate checks that the context contains non-empty identities, a non-zero session nonce,
// and a timestamp that falls within maxSkew of the given reference time.
func (c ProvisionContext) Validate(now time.Time, maxSkew time.Duration) error {
	if c.ClientID == "" || c.ServerID == "" {
		return ErrEmptyIdentity
	}

	var zeroNonce [16]byte
	if c.SessionNonce == zeroNonce {
		return ErrZeroNonce
	}

	if maxSkew <= 0 {
		maxSkew = DefaultMaxClockSkew
	}

	ts := time.Unix(c.Timestamp, 0)
	diff := now.Sub(ts)
	if diff < -maxSkew || diff > maxSkew {
		return fmt.Errorf("%w: timestamp %v differs from now %v by %v (max skew %v)",
			ErrStaleTimestamp, ts, now, diff, maxSkew)
	}

	return nil
}

// NonceCache provides thread-safe in-memory tracking of seen session nonces
// to enforce single-use and prevent replay attacks within the freshness window.
type NonceCache struct {
	mu      sync.Mutex
	entries map[[16]byte]time.Time
}

// NewNonceCache initializes a new in-memory replay cache.
func NewNonceCache() *NonceCache {
	return &NonceCache{
		entries: make(map[[16]byte]time.Time),
	}
}

// CheckAndAdd verifies that a session nonce has not been seen. If unseen, it records it
// with an expiration time after which it is eligible for eviction. If already seen and not
// expired, it returns ErrReplayDetected.
func (nc *NonceCache) CheckAndAdd(nonce [16]byte, expiry time.Time) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()
	// Lazy eviction of expired entries
	for k, exp := range nc.entries {
		if now.After(exp) {
			delete(nc.entries, k)
		}
	}

	if exp, exists := nc.entries[nonce]; exists && now.Before(exp) {
		return ErrReplayDetected
	}

	nc.entries[nonce] = expiry
	return nil
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
// It validates that mlkemPubKey is exactly EncapsulationKeySize1024 bytes.
func SignClientKey(priv ed25519.PrivateKey, mlkemPubKey []byte, ctx ProvisionContext) ([]byte, error) {
	if len(mlkemPubKey) != mlkem.EncapsulationKeySize1024 {
		return nil, fmt.Errorf("%w: want %d bytes, got %d",
			ErrInvalidPublicKeySize, mlkem.EncapsulationKeySize1024, len(mlkemPubKey))
	}
	payload := ClientSignaturePayload(mlkemPubKey, ctx)
	return ed25519.Sign(priv, payload), nil
}

// VerifyClientKey validates that the ML-KEM public key was signed by clientPubKey for this context.
// It validates key lengths and verifies the Ed25519 signature.
func VerifyClientKey(clientPubKey ed25519.PublicKey, mlkemPubKey []byte, ctx ProvisionContext, sig []byte) error {
	if len(mlkemPubKey) != mlkem.EncapsulationKeySize1024 {
		return fmt.Errorf("%w: want %d bytes, got %d",
			ErrInvalidPublicKeySize, mlkem.EncapsulationKeySize1024, len(mlkemPubKey))
	}
	if len(clientPubKey) != ed25519.PublicKeySize {
		return errors.New("crypto: invalid ed25519 public key size")
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignatureSize
	}
	payload := ClientSignaturePayload(mlkemPubKey, ctx)
	if !ed25519.Verify(clientPubKey, payload, sig) {
		return ErrClientAuthFailed
	}
	return nil
}

// ProvisionPSK is the unified server-side entry point that authenticates the client's ML-KEM
// public key, verifies context freshness/structure, and generates an encrypted PSK bound to the context.
// Tying signature verification directly to encryption prevents separating or mis-pairing the keys or context.
func ProvisionPSK(clientEdPub ed25519.PublicKey, clientMLKEMPub []byte, sig []byte, ctx ProvisionContext) ([PSKSize]byte, []byte, error) {
	if err := ctx.Validate(time.Now(), DefaultMaxClockSkew); err != nil {
		return [PSKSize]byte{}, nil, fmt.Errorf("validate context: %w", err)
	}
	if err := VerifyClientKey(clientEdPub, clientMLKEMPub, ctx, sig); err != nil {
		return [PSKSize]byte{}, nil, fmt.Errorf("verify client key: %w", err)
	}
	return GenerateEncryptedPSKWithContext(clientMLKEMPub, ctx)
}

// ConsumeProvisionedPSK is the unified client-side entry point that validates context freshness
// and unwraps the encrypted PSK blob, verifying the AEAD tag against the session context.
func ConsumeProvisionedPSK(blob []byte, dk *mlkem.DecapsulationKey1024, ctx ProvisionContext) ([PSKSize]byte, error) {
	if err := ctx.Validate(time.Now(), DefaultMaxClockSkew); err != nil {
		return [PSKSize]byte{}, fmt.Errorf("validate context: %w", err)
	}
	return DecryptPSKWithContext(blob, dk, ctx)
}

// Zeroize wipes byte slices so sensitive data doesn't linger in memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

// EncryptPSKWithContext encrypts an existing 32-byte WireGuard PSK to the recipient's ML-KEM-1024 public key,
// cryptographically binding the session context into the ChaCha20-Poly1305 AEAD tag.
func EncryptPSKWithContext(psk [PSKSize]byte, recipientPubKey []byte, ctx ProvisionContext) ([]byte, error) {
	return encryptPSKInternal(psk, recipientPubKey, func(kemCT []byte) []byte {
		return BuildAuthenticatedAAD(ctx, kemCT)
	})
}

// DecryptPSKWithContext unwraps an encrypted PSK blob and validates the session context in the AEAD tag.
func DecryptPSKWithContext(blob []byte, dk *mlkem.DecapsulationKey1024, ctx ProvisionContext) ([PSKSize]byte, error) {
	return decryptPSKInternal(blob, dk, func(kemCT []byte) []byte {
		return BuildAuthenticatedAAD(ctx, kemCT)
	})
}

// GenerateEncryptedPSKNoContext generates a random 32-byte WireGuard PSK and encrypts it
// using the recipient's ML-KEM-1024 public key WITHOUT client identity binding or session context.
//
// WARNING: This function provides NO client identity authentication and NO replay protection.
// Use ProvisionPSK or GenerateEncryptedPSKWithContext for secure tunnel provisioning.
func GenerateEncryptedPSKNoContext(recipientPubKey []byte) ([PSKSize]byte, []byte, error) {
	psk, err := GeneratePSK()
	if err != nil {
		return psk, nil, fmt.Errorf("generate psk: %w", err)
	}

	encrypted, err := EncryptPSKNoContext(psk, recipientPubKey)
	if err != nil {
		Zeroize(psk[:])
		return [PSKSize]byte{}, nil, fmt.Errorf("encrypt psk: %w", err)
	}

	return psk, encrypted, nil
}

// Deprecated: GenerateEncryptedPSK provides NO client identity authentication and NO replay
// protection, making it vulnerable to public key substitution attacks. Use ProvisionPSK instead.
func GenerateEncryptedPSK(recipientPubKey []byte) ([PSKSize]byte, []byte, error) {
	return GenerateEncryptedPSKNoContext(recipientPubKey)
}

// EncryptPSKNoContext encrypts an existing 32-byte WireGuard PSK to the recipient's ML-KEM-1024
// public key WITHOUT identity binding or session context.
//
// WARNING: This function provides NO client identity authentication and NO replay protection.
// Use EncryptPSKWithContext or ProvisionPSK instead.
func EncryptPSKNoContext(psk [PSKSize]byte, recipientPubKey []byte) ([]byte, error) {
	return encryptPSKInternal(psk, recipientPubKey, func(kemCT []byte) []byte {
		aad := make([]byte, 1+len(kemCT))
		aad[0] = FormatVersion
		copy(aad[1:], kemCT)
		return aad
	})
}

// Deprecated: EncryptPSK provides NO client identity authentication and NO replay protection.
// Use EncryptPSKWithContext instead.
func EncryptPSK(psk [PSKSize]byte, recipientPubKey []byte) ([]byte, error) {
	return EncryptPSKNoContext(psk, recipientPubKey)
}

// DecryptPSKNoContext unwraps an encrypted PSK blob WITHOUT verifying identity binding or session context.
//
// WARNING: This function does not verify caller identity or freshness. Use ConsumeProvisionedPSK
// or DecryptPSKWithContext instead.
func DecryptPSKNoContext(blob []byte, dk *mlkem.DecapsulationKey1024) ([PSKSize]byte, error) {
	return decryptPSKInternal(blob, dk, func(kemCT []byte) []byte {
		aad := make([]byte, 1+len(kemCT))
		aad[0] = FormatVersion
		copy(aad[1:], kemCT)
		return aad
	})
}

// Deprecated: DecryptPSK does not verify caller identity or freshness.
// Use ConsumeProvisionedPSK or DecryptPSKWithContext instead.
func DecryptPSK(blob []byte, dk *mlkem.DecapsulationKey1024) ([PSKSize]byte, error) {
	return DecryptPSKNoContext(blob, dk)
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
