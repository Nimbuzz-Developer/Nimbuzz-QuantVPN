package main

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	pskSize = 32

	version   = 0x01
	kemCtSize = mlkem.CiphertextSize1024 // 1568 bytes
	nonceSize = 12

	encryptedPSKSize = 1 + kemCtSize + nonceSize + pskSize + 16 // 1 + 1568 + 12 + 32 + 16 = 1629 bytes

	kdfLabel = "wireguard-psk/encrypt/mlkem1024/v1"
)

func GenerateEncryptedPSK(recipientPubKey []byte) (psk [32]byte, encrypted []byte, err error) {
	psk, err = GeneratePSK()
	if err != nil {
		return psk, nil, err
	}

	encrypted, err = EncryptPSK(psk, recipientPubKey)
	return psk, encrypted, err
}

func EncryptPSK(psk [32]byte, recipientPubKey []byte) ([]byte, error) {
	if len(recipientPubKey) != mlkem.EncapsulationKeySize1024 {
		return nil, fmt.Errorf(
			"want %d-byte ML-KEM-1024 public key, got %d bytes",
			mlkem.EncapsulationKeySize1024,
			len(recipientPubKey),
		)
	}

	ek, err := mlkem.NewEncapsulationKey1024(recipientPubKey)
	if err != nil {
		return nil, err
	}

	// Generate a fresh shared secret and KEM ciphertext.
	sharedSecret, kemCT := ek.Encapsulate()
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Derive the ChaCha20-Poly1305 key from the shared secret.
	key, err := deriveKey(sharedSecret)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, encryptedPSKSize)
	out = append(out, version)
	out = append(out, kemCT...)

	// Authenticate the version and KEM ciphertext.
	aad := out[:1+kemCtSize]

	ciphertext := aead.Seal(nil, nonce, psk[:], aad)

	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func DecryptPSK(blob []byte, dk *mlkem.DecapsulationKey1024) ([32]byte, error) {
	var psk [32]byte

	if len(blob) != encryptedPSKSize {
		return psk, fmt.Errorf(
			"bad blob size: got %d, want %d",
			len(blob),
			encryptedPSKSize,
		)
	}

	if blob[0] != version {
		return psk, fmt.Errorf(
			"unsupported format version %d",
			blob[0],
		)
	}

	kemCT := blob[1 : 1+kemCtSize]
	nonce := blob[1+kemCtSize : 1+kemCtSize+nonceSize]
	sealed := blob[1+kemCtSize+nonceSize:]

	// Decapsulate the ciphertext to recover the shared secret.
	sharedSecret, err := dk.Decapsulate(kemCT)
	if err != nil {
		return psk, err
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	key, err := deriveKey(sharedSecret)
	if err != nil {
		return psk, err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return psk, err
	}

	plain, err := aead.Open(
		nil,
		nonce,
		sealed,
		blob[:1+kemCtSize],
	)
	if err != nil {
		return psk, errors.New(
			"decryption failed: wrong key or corrupted blob",
		)
	}

	if len(plain) != pskSize {
		return psk, errors.New("invalid decrypted PSK size")
	}

	copy(psk[:], plain)

	return psk, nil
}

func GeneratePSK() ([32]byte, error) {
	var psk [32]byte

	_, err := rand.Read(psk[:])

	return psk, err
}

func deriveKey(sharedSecret []byte) ([]byte, error) {
	// Fixed context keeps key derivation consistent between both sides.
	return hkdf.Key(
		sha256.New,
		sharedSecret,
		nil,
		kdfLabel,
		32,
	)
}

func main() {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		panic(err)
	}

	pub := dk.EncapsulationKey().Bytes()

	psk, blob, err := GenerateEncryptedPSK(pub)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"PSK:       %s\n",
		base64.StdEncoding.EncodeToString(psk[:]),
	)

	fmt.Printf(
		"Blob:      %d bytes\n",
		len(blob),
	)

	got, err := DecryptPSK(blob, dk)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"Recovered: %s (match: %v)\n",
		base64.StdEncoding.EncodeToString(got[:]),
		got == psk,
	)
}
