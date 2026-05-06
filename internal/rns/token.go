package rns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Token is Reticulum's modified-Fernet authenticated encryption scheme
// (SPEC §3). The opportunistic on-the-wire form is:
//
//	ephemeral_X25519_pub(32) || IV(16) || AES-256-CBC ciphertext(N*16) || HMAC-SHA256(32)
//
// HKDF-SHA256 derives a (signing_key, encryption_key) pair from the X25519
// shared secret. The salt is the *recipient's identity hash* (NOT the
// destination hash) — see SPEC §3.2 / §9 implementation gotchas. Forgetting
// this is the most common reason a from-scratch implementation can encrypt
// to upstream RNS but not be decrypted by it.

const (
	tokenEphPubLen = 32
	tokenIVLen     = 16
	tokenHMACLen   = 32

	// tokenOverhead is the fixed-size envelope (eph_pub + IV + HMAC) that
	// wraps the AES-CBC ciphertext.
	tokenOverhead = tokenEphPubLen + tokenIVLen + tokenHMACLen

	tokenAESKeyLen  = 32 // AES-256
	tokenHMACKeyLen = 32
)

// TokenEncrypt produces an opportunistic-form Token ciphertext that the
// holder of the recipient's identity (and only that holder) can decrypt.
// recipientX25519Pub must be 32 bytes; recipientIdentityHash must be 16 bytes
// (the HKDF salt — see comment above).
func TokenEncrypt(plaintext, recipientX25519Pub, recipientIdentityHash []byte) ([]byte, error) {
	if len(recipientX25519Pub) != 32 {
		return nil, errors.New("recipient X25519 public must be 32 bytes")
	}
	if len(recipientIdentityHash) != IdentityHashLen {
		return nil, fmt.Errorf("recipient identity hash must be %d bytes", IdentityHashLen)
	}

	// 1. Generate ephemeral X25519 keypair.
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, fmt.Errorf("ephemeral key randomness: %w", err)
	}
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral X25519 public: %w", err)
	}

	// 2. ECDH shared secret with recipient's long-term X25519 public.
	shared, err := curve25519.X25519(ephPriv[:], recipientX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// 3. HKDF-SHA256 with salt = recipient's identity hash; 64 bytes total
	// split as signing_key || encryption_key.
	signingKey, encryptionKey, err := tokenDeriveKeys(shared, recipientIdentityHash)
	if err != nil {
		return nil, err
	}

	// 4. AES-256-CBC encrypt with PKCS#7 padding and a random IV.
	iv := make([]byte, tokenIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("IV randomness: %w", err)
	}
	ciphertext, err := aesCBCEncrypt(encryptionKey, iv, plaintext)
	if err != nil {
		return nil, err
	}

	// 5. HMAC-SHA256 over (IV || ciphertext) — encrypt-then-MAC.
	mac := hmacSHA256(signingKey, iv, ciphertext)

	// 6. Concatenate wire form.
	out := make([]byte, 0, tokenOverhead+len(ciphertext))
	out = append(out, ephPub...)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	out = append(out, mac...)
	return out, nil
}

// TokenDecrypt verifies the HMAC and (on success) AES-CBC decrypts the
// payload. Only the long-term X25519 private key is used here. Ratchet
// support is deferred (SPEC §7.3 / §7.4).
func TokenDecrypt(id *Identity, wire []byte) ([]byte, error) {
	if id == nil {
		return nil, errors.New("nil identity")
	}
	if len(wire) < tokenOverhead+aes.BlockSize {
		return nil, fmt.Errorf("token too short: %d bytes (need >= %d)", len(wire), tokenOverhead+aes.BlockSize)
	}
	if (len(wire)-tokenOverhead)%aes.BlockSize != 0 {
		return nil, errors.New("token ciphertext not block-aligned")
	}

	ephPub := wire[:tokenEphPubLen]
	iv := wire[tokenEphPubLen : tokenEphPubLen+tokenIVLen]
	mac := wire[len(wire)-tokenHMACLen:]
	ciphertext := wire[tokenEphPubLen+tokenIVLen : len(wire)-tokenHMACLen]

	// ECDH with our long-term X25519 private key.
	shared, err := curve25519.X25519(id.x25519Priv[:], ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// HKDF salt is OUR identity hash — we are the recipient.
	signingKey, encryptionKey, err := tokenDeriveKeys(shared, id.Hash())
	if err != nil {
		return nil, err
	}

	// Verify HMAC BEFORE decrypting (encrypt-then-MAC; defends against
	// padding-oracle attacks).
	expectedMAC := hmacSHA256(signingKey, iv, ciphertext)
	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("token HMAC mismatch")
	}

	plaintext, err := aesCBCDecrypt(encryptionKey, iv, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func tokenDeriveKeys(sharedSecret, salt []byte) (signingKey, encryptionKey []byte, err error) {
	r := hkdf.New(sha256.New, sharedSecret, salt, nil /* info */)
	derived := make([]byte, tokenHMACKeyLen+tokenAESKeyLen)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, nil, fmt.Errorf("HKDF: %w", err)
	}
	signingKey = derived[:tokenHMACKeyLen]
	encryptionKey = derived[tokenHMACKeyLen:]
	return signingKey, encryptionKey, nil
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func aesCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	return pkcs7Unpad(padded, block.BlockSize())
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("bad padded length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("bad PKCS#7 padding length")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, errors.New("bad PKCS#7 padding bytes")
		}
	}
	return data[:len(data)-padLen], nil
}
