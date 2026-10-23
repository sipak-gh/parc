// File-name encryption. A name is padded to a fixed size and encrypted to the
// recipient's X25519 public key (ECIES-style), so any holder of the public key can
// create encrypted names but only the private key holder can read them.
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// encExt marks parc files; encrypted names always end with it.
const encExt = ".parc"

// Every encrypted name has the same length regardless of the original name:
// ephemeral X25519 key (32) | AEAD(padded block (96)) | tag (16) = 144 bytes
// -> 231 base32 characters, plus the extension.
const (
	nameBlockSize = 96 // 1 length byte + up to maxNameLen bytes + zero padding
	maxNameLen    = nameBlockSize - 1
	rawNameLen    = 32 + nameBlockSize + chacha20poly1305.Overhead
	nameInfo      = "parc-name-v2"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var errBadName = errors.New("not a parc-encrypted name")

// nameAEAD derives the per-name ChaCha20-Poly1305 key from the ECDH shared
// secret, binding both public keys into the derivation.
func nameAEAD(shared, ephPub, recipient []byte) (cipher.AEAD, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	salt := append(append([]byte{}, ephPub...), recipient...)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(nameInfo)), key); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// encryptName pads name to a fixed size and encrypts it to the recipient's
// public key (ephemeral X25519 + ChaCha20-Poly1305). The ephemeral key is fresh
// per call, so equal names encrypt differently. The result is lowercase base32,
// which is URL and case-insensitive-filesystem safe.
func encryptName(km *keyMaterial, name string) (string, error) {
	if len(name) == 0 || len(name) > maxNameLen {
		return "", fmt.Errorf("file name %q must be 1-%d bytes to be encrypted", name, maxNameLen)
	}
	eph := make([]byte, 32)
	if _, err := rand.Read(eph); err != nil {
		return "", err
	}
	ephPub, err := curve25519.X25519(eph, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	shared, err := curve25519.X25519(eph, km.nameRecipient[:])
	if err != nil {
		return "", err
	}
	aead, err := nameAEAD(shared, ephPub, km.nameRecipient[:])
	if err != nil {
		return "", err
	}
	block := make([]byte, nameBlockSize)
	block[0] = byte(len(name))
	copy(block[1:], name)
	// The key is unique per name, so a zero nonce is safe.
	out := aead.Seal(ephPub, make([]byte, aead.NonceSize()), block, nil)
	return strings.ToLower(b32.EncodeToString(out)) + encExt, nil
}

// decryptName reverses encryptName. It fails for anything that is not a
// well-formed parc name for this key. Needs a private key.
func decryptName(km *keyMaterial, encName string) (string, error) {
	if km.nameSecret == nil {
		return "", errors.New("a private key is required to decrypt names")
	}
	if len(encName) <= len(encExt) || !strings.EqualFold(encName[len(encName)-len(encExt):], encExt) {
		return "", errBadName
	}
	raw, err := b32.DecodeString(strings.ToUpper(encName[:len(encName)-len(encExt)]))
	if err != nil || len(raw) != rawNameLen {
		return "", errBadName
	}
	ephPub, ct := raw[:32], raw[32:]
	shared, err := curve25519.X25519(km.nameSecret, ephPub)
	if err != nil {
		return "", errBadName
	}
	aead, err := nameAEAD(shared, ephPub, km.nameRecipient[:])
	if err != nil {
		return "", err
	}
	block, err := aead.Open(nil, make([]byte, aead.NonceSize()), ct, nil)
	if err != nil {
		return "", errors.New("cannot decrypt name (wrong key or not a parc file)")
	}
	n := int(block[0])
	if n == 0 || n > maxNameLen {
		return "", errBadName
	}
	for _, b := range block[1+n:] {
		if b != 0 {
			return "", errBadName
		}
	}
	return string(block[1 : 1+n]), nil
}
