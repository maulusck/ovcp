// Package pki: native PKI for OVCP. No easy-rsa, no shell-outs.
package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/crypto/argon2"
)

// envelope is the on-disk format for encrypted private keys.
// Key material is sealed with AES-256-GCM; the key is derived from the
// operator passphrase via argon2id. The passphrase is never persisted.
type envelope struct {
	V       int    `json:"v"`
	KDF     string `json:"kdf"` // "argon2id"
	Time    uint32 `json:"t"`
	MemKiB  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	CT      []byte `json:"ct"`
}

var ErrBadPassphrase = errors.New("pki: wrong passphrase or corrupt key file")

const (
	kdfTime    = 2
	kdfMemKiB  = 64 * 1024
	kdfThreads = 4
)

// Seal encrypts plaintext under passphrase (argon2id + AES-256-GCM) into a versioned envelope; also used by internal/backup.
func Seal(plaintext, passphrase []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, kdfTime, kdfMemKiB, kdfThreads, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	e := envelope{
		V: 1, KDF: "argon2id",
		Time: kdfTime, MemKiB: kdfMemKiB, Threads: kdfThreads,
		Salt: salt, Nonce: nonce,
		CT: gcm.Seal(nil, nonce, plaintext, nil),
	}
	return json.Marshal(e)
}

// Open reverses Seal; ErrBadPassphrase covers a wrong passphrase or tampered input (AES-GCM is authenticated, not just encrypted).
func Open(data, passphrase []byte) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, ErrBadPassphrase
	}
	if e.KDF != "argon2id" || e.V != 1 {
		return nil, errors.New("pki: unsupported key envelope")
	}
	key := argon2.IDKey(passphrase, e.Salt, e.Time, e.MemKiB, e.Threads, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, e.Nonce, e.CT, nil)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return pt, nil
}

func sealToFile(path string, plaintext, passphrase []byte) error {
	data, err := Seal(plaintext, passphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func openFromFile(path string, passphrase []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Open(data, passphrase)
}
