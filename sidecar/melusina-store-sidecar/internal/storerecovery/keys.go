package storerecovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	primitives "github.com/melusina-os/melusina-solana-primitives"
	"golang.org/x/crypto/hkdf"
)

// Recovery keys are X25519 keys. A recipient is written exactly as the
// deployer's backupcrypto writes one ("x25519:" and the unpadded base64url of
// the 32-byte public key), so one holder key can be named as a recipient in
// both the deployer's provider-identity escrow and this Store escrow.
const (
	recipientPrefix  = "x25519:"
	privateKeyPrefix = "x25519-private:"
	keySize          = 32
	maxKeyFileBytes  = 256
	sealKeyInfo      = "melusina-store-recovery-seal-v1"
)

// SealedEnvelopeV1 is a payload sealed to one recipient: an ephemeral X25519
// agreement, HKDF-SHA256 and AES-256-GCM. The key is derived from a fresh
// ephemeral key for every envelope, so no key ever seals twice; every public
// field of the enclosing document is bound into both the key derivation and
// the associated data, so an envelope cannot be moved to another document,
// role or recipient.
//
// The construction differs from the deployer's escrow only in the AEAD
// (AES-256-GCM rather than XChaCha20-Poly1305): the Store module vendors no
// ChaCha20 implementation, and a single-use key makes the 96-bit nonce safe.
type SealedEnvelopeV1 struct {
	Recipient  string `json:"recipient"`
	Ephemeral  string `json:"ephemeral"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// EncodeRecipient renders an X25519 public key as a recipient string.
func EncodeRecipient(public *ecdh.PublicKey) string {
	return recipientPrefix + base64.RawURLEncoding.EncodeToString(public.Bytes())
}

// ParseRecipient parses a canonical recipient string.
func ParseRecipient(value string) (*ecdh.PublicKey, error) {
	raw, ok := strings.CutPrefix(value, recipientPrefix)
	if !ok {
		return nil, errors.New("recipient is not an x25519 key")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != keySize || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, errors.New("recipient is not a canonical x25519 key")
	}
	return ecdh.X25519().NewPublicKey(decoded)
}

// GenerateRecoveryKey returns a fresh X25519 key: a holder key or a restore
// session key.
func GenerateRecoveryKey(random io.Reader) (*ecdh.PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	return ecdh.X25519().GenerateKey(random)
}

// EncodePrivateKey renders a private key for a mode-0600 key file.
func EncodePrivateKey(private *ecdh.PrivateKey) string {
	return privateKeyPrefix + base64.RawURLEncoding.EncodeToString(private.Bytes()) + "\n"
}

// ParsePrivateKey parses the content of a key file.
func ParsePrivateKey(content []byte) (*ecdh.PrivateKey, error) {
	text := strings.TrimSuffix(string(content), "\n")
	raw, ok := strings.CutPrefix(text, privateKeyPrefix)
	if !ok {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, "not an x25519 private key")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != keySize || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, "not a canonical x25519 private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(decoded)
	clear(decoded)
	if err != nil {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, "not a usable x25519 private key")
	}
	return private, nil
}

// WritePrivateKeyFile creates path, which must not exist, as a mode-0600 key
// file.
func WritePrivateKeyFile(path string, private *ecdh.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return Refuse(RefusalIdentityKeyFileInvalid, "create "+path+": "+err.Error())
	}
	content := []byte(EncodePrivateKey(private))
	defer clear(content)
	if _, err := f.Write(content); err != nil {
		f.Close()
		return Refuse(RefusalIdentityKeyFileInvalid, "write "+path+": "+err.Error())
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return Refuse(RefusalIdentityKeyFileInvalid, "sync "+path+": "+err.Error())
	}
	return f.Close()
}

// ReadPrivateKeyFile reads a key file that is a regular, owner-only file.
func ReadPrivateKeyFile(path string) (*ecdh.PrivateKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, "open "+path+": "+err.Error())
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxKeyFileBytes {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, path+" must be a regular owner-only file")
	}
	content, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	defer clear(content)
	if err != nil {
		return nil, Refuse(RefusalIdentityKeyFileInvalid, "read "+path+": "+err.Error())
	}
	return ParsePrivateKey(content)
}

// DestroyPrivateKeyFile overwrites a key file with zeros, syncs it and
// removes it. A restore session key is destroyed this way once the shards it
// received are written.
func DestroyPrivateKeyFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil && info.Mode().IsRegular() {
		_, err = f.Write(make([]byte, info.Size()))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Remove(path)
}

func sealTo(random io.Reader, recipient string, binding []string, plaintext []byte) (SealedEnvelopeV1, error) {
	public, err := ParseRecipient(recipient)
	if err != nil {
		return SealedEnvelopeV1{}, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return SealedEnvelopeV1{}, err
	}
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		return SealedEnvelopeV1{}, errors.New("the recipient key cannot be agreed with")
	}
	envelope := SealedEnvelopeV1{Recipient: recipient, Ephemeral: EncodeRecipient(ephemeral.PublicKey())}
	aead, bound, err := envelopeAEAD(shared, binding, envelope)
	clear(shared)
	if err != nil {
		return SealedEnvelopeV1{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return SealedEnvelopeV1{}, err
	}
	envelope.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, bound))
	return envelope, nil
}

func openFrom(private *ecdh.PrivateKey, binding []string, envelope SealedEnvelopeV1) ([]byte, error) {
	if private == nil || envelope.Recipient != EncodeRecipient(private.PublicKey()) {
		return nil, errors.New("the envelope is not sealed to this key")
	}
	ephemeral, err := ParseRecipient(envelope.Ephemeral)
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, errors.New("the envelope's ephemeral key cannot be agreed with")
	}
	aead, bound, err := envelopeAEAD(shared, binding, envelope)
	clear(shared)
	if err != nil {
		return nil, err
	}
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	sealed, sealedErr := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if nonceErr != nil || sealedErr != nil || len(nonce) != aead.NonceSize() ||
		base64.RawURLEncoding.EncodeToString(nonce) != envelope.Nonce || base64.RawURLEncoding.EncodeToString(sealed) != envelope.Ciphertext {
		return nil, errors.New("the envelope is malformed")
	}
	plaintext, err := aead.Open(nil, nonce, sealed, bound)
	if err != nil {
		return nil, errors.New("the envelope does not open")
	}
	return plaintext, nil
}

func envelopeAEAD(shared []byte, binding []string, envelope SealedEnvelopeV1) (cipher.AEAD, []byte, error) {
	for _, field := range binding {
		if strings.ContainsRune(field, '\n') {
			return nil, nil, errors.New("a bound field contains a newline")
		}
	}
	bound := []byte(strings.Join(append(append([]string(nil), binding...), envelope.Recipient, envelope.Ephemeral), "\n"))
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, append([]byte(sealKeyInfo+"|"), bound...)), key); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, bound, nil
}

// parseEd25519Key parses a canonical base58 Ed25519 public key.
func parseEd25519Key(value string) (ed25519.PublicKey, error) {
	key, err := primitives.PubkeyFromBase58(value)
	if err != nil || key.Base58() != value {
		return nil, errors.New("not a canonical base58 Ed25519 key")
	}
	return ed25519.PublicKey(append([]byte(nil), key[:]...)), nil
}
