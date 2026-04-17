// Package hostkey manages SSH host/user key pairs on disk.
//
// Keys are stored in the OpenSSH PEM format that ssh-keygen produces:
// private keys as -----BEGIN OPENSSH PRIVATE KEY----- with mode 0600,
// public keys as "algorithm base64 comment" with mode 0644.
package hostkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// MinRSABits is the smallest RSA modulus we will generate or load.
// NIST SP 800-57 considers < 2048 unsafe after 2030; we set a higher
// floor to match current OpenSSH defaults.
const MinRSABits = 3072

// Algorithm identifies the type of key we generate.
type Algorithm string

const (
	Ed25519 Algorithm = "ed25519"
	RSA     Algorithm = "rsa"
)

// KeyPair is a generated or loaded key with helpers for persistence.
type KeyPair struct {
	Signer  ssh.Signer
	Private crypto.PrivateKey
	Comment string
}

// GenerateEd25519 creates a new Ed25519 key pair.
func GenerateEd25519(comment string) (*KeyPair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 generate: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return &KeyPair{Signer: signer, Private: priv, Comment: comment}, nil
}

// GenerateRSA creates a new RSA key pair of the given bit size.
// bits must be >= MinRSABits; weaker keys are refused.
func GenerateRSA(bits int, comment string) (*KeyPair, error) {
	if bits < MinRSABits {
		return nil, fmt.Errorf("rsa: refusing to generate key with %d bits (minimum %d)", bits, MinRSABits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generate: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return &KeyPair{Signer: signer, Private: priv, Comment: comment}, nil
}

// Generate picks an algorithm and returns a new key pair.
// For RSA, bits is the modulus size; it is ignored for Ed25519.
func Generate(alg Algorithm, bits int, comment string) (*KeyPair, error) {
	switch alg {
	case Ed25519:
		return GenerateEd25519(comment)
	case RSA:
		return GenerateRSA(bits, comment)
	default:
		return nil, fmt.Errorf("unknown algorithm %q", alg)
	}
}

// Save writes the key pair to disk.
//
//	<path>      -- private key, mode 0600 (OpenSSH PEM)
//	<path>.pub  -- public key, mode 0644 (authorized_keys format)
//
// The parent directory must already exist. Save refuses to overwrite
// an existing private-key file; callers must remove it first if they
// want a rotation.
func (kp *KeyPair) Save(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing key at %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	privPEM, err := ssh.MarshalPrivateKey(kp.Private, kp.Comment)
	if err != nil {
		return fmt.Errorf("marshal private: %w", err)
	}
	privBytes := pem.EncodeToMemory(privPEM)
	// Create with 0600 directly to avoid a window where the file is world-readable.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private: %w", err)
	}
	if _, err := f.Write(privBytes); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("write private: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	pubBytes := ssh.MarshalAuthorizedKey(kp.Signer.PublicKey())
	if kp.Comment != "" {
		// ssh.MarshalAuthorizedKey does not embed a comment; append ours.
		pubBytes = appendComment(pubBytes, kp.Comment)
	}
	pubPath := path + ".pub"
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("write public: %w", err)
	}
	return nil
}

// Load reads a private key file (and public, if present) from disk.
// It refuses keys that are world- or group-readable: SSH will, too.
//
// The permission check uses the opened file descriptor (fstat) to
// close a TOCTOU where an attacker swaps in a world-readable file
// between stat and open.
func Load(path string) (*KeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("permissions %#o on %s are too open (want 0600)", mode, path)
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	priv, err := ssh.ParseRawPrivateKey(buf)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// If it's RSA, enforce minimum size on load as well.
	if rsaKey, ok := priv.(*rsa.PrivateKey); ok {
		if rsaKey.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("rsa key %s has %d bits (minimum %d)", path, rsaKey.N.BitLen(), MinRSABits)
		}
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	return &KeyPair{Signer: signer, Private: priv, Comment: filepath.Base(path)}, nil
}

// LoadOrGenerate loads the key at path, creating it with the given
// algorithm if the file is missing. Concurrency-safe it is not; the
// caller must serialize calls for a given path.
func LoadOrGenerate(path string, alg Algorithm, bits int, comment string) (*KeyPair, error) {
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	kp, err := Generate(alg, bits, comment)
	if err != nil {
		return nil, err
	}
	if err := kp.Save(path); err != nil {
		return nil, err
	}
	return kp, nil
}

func appendComment(pubBytes []byte, comment string) []byte {
	// pubBytes ends in "\n". Insert comment before newline.
	if len(pubBytes) == 0 {
		return pubBytes
	}
	trimmed := pubBytes
	if trimmed[len(trimmed)-1] == '\n' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	out := make([]byte, 0, len(trimmed)+1+len(comment)+1)
	out = append(out, trimmed...)
	out = append(out, ' ')
	out = append(out, []byte(comment)...)
	out = append(out, '\n')
	return out
}
