// Package sshcrypto centralises the cryptographic algorithm allowlists
// used across the client and server. Keeping them in one place makes
// the security posture of the whole project auditable at a glance.
//
// When in doubt: choose fewer algorithms, choose newer algorithms.
package sshcrypto

import "golang.org/x/crypto/ssh"

// KeyExchanges is our allowlist of KEX algorithms, preferred first.
//
//   - curve25519-sha256 (RFC 8731) — the modern default.
//   - curve25519-sha256@libssh.org — OpenSSH's pre-RFC alias, still
//     widely deployed.
//
// Deliberately excluded: diffie-hellman-group*, ecdh-sha2-nistp*
// (NIST curves are fine, but removing them shrinks the attack
// surface to the pair every modern SSH supports).
var KeyExchanges = []string{
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
}

// Ciphers is the symmetric cipher allowlist (AEAD only).
var Ciphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes256-gcm@openssh.com",
	"aes128-gcm@openssh.com",
}

// MACs is the MAC allowlist. Only encrypt-then-MAC variants are
// allowed. chacha20-poly1305 and *-gcm provide their own integrity,
// so MACs only matters if someone reaches for CBC — and we do not
// offer CBC.
var MACs = []string{
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com",
}

// HostKeyAlgorithms is the server-side signing algorithm allowlist.
var HostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// PublicKeyAlgorithms restricts the client-side user-auth signing
// algorithms the server will accept. Notably excludes the legacy
// "ssh-rsa" (SHA-1), which OpenSSH disabled by default in 8.8.
var PublicKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// ApplyToConfig fills in the algorithm lists on an ssh.Config (which
// is embedded in both ServerConfig and ClientConfig).
func ApplyToConfig(c *ssh.Config) {
	c.KeyExchanges = append([]string(nil), KeyExchanges...)
	c.Ciphers = append([]string(nil), Ciphers...)
	c.MACs = append([]string(nil), MACs...)
}
