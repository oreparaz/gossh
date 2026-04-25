// Package sshcrypto centralises the cryptographic algorithm allowlists
// used across the client and server. Keeping them in one place makes
// the security posture of the whole project auditable at a glance.
//
// We deliberately maintain TWO sets of lists:
//
//   - The "server" (no prefix) lists are tight: curve25519 KEX, AEAD
//     ciphers, ETM MACs, and SHA-2 signatures. These are what gosshd
//     advertises. Operators control both ends of any deployment, so
//     there is no compatibility-tax reason to widen the surface.
//
//   - The "Client*" lists are looser, tuned for real-world interop
//     with the SSH servers a user might actually need to reach: older
//     OpenSSH (<6.5, before curve25519 became the default), AIX,
//     Cisco/F5/vendor stacks, embedded devices. Everything added is
//     still considered cryptographically sound — no SHA-1, no
//     <2048-bit DH, no CBC.
//
// When in doubt: choose fewer algorithms, choose newer algorithms.
package sshcrypto

import "golang.org/x/crypto/ssh"

// KeyExchanges is the SERVER-side KEX allowlist.
//
//   - curve25519-sha256 (RFC 8731) — the modern default.
//   - curve25519-sha256@libssh.org — OpenSSH's pre-RFC alias.
var KeyExchanges = []string{
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
}

// ClientKeyExchanges is the CLIENT-side KEX allowlist. Adds:
//
//   - ecdh-sha2-nistp{256,384,521} — NIST P-curve ECDH. Cryptographically
//     sound; supported by OpenSSH ≥ 5.7 (2011) and virtually every
//     modern SSH server. We don't OFFER these from gosshd, but we
//     accept them when a server prefers them.
//   - diffie-hellman-group{14,16}-sha{256,512} — 2048/4096-bit MODP DH
//     with SHA-2. Supported since OpenSSH 7.3 (2016). Last-resort
//     fallback for the rare server that refuses ECDH entirely.
//
// Curve25519 stays first in the preference list, so the negotiated
// algorithm is curve25519 whenever both ends support it.
var ClientKeyExchanges = []string{
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group16-sha512",
	"diffie-hellman-group14-sha256",
}

// Ciphers is the SERVER-side symmetric cipher allowlist (AEAD only).
var Ciphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes256-gcm@openssh.com",
	"aes128-gcm@openssh.com",
}

// ClientCiphers is the CLIENT-side cipher allowlist. Adds AES-CTR for
// servers that don't offer any AEAD mode (some appliances, OpenSSH
// before 6.2's GCM addition). CTR is still considered secure when
// paired with a strong MAC; we never offer it from gosshd.
var ClientCiphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes256-gcm@openssh.com",
	"aes128-gcm@openssh.com",
	"aes256-ctr",
	"aes192-ctr",
	"aes128-ctr",
}

// MACs is the SERVER-side MAC allowlist. Only encrypt-then-MAC
// variants — chacha20-poly1305 and *-gcm provide their own integrity,
// so MACs only matters if someone reaches for CTR (server doesn't).
var MACs = []string{
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com",
}

// ClientMACs is the CLIENT-side MAC allowlist. Adds non-ETM SHA-2
// HMACs because some servers (OpenSSH < 6.2, vendor stacks) only
// offer the older encrypt-and-MAC form. SHA-2 is the floor — no
// SHA-1, no MD5, ever.
var ClientMACs = []string{
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com",
	"hmac-sha2-512",
	"hmac-sha2-256",
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

// ApplyToServerConfig fills in the server-side (tight) algorithm
// lists on an ssh.Config embedded in a ServerConfig.
func ApplyToServerConfig(c *ssh.Config) {
	c.KeyExchanges = append([]string(nil), KeyExchanges...)
	c.Ciphers = append([]string(nil), Ciphers...)
	c.MACs = append([]string(nil), MACs...)
}

// ApplyToClientConfig fills in the client-side (interop-tuned) lists
// on an ssh.Config embedded in a ClientConfig. Use this on the
// client only — see the package doc for the rationale on the
// asymmetry.
func ApplyToClientConfig(c *ssh.Config) {
	c.KeyExchanges = append([]string(nil), ClientKeyExchanges...)
	c.Ciphers = append([]string(nil), ClientCiphers...)
	c.MACs = append([]string(nil), ClientMACs...)
}
