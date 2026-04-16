# gossh / gosshd

A minimal, security-focused SSH client and server written in Go.
Interoperable with OpenSSH. Drop-in replacement for simple use cases.

## Status

Work in progress.

## Goals

- **Security first.** Conservative algorithm choices. No legacy ciphers. No password auth by default.
- **Correctness.** Wire-compatible with OpenSSH for the supported feature set.
- **Simplicity.** Small codebase, small surface area, easy to audit.
- **Tested.** TDD with integration tests against the system `ssh` / `sshd`.

## Supported

- Host keys: ed25519, RSA (>= 3072 bits)
- User auth: public-key only
- Sessions: interactive PTY (bash), exec, subsystems
- Forwarding: `-L` (direct-tcpip), `-R` (tcpip-forward), `-D` (SOCKS5)

## Not supported (by design)

- Password / keyboard-interactive auth (use keys)
- SSHv1 (obsolete)
- Legacy ciphers: 3DES, Blowfish, CAST, RC4, AES-CBC
- Legacy KEX: DH group1/group14-sha1, ECDH-sha1
- GSSAPI / Kerberos
- X11 forwarding
- Agent forwarding (security footgun)

## Algorithm allowlist

- KEX: `curve25519-sha256`, `curve25519-sha256@libssh.org`
- Ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`
- MACs: `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`
- Host key / pubkey: `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`

## Build

```
make build
```

Binaries land in `./bin/`.

## Test

```
make test           # unit + fast integration
make test-interop   # full interop with system ssh/sshd
```
