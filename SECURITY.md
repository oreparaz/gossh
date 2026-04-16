# Security model

## Threat model

`gossh` / `gosshd` are designed for small, trusted deployments: a
single-user box, a bastion that only you use, a CI runner. The threat
model is:

- **Network attacker** (full MITM): cannot recover plaintext; cannot
  impersonate the server given a trusted host key.
- **Credential leak**: a stolen user private key lets the attacker
  log in. A stolen host key lets the attacker impersonate the server
  to anyone who connects.
- **Malicious client on authenticated session**: runs commands as
  the server's user. This is expected — gosshd does *not* attempt
  privilege separation.

Threats **outside** the model:

- Multi-user Linux boxes with per-user authorized_keys files and uid
  switching — we do not do this. Use OpenSSH.
- Kernel-level side channels against the host key. We rely on
  `golang.org/x/crypto/ssh` and the Go runtime.

## Cryptographic allowlist

Centralised in `internal/sshcrypto/algs.go`. The server and client
negotiate using the same lists:

| Category      | Algorithms                                          |
|---------------|-----------------------------------------------------|
| KEX           | `curve25519-sha256`, `curve25519-sha256@libssh.org` |
| Cipher (AEAD) | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` |
| MAC (ETM)     | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` |
| Host key / user key | `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256` |

Everything else (ssh-rsa/SHA-1, DH group1/14-sha1, NIST ECDH, AES-CBC,
3DES, RC4, HMAC-SHA1) is refused. See `sshcrypto/algs_test.go` for
the automated check.

## Server hardening

- **Public-key auth only.** No password, no keyboard-interactive, no
  host-based. The `ssh.ServerConfig` does not set those callbacks.
- **Login grace time** (`-login-grace`, default 120s): the TCP
  deadline is armed before the handshake and cleared on success;
  slow clients are dropped.
- **Max auth tries** (`-max-auth-tries`, default 6).
- **Per-IP concurrent connection cap** (`-max-per-ip`, default 10).
- **authorized_keys permissions check**: group- or world-writable
  files are rejected at startup.
- **Private key permission check**: world- or group-readable host
  key files are rejected on load.
- **RSA minimum size 3072 bits** at both generation and load.
- **`restrict`, `command=`, `from=`, `permitopen=`, `permitlisten=`,
  `no-port-forwarding`** are all enforced by the server; the
  `authkeys` package tests exercise them.
- **env allowlist**: clients may set TERM, LANG, LC_* — nothing
  else gets into the child environment.
- **Forwarding disabled by default.** `-L` needs `-allow-local-forward`,
  `-R` needs `-allow-remote-forward`.

## Client hardening

- **Strict host-key checking by default.** `-strict-host-key yes`
  refuses unknown hosts. `accept-new` is TOFU.
  The host-key file is locked with 0600 perms on creation.
- **Host-key mismatch is always fatal.** There is no prompt to
  overwrite.
- **Identity files** are rejected if loose perms (>0600) are set,
  mirroring the server-side check.

## Things we intentionally *do not* support

These are either obsolete or open wider attack surface than they
justify for the 80%-of-OpenSSH goal:

- SSHv1.
- Password / keyboard-interactive authentication.
- Agent forwarding (`-A`): lets a malicious remote host use your
  agent for the lifetime of the connection. Too easy to misuse.
- X11 forwarding.
- GSSAPI / Kerberos.
- SFTP / SCP subsystem.
- `ssh-rsa` signatures with SHA-1.
- AES-CBC and HMAC-SHA1.

## Running as root

Don't. `gosshd` has no privilege separation and no uid switching. If
you want a multi-user SSH server, use OpenSSH. A safe deployment is:

    systemd --user
    gosshd -listen 127.0.0.1:2222 \
           -host-key ~/.config/gossh/host_ed25519 \
           -authorized-keys ~/.ssh/authorized_keys

…fronted by iptables/nftables that only allow trusted source IPs to
reach port 2222.

## Reporting issues

If you find a security problem, please do not open a public issue.
Since this is a personal project, email the author instead.
