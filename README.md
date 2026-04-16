# gossh / gosshd

A minimal, security-focused SSH client and server written in Go.
Interoperable with OpenSSH. Drop-in replacement for simple use cases.

See [`SECURITY.md`](SECURITY.md) for the threat model and full list
of what is and isn't supported and why.

## Build

```
make build
```

Binaries land in `./bin/`:

- `bin/gossh` — the client
- `bin/gosshd` — the server
- `bin/gossh-keygen` — keypair generator

## Features

- Host keys: **ed25519**, **RSA** (≥ 3072 bits)
- User auth: **public key only** (no password, no keyboard-interactive)
- Sessions: interactive PTY (bash), exec (`ssh host cmd`)
- Forwarding: `-L` (direct-tcpip), `-R` (tcpip-forward), `-D` (SOCKS5)
- `authorized_keys` options: `command=`, `from=`, `permitopen=`,
  `permitlisten=`, `restrict`, `no-port-forwarding`, `no-pty`,
  `environment=`
- `ssh_config` subset: `Host`, `Hostname`, `Port`, `User`,
  `IdentityFile`, `UserKnownHostsFile`, `StrictHostKeyChecking`
- Signal forwarding (client Ctrl-C → remote child)
- `known_hosts` with TOFU (accept-new) or strict mode

## Examples

### Run a server

Generate a host key and a user key, then start:

```sh
./bin/gossh-keygen -t ed25519 -f /etc/gossh/host_ed25519 -C "myhost"
./bin/gossh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "me@laptop"
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

./bin/gosshd \
    -listen :2222 \
    -host-key /etc/gossh/host_ed25519 \
    -authorized-keys ~/.ssh/authorized_keys \
    -shell /bin/bash \
    -allow-local-forward \
    -allow-remote-forward
```

### Connect a client

```sh
# One-off exec
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 me@host "uptime"

# Interactive shell
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 me@host

# Local forward (ssh -L)
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 \
    -L 8080:internal.svc:80 -N me@host

# Remote forward (ssh -R)
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 \
    -R 2222:localhost:22 -N me@jumpbox

# Dynamic SOCKS5 (ssh -D)
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 -D 1080 -N me@jumpbox
```

### Aliases with ssh_config

```sh
cat > ~/.config/gossh/config <<EOF
Host dev
    Hostname dev.example.com
    Port 2222
    User me
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking yes
EOF

./bin/gossh -F ~/.config/gossh/config dev "echo hello"
```

The same binary is interoperable with OpenSSH either way:

```sh
# OpenSSH client → gosshd
ssh -p 2222 -i ~/.ssh/id_ed25519 me@host

# gossh → OpenSSH sshd
./bin/gossh -p 22 -i ~/.ssh/id_ed25519 me@prodhost
```

## Testing

```
make test              # unit + integration; uses system ssh client
go test -race ./...    # same, directly
```

Integration tests spin up `gosshd` in-process on a random port and
drive it with the system `ssh` binary (when present). They also
exercise `gossh` against `gosshd` end-to-end.

Parsers have fuzz targets:

```
go test -fuzz FuzzParse ./internal/authkeys/
go test -fuzz FuzzParseLocal ./internal/forward/
go test -fuzz FuzzParseClient ./internal/sshconfig/
```

## Intentional non-features

See [`SECURITY.md`](SECURITY.md) for the reasoning. In short:

- Password / keyboard-interactive auth — **use keys**
- SSHv1 — obsolete
- Legacy ciphers (3DES, CBC, RC4) and SHA-1 signatures
- NIST ECDH (curve25519 is enough)
- GSSAPI / Kerberos
- X11 forwarding
- Agent forwarding (`-A`) — too easy to misuse
- SFTP / SCP subsystem
- Multi-user privilege separation (gosshd runs as a single user)

## Layout

```
cmd/
  gossh/           client binary
  gosshd/          server binary
  gossh-keygen/    keypair generator
internal/
  authkeys/        authorized_keys parser
  client/          ssh client package
  forward/         -L / -R / -D forwarding
  hostkey/         ed25519/RSA keypair on-disk handling
  knownhosts/      TOFU wrapper over x/crypto/ssh/knownhosts
  pty/             thin wrapper around creack/pty
  server/          sshd implementation
  sshconfig/       ssh_config / sshd_config parser
  sshcrypto/       centralised algorithm allowlists
```

## License

MIT.
