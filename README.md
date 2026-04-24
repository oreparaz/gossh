# gossh / gosshd

A minimal, security-focused SSH client and server written in Go.
Interoperable with OpenSSH. Drop-in replacement for simple use cases.

See [`SECURITY.md`](SECURITY.md) for the threat model and what is
and isn't supported, and [`docs/`](docs/) for deeper references.

## Build

```
make build
```

Binaries land in `./bin/`:

- `bin/gossh` — the client
- `bin/gosshd` — the server
- `bin/gossh-keygen` — keypair generator
- `bin/gossh-scp` — single-file SCP client

## Features

- Host keys: **ed25519**, **RSA** (≥ 3072 bits)
- User auth: **public-key only** (no password, no keyboard-interactive)
- Sessions: interactive PTY (bash), exec (`ssh host cmd`)
- Forwarding: `-L` (direct-tcpip), `-R` (tcpip-forward), `-D` (SOCKS5)
- File transfer: `gossh-scp` (single file + recursive with `-r`) and
  interop with system `scp` via `exec`
- `ProxyCommand` support for SSH-over-anything tunnels (AWS SSM,
  `nc`, `socat`, …) via `-proxy-command` or `ssh_config`
- `authorized_keys` options enforced: `command=`, `from=` (IP/CIDR/
  wildcard/negation), `permitopen=`, `permitlisten=`, `restrict`,
  `no-pty`, `no-port-forwarding`, `environment=`
- `ssh_config` subset: `Host`, `Hostname`, `Port`, `User`,
  `IdentityFile`, `UserKnownHostsFile`, `StrictHostKeyChecking`,
  `ProxyCommand`
- `sshd_config` subset: `Port`, `ListenAddress`, `HostKey`,
  `AuthorizedKeysFile`, `MaxAuthTries`, `PermitRootLogin`
- Signal forwarding (client Ctrl-C → remote child, process-group)
- `known_hosts` with TOFU (accept-new) or strict mode
- JSON-Lines audit log (see [`docs/audit.md`](docs/audit.md))
- Live `authorized_keys` reload on mtime change

## Quickstart

```sh
# Generate keys
./bin/gossh-keygen -t ed25519 -f /etc/gossh/host_ed25519 -C "myhost"
./bin/gossh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "me@laptop"
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Run the server
./bin/gosshd \
    -listen :2222 \
    -host-key /etc/gossh/host_ed25519 \
    -authorized-keys ~/.ssh/authorized_keys \
    -shell /bin/bash \
    -allow-local-forward -allow-remote-forward \
    -audit-log /var/log/gosshd/audit.jsonl

# Exec, shell, forwards
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 me@host "uptime"
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 me@host
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 -L 8080:internal.svc:80 -N me@host
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 -R 2222:localhost:22 -N me@jumpbox
./bin/gossh -p 2222 -i ~/.ssh/id_ed25519 -D 1080 -N me@jumpbox

# SCP
./bin/gossh-scp -p 2222 -i ~/.ssh/id_ed25519 ./file me@host:/dst/
./bin/gossh-scp -p 2222 -i ~/.ssh/id_ed25519 me@host:/src ./local
./bin/gossh-scp -p 2222 -i ~/.ssh/id_ed25519 -r ./project me@host:/home/me/
```

## Aliases with ssh_config

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

Interop with OpenSSH:

```sh
# OpenSSH client → gosshd
ssh -p 2222 -i ~/.ssh/id_ed25519 me@host

# gossh → OpenSSH sshd
./bin/gossh -p 22 -i ~/.ssh/id_ed25519 me@prodhost

# system scp → gosshd
scp -P 2222 -i ~/.ssh/id_ed25519 ./file me@host:/dst/
```

All three are covered by integration tests.

## Testing

```
make test           # unit + integration (system ssh required)
go test -race ./... # same, directly
```

Parsers have fuzz targets — see [`docs/testing.md`](docs/testing.md)
for the full list and commands.

## Intentional non-features

See [`SECURITY.md`](SECURITY.md) for rationale. In short:

- Password / keyboard-interactive auth — **use keys**
- SSHv1 — obsolete
- Legacy ciphers (3DES, CBC, RC4) and SHA-1 signatures
- NIST ECDH (curve25519 is enough)
- GSSAPI / Kerberos
- X11 forwarding
- Agent forwarding (`-A`) — too easy to misuse
- SFTP subsystem (use `gossh-scp -r` or `exec tar` for transfer)
- Multi-user privilege separation (gosshd runs as a single user)

## Layout

```
cmd/
  gossh/           client binary
  gosshd/          server binary
  gossh-keygen/    keypair generator
  gossh-scp/       file transfer client
internal/
  audit/           JSON-Lines audit event sink
  authkeys/        authorized_keys parser + from= matcher
  client/          ssh client package
  forward/         -L / -R / -D forwarding + SOCKS5
  hostkey/         ed25519/RSA keypair on-disk handling
  knownhosts/      TOFU wrapper over x/crypto/ssh/knownhosts
  pty/             thin wrapper around creack/pty
  scp/             SCP upload/download
  server/          sshd implementation
  sshconfig/       ssh_config / sshd_config parser
  sshcrypto/       centralised algorithm allowlists
docs/
  auditor-guide.md where to start if you're reviewing this code
  architecture.md  data flow and component responsibilities
  audit.md         audit-log event reference
  bugs-found.md    historical record of bugs found + fixed
  configuration.md every CLI flag and config keyword
  testing.md       test matrix, interop coverage, fuzz targets
```

## License

MIT.
