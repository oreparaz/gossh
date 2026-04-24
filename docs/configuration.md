# Configuration reference

Every operator-reachable knob, with its default and where the
default lives in code.

## `gosshd` flags

| Flag | Default | Behavior |
|---|---|---|
| `-listen` | `0.0.0.0:2222` | TCP bind address |
| `-host-key` | `./host_ed25519` | Path(s) to host private keys; repeatable. Generates ed25519 if missing. |
| `-authorized-keys` | *(required)* | File listing authorised public keys |
| `-shell` | `/bin/bash` | Shell launched for `shell` / PTY requests |
| `-allow-exec` | `true` | Accept `exec` channel requests |
| `-allow-pty` | `true` | Accept `pty-req` |
| `-allow-local-forward` | `false` | Accept `direct-tcpip` (`ssh -L`) |
| `-allow-remote-forward` | `false` | Accept `tcpip-forward` (`ssh -R`) |
| `-login-grace` | `120s` | Hard timeout on the handshake; includes user-auth |
| `-max-auth-tries` | `6` | Per-connection public-key offers before disconnect |
| `-max-per-ip` | `10` | Concurrent connections per remote IP (`0` = unlimited) |
| `-max-connections` | `0` | Global concurrent-connection cap (`0` = unlimited) |
| `-shutdown-grace` | `10s` | On SIGTERM, wait this long for sessions to finish before forcing |
| `-client-alive-interval` | `0` | `0` disables. Otherwise send keepalive every N seconds when idle |
| `-client-alive-count-max` | `3` | Drop connection after this many consecutive keepalive failures |
| `-audit-log` | *(empty = disabled)* | Path to JSON-Lines audit file |
| `-audit-fsync` | `false` | `fdatasync` after every event (expensive, safer) |
| `-f` | *(empty)* | Path to an `sshd_config`-style file (CLI values win on conflict) |
| `-v` | `false` | Debug-level logging |

Internal defaults that are *not* on the CLI:

- **`MaxChannelsPerConn`**: 64. Bounds sessions + `-L` fan-out per conn.
- **`DirectTCPIPDialTimeout`**: 10 s. Time bound on the server's
  dial to a `-L` target.
- **TCP keepalive**: 30 s probe period, always on.

## `gossh` flags

| Flag | Default | Behavior |
|---|---|---|
| `-p` | `22` | Remote port |
| `-l` | *(derived from arg)* | Remote username override |
| `-i` | *(probes ~/.ssh/id_ed25519, id_rsa)* | Identity file; repeatable |
| `-L` | — | Local forward spec `[bind:]port:host:hostport` (repeatable) |
| `-R` | — | Remote forward spec |
| `-D` | — | Dynamic SOCKS5 spec `[bind:]port` |
| `-N` | `false` | No remote command; useful with `-L/-R/-D` |
| `-T` | `false` | Disable PTY |
| `-t` | `false` | Force PTY for exec |
| `-F` | *(auto: `~/.ssh/config` if present)* | Path to `ssh_config`-style file |
| `-known-hosts` | `~/.ssh/known_hosts` | Override path. If empty and `$HOME` is unresolvable, Dial errors rather than fall back to `./ .ssh/known_hosts`. |
| `-strict-host-key` | `yes` | `yes` (refuse unknown, default) \| `accept-new` (TOFU) |
| `-proxy-command` | *(empty)* | Shell command to tunnel the SSH transport; `%h` / `%p` / `%r` are substituted (with shell-safety validation) and the result is run via `sh -c`. Same as the `ProxyCommand` keyword in `ssh_config`. |

## `gossh-scp` flags

Same auth flags as `gossh`, plus:
- `-r` — recursively copy directory trees (see SCP section below).
- `-proxy-command` — same semantics as on `gossh`.
- `-connect-timeout` (default 10 s).

## `gossh-keygen` flags

| Flag | Default | Behavior |
|---|---|---|
| `-t` | `ed25519` | `ed25519` or `rsa` |
| `-b` | `3072` | RSA bits (minimum 3072) |
| `-C` | *(empty)* | Comment embedded in the `.pub` |
| `-f` | *(required)* | Output path (writes `.pub` alongside) |
| `-l` | `false` | Print fingerprint of an existing key and exit |

## Recognised `authorized_keys` options

Enforced:

| Option | Effect | Enforcement site |
|---|---|---|
| `restrict` | Implies all `no-*` unless another option opts out | `authkeys.parseOptions` |
| `command="..."` | Forced command; client command in `$SSH_ORIGINAL_COMMAND` | `server.handleRequest` (`exec`) |
| `from="pat,..."` | Allow only matching sources; CIDR, wildcard, negation | `server.PublicKeyCallback` + `authkeys.MatchFrom` |
| `permitopen="host:port"` | Restricts `-L` targets | `server.handleDirectTCPIP` |
| `permitlisten="host:port"` | Restricts `-R` binds | `server.doRemoteForward` |
| `environment="NAME=VALUE"` | Injects into child env | `server.finalEnv` |
| `no-port-forwarding` | Blocks `-L` and `-R` | |
| `no-pty` | Blocks PTY allocation | |
| `port-forwarding`, `pty` | Re-enable after `restrict` | |

Accepted but not acted on (present for compatibility with real
OpenSSH authorized_keys files):

- `cert-authority`
- `principals`
- `tunnel`
- `expiry-time`
- `verify-required`

**Anything else is rejected at parse time.** A typo like
`cmmand="..."` will not silently disable the restriction.

## `sshd_config` subset

| Keyword | Effect |
|---|---|
| `Port N` | Applied to `-listen`'s port when `-listen` was not explicitly set on the CLI |
| `ListenAddress addr` | Recorded; not currently multi-bound |
| `HostKey path` | Added to host-key list (repeatable) |
| `AuthorizedKeysFile path` | Used when `-authorized-keys` not set |
| `PermitRootLogin no|prohibit-password|yes` | Validated; `yes` warns; unknown → error |
| `PasswordAuthentication yes` | **refused at startup** — we don't support it |
| `AllowTcpForwarding ...` | Recorded only |
| `LoginGraceTime T` | Recorded |
| `MaxAuthTries N` | Applied unless `-max-auth-tries` was set |

Unknown keywords are logged as warnings, not rejected, because
upstream `sshd_config` has a large vocabulary and we want drop-in
files to work.

## `ssh_config` subset (client)

| Keyword | Effect |
|---|---|
| `Host pat [pat...]` | Section selector |
| `Hostname` | Real host to dial |
| `Port` | Remote port. Explicit CLI `-p` or `host:port` beats this. |
| `User` | Login name |
| `IdentityFile` | Identity path; additive across lines and matching sections. Stored as a list at parse time, so paths with spaces (quoted) survive intact. |
| `UserKnownHostsFile` | Override |
| `StrictHostKeyChecking yes|accept-new` | `no` / `off` are refused — disabling host-key verification is a MITM foot-gun. |
| `ProxyCommand` | Shell command used to carry the SSH transport; `%h` / `%p` / `%r` substituted (shell-safety validated) before `sh -c`. |
| `Match`, `Include` | **ignored** (warned) |

Client uses first-match semantics per keyword (matches OpenSSH).
`IdentityFile` is additive across matching sections.

Quoted values — e.g. `Hostname "host.example"` or `IdentityFile
"~/my key"` — are unquoted once at parse time (one layer, with `\"`
escapes honoured). This matches OpenSSH's shell-like quoting for the
directives we support.

## `gossh-scp` recursion and ProxyCommand

With `-r`, `gossh-scp` walks a source tree depth-first, emitting the
OpenSSH SCP D/E/C wire protocol. Guards:

- **Max depth 64** (both send and receive). A hostile peer cannot walk
  the receiver through unbounded nesting.
- **Symlink-write refusal**: on download, every existing path component
  is `Lstat`-ed from root to leaf; any symlink in the chain aborts
  the write.
- **Filename validator**: C-line and D-line names are rejected if they
  contain `/`, `\`, `\x00`, `.`, `..`, or look like a Windows drive
  letter / UNC prefix.
- **Consecutive T directives rejected**: T-spam DoS is capped at one
  pending T between C/D.
- **Stderr from remote capped at 4 KiB** on error paths, so a chatty
  remote can't exhaust client memory.

Trailing-slash upload destinations (e.g. `./file host:/dst/`) are
treated as "drop into this directory under its own basename", not
"rename to `/dst`".

`-proxy-command` carries the same semantics as `gossh`'s flag and the
`ProxyCommand` keyword in `ssh_config`.

## Cryptographic allowlist

See `internal/sshcrypto/algs.go`:

- **KEX**: `curve25519-sha256`, `curve25519-sha256@libssh.org`
- **Ciphers**: `chacha20-poly1305@openssh.com`,
  `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`
- **MACs**: `hmac-sha2-512-etm@openssh.com`,
  `hmac-sha2-256-etm@openssh.com`
- **Host-key / user-key signatures**: `ssh-ed25519`,
  `rsa-sha2-512`, `rsa-sha2-256`

Refused (automated test in `algs_test.go`):
- `ssh-rsa` (SHA-1), `ssh-dss`
- `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `ecdh-sha2-nistp*`
- `3des-cbc`, `aes*-cbc`, `blowfish-cbc`, `arcfour*`
- `hmac-sha1`, `hmac-md5`
