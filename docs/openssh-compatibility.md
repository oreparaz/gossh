# OpenSSH client CLI compatibility — future work

This file captures the gap between `gossh` and the OpenSSH `ssh(1)`
client. Today gossh is **wire-protocol compatible** (handshakes,
channels, requests, exit-status all match what OpenSSH speaks) but
**not drop-in at the command-line level**. Most existing `ssh ...`
invocations and `~/.ssh/config` files won't transfer over without
edits.

This is a tracking document for closing that gap. Nothing here is a
bug in shipped code — it's missing surface area.

## Current state (snapshot 2026-04-25)

`gossh` ships these flags:

```
-D -F -L -N -R -T -i -known-hosts -l -p -proxy-command
-strict-host-key -t
```

Wire-level it speaks SSH-2 with the same algorithm allowlist as
OpenSSH's secure-only profile (curve25519 KEX, AEAD ciphers,
ed25519/RSA-SHA2 signatures), so a connection from gossh to an
OpenSSH sshd, or vice versa, works.

CLI-level it diverges in five ways, in priority order.

## Gap 1 — `-o KEY=VALUE` is missing  *(blocker)*

OpenSSH's universal escape hatch. Almost every CI script and
tutorial relies on it:

```
ssh -o StrictHostKeyChecking=no host
ssh -o UserKnownHostsFile=/dev/null host
ssh -o ProxyCommand="aws ssm …" host
ssh -o ConnectTimeout=5 host
ssh -o IdentitiesOnly=yes -i key host
ssh -o BatchMode=yes host
```

Without `-o`, those command lines don't run at all under gossh.
Today we expose the same knobs under bespoke flag names
(`-strict-host-key`, `-known-hosts`, `-proxy-command`) that don't
exist in OpenSSH.

**Suggested approach.** Add a `cliutil.MultiFlag`-style `-o` flag
on `gossh` and `gossh-scp`. Parse each `-o KEY=VALUE` token after
ssh_config has been resolved. Keys we already act on map to the
existing fields; unknown keys log a warning at startup and are
ignored (matching `man ssh_config`'s "unknown directives are
ignored" posture). Keep the bespoke flags as aliases for one
release for backward compat, then deprecate them.

Keys to wire up first (existing field exists in `client.Config` or
`sshconfig.ClientHost`):

| -o key                  | gossh field                      |
| ----------------------- | -------------------------------- |
| `Port`                  | `cfg.Port`                       |
| `User`                  | `cfg.User`                       |
| `IdentityFile`          | `cfg.IdentityFiles`              |
| `IdentitiesOnly`        | suppress default key probing     |
| `UserKnownHostsFile`    | `cfg.KnownHostsPath`             |
| `StrictHostKeyChecking` | `cfg.HostCheckMode`              |
| `ProxyCommand`          | `cfg.ProxyCommand`               |
| `ConnectTimeout`        | `cfg.ConnectTimeout`             |

Keys to accept-but-warn (no-op for now):

```
BatchMode CheckHostIP Compression LogLevel ServerAliveInterval
ServerAliveCountMax TCPKeepAlive HashKnownHosts VerifyHostKeyDNS
```

Keys to reject loudly (security or scope refusal):

```
PasswordAuthentication=yes        # we never accept passwords
KbdInteractiveAuthentication=yes  # ditto
StrictHostKeyChecking=no          # already refused via -strict-host-key
GSSAPIAuthentication=yes
ForwardAgent=yes
ForwardX11=yes
```

## Gap 2 — Common short flags missing

| Flag | What `ssh` does | gossh today | Notes |
| --- | --- | --- | --- |
| `-V` | print version, exit | "flag provided but not defined" | Trivial. Pick a version string. |
| `-q` | quiet (suppress warnings) | not implemented | Mute slog handler. |
| `-J host` | ProxyJump (chain through bastion) | not implemented | Equivalent to `-o ProxyCommand="gossh -W %h:%p host"` once `-W` exists. |
| `-W host:port` | stdio-forward to `host:port` over the conn | not implemented | Used inside ProxyCommand chains. Implement after `-J`. |
| `-v` (levels) | `-v / -vv / -vvv` increases verbosity | only boolean | OpenSSH allows three levels. |
| `-4` / `-6` | force IPv4/IPv6 | not implemented | One line each in the dialer. |

## Gap 3 — Flag-after-positional argument ordering

OpenSSH allows:

```
ssh user@host -p 2222 cmd
ssh host -L 8080:localhost:80 -N
```

Go's `flag` package requires every flag to appear **before** the
first positional argument. Right now `gossh user@host -p 2222 cmd`
treats `-p`, `2222`, and `cmd` as remote arguments.

**Suggested approach.** Before `flag.Parse()`, do a single pass over
`os.Args` that pulls out the first token that looks like a
destination (`[user@]host[:port]` with no leading `-`), set it
aside, and let `flag.Parse()` see only flags + the eventual remote
command. This preserves the rest of the standard flag semantics.

## Gap 4 — Many flags neither accept-noop nor reject

OpenSSH users have muscle memory for these. Today, passing any of
them produces `flag provided but not defined`. Better behavior
(matching how OpenSSH ignores some, errors on others) groups them:

**Accept and ignore (silent or one-line warning):**

```
-a   # disable agent forwarding — we have no agent, so true by default
-x   # disable X11 forwarding — we never enabled it
-y   # syslog instead of stderr — we don't ship syslog
-n   # redirect stdin from /dev/null — easy to honour
-C   # compression — we don't support it; warn once
-e   # escape char — relevant only with PTY; accept any value
-g   # forwarded-port gatewaying — accept; we already bind on 0.0.0.0 by default
-c cipher_spec / -m mac_spec   # we use a fixed allowlist; accept-and-validate
```

**Reject loudly (out of scope by design):**

```
-A      # agent forwarding
-X / -Y # X11 forwarding
-K / -k # GSSAPI
-M / -O / -S  # connection multiplexing
-w      # tun device forwarding
-s      # subsystem (we don't ship sftp)
-f      # background after auth — leaks credential prompt semantics
-I pkcs11
```

A single table at the top of `cmd/gossh/main.go` driving both
behaviors keeps this maintainable.

## Gap 5 — Defaults and cosmetics

- **Default identity probing** picks `id_ed25519` then `id_rsa`.
  OpenSSH probes `id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519,
  id_ed25519_sk, id_dsa`. We don't accept ECDSA or DSA on principle,
  so the divergence here is intentional — but document it.
- **Client banner** is `SSH-2.0-gossh`. Some servers' `from=` audit
  logs key off the banner. Cosmetic; mention in `SECURITY.md`.
- **`StrictHostKeyChecking=no`** is intentionally refused. This will
  break some scripts. Keep refused; document it under "intentional
  divergences" so users see it in the README.
- **Stderr message prefix** is `gossh: `. OpenSSH usually has no
  prefix or `Warning: …`. Scripts that grep stderr will need
  adjustment. Cosmetic.

## Effort estimate

| Item | Files touched | Effort |
| --- | --- | --- |
| `-o KEY=VALUE` parser + dispatch table | `cmd/gossh`, `cmd/gossh-scp`, `internal/cliutil` | 4–6 h |
| `-V`, `-q`, `-4`, `-6`, multilevel `-v` | `cmd/gossh` | 1 h |
| `-J`, `-W` | `cmd/gossh`, `internal/client` | 3–4 h (W needs a stdio channel adapter) |
| Flag-after-positional pre-pass | `cmd/gossh`, `cmd/gossh-scp` | 1 h |
| Accept-noop / reject-loudly table | `cmd/gossh`, `cmd/gossh-scp` | 1 h |
| Tests for each above | `cmd/gossh`, `internal/cliutil` | 2–3 h |
| Docs update | `README.md`, `SECURITY.md`, `docs/configuration.md` | 1 h |

Total: ~13–18 h of focused work. Each item lands as its own commit
with a regression test.

## Out of scope (intentional divergences to document, not close)

- Password / keyboard-interactive prompts.
- Agent forwarding (`-A`).
- X11 forwarding (`-X`, `-Y`).
- Connection multiplexing (`-M`, `-O`, `-S`).
- Subsystems / SFTP (`-s`).
- Tunnel device forwarding (`-w`).
- GSSAPI (`-K`, `-k`).
- `StrictHostKeyChecking=no`.

These should be listed once in `SECURITY.md` and once in the
README, with a one-line rationale each.

## Acceptance criteria for "drop-in"

The CLI is "drop-in compatible with OpenSSH" when:

1. Any `ssh` command line that uses only the supported feature set
   runs unchanged when `gossh` is substituted (modulo the binary
   name).
2. `~/.ssh/config` files that use only supported keywords resolve
   identically (`-G` output should match the relevant subset).
3. Unsupported flags either no-op with a warning or error with a
   clear "not supported by gossh" message — never `flag provided
   but not defined`.
4. The seven explicit divergences above are documented in
   `SECURITY.md` and called out in the README.
