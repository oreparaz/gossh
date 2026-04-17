# Auditor guide

This document is the intended entry point if you're doing an
external security or correctness review of this repository. Start
here, then follow the links to deeper material.

## 30-second summary

- **What this is:** a Go implementation of an SSH server (`gosshd`)
  and client (`gossh`), built on top of `golang.org/x/crypto/ssh`.
- **What it is not:** a rewrite of SSH. All wire-protocol parsing,
  key exchange, cipher suite handling, and authentication
  primitives live in the stdlib; we layer policy, session
  orchestration, and CLI on top.
- **Scope target:** "80 % of OpenSSH" for single-user-shell and
  port-forwarding workloads. No multi-user privsep, no SFTP
  subsystem, no agent forwarding.
- **LoC:** ~11 k Go. Single repo, no external runtime deps beyond
  `x/crypto`, `x/term`, `x/sys`, `creack/pty`.
- **Tests:** unit + integration + fuzz + interop against the
  system `ssh` / `sshd`. `go test -race ./...` runs in ~60 s.

## Where policy lives (audit these first)

| Concern | File | Why |
|---|---|---|
| Algorithm allowlist | `internal/sshcrypto/algs.go` | Single source of truth for ciphers/KEX/MACs/pubkey algos |
| Pubkey auth + `from=` match | `internal/server/server.go` (`serverConfig`) | Rejects unknown keys, enforces IP restriction |
| `authorized_keys` parsing | `internal/authkeys/authkeys.go` | Unknown options are **rejected** (strict) |
| Host-key verification | `internal/knownhosts/knownhosts.go` | TOFU/strict modes, MITM rejection always fatal |
| Session dispatch | `internal/server/server.go` (`handleSession`) | `env`/`pty-req` caps, exec/shell gating |
| Forwarding policy | `internal/server/server.go`, `internal/server/remote_forward.go` | `permitopen`/`permitlisten` enforcement, disabled by default |
| SCP traversal guard | `internal/scp/scp.go` (`parseCLine`) | Filters `..` / `/` / setuid in remote C-lines |

## Threat model

See [`SECURITY.md`](../SECURITY.md). Short version: we defend
against network MITM and accidental misconfiguration; we do *not*
defend against a compromised operator (they own the host key and
authorized_keys) or against kernel-level attacks on the Go runtime.

## Historical bugs

[`bugs-found.md`](bugs-found.md) tracks **every** correctness or
security bug we've found during this project, with fix commit,
regression test, and brief root-cause. 26 entries to date.
This is the best way to calibrate what classes of issue have
already been considered.

## Test matrix

[`testing.md`](testing.md) lists:
- which packages have unit tests,
- which tests spin up a real OpenSSH client/server,
- the fuzz targets and how long each has been fuzzed,
- the chaos and stress scenarios covered.

## Audit log reference

[`audit.md`](audit.md) is the event-type reference for the
`-audit-log` JSON-Lines output. Operators who need a security
data feed should read that; auditors should use it to check that
each auth/forward/session event that *should* be recorded actually
is.

## Configuration reference

[`configuration.md`](configuration.md) is the exhaustive list of
CLI flags and config-file keywords, including what is rejected
and why. Use it as a checklist: for every operator-reachable
setting, is the default safe?

## Architecture

[`architecture.md`](architecture.md) walks the data flow of one
connection from accept through teardown, with file/line pointers.

## How to reproduce the test suite

```sh
make build                              # builds 4 binaries
go test -race -timeout 300s ./...       # unit + integration
go test -fuzz FuzzParseCLine -fuzztime 30s ./internal/scp/
go test -fuzz FuzzAppend -fuzztime 30s ./internal/knownhosts/
```

All fuzz corpora are committed under `internal/*/testdata/fuzz/`
and replay automatically as regression tests.

## Quick sanity checks an auditor can run

1. `grep -rn "PasswordCallback\|KeyboardInteractive" internal/`
   should return empty — we never accept passwords.
2. `grep -rn "ssh-rsa\b\|ssh-dss\|aes.*-cbc\|hmac-sha1"
   internal/sshcrypto/` should show only *forbidden*-list entries
   in the test file.
3. `go vet ./...` and `go test -race ./...` must both pass.
4. Every `authorized_keys` option we recognise is listed in
   `knownOptions` in `internal/authkeys/authkeys.go`; any keyword
   *not* in that map is rejected.
5. `defer recover()` appears at every exported handler entry in
   `internal/server/server.go`: `handle`, `handleSession`,
   `handleDirectTCPIP`, `handleGlobalRequests`.
