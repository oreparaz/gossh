# Testing

## Commands

```sh
make test                                          # go test -race -timeout 120s ./...
go test -race -timeout 300s ./...                  # same, direct invocation
go test -short ./...                               # skip integration; unit only
go test -fuzz FuzzParseCLine -fuzztime 30s \
    ./internal/scp/                                # run one fuzz target
```

Integration tests skip automatically when `ssh` or `sshd` is not
on `$PATH`. Every one of them asserts on the system binary where
available; see [Interop matrix](#interop-matrix).

## Layout

Each `internal/<pkg>/` has:

- `*_test.go` — unit tests, always runnable.
- `*_integration_test.go` — tests that spin up a real `gosshd`
  on a random port and drive it with the system `ssh` binary, or
  vice versa.
- `fuzz_*_test.go` — Go native fuzz targets (`go test -fuzz`).
  Corpora are checked into `testdata/fuzz/` and replay as
  regression tests under a plain `go test` run.

## Interop matrix

| Direction | File | Status |
|---|---|---|
| system-ssh → gosshd (exec) | `internal/server/integration_test.go` | exec, exit code, stderr routing |
| system-ssh → gosshd (PTY) | `internal/server/pty_test.go` | allocates a tty |
| system-ssh → gosshd (`-L`) | `internal/server/forward_test.go` | local forwarding |
| system-ssh → gosshd (`-R`) | `internal/server/forward_test.go` | remote forwarding |
| system-ssh → gosshd (RSA host key) | `internal/server/rsa_interop_test.go` | 3072-bit RSA |
| system-ssh → gosshd (RSA user key) | `internal/server/rsa_interop_test.go` | rsa-sha2 negotiation |
| system-scp → gosshd | `internal/server/scp_interop_test.go` | upload + download |
| gossh → gosshd | `internal/client/client_test.go` | exec, TOFU, strict mode |
| gossh → gosshd (`-L`/`-R`/`-D`) | `internal/client/forward_test.go` | all three forward types |
| gossh → OpenSSH sshd | `internal/client/openssh_interop_test.go` | spawns unprivileged sshd |
| gossh-scp → gosshd | `internal/scp/scp_test.go` | upload + download |

## Algorithm-negotiation negatives

`internal/server/negotiation_test.go`:

- `TestRefusesLegacyKEX` — dh-group14-sha1 client fails handshake.
- `TestRefusesLegacyCipher` — aes128-cbc client fails handshake.

These lock in the `sshcrypto` allowlist against regressions.

## Authorization negatives (system ssh)

`internal/server/authz_test.go`:

- `TestForcedCommand` — `command=` overrides client input.
- `TestNoPortForwardingBlocksLocalForward`.
- `TestPermitOpenEnforcement` — allowed target passes, other is rejected.
- `TestFromAllowAndDeny` — `from=` accepts matching source, refuses otherwise.
- `TestAuthorizedKeysEnvironmentApplied` — `environment=` reaches the child.
- `TestAuthorizedKeysEnvironmentNoShellInjection` — value is a literal.
- `TestCombinedFromAndCommand`.

## Chaos / reliability

`internal/server/chaos_test.go`:

- `TestManyConnectionsNoGoroutineLeak` — 64 concurrent
  connect+exec; asserts no goroutine leak past a small delta.
- `TestServerHandlesClientAbruptDisconnect` — rude hangup in
  mid-handshake; server must stay healthy.
- `TestPerIPCapStopsFlood`, `TestGlobalCapStopsFlood` — per-IP
  and global limiters engage under flood.
- `TestShutdownTearsDownActiveSession` — SIGTERM + grace closes
  in-flight sessions and the underlying conn.

## Concurrency / stream

- `internal/client/concurrent_test.go` — 16 concurrent `Exec`
  sessions over one connection.
- `internal/client/throughput_test.go` — 4 MiB stdout, 1 MiB
  stdin, 1 MiB `-L` tunnel.
- `internal/client/exec_ctx_test.go` — `ExecContext` cancel
  kills remote; also asserts no goroutine leak per iteration.
- `internal/client/bench_test.go` — `BenchmarkExecSmall` (~1.2 ms
  overhead) and `BenchmarkForwardThroughput` (~88 MB/s locally).

## Signals

- `TestSignalForwarding` — SIGTERM reaches a remote `sleep`.
- `TestSignalForwardingKillsProcessGroup` — proves `Setpgid` +
  `kill(-pid)`; trapped-INT shell + `sleep 30` only terminates
  when the signal reaches the child. (Fails without the fix.)

## Fuzz targets

Every parser that consumes bytes from the wire or the filesystem
has a fuzz target. Corpora are committed.

| Target | Package | What it parses |
|---|---|---|
| `FuzzParse` | `internal/authkeys` | `authorized_keys` lines |
| `FuzzUnquote` | `internal/authkeys` | option values |
| `FuzzParseHostPort` | `internal/authkeys` | `permitopen/permitlisten` values |
| `FuzzMatchFrom` | `internal/authkeys` | `from=` pattern matcher |
| `FuzzParseLocal` / `FuzzParseDynamic` | `internal/forward` | `-L/-D` specs |
| `FuzzParseClient` / `FuzzParseServer` | `internal/sshconfig` | `ssh_config` / `sshd_config` |
| `FuzzResolveHost` | `internal/sshconfig` | alias resolution |
| `FuzzTakeString` / `FuzzParseStringRequest` / `FuzzParseEnvRequest` / `FuzzParsePTYReq` / `FuzzParseWindowChange` / `FuzzIsSafeEnvName` | `internal/server` | SSH request payloads |
| `FuzzServerHandshake` | `internal/server` | arbitrary bytes at a live `gosshd` |
| `FuzzSessionRequestPayload` | `internal/server` | post-auth session requests |
| `FuzzDirectTCPIPPayload` | `internal/server` | `direct-tcpip` channel open |
| `FuzzChannelIO` | `internal/server` | stdin bytes into a remote command |
| `FuzzAppend` | `internal/knownhosts` | `known_hosts` append path |
| `FuzzParseCLine` / `FuzzShellQuote` / `FuzzReadAck` | `internal/scp` | SCP wire format |

### Fuzz time accumulated

Between the first and second rounds, each hot target has been
run for at least the following in our session. Repeat runs on CI
or a dev machine are cheap.

- `FuzzServerHandshake`: ~10 min
- `FuzzSessionRequestPayload`: ~12 min
- `FuzzChannelIO`: ~10 min
- `FuzzAppend`: ~11 min
- `FuzzUnquote`: ~11 min
- `FuzzParseCLine`: ~10 min (30 M execs)
- Parsers in `sshconfig` / `authkeys` / `forward`: 1–2 min each
- `FuzzMatchFrom`: ~1 min

Two real panics found and fixed from these — see
[`bugs-found.md`](bugs-found.md) entries 24 & 25. Both failing
inputs are pinned in `testdata/fuzz/` as permanent regression
tests.

## CI

`.github/workflows/ci.yml`:
- `go vet ./...`
- `go build ./...`
- `go test -race -timeout 240s ./...`
- 30 s of fuzzing per parser target

## Coverage

```sh
go test -race -coverprofile=/tmp/cov.out ./internal/...
go tool cover -func=/tmp/cov.out
```

Last run: ~66 % aggregate. The gaps are mostly in packages whose
exported surface is exercised end-to-end through interop tests
(e.g., `sshcrypto.ApplyToConfig`) — direct package-level coverage
under-reports these.
