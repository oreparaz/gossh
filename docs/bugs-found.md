# Bugs found and fixed during audit

This is a record of correctness / security bugs discovered during a
deliberate audit pass. Each has a regression test.

## Security bugs

### 1. `from="..."` pattern silently ignored (commit `443af05`)

**Severity:** high.

`authkeys.Options.From` was parsed but the server never called a
match function against the remote address. An administrator setting
`from="10.0.0.0/8"` expected IP restriction; they got no restriction.

**Fix:** added `authkeys.MatchFrom` with CIDR, wildcard hostname,
and negation support. Enforced in the `PublicKeyCallback`. E2E test
`TestFromAllowAndDeny`.

### 2. `environment="NAME=VALUE"` dropped (commit `d2cc14a`)

**Severity:** medium.

Same pattern: parsed, never applied. An operator setting
`environment="ROLE=ci"` expected the child to see `ROLE=ci`. It
didn't.

**Fix:** encode env map in `Permissions.Extensions` and merge into
`finalEnv()`. E2E test `TestAuthorizedKeysEnvironmentApplied`.

### 3. Typo in `authorized_keys` option silently dropped (commit `f1e1bdf`)

**Severity:** high.

A misspelled option like `cmmand="..."` (missing `o`) used to be
silently ignored, leaving the key unrestricted. The user thought
they were enforcing a forced command.

**Fix:** whitelist of recognised keywords; parsing rejects any
other. Known OpenSSH options we don't enforce (`cert-authority`,
`principals`, etc.) are on the whitelist so real files don't break.

### 4. `permitopen=host:80abc` silently parsed as port 80 (commit `f1e1bdf`)

**Severity:** medium.

`fmt.Sscanf("%d", ...)` returns success when the numeric prefix
consumes *part* of the input. Trailing garbage was ignored,
silently widening the permitted target set.

**Fix:** switched to `strconv.ParseUint` which rejects trailing
non-digits.

### 5. SOCKS5 handler had no read deadline (commit `f1e1bdf`)

**Severity:** medium (DoS).

A slow-loris attacker could connect to the SOCKS5 listener and
never send a greeting, holding a goroutine and fd indefinitely.

**Fix:** `SetReadDeadline(now + 10s)` on accept; cleared after the
CONNECT succeeds. Test `TestSOCKSHandshakeTimeout`.

### 6. TOFU known_hosts race → duplicate entries (commit `f1e1bdf`)

**Severity:** medium.

Two concurrent first-connects to the same host both saw "unknown"
(lock released between check and append), both wrote the host line.

**Fix:** hold `Verifier.mu` across the entire callback and re-check
under lock before appending. Tests
`TestConcurrentTOFUNoDuplicates` and
`TestConcurrentTOFUDifferentHosts`.

### 7. No global concurrent connection cap (commit `aaff531`)

**Severity:** medium (DoS).

`MaxConnectionsPerIP` stops a single IP; an attacker with many IPs
could still exhaust fds/memory.

**Fix:** `MaxConnections` semaphore, plus `MaxChannelsPerConn` for
in-connection fan-out.

## Correctness bugs

### 8. Signal only hit the shell, not its children (commit `f1e1bdf`)

`cmd.Process.Signal(sig)` only targets the direct child. For a
shell running `sleep`, sending SIGINT reached bash (which ignored
it) but not sleep. The client expected the session to end; it
timed out.

**Fix:** set `Setpgid` (non-PTY) / `Setsid` (PTY) so the child has
its own process group, then `syscall.Kill(-pid, sig)` to hit the
whole group. Verified by the regression test
`TestSignalForwardingKillsProcessGroup`, which fails without the
fix.

### 9. `ExecContext` busy-looped on cancelled context (commit `f1e1bdf`)

The signal-forwarding goroutine re-entered `select` after each
delivery. `ctx.Done()` stays closed, so after one cancel it fired
SIGTERM in a hot loop. Also, the function called `signal.Notify`
from a library entry point — stealing SIGINT from the parent
process.

**Fix:** single-shot goroutine, no `signal.Notify` in the library.
The CLI installs its own handler via `signal.NotifyContext`.

### 10. Shutdown grace didn't close the TCP conn (commit `337d65b`)

On `ShutdownGrace` expiry the server cancelled the inner context
(killing child processes) but left the SSH TCP connection open.
Active `-L` tunnels and idle sessions stayed up indefinitely.

**Fix:** goroutine per connection listening for ctx cancel, which
closes `*ssh.ServerConn`. Test
`TestShutdownTearsDownActiveSession`.

### 11. `env` / `pty-req` after `exec` raced with runner (commit `7ead2ed`)

The session runner reads `st.env` and `st.ptyReq` after `exec`
dispatches. Extra `env` requests arriving in flight mutated those
slices concurrently.

**Fix:** reject `env`/`pty-req` once `st.started`. Session-request
ordering is protocol-specified to place these before exec anyway.

### 12. `gossh -N` didn't notice remote disconnects (commit `59e8a4b`)

`gossh -N` blocked on `<-ctx.Done()` only; a remote-side crash or
kill of `gosshd` left the client running forever until Ctrl-C.

**Fix:** also watch `c.Raw().Wait()`, return non-zero on early
connection loss.

### 13. `spliceChannel` could block forever after half-close (commit `443af05`)

When one side EOFs and the peer keeps writing (or just keeps the
half-open connection), the other copy goroutine waited
indefinitely.

**Fix:** 10s force-close timer scheduled on half-close, matching
OpenSSH's behaviour of terminating idle half-open tunnels.

## Robustness

### 14. No panic recovery (commit `7ead2ed`, `c8726cb`)

An unrecovered panic in any Go goroutine terminates the process.
A bad session could thus kill the whole server.

**Fix:** `defer recover()` at each connection and channel boundary
(`handle`, `handleSession`, `handleDirectTCPIP`,
`handleGlobalRequests`).

### 15. `authorized_keys` never reloaded (commit `6c1b...`)

Entries were cached forever. Revoking a key required restarting
the server.

**Fix:** `ReloadingAuthorizedKeys` stats the file on each auth and
re-parses when mtime changes. `gosshd` always uses it — there is
no off-switch. Test `TestReloadingAuthorizedKeysRevocationE2E`.

### 16. TOCTOU between perm check and file open

The stat-then-open pattern let an attacker who controls the
directory race between the two calls to swap in a world-readable
file. We'd believe the stat'd perms and read the swapped file.

**Fix:** `os.Open` first, then `f.Stat()` (fstat on the open fd).
Applied in `authkeys.ParseFile` and `hostkey.Load`.

### 17. `remoteForwards.add` races with `closeAll`

A tcpip-forward arriving just before connection shutdown could
install its listener AFTER `closeAll` had already iterated and
emptied the map, leaking the listener past connection close.

**Fix:** latch a `closed` flag in `remoteForwards`; `add` checks it
and closes the new listener without adding.

### 18. `forward.{Local,Remote,Dynamic}` ignored their ctx

Accept loops only stopped when the caller explicitly invoked the
returned `stop()` func. Cancelling the enclosing context left
listeners up.

**Fix:** a watch goroutine closes the listener on `ctx.Done` and
exits on `stop()`.

### 19. `spliceChannel` half-close could hang forever

When one direction EOFs and the peer keeps its end open, the
other copy blocked indefinitely.

**Fix:** 10s force-close timer scheduled when the first copy ends
(also in the client's `splice`).

### 20. No TCP keepalive on accepted connections

Half-dead TCPs (crashed peer, NATs that dropped state) accumulate
until `ClientAliveInterval` fires — and that feature is opt-in.
Without either, a stuck connection lives forever.

**Fix:** `SetKeepAlive(true)` + `SetKeepAlivePeriod(30s)` on each
accepted `*net.TCPConn` in `handle`.

### 21. SCP path traversal (CVE-2019-6111 class)

A malicious *server* responding to an SCP download could include
filenames like `../../etc/passwd` in its C-line and trick the
client into writing outside the intended directory.

**Fix:** the `scp` package's `parseCLine` rejects names containing
`/`, `\x00`, or the pseudo-entries `.`/`..`. Also refuses setuid
/ setgid / sticky modes in the C-line.

### 22. Handshake-failure log spam

Port scanners triggering handshake failures filled operators'
stderr at INFO level.

**Fix:** downgrade to DEBUG. The audit log still records every
`handshake.fail` event for security correlation.

### 23. `sshd_config` silently accepted contradictory values

Values like `PermitRootLogin=weird` were parsed without validation.

**Fix:** validate the enum at gosshd startup; reject unsupported
strings; warn on `yes` (gosshd doesn't map SSH users to uids, so
it's advisory at best).

## Fuzz round 2

Second fuzz pass covering protocol-level paths (handshake,
post-auth session requests, direct-tcpip channel payloads) and
deeper data-parse paths (takeString, parsePTYReq, unquote,
parseHostPort, parseCLine, readAck, MatchFrom, ParseServer,
ResolveHost). ~25 minutes of cumulative fuzz time; two real
panics found and fixed.

### 24. `scp.parseCLine` panic on empty string (found by fuzz)

`parseCLine("")` did `line[1:]` without length check and indexed
out of range. Not reachable from a well-formed remote `scp -f`
but reachable from a hostile / buggy one.

**Fix:** length + prefix-byte check at the top. Found by
`FuzzParseCLine` seed #13 on first run.

### 25. `knownhosts.Append` panic on nil `remote net.Addr` (found by fuzz)

Passing `remote == nil` to `Append` caused `x/crypto/ssh/knownhosts`
to NPE deep inside `hostKeyDB.check`. A misuse by a library
consumer that shouldn't have crashed the process.

**Fix:** substitute a `placeholderAddr` before the stdlib call.
Found by `FuzzAppend` after ~30s.

### 26. `direct-tcpip` 10s dial timeout hard-coded

Fuzzing surfaced that the 10s `net.Dialer` timeout was not
configurable; under heavy channel churn this multiplies into
long per-connection latency and pushes the fuzzer over its
per-iteration budget.

**Fix:** `Config.DirectTCPIPDialTimeout` field; tests (and any
operator wanting a tighter bound) can override.

## External review (2026-04-17)

Eight findings from `docs/security-correctness-audit-2026-04-17.txt`.
All reproduced; each fix has a regression test.

### 27. CLI default was TOFU, contradicting SECURITY.md (audit #1)

`gossh` and `gossh-scp` defaulted `-strict-host-key` to
`accept-new`, but the documentation claimed strict was the
default. A network attacker could impersonate on first contact
and permanently seed a key.

**Fix:** changed the default to `yes` (strict) in both CLIs;
updated README, SECURITY.md, and docs/configuration.md.

### 28. `client.Dial` handshake unbounded (audit #2)

`ssh.NewClientConn` was called on the raw socket with no
deadline; a server that accepts TCP and then stalls could hang
callers forever even with `ConnectTimeout` set.

**Fix:** set a deadline on `nc` covering the full handshake;
spawn a ctx watcher that closes the socket on cancel; clear the
deadline after success. Tests `TestDialBoundsHandshake` and
`TestDialCtxCancelDuringHandshake`.

### 29. `-R 0:...` lifecycle broken (audit #3)

The server stored the listener under the *requested* port
(`0`) while `x/crypto/ssh` sends the *assigned* port in
`cancel-tcpip-forward`. Cancellation silently failed and two
concurrent `-R 0:...` requests collided on the same `host:0`
key.

**Fix:** key the registry by the actual bound port returned by
`net.Listen`. Test `TestRemoteForwardPort0Cancel`.

### 30. `forwarded-tcpip` bypassed `MaxChannelsPerConn` (audit #4)

The cap was only enforced on inbound channel-opens (`session`,
`direct-tcpip`). Server-initiated `forwarded-tcpip` channels
created by inbound `-R` traffic were uncapped — a flood could
defeat the advertised limit.

**Fix:** share the per-connection semaphore with
`acceptRemoteForward`; non-blocking reservation drops overflow.
Test `TestForwardedTCPIPRespectsChannelCap`.

### 31. SCP traversal guard was POSIX-only (audit #5)

`parseCLine` rejected `/` and NUL but not `\`, drive-letter
prefixes (`C:evil`), or UNC-style names. A Windows gossh-scp
client could still be tricked into writing outside the
destination directory by a malicious server.

**Fix:** new `validateSCPFilename` rejects `\`, drive-letter
prefixes, empty / oversized names, and both dot pseudo-entries.
Tests cover `..\evil`, `a\b`, `C:evil`, `c:`, `Z:\path`.

### 32. Audit-log failures silently swallowed (audit #6)

`audit.JSONLogger.Emit` ignored both `Write` and `Sync` errors,
defeating the durability promise under disk-full / permission /
NFS conditions.

**Fix:** added a `Failures()` counter, `OnError` per-failure
callback, and a `FailClosed` one-shot. `gosshd` wires `OnError`
to emit each failure via the main `slog` logger. Test
`TestJSONLoggerSurfacesWriteFailures`.

### 33. `Client.Shell()` SIGWINCH goroutine leak (audit #7)

`for range winch` never exited because `signal.Stop` does not
close the channel. Long-lived callers accumulated goroutines.

**Fix:** added a `winchDone` channel; the goroutine `select`s
on both and returns on shell exit.

### 34. `ssh_config` inline comments not stripped (audit #8)

`Port 2222 # comment` was parsed with the comment inside the
value. Numeric fields failed loudly; string fields silently
produced garbage.

**Fix:** rewrote `stripComment` to scan for an unquoted `#`,
honouring double quotes and `\"` escapes. Tests added for
both `ParseClient` and `ParseServer`.
