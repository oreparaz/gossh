# Architecture

High-level data flow for one inbound connection, from `accept(2)`
through teardown.

## Process model

`gosshd` is a single Go process with one goroutine per connection,
plus child goroutines per session/channel. No forking, no privilege
separation, no uid switching. The process runs as whatever user
invoked it; every authenticated session executes commands as that
same uid.

```
   gosshd (uid=U)
     └─ accept-loop goroutine
          ├─ conn 1 goroutine (ssh.NewServerConn)
          │    ├─ handleGlobalRequests goroutine
          │    ├─ keepalive prober (optional)
          │    ├─ ctx-watch goroutine (closes conn on shutdown)
          │    ├─ session goroutine × N  (exec / shell / pty-req)
          │    │    └─ child process (uid=U) with stdio piped
          │    │       to the SSH channel
          │    └─ direct-tcpip goroutine × N
          │         └─ splice to TCP dest
          └─ conn 2 goroutine …
```

## Connection lifecycle

Entry points in `internal/server/server.go`. Line numbers are
approximate — treat them as waypoints, not fixed addresses.

1. **Accept.** `Serve` loops on `l.Accept()`. Each accepted
   `net.Conn` is handed to `handle` in a fresh goroutine. A
   per-IP concurrency limiter (`internal/server/limits.go`) can
   refuse before we do any SSH work.

2. **TCP knobs.** `handle` enables `TCP_KEEPALIVE` with a 30 s
   probe. Silent half-dead peers get reaped by the kernel even
   without the application-layer keepalive.

3. **Audit: `connection.accept`.** See [`audit.md`](audit.md) for
   the full event shape.

4. **Panic recovery.** `defer recover()` so a panicking goroutine
   can't take down the process.

5. **Login grace timer.** `nc.SetDeadline` is set to
   `LoginGraceTime` (default 120 s) before handshake; cleared on
   success. Slow/stuck clients drop automatically.

6. **Handshake.** `ssh.NewServerConn` runs KEX, user-auth with
   the callback we supply. The algorithm allowlist
   (`internal/sshcrypto/algs.go`) narrows both KEX and ciphers.

7. **Public-key callback.** `serverConfig.PublicKeyCallback`:
   - look up `authorized_keys` (static or mtime-reloading),
   - `authkeys.Find` matches by marshalled bytes,
   - `authkeys.MatchFrom` enforces `from=` against the remote IP,
   - options (`command=`, `permitopen=`, `environment=`, no-*)
     are serialised into `ssh.Permissions.Extensions` for the
     session handlers.

8. **Channel loop.** `for newCh := range chans`:
   - `session` → `handleSession`
   - `direct-tcpip` → `handleDirectTCPIP`
   - anything else → reject with `UnknownChannelType`.
   A per-connection semaphore caps this at `MaxChannelsPerConn`
   (default 64).

9. **Global requests.** `handleGlobalRequests` handles
   `tcpip-forward` / `cancel-tcpip-forward` / keepalive. Bound
   listeners are tracked in a `remoteForwards` struct so they
   can be closed atomically on connection teardown.

10. **Session dispatch.** `handleSession` collects `env` and
    `pty-req` until it sees `exec` or `shell`, then spawns the
    runner goroutine. Requests *after* start are handled for
    `window-change` and `signal` only — other kinds race with
    the runner and are rejected.

11. **Command execution.**
    - `runPipe` for non-PTY: `cmd.StdinPipe()` manually copied
      from the channel so `cmd.Wait` can return when bash EOFs,
      not when the client closes stdin. `Setpgid` puts the child
      in its own process group so signal forwarding reaches
      subcommands.
    - `runPTY` for PTY: `creack/pty` allocates the pseudo-tty;
      one goroutine copies pty→channel, another copies channel→pty;
      a resize goroutine drains the window-change channel.
      `Setsid`+`Setctty` make the child a session leader.
      On teardown, `runPTY` signals the resize goroutine to stop and
      waits for it before closing the master — a late window-change
      that arrived as the child exited must not ioctl a closed fd.

12. **Signal forwarding.** `deliverSignal` resolves an SSH signal
    name to `syscall.Signal` and sends via `kill(-pid, sig)` when
    the child has its own process group; otherwise falls back to
    `cmd.Process.Signal`.

13. **Exit.** `cmd.Wait` returns → CloseWrite → `exit-status`
    request → `ch.Close`. Order matters: the client's
    `ssh.Session.Wait` needs the exit-status to arrive before the
    close message.

14. **Teardown.** When the connection drops (client disconnect,
    shutdown grace expiry, or keepalive timeout):
    - `fwd.closeAll()` closes every `-R` listener (latches a
      `closed` flag so a racing `add` also bails),
    - `conn.Close()` tears the SSH connection down,
    - `nc.Close()` drops the TCP socket,
    - audit emits `session.close` per session and
      `connection.close` for the outer wrap.

## Client lifecycle

Entry points in `internal/client/client.go`.

1. **Identity loading.** `hostkey.Load` enforces mode `0600` via
   fstat-after-open; files > 1 MiB are rejected.
2. **Host-key verification.** `internal/knownhosts` wraps
   `x/crypto/ssh/knownhosts`:
   - `Strict`: refuse unknown hosts,
   - `TOFU` / `AcceptNew`: add to file on first sight; mismatch
     is always fatal.
   The callback holds the verifier mutex for the entire
   verification so concurrent first-connects can't write
   duplicate entries. If `KnownHostsPath` is empty and `$HOME`
   can't be resolved, Dial errors instead of silently falling
   back to `./.ssh/known_hosts` in the working directory.
3. **Dial.** Two paths:
   - Direct TCP: `net.Dialer.DialContext` honours the caller's
     context and is bounded by `ConnectTimeout`.
   - `ProxyCommand`: `sh -c <expanded>` is exec'd; its stdio is
     wrapped as a `net.Conn` (`internal/client/proxy.go`). `%h` /
     `%p` / `%r` substitutions are rejected if they contain
     anything outside a tight shell-safe allowlist, so a malicious
     host/user on the CLI can't inject commands.
   `ssh.NewClientConn` then runs the handshake under the same
   algorithm allowlist. The handshake is bounded by a
   context-cancel watcher + socket deadline, so a TCP-accept
   followed by a stall at the SSH layer can't hang forever.
4. **Session.** `Exec` / `ExecContext` / `Shell`. `ExecContext`
   forwards a single `SIGTERM` to the remote when ctx is
   cancelled; no `signal.Notify` is installed from library
   code (that's the CLI's job in `cmd/gossh`).
5. **Forwarding.** `forward.{Local,Remote,Dynamic}` each start
   an accept loop and a `ctx`-watcher; cancelling ctx closes
   the listener and the goroutine exits.

## SCP path (client)

`internal/scp/scp.go`. We drive the remote `scp -t` / `scp -rt`
(upload) or `scp -f` / `scp -rf` (download) subprocess by
sending/receiving the legacy SCP wire format over stdin/stdout of
an SSH exec channel:

- Upload (single file): send `C<mode> <size> <name>\n`, read ack,
  stream bytes, send trailing `\0`, read final ack, close stdin.
- Upload (`-r`): `uploadTree` walks the local dir depth-first,
  emitting `D<mode> 0 <name>\n` + body + `E\n` around each
  directory and `C` for each regular file. Non-regular entries
  (symlinks, sockets, devices) are skipped — OpenSSH behaves
  the same.
- Download: send `\0` ready; `receiverState.run` reads C / D / E
  / T directives. D pushes the path stack, E pops, C writes a
  regular file. Only ENOENT is treated as "nothing to check" on
  symlink-refusal Lstat; other errors surface.

`parseHeader` (shared by `parseCLine` + `parseDLine`) rejects
path-traversal names (`..`, `/`, `\`, `\0`, Windows drive/UNC
prefixes) and setuid/setgid/sticky modes — this is the single
most important defensive parser in the codebase from a
malicious-server standpoint. `refuseExistingSymlink` walks every
existing parent component from root to leaf so a symlinked
parent can't redirect the write. Recursive transfers are capped
at 64 levels (both send and receive). Consecutive `T` directives
are rejected and remote stderr reads are capped at 4 KiB to
neutralise trivial DoS shapes from a hostile peer.

## Audit log

`internal/audit/audit.go`. A single mutex serialises writes so
JSON lines never interleave. `Fsync: true` turns each emit into a
durable `fdatasync(2)`. Events are fired at every auth, session,
forward, and teardown boundary. See [`audit.md`](audit.md) for
the full list.

## Error philosophy

- Handshake failures: log at `DEBUG` (scanners flood it otherwise)
  but always emit an audit `handshake.fail` event.
- Unknown / unsupported values in `sshd_config`: return an error
  at startup rather than silently defaulting.
- Unknown `authorized_keys` options: reject the line (a typo in
  `command=` must never silently disable the restriction).
- Parser input: prefer `strconv.ParseUint` over `fmt.Sscanf` —
  the latter accepts trailing garbage.
