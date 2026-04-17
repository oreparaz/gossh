# Audit events

Events are JSON-Lines. Enable with `gosshd -audit-log /var/log/gosshd/audit.jsonl`.
Add `-audit-fsync` to `fsync` after every event (slower, safer).

Each event has a fixed shape:

```json
{
  "time":   "RFC3339 UTC",
  "type":   "string, dotted, stable",
  "remote": "client tcp addr (host:port), when known",
  "user":   "SSH login name, when authenticated",
  "fields": { "...": "event-specific" }
}
```

## Events

| Type | When | Key fields |
|---|---|---|
| `connection.accept` | TCP accepted, handshake not yet started | — |
| `connection.reject` | Refused before handshake (e.g. per-IP cap) | `reason` |
| `handshake.fail` | SSH handshake failed | `err` |
| `auth.ok` | Public-key auth succeeded | `fp`, `key_type`, `has_forced` |
| `auth.fail` | Public-key auth refused | `fp`, `reason` (`key-not-authorized`, `from`, `authorized_keys`) |
| `session.open` | Session channel accepted | — |
| `session.exec` | `exec` request dispatched | `command`, `client_command`, `forced`, `pty` |
| `session.shell` | `shell` request dispatched | `forced`, `pty`, `command` |
| `session.signal` | Client sent a "signal" request | `name` |
| `session.close` | Session returned | `duration_ms`, `exit`, `started` |
| `channel.direct-tcpip.open` | `-L` tunnel opened | `target` |
| `channel.direct-tcpip.reject` | `-L` refused | `target`, `reason` (`permitopen`, `dial-fail`) |
| `channel.direct-tcpip.close` | `-L` tunnel closed | `target`, `duration_ms` |
| `global.tcpip-forward.bind` | `-R` listener created | `host`, `port` |
| `global.tcpip-forward.reject` | `-R` refused | `host`, `port`, `reason` (`no-port-forwarding`, `permitlisten`, `listen-fail`) |
| `global.tcpip-forward.cancel` | Client cancelled `-R` | `host`, `port`, `ok` |
| `channel.forwarded-tcpip.open` | Inbound connection on `-R` listener accepted | `bind_host`, `bind_port`, `orig` |
| `channel.forwarded-tcpip.close` | Splice ended | `bind_host`, `bind_port`, `duration_ms` |
| `conn.keepalive-timeout` | ClientAliveCountMax exceeded | `fails` |
| `connection.close` | TCP/SSH connection ended | `duration_ms` |
| `server.shutdown.begin` | Shutdown initiated | — |
| `server.shutdown.force` | Grace expired, sessions killed | — |
| `server.panic` | A handler goroutine panicked | `panic` |

## Per-connection causal order

For a well-behaved session, you will see the following sequence:

```
connection.accept
(auth.fail*)
auth.ok
session.open
[session.exec | session.shell]
(session.signal*)
session.close
connection.close
```

`channel.direct-tcpip.*` and `global.tcpip-forward.*` interleave freely
while the connection is live.

## Integrity guarantees

- Each event is a single `write()` holding an internal mutex. Lines
  never interleave, even under heavy concurrency.
- Timestamps are UTC.
- The file is opened `O_APPEND | O_CREATE` with `0600` permissions. If
  it is rotated out from under `gosshd`, the server keeps writing to
  the old (unlinked) inode — send SIGHUP and restart, or use an
  external shipper that reopens on rename.
- `-audit-fsync` forces `fdatasync()` after every event. Without it,
  events can be lost in a power loss within the kernel's writeback
  window (typically 5s).

## What is NOT logged

- Byte counts (in or out) per connection — not tracked.
- TCP flags, MTU, jitter — this is an SSH audit log, not a pcap.
- PTY output or exec stdout/stderr — that's user data and is never
  captured.
- Passwords or auth secrets (we don't accept them).
