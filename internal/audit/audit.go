// Package audit is a focused audit-log sink for gosshd.
//
// Unlike the server's slog logger (which is for debugging), audit
// events are meant to be a durable, append-only record of
// security-relevant things that happened: who authenticated, what
// commands they ran, what tunnels they opened.
//
// An audit.Logger consumes Event values. The default implementation
// writes JSON Lines to a provided io.Writer. Operators who want
// durable storage can pass an os.File opened with O_APPEND and set
// Fsync=true to force fdatasync after each event.
//
// Fields are intentionally untyped to keep the surface small; callers
// pass arbitrary key/value pairs. Keep values JSON-serialisable.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is a single audit record.
type Event struct {
	Time   time.Time              `json:"time"`
	Type   string                 `json:"type"`
	Remote string                 `json:"remote,omitempty"`
	User   string                 `json:"user,omitempty"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// Event type constants. These are stable — parsers in SIEM pipelines
// depend on them.
const (
	TypeConnectionAccept    = "connection.accept"
	TypeConnectionReject    = "connection.reject"
	TypeConnectionClose     = "connection.close"
	TypeHandshakeFail       = "handshake.fail"
	TypeAuthOK              = "auth.ok"
	TypeAuthFail            = "auth.fail"
	TypeSessionOpen         = "session.open"
	TypeSessionExec         = "session.exec"
	TypeSessionShell        = "session.shell"
	TypeSessionClose        = "session.close"
	TypeSessionSignal       = "session.signal"
	TypeDirectTCPIPOpen     = "channel.direct-tcpip.open"
	TypeDirectTCPIPReject   = "channel.direct-tcpip.reject"
	TypeDirectTCPIPClose    = "channel.direct-tcpip.close"
	TypeTCPIPForwardBind    = "global.tcpip-forward.bind"
	TypeTCPIPForwardReject  = "global.tcpip-forward.reject"
	TypeTCPIPForwardCancel  = "global.tcpip-forward.cancel"
	TypeForwardedTCPIPOpen  = "channel.forwarded-tcpip.open"
	TypeForwardedTCPIPClose = "channel.forwarded-tcpip.close"
	TypeKeepaliveTimeout    = "conn.keepalive-timeout"
	TypeShutdownBegin       = "server.shutdown.begin"
	TypeShutdownForce       = "server.shutdown.force"
)

// Logger is the sink for audit events.
type Logger interface {
	Emit(Event)
}

// Nop is a Logger that drops every event. Use it as the default
// when audit logging isn't configured.
var Nop Logger = nopLogger{}

type nopLogger struct{}

func (nopLogger) Emit(Event) {}

// JSONLogger writes events as JSON lines to Writer. Thread-safe; a
// single line is written under a mutex so concurrent Emit calls
// never interleave.
//
// If Fsync is true and Writer is an *os.File, Sync is called after
// each event. This is expensive but necessary to survive a crash
// with integrity.
//
// On Write or Sync failure the event is silently accepted by Emit
// (Emit has no return value), but the failure is surfaced in three
// ways an operator can observe:
//   - `Failures()` returns the cumulative failed-write count.
//   - If `OnError` is set, it is called for each failure with the
//     underlying error and the event type. It runs while l.mu is
//     held, so keep it short (or hand off to a channel).
//   - If FailClosed is set to a non-nil callback, that callback
//     is invoked on the first failure; callers can use it to
//     terminate the server rather than continue unlogged.
type JSONLogger struct {
	Writer     io.Writer
	Fsync      bool
	OnError    func(err error, eventType string) // optional, called on each failure
	FailClosed func(err error)                   // optional, called once on first failure

	mu            sync.Mutex
	failures      uint64
	failClosedRun bool
}

// Failures returns the cumulative number of Write/Sync errors since
// the logger was created. Safe to call concurrently with Emit.
func (l *JSONLogger) Failures() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}

// Emit serialises e to a single JSON line.
func (l *JSONLogger) Emit(e Event) {
	if l == nil || l.Writer == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	buf, err := json.Marshal(e)
	if err != nil {
		l.record(err, e.Type)
		return
	}
	buf = append(buf, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, werr := l.Writer.Write(buf); werr != nil {
		l.recordLocked(werr, e.Type)
		return
	}
	if l.Fsync {
		if f, ok := l.Writer.(*os.File); ok {
			if serr := f.Sync(); serr != nil {
				l.recordLocked(serr, e.Type)
				return
			}
		}
	}
}

// record takes l.mu and forwards to recordLocked.
func (l *JSONLogger) record(err error, eventType string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordLocked(err, eventType)
}

// recordLocked increments the failure counter and invokes callbacks.
// Caller must hold l.mu.
func (l *JSONLogger) recordLocked(err error, eventType string) {
	l.failures++
	if l.OnError != nil {
		l.OnError(err, eventType)
	}
	if l.FailClosed != nil && !l.failClosedRun {
		l.failClosedRun = true
		l.FailClosed(err)
	}
}

// OpenFile opens path in append mode with 0600 permissions. If the
// file does not exist it is created.
func OpenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// Multi fans an event out to several Loggers. It emits to each in
// order; a slow sink blocks all of them (intentional — audit logs
// are load-bearing, we'd rather block than drop).
type Multi []Logger

// Emit dispatches e to every sub-logger.
func (m Multi) Emit(e Event) {
	for _, l := range m {
		l.Emit(e)
	}
}
