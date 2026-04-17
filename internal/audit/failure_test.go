package audit

import (
	"errors"
	"sync/atomic"
	"testing"
)

// errWriter fails every Write with a fixed error.
type errWriter struct {
	writes atomic.Int32
	err    error
}

func (e *errWriter) Write(p []byte) (int, error) {
	e.writes.Add(1)
	return 0, e.err
}

func TestJSONLoggerSurfacesWriteFailures(t *testing.T) {
	target := &errWriter{err: errors.New("disk full")}
	var onErrorCalls atomic.Int32
	l := &JSONLogger{
		Writer: target,
		OnError: func(err error, eventType string) {
			if err == nil {
				t.Error("OnError got nil err")
			}
			if eventType != TypeAuthOK {
				t.Errorf("unexpected type %q", eventType)
			}
			onErrorCalls.Add(1)
		},
	}
	for i := 0; i < 5; i++ {
		l.Emit(Event{Type: TypeAuthOK})
	}
	if got, want := l.Failures(), uint64(5); got != want {
		t.Fatalf("Failures() = %d, want %d", got, want)
	}
	if onErrorCalls.Load() != 5 {
		t.Fatalf("OnError called %d times, want 5", onErrorCalls.Load())
	}
}

func TestJSONLoggerSuccessDoesNotCount(t *testing.T) {
	var buf sink
	l := &JSONLogger{Writer: &buf}
	l.Emit(Event{Type: TypeAuthOK})
	if got := l.Failures(); got != 0 {
		t.Fatalf("Failures() = %d after successful emit, want 0", got)
	}
}

type sink struct{}

func (sink) Write(p []byte) (int, error) { return len(p), nil }
