package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSONLoggerEmit(t *testing.T) {
	var buf bytes.Buffer
	l := &JSONLogger{Writer: &buf}
	l.Emit(Event{
		Type: TypeAuthOK,
		User: "alice",
		Fields: map[string]interface{}{
			"fp": "SHA256:abc",
		},
	})
	line := strings.TrimSpace(buf.String())
	var got Event
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("unmarshal: %v raw=%s", err, line)
	}
	if got.Type != TypeAuthOK || got.User != "alice" {
		t.Fatalf("got %+v", got)
	}
	if got.Time.IsZero() {
		t.Fatal("time should be filled in")
	}
	if got.Fields["fp"] != "SHA256:abc" {
		t.Fatalf("fields: %+v", got.Fields)
	}
}

func TestJSONLoggerOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	l := &JSONLogger{Writer: &buf}
	for i := 0; i < 5; i++ {
		l.Emit(Event{Type: TypeSessionExec, Fields: map[string]interface{}{"i": i}})
	}
	// Must have 5 newlines, 5 non-empty lines.
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines", len(lines))
	}
	for _, ln := range lines {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("unmarshal %q: %v", ln, err)
		}
	}
}

func TestJSONLoggerConcurrent(t *testing.T) {
	var buf bytes.Buffer
	l := &JSONLogger{Writer: &buf}
	var wg sync.WaitGroup
	const N = 100
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Emit(Event{Type: "test", Fields: map[string]interface{}{"i": i}})
		}(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != N {
		t.Fatalf("got %d lines, want %d", len(lines), N)
	}
	// Each line must parse, proving no interleaving.
	for i, ln := range lines {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("line %d: %v\n%s", i, err, ln)
		}
	}
}

func TestNopLoggerNoPanic(t *testing.T) {
	Nop.Emit(Event{Type: "x"})
}

func TestMultiFansOut(t *testing.T) {
	var a, b bytes.Buffer
	m := Multi{&JSONLogger{Writer: &a}, &JSONLogger{Writer: &b}}
	m.Emit(Event{Type: "x", Time: time.Unix(0, 0).UTC()})
	if a.Len() == 0 || b.Len() == 0 {
		t.Fatalf("both sub-loggers should have received: %q %q", a.String(), b.String())
	}
}

func TestJSONLoggerNilWriterIsSafe(t *testing.T) {
	var l *JSONLogger
	l.Emit(Event{Type: "x"}) // must not panic
	l2 := &JSONLogger{Writer: nil}
	l2.Emit(Event{Type: "x"})
}
