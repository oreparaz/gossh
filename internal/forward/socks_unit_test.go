package forward

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn implements net.Conn over buffers. Used to exercise the
// SOCKS5 reader/writer without a full SSH round-trip.
type fakeConn struct {
	r io.Reader
	w io.Writer
}

func (f *fakeConn) Read(p []byte) (int, error)         { return f.r.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error)        { return f.w.Write(p) }
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake:0" }

func TestSOCKSWrongVersionIgnored(t *testing.T) {
	// Greeting with version 4, not 5: handler must not panic.
	in := bytes.NewBuffer([]byte{0x04, 0x01, 0x00})
	var out bytes.Buffer
	c := &fakeConn{r: in, w: &out}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); handleSOCKS(c, nil, log); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleSOCKS did not return on bad version")
	}
	wg.Wait()
}

func TestSOCKSUnsupportedMethodRejected(t *testing.T) {
	// Offer method 0x02 (user/pass) only — we must respond 0xFF.
	in := bytes.NewBuffer([]byte{0x05, 0x01, 0x02})
	var out bytes.Buffer
	c := &fakeConn{r: in, w: &out}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleSOCKS(c, nil, log)
	b := out.Bytes()
	if len(b) != 2 || b[0] != 0x05 || b[1] != 0xFF {
		t.Fatalf("got reply %v, want [05 FF]", b)
	}
}

func TestSOCKSUnsupportedCommandRejected(t *testing.T) {
	// Methods negotiate OK, then send CMD=BIND (0x02) which we don't do.
	buf := append([]byte{0x05, 0x01, 0x00}, // greeting
		0x05, 0x02, 0x00, 0x01, // VER CMD RSV ATYP(ipv4)
		127, 0, 0, 1, 0x00, 0x50, // 127.0.0.1:80
	)
	in := bytes.NewBuffer(buf)
	var out bytes.Buffer
	c := &fakeConn{r: in, w: &out}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleSOCKS(c, nil, log)
	b := out.Bytes()
	// First response: greeting reply [05 00]. Then CONNECT reply with
	// error code replyCommandUnsup (0x07).
	if len(b) < 2+10 {
		t.Fatalf("short reply %v", b)
	}
	if b[0] != 0x05 || b[1] != 0x00 {
		t.Fatalf("bad greeting reply: %v", b[:2])
	}
	reply := b[2:]
	if reply[0] != 0x05 || reply[1] != 0x07 {
		t.Fatalf("expected replyCommandUnsup, got %v", reply[:2])
	}
}

func TestSOCKSTruncatedGreetingIgnored(t *testing.T) {
	in := bytes.NewBuffer([]byte{0x05}) // truncated
	var out bytes.Buffer
	c := &fakeConn{r: in, w: &out}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleSOCKS(c, nil, log) // must not panic
	if out.Len() != 0 {
		t.Fatalf("no reply expected, got %v", out.Bytes())
	}
}
