package server_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
)

// FuzzServerHandshake feeds arbitrary bytes at an accepted gosshd
// connection and ensures the server never panics. The handshake is
// guaranteed to fail; we only care that the server cleans up.
func FuzzServerHandshake(f *testing.F) {
	// Seeds: plausible SSH banners and garbage.
	f.Add([]byte("SSH-2.0-garbage\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("SSH-1.99-old\r\nmore stuff that is not valid KEX"))

	// Set up a single gosshd for all fuzz iterations — cheaper than
	// spinning one per execution.
	dir := f.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		f.Fatal(err)
	}
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		f.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)
	l, _ := net.Listen("tcp", "127.0.0.1:0")

	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		LoginGraceTime: 500 * time.Millisecond, // keep fuzz iterations snappy
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	f.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	addr := l.Addr().String()

	f.Fuzz(func(t *testing.T, in []byte) {
		// Connect, write the garbage, then close. The server's
		// handle() goroutine must finish without panicking.
		c, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			// The listener may be temporarily busy; skip rather than
			// fail — we're only interested in server panics.
			return
		}
		_ = c.SetDeadline(time.Now().Add(1 * time.Second))
		if len(in) > 0 {
			_, _ = c.Write(in)
		}
		_ = c.Close()
	})
}
