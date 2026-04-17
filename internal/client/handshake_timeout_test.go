package client_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
)

// TestDialBoundsHandshake verifies that a server that accepts TCP
// and then never says anything can't hang client.Dial. Before the
// fix, ssh.NewClientConn would wait for a banner indefinitely once
// the TCP connect had succeeded, even with a short ConnectTimeout.
func TestDialBoundsHandshake(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Accept and never write anything.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open, silent.
			_ = c
		}
	}()

	port := l.Addr().(*net.TCPAddr).Port

	// Provide a real identity so we actually reach NewClientConn.
	dir := t.TempDir()
	userKey := filepath.Join(dir, "id")
	if _, err := hostkey.LoadOrGenerate(userKey, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	// ConnectTimeout bounds the handshake after the fix.
	_, err = client.Dial(context.Background(), client.Config{
		Host:           "127.0.0.1",
		Port:           port,
		User:           "u",
		IdentityFiles:  []string{userKey},
		HostCheckMode:  knownhosts.Off,
		ConnectTimeout: 1 * time.Second,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected Dial to fail against a silent server")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Dial took %v against a silent server — handshake not bounded", elapsed)
	}
}

// TestDialCtxCancelDuringHandshake verifies that cancelling the
// supplied context while the handshake is in flight returns
// promptly, not after some hard-coded timeout.
func TestDialCtxCancelDuringHandshake(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			if _, err := l.Accept(); err != nil {
				return
			}
		}
	}()

	port := l.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	userKey := filepath.Join(dir, "id")
	if _, err := hostkey.LoadOrGenerate(userKey, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err = client.Dial(ctx, client.Config{
		Host:           "127.0.0.1",
		Port:           port,
		User:           "u",
		IdentityFiles:  []string{userKey},
		HostCheckMode:  knownhosts.Off,
		ConnectTimeout: 60 * time.Second,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected Dial to fail when ctx cancelled")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Dial did not honor ctx cancel: took %v", elapsed)
	}
}
