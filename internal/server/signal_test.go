package server_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/knownhosts"
)

// TestSignalForwarding kicks off a long sleep through gossh's client
// package, then sends SIGTERM via ssh's "signal" request. The server
// must deliver the signal and the remote shell must exit.
func TestSignalForwarding(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, client.Config{
		Host:           h.Host,
		Port:           atoi(h.Port),
		User:           "testuser",
		IdentityFiles:  []string{h.UserKeyPath},
		KnownHostsPath: h.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	s, err := c.Raw().NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Start a sleep in the background so stdout returns quickly.
	stdout, _ := s.StdoutPipe()
	stderr, _ := s.StderrPipe()
	go func() {
		_, _ = io.Copy(io.Discard, stdout)
	}()
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	if err := s.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}
	// Give the server a chance to start the child.
	time.Sleep(200 * time.Millisecond)
	if err := s.Signal(ssh.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	waitErrCh := make(chan error, 1)
	go func() { waitErrCh <- s.Wait() }()
	select {
	case err := <-waitErrCh:
		// sh -c "sleep 30" killed by SIGTERM should return an error
		// indicating the signal. exitStatus(signal) → 128+15 = 143.
		if err == nil {
			t.Fatal("expected non-zero exit from sigterm")
		}
		if !strings.Contains(err.Error(), "143") && !strings.Contains(err.Error(), "TERM") {
			t.Logf("exit error: %v (not fatal; shells vary)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote command did not exit after SIGTERM")
	}
}

func atoi(s string) int {
	var n int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
