package server_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/forward"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/knownhosts"
	"github.com/oreparaz/gossh/internal/server"
)

// TestRemoteForwardPort0Cancel verifies that opening a `-R 0:...`
// and then cancelling it actually releases the server-side listener.
// Before the fix, the listener was keyed by the requested port (0)
// while x/crypto/ssh's cancel-tcpip-forward sent the assigned port,
// so cancellation did nothing and the listener leaked.
func TestRemoteForwardPort0Cancel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hk, _ := hostkey.LoadOrGenerate(filepath.Join(dir, "h"), hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())

	s, _ := server.New(server.Config{
		HostKeys:           []ssh.Signer{hk.Signer},
		AuthorizedKeys:     server.StaticAuthorizedKeys(entries),
		Shell:              "/bin/bash",
		AllowExec:          true,
		AllowRemoteForward: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmtKnownHosts(portStr, hk.Signer.PublicKey())), 0o600)
	port := atoi(portStr)

	cCtx, cCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cCancel()
	c, err := client.Dial(cCtx, client.Config{
		Host: "127.0.0.1", Port: port, User: "u",
		IdentityFiles:  []string{userPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Open a -R 0:... (server picks port).
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Remote(cCtx, c.Raw(), forward.Spec{
		BindAddr:   "127.0.0.1",
		BindPort:   0, // let the server assign
		TargetHost: "127.0.0.1",
		TargetPort: 1,
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	// The x/crypto/ssh listener has the assigned port now. Cancel.
	stop()
	// Give cancel-tcpip-forward time to reach the server.
	time.Sleep(200 * time.Millisecond)

	// The freed port should be bindable by a plain net.Listen
	// — but we can't know which port was assigned without poking
	// internals. Instead assert indirectly: open a second -R 0:...
	// and make sure it succeeds (would previously collide with the
	// stale key).
	stop2, err := forward.Remote(cCtx, c.Raw(), forward.Spec{
		BindAddr:   "127.0.0.1",
		BindPort:   0,
		TargetHost: "127.0.0.1",
		TargetPort: 1,
	}, log)
	if err != nil {
		t.Fatalf("second -R 0:... failed (first cancel did not release): %v", err)
	}
	stop2()
}
