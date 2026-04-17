package server_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/forward"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

// TestForwardedTCPIPRespectsChannelCap floods an inbound -R listener
// and asserts that goroutine creation stays bounded by
// MaxChannelsPerConn. Before the fix, forwarded-tcpip channels
// bypassed the cap (audit #4).
func TestForwardedTCPIPRespectsChannelCap(t *testing.T) {
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

	const cap = 8
	s, _ := server.New(server.Config{
		HostKeys:           []ssh.Signer{hk.Signer},
		AuthorizedKeys:     server.StaticAuthorizedKeys(entries),
		Shell:              "/bin/bash",
		AllowExec:          true,
		AllowRemoteForward: true,
		MaxChannelsPerConn: cap,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmtKnownHosts(portStr, hk.Signer.PublicKey())), 0o600)
	port := atoi(portStr)

	// A local "destination" the forwarded-tcpip traffic should reach —
	// it immediately closes, so each channel is short-lived but we
	// flood enough that the concurrent high-water mark exceeds cap.
	dst, _ := net.Listen("tcp", "127.0.0.1:0")
	defer dst.Close()
	go func() {
		for {
			c, err := dst.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = c.Close()
			}()
		}
	}()
	dstHost, dstPortStr, _ := net.SplitHostPort(dst.Addr().String())
	var dstPort int
	fmt.Sscanf(dstPortStr, "%d", &dstPort)

	cCtx, cCancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	// Pick a free port for the server-side bind.
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	bindPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Remote(cCtx, c.Raw(), forward.Spec{
		BindAddr: "127.0.0.1", BindPort: bindPort,
		TargetHost: dstHost, TargetPort: dstPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	time.Sleep(100 * time.Millisecond)

	before := runtime.NumGoroutine()
	// Flood the -R listener from outside.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cconn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort), 2*time.Second)
			if err != nil {
				return
			}
			defer cconn.Close()
			_ = cconn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 1)
			_, _ = cconn.Read(buf)
		}()
	}
	// Sample goroutine count mid-flood.
	time.Sleep(50 * time.Millisecond)
	mid := runtime.NumGoroutine()

	wg.Wait()
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	// If the cap is enforced, the server won't spawn 100 forwarded-
	// tcpip goroutines simultaneously. We allow plenty of slack for
	// test plumbing; 80+ extra goroutines would be a definite leak.
	if mid-before > 80 {
		t.Fatalf("channel cap bypassed: goroutine delta mid-flood=%d (before=%d, mid=%d)", mid-before, before, mid)
	}
	if after > before+10 {
		t.Fatalf("goroutine leak after flood: before=%d after=%d", before, after)
	}
}
