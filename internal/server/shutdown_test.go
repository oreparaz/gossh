package server_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

// TestShutdownTearsDownActiveSession kicks off a long-running remote
// command, cancels the server's context (simulating SIGTERM), and
// checks that the client session returns within a bounded time —
// proving that ShutdownGrace expiry actually closes the SSH TCP conn
// (a previous version left it open indefinitely).
func TestShutdownTearsDownActiveSession(t *testing.T) {
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
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		ShutdownGrace:  300 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = s.Serve(ctx, l) }()
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	port := atoi(portStr)
	cCtx, cCancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	// Kick off a long remote command.
	done := make(chan error, 1)
	go func() {
		_, err := c.Exec("sleep 30", nil, io.Discard, io.Discard)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)

	// Shutdown the server.
	shutdownStart := time.Now()
	cancel()

	// Expect the exec to return within 2s (grace period 300ms + some
	// slack). Previously this would hang forever because shutdown
	// left the TCP connection up.
	select {
	case <-done:
		if d := time.Since(shutdownStart); d > 2*time.Second {
			t.Fatalf("exec took %v to notice shutdown", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec did not return after shutdown + grace period")
	}
	<-serverDone
}

// TestServeStopsOnContext verifies that a canceled context cleanly
// returns from Serve without leaking.
func TestServeStopsOnContext(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		ShutdownGrace:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
