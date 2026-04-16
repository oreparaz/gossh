package client_test

import (
	"context"
	"fmt"
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

// benchRig mirrors testRig but uses testing.TB so it can be driven
// from benchmarks.
type benchRig = testRig

func startGosshdB(tb testing.TB) *benchRig { return startGosshdBImpl(tb, false) }

func startGosshdBWithForward(tb testing.TB) *benchRig { return startGosshdBImpl(tb, true) }

func startGosshdBImpl(tb testing.TB, withForward bool) *benchRig {
	tb.Helper()
	dir := tb.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		tb.Fatal(err)
	}
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		tb.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	s, err := server.New(server.Config{
		HostKeys:          []ssh.Signer{hk.Signer},
		AuthorizedKeys:    server.StaticAuthorizedKeys(entries),
		Shell:             "/bin/bash",
		AllowExec:         true,
		AllowPTY:          true,
		AllowLocalForward: withForward,
	})
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	tb.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	os.WriteFile(kh, []byte(line), 0o600)

	return &benchRig{
		Host: "127.0.0.1", Port: port,
		KnownHosts:  kh,
		UserKeyPath: userPath,
		HostFP:      ssh.FingerprintSHA256(hk.Signer.PublicKey()),
		cancel:      cancel,
	}
}

// startEchoB mirrors startEcho but uses testing.TB.
func startEchoB(tb testing.TB) (string, func()) {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String(), func() { _ = l.Close() }
}
