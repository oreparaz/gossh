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

// startGosshdWithCfg is like startGosshd but lets the caller toggle
// local and remote forwarding.
func startGosshdWithCfg(t *testing.T, allowLocal, allowRemote bool) *testRig {
	t.Helper()
	dir := t.TempDir()

	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "host@test")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "user@test"); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	pubBytes, _ := os.ReadFile(userPath + ".pub")
	if err := os.WriteFile(akPath, pubBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := authkeys.ParseFile(akPath)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	s, err := server.New(server.Config{
		HostKeys:           []ssh.Signer{hk.Signer},
		AuthorizedKeys:     server.StaticAuthorizedKeys(entries),
		Shell:              "/bin/bash",
		AllowExec:          true,
		AllowPTY:           true,
		AllowLocalForward:  allowLocal,
		AllowRemoteForward: allowRemote,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, l)
	}()
	time.Sleep(50 * time.Millisecond)

	khPath := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(khPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &testRig{
		Host:        "127.0.0.1",
		Port:        port,
		KnownHosts:  khPath,
		UserKeyPath: userPath,
		HostFP:      ssh.FingerprintSHA256(hk.Signer.PublicKey()),
		cancel:      cancel,
	}
	t.Cleanup(func() {
		r.cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return r
}
