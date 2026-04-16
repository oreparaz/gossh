package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
)

// TestRSAHostKeyInterop starts gosshd with an RSA host key (generated
// on the fly) and checks that the system ssh client connects and runs
// a command. This covers the RSA path end-to-end.
func TestRSAHostKeyInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (rsa 3072)")
	}
	dir := t.TempDir()

	hkPath := filepath.Join(dir, "host_rsa")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.RSA, 3072, "rsa-host@test")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	pub, _ := os.ReadFile(userPath + ".pub")
	if err := os.WriteFile(akPath, pub, 0o600); err != nil {
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

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	khPath := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(khPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	h := &testHarness{
		Host:        "127.0.0.1",
		Port:        portStr,
		KnownHosts:  khPath,
		UserKeyPath: userPath,
	}

	var stdout, stderr bytes.Buffer
	cmd := h.sshCmd(t, nil, "echo", "rsa-works")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rsa-works") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

// TestRSAUserKeyInterop: user auths with an RSA key against an
// ed25519-host gosshd.
func TestRSAUserKeyInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (rsa 3072)")
	}
	dir := t.TempDir()

	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id_rsa")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.RSA, 3072, "rsa-user"); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	pub, _ := os.ReadFile(userPath + ".pub")
	if err := os.WriteFile(akPath, pub, 0o600); err != nil {
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

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	khPath := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(khPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	h := &testHarness{Host: "127.0.0.1", Port: portStr, KnownHosts: khPath, UserKeyPath: userPath}
	var stdout, stderr bytes.Buffer
	cmd := h.sshCmd(t, nil, "echo", "rsa-user-ok")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rsa-user-ok") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
