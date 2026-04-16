package client_test

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
	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

// startGosshd starts a gosshd on localhost and returns its address
// along with paths to a usable known_hosts and a user key.
type testRig struct {
	Host        string
	Port        int
	KnownHosts  string
	UserKeyPath string
	HostFP      string
	cancel      context.CancelFunc
}

func startGosshd(t *testing.T) *testRig {
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
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		AllowPTY:       true,
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

func TestClientExec(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, client.Config{
		Host:           r.Host,
		Port:           r.Port,
		User:           "testuser",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: r.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var stdout, stderr bytes.Buffer
	status, err := c.Exec("echo hi; echo err 1>&2; exit 3", nil, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if status != 3 {
		t.Fatalf("status = %d, want 3", status)
	}
	if strings.TrimSpace(stdout.String()) != "hi" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "err") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestClientRejectsUnknownHostInStrictMode(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)

	// Point at an empty known_hosts so the host is unknown.
	dir := t.TempDir()
	empty := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Dial(ctx, client.Config{
		Host:           r.Host,
		Port:           r.Port,
		User:           "testuser",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: empty,
		HostCheckMode:  knownhosts.Strict,
	})
	if err == nil {
		t.Fatal("expected strict mode to reject unknown host")
	}
}

func TestClientTOFUWritesHost(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)

	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, client.Config{
		Host:           r.Host,
		Port:           r.Port,
		User:           "testuser",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.TOFU,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	b, err := os.ReadFile(kh)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("TOFU did not write known_hosts")
	}
}
