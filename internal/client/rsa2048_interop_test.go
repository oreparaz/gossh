package client_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/knownhosts"
	"github.com/oreparaz/gossh/internal/server"
)

// TestClientUses2048BitRSAKey verifies that a typical ssh-keygen-
// generated 2048-bit RSA identity (OpenSSH's pre-2019 default) is
// accepted for authentication. Regression for the old 3072-bit
// load-time minimum that broke everyone with an existing
// ~/.ssh/id_rsa.
func TestClientUses2048BitRSAKey(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	dir := t.TempDir()
	rsaPath := filepath.Join(dir, "id_rsa")
	if err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048",
		"-N", "", "-f", rsaPath).Run(); err != nil {
		t.Fatalf("ssh-keygen: %v", err)
	}
	if err := os.Chmod(rsaPath, 0o600); err != nil {
		t.Fatal(err)
	}

	// Boot a gosshd whose only authorized key is this RSA pubkey.
	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	pubBytes, err := os.ReadFile(rsaPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
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

	kh := filepath.Join(dir, "known_hosts")
	khLine := fmt.Sprintf("[127.0.0.1]:%s %s",
		portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(kh, []byte(khLine), 0o600); err != nil {
		t.Fatal(err)
	}

	port := l.Addr().(*net.TCPAddr).Port
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	c, err := client.Dial(dialCtx, client.Config{
		Host:           "127.0.0.1",
		Port:           port,
		User:           "u",
		IdentityFiles:  []string{rsaPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatalf("dial with 2048-bit RSA key: %v", err)
	}
	defer c.Close()
	if _, err := c.Exec("true", nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("exec with RSA key: %v", err)
	}
}
