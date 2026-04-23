package client

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

func TestExpandProxyTokens(t *testing.T) {
	cases := []struct {
		name string
		in   string
		host string
		port int
		user string
		want string
	}{
		{"plain", "nc %h %p", "example.com", 22, "alice",
			"nc example.com 22"},
		{"with_user", "ssm --target %h --user %r --port %p", "i-123", 22, "oscar",
			"ssm --target i-123 --user oscar --port 22"},
		{"literal_percent", "echo %%h stays", "example.com", 22, "alice",
			"echo %h stays"},
		{"no_tokens", "socat STDIO TCP:example:22", "example.com", 22, "alice",
			"socat STDIO TCP:example:22"},
		{"unknown_token_preserved", "proxy %x %h", "example.com", 22, "alice",
			"proxy %x example.com"},
		{"ipv6_bracketed", "nc %h %p", "[::1]", 22, "alice",
			"nc [::1] 22"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandProxyTokens(tc.in, tc.host, tc.port, tc.user)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExpandProxyTokensRejectsShellMetachars is the regression guard
// for the command-injection vector: a user typing a malicious host
// or username on the command line must not be able to inject shell
// syntax into the `sh -c <ProxyCommand>` we run.
func TestExpandProxyTokensRejectsShellMetachars(t *testing.T) {
	bad := []struct{ host, user string }{
		{"foo; rm -rf ~", ""},
		{"foo$(id)", ""},
		{"foo`id`", ""},
		{"foo|bar", ""},
		{"foo\nbar", ""},
		{"ok.example", "alice; rm -rf ~"},
		{"ok.example", "alice$(id)"},
		{"ok.example", "a b"},
		{"with space", ""},
		{"quote'here", ""},
	}
	for _, c := range bad {
		t.Run(c.host+"|"+c.user, func(t *testing.T) {
			user := c.user
			if user == "" {
				user = "alice"
			}
			_, err := expandProxyTokens("nc %h %p -l %r", c.host, 22, user)
			if err == nil {
				t.Fatalf("expected rejection for host=%q user=%q", c.host, c.user)
			}
		})
	}
}

// TestProxyCommandEndToEnd runs a gosshd on a real loopback port and
// connects through a ProxyCommand that does netcat to that port.
// Verifies that the handshake succeeds and an exec round-trips.
func TestProxyCommandEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not installed (integration test needs netcat)")
	}

	dir := t.TempDir()
	hk, err := hostkey.LoadOrGenerate(filepath.Join(dir, "h"), hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(userPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "ak")
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
	port := l.Addr().(*net.TCPAddr).Port

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, cancelSrv := context.WithCancel(context.Background())
	srvDone := make(chan struct{})
	go func() { defer close(srvDone); _ = s.Serve(srvCtx, l) }()
	t.Cleanup(func() {
		cancelSrv()
		select {
		case <-srvDone:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	if err := os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%d %s",
		port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600); err != nil {
		t.Fatal(err)
	}

	// ProxyCommand uses %h/%p expansion. The client passes
	// cfg.Host="127.0.0.1" and cfg.Port=<port>, which get substituted
	// before sh -c runs. "-q0" tells OpenBSD nc to exit with EOF so
	// our proxy process doesn't linger.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{
		Host:           "127.0.0.1",
		Port:           port,
		User:           "u",
		IdentityFiles:  []string{userPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
		ProxyCommand:   "nc -q0 %h %p",
	})
	if err != nil {
		t.Fatalf("dial via ProxyCommand: %v", err)
	}
	defer c.Close()

	// Prove the channel actually carries SSH: run a command.
	var out, errBuf bytes.Buffer
	status, err := c.Exec("echo proxy-path-works", nil, &out, &errBuf)
	if err != nil {
		t.Fatalf("exec: %v (stderr=%q)", err, errBuf.String())
	}
	if status != 0 {
		t.Fatalf("exit=%d stderr=%q", status, errBuf.String())
	}
	if got := out.String(); got != "proxy-path-works\n" {
		t.Fatalf("stdout=%q", got)
	}
}

// TestProxyCommandFailurePropagates makes sure that when the proxy
// exits immediately with no output, Dial fails cleanly rather than
// hanging on the handshake.
func TestProxyCommandFailurePropagates(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	// We still need a valid identity so loadIdentities doesn't fail
	// before the proxy is ever spawned.
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte{}, 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, Config{
		Host:           "127.0.0.1",
		Port:           1,
		User:           "u",
		IdentityFiles:  []string{userPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
		ProxyCommand:   "false", // exits 1 immediately, no bytes written
		ConnectTimeout: 2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected Dial to fail when proxy immediately dies")
	}
}
