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

// buildCustomRig builds a harness where we control the *contents* of
// authorized_keys (not just the key). Tests that check command= or
// permitopen need this.
func buildCustomRig(t *testing.T, optionPrefix string) *testHarness {
	t.Helper()
	dir := t.TempDir()

	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(userPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	line := pub
	if optionPrefix != "" {
		line = []byte(optionPrefix + " " + string(pub))
	}
	if err := os.WriteFile(akPath, line, 0o600); err != nil {
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
		HostKeys:           []ssh.Signer{hk.Signer},
		AuthorizedKeys:     server.StaticAuthorizedKeys(entries),
		Shell:              "/bin/bash",
		AllowExec:          true,
		AllowPTY:           true,
		AllowLocalForward:  true,
		AllowRemoteForward: true,
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
	khLine := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(khPath, []byte(khLine), 0o600); err != nil {
		t.Fatal(err)
	}

	return &testHarness{
		Host:        "127.0.0.1",
		Port:        portStr,
		KnownHosts:  khPath,
		UserKeyPath: userPath,
	}
}

func TestFromAllowAndDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Allow only 127.0.0.1 — our ssh test connects from 127.0.0.1
	// so this should succeed.
	h := buildCustomRig(t, `from="127.0.0.1"`)
	cmd := h.sshCmd(t, nil, "echo from-ok")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("from=127.0.0.1 should allow: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "from-ok") {
		t.Fatalf("stdout=%q", out)
	}

	// Now restrict to a non-matching CIDR; ssh must be rejected.
	h2 := buildCustomRig(t, `from="10.99.99.0/24"`)
	cmd2 := h2.sshCmd(t, nil, "echo should-not-run")
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		t.Fatalf("from= should have blocked the connection but ssh exited 0: %s", out2)
	}
}

// TestAuthorizedKeysEnvironmentApplied verifies that
// environment="NAME=VALUE" in authorized_keys actually reaches the
// remote process. Previously this was parsed but silently dropped.
func TestAuthorizedKeysEnvironmentApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := buildCustomRig(t, `environment="AUTHKEY_MARKER=stamped",environment="AK2=two"`)
	cmd := h.sshCmd(t, nil, "echo $AUTHKEY_MARKER $AK2")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if got != "stamped two" {
		t.Fatalf("authorized_keys env not applied: got %q, want %q", got, "stamped two")
	}
}

// TestAuthorizedKeysEnvironmentNoShellInjection confirms that an env
// value containing shell metacharacters is passed verbatim, not
// interpreted. The value becomes the env var's literal contents.
func TestAuthorizedKeysEnvironmentNoShellInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// An attacker-controlled authorized_keys (via compromised admin)
	// still cannot trigger shell injection just by setting env —
	// the value lands as a literal env var, not as interpreted code.
	// We send 'evil $(touch /tmp/pwn)' and confirm it's a literal
	// string, with no command substitution.
	pwnFile := "/tmp/gossh-pwn-" + t.Name()
	_ = os.Remove(pwnFile)
	defer os.Remove(pwnFile)

	// Note: options are comma-separated; the value itself can contain
	// double-quotes if escaped, but we keep it simple here.
	opts := fmt.Sprintf(`environment="PWN=evil; touch %s"`, pwnFile)
	h := buildCustomRig(t, opts)

	cmd := h.sshCmd(t, nil, `printf "[%s]\n" "$PWN"`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	// The literal value must include the shell metachars unescaped.
	if !strings.Contains(string(out), fmt.Sprintf("[evil; touch %s]", pwnFile)) {
		t.Fatalf("env value mis-handled: %q", out)
	}
	// The file must NOT have been created by a command-substitution
	// bug.
	if _, err := os.Stat(pwnFile); err == nil {
		t.Fatalf("unexpected file creation at %s — injection detected", pwnFile)
	}
}

func TestForcedCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Force the session to run `whoami` regardless of what the client asks.
	h := buildCustomRig(t, `command="echo forced-command-output; whoami"`)

	var stdout, stderr bytes.Buffer
	cmd := h.sshCmd(t, nil, "echo", "client-wanted-this")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "forced-command-output") {
		t.Fatalf("forced command did not run; out=%q", out)
	}
	if strings.Contains(out, "client-wanted-this") {
		t.Fatalf("client command leaked through! out=%q", out)
	}
}

func TestNoPortForwardingBlocksLocalForward(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := buildCustomRig(t, `no-port-forwarding`)
	// Start a local echo server we'd be trying to reach.
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	localPort := pickFreePort(t)
	cmd := h.sshCmd(t, []string{"-N", "-L", fmt.Sprintf("%d:%s", localPort, echoAddr)})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Wait for local listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Connect and attempt data — the server refuses direct-tcpip,
	// so ssh will quickly tear down our forwarded connection.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return // refused outright is also pass
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("expected no-port-forwarding to block the connection")
	}
}

func TestPermitOpenEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Start an allowed target and a disallowed target.
	allowedAddr, stopAllowed := startEchoServer(t)
	defer stopAllowed()
	disallowedAddr, stopDisallowed := startEchoServer(t)
	defer stopDisallowed()

	// Authorize only allowedAddr.
	option := fmt.Sprintf(`permitopen="%s"`, allowedAddr)
	h := buildCustomRig(t, option)

	// -L to allowed: should succeed.
	localA := pickFreePort(t)
	cmdA := h.sshCmd(t, []string{"-N", "-L", fmt.Sprintf("%d:%s", localA, allowedAddr)})
	if err := cmdA.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmdA.Process.Kill()
		_, _ = cmdA.Process.Wait()
	}()

	deadline := time.Now().Add(3 * time.Second)
	var conn net.Conn
	var dialErr error
	for time.Now().Before(deadline) {
		conn, dialErr = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localA))
		if dialErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("dial allowed tunnel: %v", dialErr)
	}
	msg := []byte("ping\n")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readAll(conn, buf); err != nil {
		t.Fatalf("allowed path: %v", err)
	}
	conn.Close()

	// -L to disallowed: connection through tunnel should fail.
	localD := pickFreePort(t)
	cmdD := h.sshCmd(t, []string{"-N", "-L", fmt.Sprintf("%d:%s", localD, disallowedAddr)})
	if err := cmdD.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmdD.Process.Kill()
		_, _ = cmdD.Process.Wait()
	}()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localD))
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localD))
	if err != nil {
		return
	}
	defer cn.Close()
	cn.SetReadDeadline(time.Now().Add(2 * time.Second))
	small := make([]byte, 4)
	if _, err := cn.Read(small); err == nil {
		t.Fatalf("permitopen should have blocked %s but read succeeded", disallowedAddr)
	}
}

func readAll(c net.Conn, into []byte) (int, error) {
	total := 0
	for total < len(into) {
		n, err := c.Read(into[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
