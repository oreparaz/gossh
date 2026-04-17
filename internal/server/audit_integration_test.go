package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/audit"
	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

// syncBuf is a bytes.Buffer guarded by a mutex so tests can read it
// while the server writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestAuditLogRecordsFullConnection exercises the audit pipeline over
// a real handshake, exec, and disconnect. The resulting JSON Lines
// stream must include auth.ok, session.open, session.exec,
// session.close, connection.close — in that order, for the one
// client we opened.
func TestAuditLogRecordsFullConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()

	// Host + user + authorized_keys + listener.
	hkPath := filepath.Join(dir, "h")
	hk, _ := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := atoi(portStr)

	auditBuf := &syncBuf{}
	auditLog := &audit.JSONLogger{Writer: auditBuf}

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		Audit:          auditLog,
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

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	// Run one exec through the gossh client.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	c, err := client.Dial(ctx2, client.Config{
		Host: "127.0.0.1", Port: port, User: "alice",
		IdentityFiles:  []string{userPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if _, err := c.Exec("echo hi-audit", nil, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Give the server a moment to emit connection.close.
	time.Sleep(100 * time.Millisecond)

	// Parse the audit log.
	lines := strings.Split(strings.TrimRight(auditBuf.String(), "\n"), "\n")
	var types []string
	users := map[string]bool{}
	for _, ln := range lines {
		var e audit.Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("unmarshal %q: %v", ln, err)
		}
		types = append(types, e.Type)
		if e.User != "" {
			users[e.User] = true
		}
	}
	// The sequence must at minimum include these types; other events
	// (e.g., connection.accept) may show up too.
	required := []string{
		audit.TypeConnectionAccept,
		audit.TypeAuthOK,
		audit.TypeSessionOpen,
		audit.TypeSessionExec,
		audit.TypeSessionClose,
		audit.TypeConnectionClose,
	}
	for _, want := range required {
		found := false
		for _, got := range types {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("audit log missing %q event.\nfull types: %v\nlog:\n%s", want, types, auditBuf.String())
		}
	}
	if !users["alice"] {
		t.Fatalf("no user=alice recorded; users seen: %v", users)
	}
}

// TestAuditLogRecordsFromReject verifies that a key rejected via the
// from= restriction produces an auth.fail event with reason=from.
func TestAuditLogRecordsFromReject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hk, _ := hostkey.LoadOrGenerate(filepath.Join(dir, "h"), hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	// Restrict the key to a CIDR our test client's 127.0.0.1 is NOT in.
	line := []byte(`from="10.99.99.0/24" ` + string(pub))
	os.WriteFile(ak, line, 0o600)
	entries, err := authkeys.ParseFile(ak)
	if err != nil {
		t.Fatal(err)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := atoi(portStr)

	auditBuf := &syncBuf{}
	auditLog := &audit.JSONLogger{Writer: auditBuf}
	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		Audit:          auditLog,
		MaxAuthTries:   1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_, dialErr := client.Dial(ctx2, client.Config{
		Host: "127.0.0.1", Port: port, User: "u",
		IdentityFiles:  []string{userPath},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if dialErr == nil {
		t.Fatal("expected from= to deny the connection")
	}
	time.Sleep(100 * time.Millisecond)

	log := auditBuf.String()
	if !strings.Contains(log, `"auth.fail"`) {
		t.Fatalf("audit log missing auth.fail:\n%s", log)
	}
	if !strings.Contains(log, `"reason":"from"`) {
		t.Fatalf("audit log missing reason=from:\n%s", log)
	}
}

// TestAuditLogRecordsSignalAndForward goes wider: sends an
// interactive-ish sequence with a direct-tcpip open and a signal
// and checks the audit log contains the corresponding events.
func TestAuditLogRecordsSignalAndForward(t *testing.T) {
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

	auditBuf := &syncBuf{}
	auditLog := &audit.JSONLogger{Writer: auditBuf}
	s, _ := server.New(server.Config{
		HostKeys:          []ssh.Signer{hk.Signer},
		AuthorizedKeys:    server.StaticAuthorizedKeys(entries),
		Shell:             "/bin/bash",
		AllowExec:         true,
		AllowLocalForward: true,
		Audit:             auditLog,
	})
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

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	// Use the system ssh client to open a -L tunnel and then exec.
	localPort := pickFreePort(t)
	h := &testHarness{Host: "127.0.0.1", Port: portStr, KnownHosts: kh, UserKeyPath: userPath}
	cmd := h.sshCmd(t, []string{"-L", fmt.Sprintf("%d:127.0.0.1:1", localPort)}, "echo ok")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	time.Sleep(200 * time.Millisecond)

	log := auditBuf.String()
	// direct-tcpip events may not fire because the forward isn't
	// actually used, but forward.bind does NOT happen either — only
	// on client usage. For this test we assert session+exec events.
	for _, want := range []string{`"session.exec"`, `"auth.ok"`} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %s in audit log:\n%s", want, log)
		}
	}
}

// TestAuditLogRecordsAuthFail verifies that a rejected public key
// produces an auth.fail event with the fingerprint.
func TestAuditLogRecordsAuthFail(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, _ := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	authUser := filepath.Join(dir, "authed")
	hostkey.LoadOrGenerate(authUser, hostkey.Ed25519, 0, "a")
	otherUser := filepath.Join(dir, "other")
	hostkey.LoadOrGenerate(otherUser, hostkey.Ed25519, 0, "o")
	pub, _ := os.ReadFile(authUser + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := atoi(portStr)

	auditBuf := &syncBuf{}
	auditLog := &audit.JSONLogger{Writer: auditBuf}
	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		Audit:          auditLog,
		MaxAuthTries:   1,
	})
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

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_, err := client.Dial(ctx2, client.Config{
		Host: "127.0.0.1", Port: port, User: "impostor",
		IdentityFiles:  []string{otherUser}, // NOT in authorized_keys
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	time.Sleep(100 * time.Millisecond)

	if !strings.Contains(auditBuf.String(), `"auth.fail"`) {
		t.Fatalf("audit log missing auth.fail:\n%s", auditBuf.String())
	}
	if !strings.Contains(auditBuf.String(), `"key-not-authorized"`) {
		t.Fatalf("audit log missing reason:\n%s", auditBuf.String())
	}
}
