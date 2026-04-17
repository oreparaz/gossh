package knownhosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fakeAddr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTOFUAddsAndThenAccepts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	v, err := New(path, TOFU)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t)
	cbk := v.HostKeyCallback()
	if err := cbk("example.com:22", fakeAddr(t, "1.2.3.4:22"), key); err != nil {
		t.Fatalf("first TOFU should succeed: %v", err)
	}
	// File should now contain a line.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("known_hosts not populated")
	}
	// Second call with the same key succeeds.
	if err := cbk("example.com:22", fakeAddr(t, "1.2.3.4:22"), key); err != nil {
		t.Fatalf("second accept failed: %v", err)
	}
	// Different key for same host → mismatch, reject.
	other := newKey(t)
	err = cbk("example.com:22", fakeAddr(t, "1.2.3.4:22"), other)
	if err == nil {
		t.Fatal("expected mismatch rejection")
	}
	if err == nil {
		t.Fatal("expected host-key-mismatch rejection")
	}
}

func TestStrictRefusesUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	v, err := New(path, Strict)
	if err != nil {
		t.Fatal(err)
	}
	err = v.HostKeyCallback()("example.com:22", fakeAddr(t, "1.2.3.4:22"), newKey(t))
	if err == nil {
		t.Fatal("strict should have refused unknown host")
	}
	// And nothing was written to disk.
	info, _ := os.Stat(path)
	if info != nil && info.Size() != 0 {
		t.Fatal("strict mode should not have written to known_hosts")
	}
}

func TestEmptyPathRejected(t *testing.T) {
	if _, err := New("", Strict); err == nil {
		t.Fatal("empty path must be rejected")
	}
}

func TestTOFUPersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	key := newKey(t)

	v1, err := New(path, TOFU)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.HostKeyCallback()("h:22", fakeAddr(t, "1.2.3.4:22"), key); err != nil {
		t.Fatal(err)
	}
	// A fresh Verifier should see the host from disk.
	v2, err := New(path, Strict)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.HostKeyCallback()("h:22", fakeAddr(t, "1.2.3.4:22"), key); err != nil {
		t.Fatalf("second instance rejected known host: %v", err)
	}
}
