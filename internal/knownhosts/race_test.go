package knownhosts

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestConcurrentTOFUDifferentHosts is the positive cousin of
// TestConcurrentTOFUNoDuplicates: when many goroutines TOFU-append
// DIFFERENT hosts concurrently, they should all succeed and the
// file should contain one entry per host.
func TestConcurrentTOFUDifferentHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	v, err := New(path, TOFU)
	if err != nil {
		t.Fatal(err)
	}
	cbk := v.HostKeyCallback()

	const N = 12
	type pair struct {
		host string
		key  ssh.PublicKey
	}
	pairs := make([]pair, N)
	for i := 0; i < N; i++ {
		pairs[i].host = fmt.Sprintf("host%02d.example:22", i)
		pairs[i].key = newKey(t)
	}

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := cbk(pairs[i].host, fakeAddr(t, "1.2.3.4:22"), pairs[i].key); err != nil {
				t.Errorf("host %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Count lines — should be exactly N.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) > 0 {
			lines++
		}
	}
	if lines != N {
		t.Fatalf("expected %d lines, got %d", N, lines)
	}
}

// TestConcurrentTOFUNoDuplicates exercises the TOCTOU path: many
// goroutines call the callback for the same host+key at once. Before
// the fix, each goroutine saw "unknown" and wrote a line, yielding N
// duplicate entries. After the fix, exactly one line must appear.
func TestConcurrentTOFUNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	v, err := New(path, TOFU)
	if err != nil {
		t.Fatal(err)
	}
	cbk := v.HostKeyCallback()
	key := newKey(t)
	addr := fakeAddr(t, "1.2.3.4:22")

	const N = 20
	var wg sync.WaitGroup
	errCh := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- cbk("host.example:22", addr, key)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("callback returned error: %v", err)
		}
	}

	// Count the non-blank lines in known_hosts; must be exactly 1.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) > 0 {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("expected exactly 1 known_hosts line, got %d:\n%s", lines, b)
	}
}
