package knownhosts

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

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
