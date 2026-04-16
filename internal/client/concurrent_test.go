package client_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/knownhosts"
)

// TestConcurrentSessions opens many sessions over a single SSH
// connection in parallel and verifies each gets its own stdout.
func TestConcurrentSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	const N = 16
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			var stdout, stderr bytes.Buffer
			status, err := c.Exec(fmt.Sprintf("echo session-%d", i), nil, &stdout, &stderr)
			if err != nil {
				errs <- fmt.Errorf("session %d: %w stderr=%s", i, err, stderr.String())
				return
			}
			if status != 0 {
				errs <- fmt.Errorf("session %d: status %d", i, status)
				return
			}
			want := fmt.Sprintf("session-%d", i)
			if !strings.Contains(stdout.String(), want) {
				errs <- fmt.Errorf("session %d: got %q, want %q", i, stdout.String(), want)
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// Extra: quick exec works after the parallel wave.
	var out bytes.Buffer
	if _, err := c.Exec("echo after", nil, &out, io.Discard); err != nil {
		t.Fatalf("post-parallel exec failed: %v", err)
	}
	if !strings.Contains(out.String(), "after") {
		t.Fatalf("post-parallel exec output: %q", out.String())
	}
}
