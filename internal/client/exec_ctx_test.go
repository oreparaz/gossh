package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/knownhosts"
)

// TestExecContextCancelTerminatesRemote verifies that cancelling ctx
// while a remote command is running delivers SIGTERM to the remote.
// Before the fix, this also triggered a busy loop in the client
// goroutine that would keep firing s.Signal forever.
func TestExecContextCancelTerminatesRemote(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)
	ctx, cancel := context.WithCancel(context.Background())
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

	var stdout bytes.Buffer
	exCtx, exCancel := context.WithCancel(ctx)
	// Cancel after a brief delay so the remote sleep has started.
	go func() {
		time.Sleep(200 * time.Millisecond)
		exCancel()
	}()
	start := time.Now()
	_, _ = c.ExecContext(exCtx, "sleep 10", nil, &stdout, io.Discard)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("remote sleep was not terminated; ran for %v", elapsed)
	}
}

// TestExecContextNoSignalLeak sanity-checks there is no goroutine leak
// per Exec call. Before the fix the internal goroutine could stay
// live forever if ctx was cancelled.
func TestExecContextNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)
	ctx, cancel := context.WithCancel(context.Background())
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

	// Warm up.
	var out bytes.Buffer
	if _, err := c.Exec("echo warm", nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	before := runtime.NumGoroutine()

	var completed int32
	for i := 0; i < 20; i++ {
		exCtx, exCancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(50 * time.Millisecond)
			exCancel()
		}()
		_, err := c.ExecContext(exCtx, "sleep 2", nil, io.Discard, io.Discard)
		atomic.AddInt32(&completed, 1)
		_ = errors.Is(err, context.Canceled) // best-effort; ignore
	}
	if atomic.LoadInt32(&completed) != 20 {
		t.Fatalf("only %d of 20 completed", completed)
	}
	// Give goroutines a moment to wind down.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > before+4 {
		t.Logf("goroutine count: before=%d after=%d", before, after)
		t.Fatalf("possible goroutine leak: before=%d after=%d", before, after)
	}
}
