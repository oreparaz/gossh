package scp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/scp"
)

// TestSCPRoundTripTree uploads a small directory tree through gosshd
// (which shells out to system scp on the far side), then downloads
// it back and verifies byte-exact equality.
func TestSCPRoundTripTree(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, r.clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Build a source tree with three files and a nested directory.
	localSrc := filepath.Join(r.userDir, "src_tree")
	mustMkdir(t, localSrc)
	mustMkdir(t, filepath.Join(localSrc, "nested"))
	mustWrite(t, filepath.Join(localSrc, "a.bin"), randBytes(3000))
	mustWrite(t, filepath.Join(localSrc, "nested", "b.bin"), randBytes(1500))
	mustWrite(t, filepath.Join(localSrc, "nested", "c.txt"), []byte("hello\nworld\n"))

	// Upload recursively into userDir/uploaded/.
	uploadedParent := filepath.Join(r.userDir, "uploaded")
	mustMkdir(t, uploadedParent)
	if err := scp.Upload(c.Raw(), localSrc, uploadedParent, true); err != nil {
		t.Fatalf("upload tree: %v", err)
	}

	// Now download back to userDir/round_trip/src_tree.
	downloadDst := filepath.Join(r.userDir, "round_trip")
	mustMkdir(t, downloadDst)
	uploadedTree := filepath.Join(uploadedParent, "src_tree")
	if err := scp.Download(c.Raw(), uploadedTree, downloadDst, true); err != nil {
		t.Fatalf("download tree: %v", err)
	}

	// Compare contents of the three files between src and the round-
	// tripped copy.
	finalRoot := filepath.Join(downloadDst, "src_tree")
	for _, rel := range []string{"a.bin", "nested/b.bin", "nested/c.txt"} {
		want, err := os.ReadFile(filepath.Join(localSrc, rel))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(finalRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: mismatched contents (%d vs %d bytes)", rel, len(got), len(want))
		}
	}
}

func TestUploadDirWithoutRecursiveFails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, r.clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	localDir := filepath.Join(r.userDir, "some_dir")
	mustMkdir(t, localDir)
	err = scp.Upload(c.Raw(), localDir, filepath.Join(r.userDir, "dst"), false)
	if err == nil {
		t.Fatal("expected Upload on a directory without recursive=true to fail")
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
