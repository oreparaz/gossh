package server_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/server"
)

// FuzzDirectTCPIPPayload opens a direct-tcpip channel with
// fuzzer-controlled raw payload bytes. The server's ssh.Unmarshal
// path must not panic and handleDirectTCPIP must clean up.
func FuzzDirectTCPIPPayload(f *testing.F) {
	// Valid: dest=127.0.0.1:1 orig=1.2.3.4:0
	f.Add([]byte{
		0, 0, 0, 9, '1', '2', '7', '.', '0', '.', '0', '.', '1', 0, 0, 0, 1,
		0, 0, 0, 7, '1', '.', '2', '.', '3', '.', '4', 0, 0, 0, 0,
	})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // length > buffer
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	dir := f.TempDir()
	hk, _ := hostkey.LoadOrGenerate(filepath.Join(dir, "h"), hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	s, _ := server.New(server.Config{
		HostKeys:               []ssh.Signer{hk.Signer},
		AuthorizedKeys:         server.StaticAuthorizedKeys(entries),
		Shell:                  "/bin/bash",
		AllowExec:              true,
		AllowLocalForward:      true,
		DirectTCPIPDialTimeout: 200 * time.Millisecond, // keep fuzz iters snappy
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	f.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port := atoi(portStr)
	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmtKnownHosts(portStr, hk.Signer.PublicKey())), 0o600)

	f.Fuzz(func(t *testing.T, payload []byte) {
		cCtx, cCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cCancel()
		c, err := client.Dial(cCtx, client.Config{
			Host: "127.0.0.1", Port: port, User: "u",
			IdentityFiles:  []string{userPath},
			KnownHostsPath: kh,
			HostCheckMode:  knownhosts.Strict,
		})
		if err != nil {
			return
		}
		defer c.Close()

		// OpenChannel exposes the raw payload we're after.
		ch, _, err := c.Raw().OpenChannel("direct-tcpip", payload)
		if err == nil {
			_ = ch.Close()
		}
	})
}
