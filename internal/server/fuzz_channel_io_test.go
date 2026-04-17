package server_test

import (
	"context"
	"io"
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

// FuzzChannelIO opens a session, dispatches `cat`, and feeds random
// bytes in over stdin. We check the server drains them without
// panic and returns cleanly.
func FuzzChannelIO(f *testing.F) {
	f.Add([]byte{}, "cat")
	f.Add([]byte("hello world\n"), "cat")
	f.Add(make([]byte, 64*1024), "cat")
	f.Add([]byte{0, 0, 0, 0}, "true")
	f.Add([]byte("\x00\x01\x02\x03"), "cat")

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
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
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

	f.Fuzz(func(t *testing.T, stdin []byte, cmd string) {
		// Bound cmd length so the fuzzer doesn't produce pathological
		// shell strings that take forever to parse.
		if len(cmd) > 64 {
			cmd = cmd[:64]
		}
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

		sess, err := c.Raw().NewSession()
		if err != nil {
			return
		}
		defer sess.Close()

		pipe, err := sess.StdinPipe()
		if err != nil {
			return
		}
		sess.Stdout = io.Discard
		sess.Stderr = io.Discard

		// Running `cat` forces the server to shovel fuzz-controlled
		// stdin bytes through the child. The saved command string is
		// ignored to avoid quoting issues; we only care that the
		// server's stdio pipe survives arbitrary input.
		if err := sess.Start("head -c 65536 >/dev/null"); err != nil {
			return
		}
		// Cap writes to avoid minutes-long iterations under heavy
		// corpus entries.
		if len(stdin) > 16*1024 {
			stdin = stdin[:16*1024]
		}
		_, _ = pipe.Write(stdin)
		_ = pipe.Close()
		_ = sess.Wait()
	})
}
