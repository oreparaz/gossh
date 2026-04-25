package server_test

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/knownhosts"
	"github.com/oreparaz/gossh/internal/server"
)

// FuzzSessionRequestPayload opens an authenticated session and sends
// arbitrary bytes as the payload of an SSH request whose type is
// controlled by the fuzzer. The server must not panic regardless of
// payload shape.
func FuzzSessionRequestPayload(f *testing.F) {
	f.Add("exec", []byte("echo hi"))
	f.Add("env", []byte{0, 0, 0, 1, 'A', 0, 0, 0, 1, 'B'})
	f.Add("env", []byte{0xff, 0xff, 0xff, 0xff})
	f.Add("pty-req", []byte{0, 0, 0, 5, 'x', 't', 'e', 'r', 'm', 0, 0, 0, 80, 0, 0, 0, 24})
	f.Add("window-change", []byte{})
	f.Add("signal", []byte{0, 0, 0, 3, 'I', 'N', 'T'})
	f.Add("subsystem", []byte{0, 0, 0, 4, 's', 'f', 't', 'p'})
	f.Add("unknown-type", []byte("garbage"))
	f.Add("", []byte{}) // empty type

	// Shared gosshd.
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
		AllowPTY:       true,
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

	f.Fuzz(func(t *testing.T, reqType string, payload []byte) {
		// Each iteration gets its own SSH connection to isolate state.
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

		// SendRequest sends an in-band request on the session channel.
		// The server must not panic regardless of reqType / payload.
		_, _ = sess.SendRequest(reqType, false, payload)
		// Give the server a moment to process.
		time.Sleep(5 * time.Millisecond)
	})
}

func fmtKnownHosts(portStr string, key ssh.PublicKey) string {
	return "[127.0.0.1]:" + portStr + " " + string(ssh.MarshalAuthorizedKey(key))
}

// little-endian view guard for seed payloads.
var _ = binary.BigEndian
