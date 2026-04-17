package knownhosts

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzAppend exercises TOFU append with arbitrary hostnames and
// remote addresses. Must never panic; malformed entries can error.
func FuzzAppend(f *testing.F) {
	f.Add("example.com:22", "1.2.3.4:22")
	f.Add("[::1]:22", "[::1]:22")
	f.Add("", "")
	f.Add("host.with.wildcards.*", "1.1.1.1:22")
	f.Add("very-long-hostname.that.goes.on.and.on.and.on.example.com:22", "8.8.8.8:22")
	f.Fuzz(func(t *testing.T, hostname, remoteStr string) {
		dir := t.TempDir()
		v, err := New(filepath.Join(dir, "kh"), TOFU)
		if err != nil {
			t.Fatal(err)
		}
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		key, _ := ssh.NewPublicKey(pub)
		var remote net.Addr
		if r, rerr := net.ResolveTCPAddr("tcp", remoteStr); rerr == nil {
			remote = r
		}
		_ = v.Append(hostname, remote, key)
	})
}
