package client_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/knownhosts"
)

// syncBuffer is a tiny mutex-wrapped bytes.Buffer for capturing
// subprocess stderr without racing the os/exec stderr-pump goroutine.
// Reads via String() are safe to call from the test goroutine while
// the subprocess is still running.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestGosshAgainstOpenSSHSshd spawns an unprivileged OpenSSH sshd and
// connects gossh to it. If the sshd binary is missing or refuses to
// run without root, the test skips.
func TestGosshAgainstOpenSSHSshd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (needs system sshd)")
	}
	sshdBin := "/usr/sbin/sshd"
	if _, err := os.Stat(sshdBin); err != nil {
		t.Skipf("system sshd not found at %s", sshdBin)
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}

	dir := t.TempDir()
	// Must be a path the sshd process can read; t.TempDir is fine.
	// Generate an OpenSSH-format host key via ssh-keygen to ensure
	// sshd accepts it without complaint.
	hostKey := filepath.Join(dir, "host_ed25519")
	if err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey, "-C", "test").Run(); err != nil {
		t.Fatalf("ssh-keygen: %v", err)
	}
	if err := os.Chmod(hostKey, 0o600); err != nil {
		t.Fatal(err)
	}

	// User key the client will use. Put the matching pubkey into
	// authorized_keys for our UID.
	userKey := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userKey, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	userPub, _ := os.ReadFile(userKey + ".pub")
	ak := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(ak, userPub, 0o600); err != nil {
		t.Fatal(err)
	}

	// Pick a port for sshd.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	// `UsePAM no` matters on glibc distros whose PAM stack rejects
	// root logins under sshd by default (Fedora is the example we
	// hit). On Alpine, openssh-server is built without PAM and the
	// directive itself is unrecognised, so we omit it there.
	usePAMLine := "UsePAM no"
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		usePAMLine = "# UsePAM omitted: Alpine's openssh has no PAM"
	}

	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PasswordAuthentication no
PubkeyAuthentication yes
%s
PidFile %s/sshd.pid
# prohibit-password (not "no") because the test runs under whatever
# user invoked it, which is "root" inside CI containers; "no" plus
# AllowUsers root would refuse the login. We're already pubkey-only
# via PasswordAuthentication=no above, so this is equivalent on
# non-root hosts.
PermitRootLogin prohibit-password
AllowUsers %s
StrictModes no
LogLevel DEBUG2
`, port, hostKey, ak, usePAMLine, dir, me.Username)), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshdBin, "-D", "-e", "-f", cfg)
	// sshdLog is read from a different goroutine than the one os/exec
	// copies subprocess stderr into; bytes.Buffer isn't safe for that.
	// Wrap with a mutex so the t.Fatalf path can read the buffer
	// without racing the live sshd writer goroutine.
	sshdLog := &syncBuffer{}
	cmd.Stderr = sshdLog
	if err := cmd.Start(); err != nil {
		t.Skipf("failed to start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Wait for sshd to bind.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Pre-populate known_hosts so gossh strict mode works.
	hk, err := hostkey.Load(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, client.Config{
		Host:           "127.0.0.1",
		Port:           port,
		User:           me.Username,
		IdentityFiles:  []string{userKey},
		KnownHostsPath: kh,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatalf("gossh dial: %v\nsshd log: %s", err, sshdLog.String())
	}
	defer c.Close()

	var stdout, stderr bytes.Buffer
	status, err := c.Exec("echo gossh-vs-openssh-sshd-ok", nil, &stdout, &stderr)
	if err != nil || status != 0 {
		t.Fatalf("exec status=%d err=%v stderr=%s", status, err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gossh-vs-openssh-sshd-ok") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
