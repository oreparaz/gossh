package sshconfig

import (
	"strings"
	"testing"
)

const sampleClient = `
# Standard ssh_config style: specifics first, catch-all last.
Host tricky
    Hostname tricky.example.com
    Port 2222
    User alice
    IdentityFile ~/.ssh/id_alice_ed25519
    IdentityFile ~/.ssh/id_alice_rsa
    ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p

Host *
    Port 22
    StrictHostKeyChecking accept-new
`

func TestParseClient(t *testing.T) {
	c, err := ParseClient(strings.NewReader(sampleClient))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sections) != 2 {
		t.Fatalf("sections=%d", len(c.Sections))
	}
	h := c.ResolveHost("tricky")
	if h.Hostname != "tricky.example.com" {
		t.Fatalf("hostname=%q", h.Hostname)
	}
	if h.Port != 2222 {
		t.Fatalf("port=%d", h.Port)
	}
	if h.User != "alice" {
		t.Fatalf("user=%q", h.User)
	}
	if len(h.IdentityFiles) != 2 {
		t.Fatalf("identities=%v", h.IdentityFiles)
	}
	if h.StrictHost != "accept-new" {
		t.Fatalf("strict=%q", h.StrictHost)
	}
	const wantProxy = "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"
	if h.ProxyCommand != wantProxy {
		t.Fatalf("proxycommand=%q", h.ProxyCommand)
	}

	// Unknown host falls back to the "*" block.
	h2 := c.ResolveHost("unknown.example")
	if h2.Port != 22 {
		t.Fatalf("default port=%d", h2.Port)
	}
	if h2.StrictHost != "accept-new" {
		t.Fatalf("default strict=%q", h2.StrictHost)
	}
}

const sampleServer = `
# sshd_config excerpt
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/gossh/host_ed25519
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
AllowTcpForwarding yes
MaxAuthTries 3
LoginGraceTime 30s

# unknown things should be warned about, not rejected
Banner /etc/motd
`

func TestParseServer(t *testing.T) {
	s, err := ParseServer(strings.NewReader(sampleServer))
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != 2222 {
		t.Fatalf("port=%d", s.Port)
	}
	if len(s.HostKeys) != 1 || s.HostKeys[0] != "/etc/gossh/host_ed25519" {
		t.Fatalf("hostkeys=%v", s.HostKeys)
	}
	if s.PasswordAuthentication {
		t.Fatal("password should be off")
	}
	if s.MaxAuthTries != 3 {
		t.Fatalf("maxauth=%d", s.MaxAuthTries)
	}
}

func TestEqualsForm(t *testing.T) {
	c, err := ParseClient(strings.NewReader(`Host x
Port=4242
User=bob`))
	if err != nil {
		t.Fatal(err)
	}
	h := c.ResolveHost("x")
	if h.Port != 4242 || h.User != "bob" {
		t.Fatalf("h=%+v", h)
	}
}

// TestQuotedValues guards audit finding #6: ssh_config values wrapped
// in double quotes must round-trip WITHOUT the quotes, and a quoted
// IdentityFile path with spaces must survive as one identity — not
// get split by whitespace tokenisation on the way out.
func TestQuotedValues(t *testing.T) {
	c, err := ParseClient(strings.NewReader(`Host q
    Hostname "server.example"
    UserKnownHostsFile "~/known hosts"
    IdentityFile "~/my key"
    IdentityFile ~/plain_key
`))
	if err != nil {
		t.Fatal(err)
	}
	h := c.ResolveHost("q")
	if h.Hostname != "server.example" {
		t.Errorf("Hostname = %q, want %q", h.Hostname, "server.example")
	}
	// UserKnownHostsFile expands ~ and preserves the space.
	if !strings.HasSuffix(h.KnownHosts, "/known hosts") {
		t.Errorf("KnownHosts = %q, want suffix %q", h.KnownHosts, "/known hosts")
	}
	if len(h.IdentityFiles) != 2 {
		t.Fatalf("IdentityFiles count = %d, want 2: %v", len(h.IdentityFiles), h.IdentityFiles)
	}
	if !strings.HasSuffix(h.IdentityFiles[0], "/my key") {
		t.Errorf("IdentityFiles[0] = %q, want suffix %q", h.IdentityFiles[0], "/my key")
	}
	if !strings.HasSuffix(h.IdentityFiles[1], "/plain_key") {
		t.Errorf("IdentityFiles[1] = %q, want suffix %q", h.IdentityFiles[1], "/plain_key")
	}
}
