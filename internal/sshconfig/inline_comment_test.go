package sshconfig

import (
	"strings"
	"testing"
)

func TestStripInlineComment(t *testing.T) {
	cases := map[string]string{
		`Port 2222`:                   `Port 2222`,
		`Port 2222 # trailing`:        `Port 2222`,
		`Port 2222#nospace`:           `Port 2222`,
		`#whole`:                      ``,
		`   # indented whole`:         ``,
		``:                            ``,
		`Host "quoted # with hash"`:   `Host "quoted # with hash"`,
		`Host "quoted \" # still in"`: `Host "quoted \" # still in"`,
		`Value v # c1 # c2`:           `Value v`,
		`IdentityFile ~/k # comment`:  `IdentityFile ~/k`,
	}
	for in, want := range cases {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseClientWithInlineComment verifies that end-to-end parsing
// now tolerates inline comments on value-bearing keywords.
func TestParseClientWithInlineComment(t *testing.T) {
	input := `
Host inline
    Hostname real.example # primary host
    Port 4242             # ssh listener
    User alice            # service account
`
	c, err := ParseClient(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	h := c.ResolveHost("inline")
	if h.Hostname != "real.example" {
		t.Fatalf("Hostname = %q, inline comment not stripped", h.Hostname)
	}
	if h.Port != 4242 {
		t.Fatalf("Port = %d, inline comment not stripped", h.Port)
	}
	if h.User != "alice" {
		t.Fatalf("User = %q, inline comment not stripped", h.User)
	}
}

func TestParseServerWithInlineComment(t *testing.T) {
	input := `
Port 2323 # listener
HostKey /etc/gossh/host_ed25519 # main host key
MaxAuthTries 3 # enforce
`
	s, err := ParseServer(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != 2323 {
		t.Fatalf("Port = %d", s.Port)
	}
	if len(s.HostKeys) != 1 || s.HostKeys[0] != "/etc/gossh/host_ed25519" {
		t.Fatalf("HostKeys = %v, inline comment not stripped", s.HostKeys)
	}
	if s.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries = %d", s.MaxAuthTries)
	}
}
