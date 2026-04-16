package authkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const samplePubEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMrbmQqVVWUbrs7TeNpKYJ+IpRPMVeA5UwiMH8Wj0Zp alice@host"

func parseOne(t *testing.T, line string) Entry {
	t.Helper()
	entries, err := Parse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	return entries[0]
}

func TestParseBareKey(t *testing.T) {
	e := parseOne(t, samplePubEd25519)
	if e.Comment != "alice@host" {
		t.Fatalf("comment = %q", e.Comment)
	}
	if e.Key.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("type = %q", e.Key.Type())
	}
}

func TestParseCommentAndBlankSkipped(t *testing.T) {
	input := "\n# a comment\n\n" + samplePubEd25519 + "\n"
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1, got %d", len(entries))
	}
}

func TestParseRestrictAndCommand(t *testing.T) {
	line := `restrict,command="/usr/bin/rsync --server",environment="LANG=en_US.UTF-8" ` + samplePubEd25519
	e := parseOne(t, line)
	if !e.Options.Restrict {
		t.Fatal("restrict not set")
	}
	if !e.Options.NoPortForwarding || !e.Options.NoPTY || !e.Options.NoX11Forwarding || !e.Options.NoAgentForwarding {
		t.Fatalf("restrict should imply all no-* flags: %+v", e.Options)
	}
	if e.Options.Command != "/usr/bin/rsync --server" {
		t.Fatalf("command = %q", e.Options.Command)
	}
	if got := e.Options.Environment["LANG"]; got != "en_US.UTF-8" {
		t.Fatalf("env LANG = %q", got)
	}
}

func TestParsePermitOpen(t *testing.T) {
	line := `permitopen="127.0.0.1:8080",permitopen="localhost:*" ` + samplePubEd25519
	e := parseOne(t, line)
	if len(e.Options.PermitOpen) != 2 {
		t.Fatalf("want 2 permitopen, got %d", len(e.Options.PermitOpen))
	}
	if e.Options.PermitOpen[0].Host != "127.0.0.1" || e.Options.PermitOpen[0].Port != 8080 {
		t.Fatalf("permitopen[0] = %+v", e.Options.PermitOpen[0])
	}
	if e.Options.PermitOpen[1].Port != 0 {
		t.Fatalf("permitopen[1] port should be 0 (any), got %d", e.Options.PermitOpen[1].Port)
	}
}

func TestParseFromPatternList(t *testing.T) {
	line := `from="10.0.0.0/8,!10.0.0.13,*.example.com" ` + samplePubEd25519
	e := parseOne(t, line)
	want := []string{"10.0.0.0/8", "!10.0.0.13", "*.example.com"}
	if len(e.Options.From) != len(want) {
		t.Fatalf("from = %v", e.Options.From)
	}
	for i, w := range want {
		if e.Options.From[i] != w {
			t.Fatalf("from[%d] = %q, want %q", i, e.Options.From[i], w)
		}
	}
}

func TestParseRestrictCanBeRelaxed(t *testing.T) {
	// Per OpenSSH, "restrict,pty" removes the no-pty restriction.
	line := `restrict,pty ` + samplePubEd25519
	e := parseOne(t, line)
	if !e.Options.Restrict {
		t.Fatal("restrict not set")
	}
	if e.Options.NoPTY {
		t.Fatal("pty should override restrict's no-pty")
	}
	// But the other restrictions are still in force.
	if !e.Options.NoPortForwarding {
		t.Fatal("port forwarding still banned")
	}
}

func TestParseFileRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(samplePubEd25519+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error on world-writable file")
	}
}

func TestParseFileOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(samplePubEd25519+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
}

func TestFind(t *testing.T) {
	entries, err := Parse(strings.NewReader(samplePubEd25519))
	if err != nil {
		t.Fatal(err)
	}
	found, err := Find(entries, entries[0].Key)
	if err != nil || found == nil {
		t.Fatalf("Find: %v", err)
	}
	// Mismatched key returns ErrKeyNotFound.
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICWhLZLrLs9JPwX+sDJtPX3QASxHXM2PzeA7c6fR+t6l bob@host"
	otherEntries, _ := Parse(strings.NewReader(other))
	if _, err := Find(entries, otherEntries[0].Key); err == nil {
		t.Fatal("expected ErrKeyNotFound")
	}
}
