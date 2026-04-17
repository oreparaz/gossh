package scp

import (
	"strings"
	"testing"
)

func TestParseCLineValid(t *testing.T) {
	mode, size, name, err := parseCLine("C0644 1024 readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if mode.Perm() != 0o644 {
		t.Fatalf("mode = %#o", mode)
	}
	if size != 1024 {
		t.Fatalf("size = %d", size)
	}
	if name != "readme.txt" {
		t.Fatalf("name = %q", name)
	}
}

func TestParseCLineRejectsPathTraversal(t *testing.T) {
	bad := []string{
		"C0644 10 ../etc/passwd",
		"C0644 10 /etc/passwd",
		"C0644 10 ..",
		"C0644 10 .",
		"C0644 10 ",
		"C0644 10 a/b",
		"C0644 10 evil\x00name",
	}
	for _, line := range bad {
		if _, _, _, err := parseCLine(line); err == nil {
			t.Errorf("expected rejection of %q", line)
		}
	}
}

func TestParseCLineRejectsSetuid(t *testing.T) {
	if _, _, _, err := parseCLine("C4755 10 x"); err == nil {
		t.Fatal("setuid mode should be refused")
	}
	if _, _, _, err := parseCLine("C7000 0 x"); err == nil {
		t.Fatal("high bits should be refused")
	}
}

func TestParseCLineRejectsNegativeSize(t *testing.T) {
	if _, _, _, err := parseCLine("C0644 -1 x"); err == nil {
		t.Fatal("negative size should be refused")
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/tmp":        "'/tmp'",
		"hello world": "'hello world'",
		"it's":        `'it'"'"'s'`,
		"":            "''",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
	_ = strings.Builder{}
}
