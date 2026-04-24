package main

import "testing"

// TestSplitRemote covers the SCP [user@]host[:port]:path splitter,
// including the case where user@ precedes an IPv6 bracket literal
// — a combination the original implementation mis-split at the
// first colon inside the bracket.
func TestSplitRemote(t *testing.T) {
	cases := []struct {
		in         string
		wantRemote string
		wantPath   string
	}{
		{"host:/tmp/x", "host", "/tmp/x"},
		{"user@host:/tmp/x", "user@host", "/tmp/x"},

		// IPv6 without user. Bracketed form is the only way to express
		// a port in the SCP argument; `-P/-p` is preferred otherwise.
		{"[::1]:/tmp/x", "[::1]", "/tmp/x"},
		{"[::1]:2222:/tmp/x", "[::1]:2222", "/tmp/x"},

		// IPv6 with user@ — regression guard for audit finding #5.
		{"alice@[::1]:/tmp/x", "alice@[::1]", "/tmp/x"},
		{"alice@[2001:db8::1]:/tmp/x", "alice@[2001:db8::1]", "/tmp/x"},
		{"alice@[2001:db8::1]:2222:/tmp/x", "alice@[2001:db8::1]:2222", "/tmp/x"},

		// Plain local path — no colon, no remote.
		{"./file", "", "./file"},
		{"/abs/path", "", "/abs/path"},
	}
	for _, c := range cases {
		gotR, gotP := splitRemote(c.in)
		if gotR != c.wantRemote || gotP != c.wantPath {
			t.Errorf("splitRemote(%q) = (%q, %q); want (%q, %q)",
				c.in, gotR, gotP, c.wantRemote, c.wantPath)
		}
	}
}
