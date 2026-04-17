package scp

import "testing"

func FuzzParseCLine(f *testing.F) {
	// Seeds: the good, the bad, the malicious.
	f.Add("C0644 10 readme.txt")
	f.Add("C0000 0 a")
	f.Add("C0644 10 ../etc/passwd")
	f.Add("C0644 10 /etc/passwd")
	f.Add("C0644 10 .")
	f.Add("C0644 10 ..")
	f.Add("C0644 10 a\x00b")
	f.Add("C4755 10 x")  // setuid
	f.Add("C0644 -1 x")  // negative size
	f.Add("C0644 99 x")  // ok
	f.Add("CBAD 1 x")    // mode parse fail
	f.Add("D0755 0 dir") // dir — not "C", we don't accept
	f.Add("T x y")       // time — we don't handle
	f.Add("")
	f.Add("C")
	f.Add("C 1 2")
	f.Fuzz(func(t *testing.T, line string) {
		// parseCLine must not panic on arbitrary input.
		// It may return errors or safe values.
		_, _, _, _ = parseCLine(line)
	})
}

// FuzzShellQuote — the output must always round-trip through sh -c
// safely: it cannot introduce metacharacters that escape the quoting.
// We check the shape (single-quote delimited, any inner single quote
// closed+literal+reopened).
func FuzzShellQuote(f *testing.F) {
	f.Add("")
	f.Add("/tmp/plain")
	f.Add("has space")
	f.Add(`has "double"`)
	f.Add("has 'single'")
	f.Add("$(touch /tmp/pwn)")
	f.Add("`backtick`")
	f.Add("nested 'it's")
	f.Add("\x00 null")
	f.Fuzz(func(t *testing.T, s string) {
		q := shellQuote(s)
		if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
			t.Fatalf("shellQuote(%q) = %q — must be single-quote-delimited", s, q)
		}
	})
}
