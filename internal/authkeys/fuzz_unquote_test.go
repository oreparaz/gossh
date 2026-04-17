package authkeys

import "testing"

// FuzzUnquote exercises the option-value unquoter with arbitrary
// quoted/escaped input. Must never panic; accepts any non-string.
func FuzzUnquote(f *testing.F) {
	f.Add(`"hello"`)
	f.Add(`"embedded \"quote\""`)
	f.Add(`bare`)
	f.Add(`""`)
	f.Add(`"trailing\\"`)
	f.Add(`"unterminated`)
	f.Add(``)
	f.Add(`"\x00embedded null\x00"`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = unquote(s)
	})
}

// FuzzParseHostPort exercises the permitopen/permitlisten parser.
func FuzzParseHostPort(f *testing.F) {
	f.Add("127.0.0.1:80")
	f.Add("*:*")
	f.Add("[::1]:22")
	f.Add("host:0")
	f.Add("host:999999") // over uint16
	f.Add("host:80abc")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseHostPort(s)
	})
}
