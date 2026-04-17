package server

import "testing"

// FuzzTakeString exercises the length-prefixed SSH string reader.
// The parser must never panic or return a slice past len(p).
func FuzzTakeString(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})                  // empty string
	f.Add([]byte{0, 0, 0, 3, 'f', 'o', 'o'})   // well-formed
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})      // length > buffer
	f.Add([]byte{})                            // empty buffer
	f.Add([]byte{0, 0})                        // partial header
	f.Add([]byte{0x7F, 0xFF, 0xFF, 0xFF, 'x'}) // near-max length
	f.Add([]byte{0, 0, 0, 1, 0})               // null byte string
	f.Fuzz(func(t *testing.T, in []byte) {
		s, rest, err := takeString(in)
		if err != nil {
			return
		}
		if uint64(len(s))+uint64(len(rest)) > uint64(len(in)) {
			t.Fatalf("takeString over-consumed: sz=%d rest=%d in=%d", len(s), len(rest), len(in))
		}
	})
}

func FuzzParseStringRequest(f *testing.F) {
	f.Add([]byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'x'})
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = parseStringRequest(in)
	})
}

func FuzzParseEnvRequest(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 'F', 'O', 'O', 0, 0, 0, 3, 'b', 'a', 'r'})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _, _ = parseEnvRequest(in)
	})
}

func FuzzParsePTYReq(f *testing.F) {
	// Well-formed: term="xterm", 80x24, no modes.
	f.Add([]byte{
		0, 0, 0, 5, 'x', 't', 'e', 'r', 'm',
		0, 0, 0, 80, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, // empty modes
	})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 4, 'x', 't', 'e'}) // truncated term
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = parsePTYReq(in)
	})
}

func FuzzParseWindowChange(f *testing.F) {
	f.Add([]byte{0, 0, 0, 80, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = parseWindowChange(in)
	})
}

// FuzzIsSafeEnvName ensures the charset classifier never panics on
// arbitrary bytes and returns a bool deterministically.
func FuzzIsSafeEnvName(f *testing.F) {
	f.Add("TERM")
	f.Add("")
	f.Add("\x00")
	f.Add("LC_WITH=EQUAL")
	f.Add("lc_lower")
	f.Fuzz(func(t *testing.T, s string) {
		_ = isSafeEnvName(s)
	})
}
