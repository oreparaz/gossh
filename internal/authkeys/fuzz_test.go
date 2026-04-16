package authkeys

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add(samplePubEd25519)
	f.Add("# comment\n" + samplePubEd25519)
	f.Add(`command="foo",from="1.2.3.4" ` + samplePubEd25519)
	f.Add(`restrict,pty ` + samplePubEd25519)
	f.Add("permitopen=\"127.0.0.1:80\" " + samplePubEd25519)
	f.Add("")
	f.Add("garbage")
	f.Add(`"unterminated`)
	f.Add(samplePubEd25519 + "\n" + `bad options ` + samplePubEd25519)

	f.Fuzz(func(t *testing.T, in string) {
		// The parser may return an error, but must not panic.
		_, _ = Parse(strings.NewReader(in))
	})
}
