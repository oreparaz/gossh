package forward

import "testing"

func FuzzParseLocal(f *testing.F) {
	f.Add("8080:host:80")
	f.Add("127.0.0.1:8080:host:80")
	f.Add("[::1]:80:[::2]:80")
	f.Add("")
	f.Add("not:enough")
	f.Add("[missing-bracket:80:host:80")
	f.Add("[:]:[:]:[:]") // nested empty brackets
	f.Add("0:0:0:0")     // all zeros
	f.Add(":::")         // nothing but colons
	f.Add("[]:80:[]:80") // empty brackets
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseLocal(in)
	})
}

func FuzzParseDynamic(f *testing.F) {
	f.Add("1080")
	f.Add("127.0.0.1:1080")
	f.Add("")
	f.Add("weird:too:many:colons")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseDynamic(in)
	})
}
