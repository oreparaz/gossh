package sshconfig

import (
	"strings"
	"testing"
)

func FuzzParseClient(f *testing.F) {
	f.Add(sampleClient)
	f.Add("")
	f.Add("Host\n")
	f.Add("Port garbage\n")
	f.Add("Host *\n  Port 22\nHost tricky\n  Hostname x\n")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseClient(strings.NewReader(in))
	})
}

func FuzzParseServer(f *testing.F) {
	f.Add(sampleServer)
	f.Add("")
	f.Add("Port zero\n")
	f.Add("MaxAuthTries -1\n")
	f.Add("HostKey \x00\x01\n")
	f.Add("ListenAddress [bogus\n")
	f.Add(strings.Repeat("Port 22\n", 10000)) // stress
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseServer(strings.NewReader(in))
	})
}

// FuzzResolveHost ensures the host-alias resolver can't be driven
// into a panic by pathological Host patterns + query hostnames.
func FuzzResolveHost(f *testing.F) {
	f.Add("Host *\n  Port 22\n", "example.com")
	f.Add("Host a b c\n  Hostname x\n", "b")
	f.Add("", "x")
	f.Add("Host ****\n  Port 22\n", "")
	f.Fuzz(func(t *testing.T, cfgText, query string) {
		c, err := ParseClient(strings.NewReader(cfgText))
		if err != nil {
			return
		}
		_ = c.ResolveHost(query)
	})
}
