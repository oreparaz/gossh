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
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseServer(strings.NewReader(in))
	})
}
