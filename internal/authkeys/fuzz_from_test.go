package authkeys

import (
	"net"
	"strings"
	"testing"
)

func FuzzMatchFrom(f *testing.F) {
	f.Add("10.0.0.0/8,*.example.com,!10.0.0.13", "10.2.3.4", "foo.example.com")
	f.Add("*", "", "")
	f.Add("", "1.2.3.4", "host")
	f.Add("!", "1.2.3.4", "x")
	f.Add("[", "", "")
	f.Add("bad/cidr", "1.2.3.4", "")
	f.Fuzz(func(t *testing.T, patternsCSV, ipStr, host string) {
		var patterns []string
		if patternsCSV != "" {
			patterns = strings.Split(patternsCSV, ",")
		}
		var ip net.IP
		if ipStr != "" {
			ip = net.ParseIP(ipStr)
		}
		_ = MatchFrom(patterns, ip, host)
	})
}
