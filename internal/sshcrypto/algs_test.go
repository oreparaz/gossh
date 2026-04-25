package sshcrypto

import (
	"strings"
	"testing"
)

// trulyForbidden is the set of algorithms that must NEVER appear in
// any of our lists (server or client). These are broken or
// dangerously weak — adding them would be a security regression.
var trulyForbidden = []string{
	"ssh-rsa",                     // SHA-1 RSA signatures
	"ssh-dss",                     // DSA
	"diffie-hellman-group1-sha1",  // 1024-bit DH
	"diffie-hellman-group14-sha1", // SHA-1
	"3des-cbc",
	"aes128-cbc",
	"aes192-cbc",
	"aes256-cbc",
	"blowfish-cbc",
	"arcfour",
	"hmac-sha1",
	"hmac-md5",
}

func TestNoForbiddenAlgorithmsAnywhere(t *testing.T) {
	all := append([]string{}, KeyExchanges...)
	all = append(all, ClientKeyExchanges...)
	all = append(all, Ciphers...)
	all = append(all, ClientCiphers...)
	all = append(all, MACs...)
	all = append(all, ClientMACs...)
	all = append(all, HostKeyAlgorithms...)
	all = append(all, PublicKeyAlgorithms...)
	for _, a := range all {
		for _, f := range trulyForbidden {
			if a == f {
				t.Fatalf("forbidden algorithm %q present", a)
			}
		}
	}
}

// TestServerListsTight pins the server-side stance: curve25519-only
// KEX, AEAD-only ciphers, ETM-only MACs. Loosening any of these is
// a deliberate posture change and should not happen by accident.
func TestServerListsTight(t *testing.T) {
	for _, k := range KeyExchanges {
		if !strings.HasPrefix(k, "curve25519-sha256") {
			t.Errorf("server KEX %q is not curve25519", k)
		}
	}
	for _, c := range Ciphers {
		if !strings.Contains(c, "@openssh.com") {
			t.Errorf("server cipher %q is not AEAD", c)
		}
	}
	for _, m := range MACs {
		if !strings.HasSuffix(m, "-etm@openssh.com") {
			t.Errorf("server MAC %q is not ETM", m)
		}
	}
}

// TestClientIsServerSuperset enforces that everything the server
// accepts, the client also accepts — so a deployment of gosshd
// can always be reached by gossh.
func TestClientIsServerSuperset(t *testing.T) {
	check := func(name string, server, client []string) {
		t.Helper()
		set := map[string]bool{}
		for _, c := range client {
			set[c] = true
		}
		for _, s := range server {
			if !set[s] {
				t.Errorf("%s: %q is in server list but not client list", name, s)
			}
		}
	}
	check("KEX", KeyExchanges, ClientKeyExchanges)
	check("Ciphers", Ciphers, ClientCiphers)
	check("MACs", MACs, ClientMACs)
}

// TestClientLegacyAdditionsAreSane spells out exactly what the
// client's wider posture allows beyond the server's. Any change
// here forces a doc/SECURITY.md update.
func TestClientLegacyAdditionsAreSane(t *testing.T) {
	expectExtras := func(t *testing.T, name string, server, client, want []string) {
		t.Helper()
		serverSet := map[string]bool{}
		for _, s := range server {
			serverSet[s] = true
		}
		var got []string
		for _, c := range client {
			if !serverSet[c] {
				got = append(got, c)
			}
		}
		if !equal(got, want) {
			t.Errorf("%s extras: got %v, want %v", name, got, want)
		}
	}
	expectExtras(t, "KEX", KeyExchanges, ClientKeyExchanges, []string{
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group14-sha256",
	})
	expectExtras(t, "Ciphers", Ciphers, ClientCiphers, []string{
		"aes256-ctr",
		"aes192-ctr",
		"aes128-ctr",
	})
	expectExtras(t, "MACs", MACs, ClientMACs, []string{
		"hmac-sha2-512",
		"hmac-sha2-256",
	})
}

func TestAllowlistsNonEmpty(t *testing.T) {
	if len(KeyExchanges) == 0 || len(Ciphers) == 0 || len(MACs) == 0 {
		t.Fatal("server allowlists empty")
	}
	if len(ClientKeyExchanges) == 0 || len(ClientCiphers) == 0 || len(ClientMACs) == 0 {
		t.Fatal("client allowlists empty")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
