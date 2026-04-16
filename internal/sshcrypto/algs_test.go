package sshcrypto

import (
	"strings"
	"testing"
)

func TestNoLegacyAlgorithms(t *testing.T) {
	forbidden := []string{
		"ssh-rsa",                     // SHA-1 signatures
		"ssh-dss",                     // DSA
		"diffie-hellman-group1-sha1",  // 1024-bit DH
		"diffie-hellman-group14-sha1", // SHA-1
		"ecdh-sha2-nistp",             // we remove NIST curves
		"3des-cbc",
		"aes128-cbc",
		"aes256-cbc",
		"blowfish-cbc",
		"arcfour",
		"hmac-sha1",
		"hmac-md5",
	}
	all := append([]string{}, KeyExchanges...)
	all = append(all, Ciphers...)
	all = append(all, MACs...)
	all = append(all, HostKeyAlgorithms...)
	all = append(all, PublicKeyAlgorithms...)
	for _, a := range all {
		for _, f := range forbidden {
			if strings.Contains(a, f) {
				t.Fatalf("forbidden algorithm %q present (matched pattern %q)", a, f)
			}
		}
	}
}

func TestAllowlistsNonEmpty(t *testing.T) {
	if len(KeyExchanges) == 0 || len(Ciphers) == 0 || len(MACs) == 0 {
		t.Fatal("allowlists empty")
	}
}
