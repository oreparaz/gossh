package scp

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadAck exercises the small ack-reader that turns scp-protocol
// reply bytes into Go errors. It must never panic on arbitrary input,
// including very long error messages and zero-length streams.
func FuzzReadAck(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 'o', 'h', ' ', 'n', 'o', '\n'})
	f.Add([]byte{2, '\n'})
	f.Add([]byte{})
	f.Add([]byte{3})
	// Malicious: warn byte + enormous message without newline.
	big := make([]byte, 1<<16)
	big[0] = 1
	for i := range big[1:] {
		big[i+1] = 'A'
	}
	f.Add(big)

	f.Fuzz(func(t *testing.T, in []byte) {
		r := bufio.NewReader(bytes.NewReader(in))
		_ = readAck(r, bytes.NewReader(nil))
	})
}
