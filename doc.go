// Package gossh is a minimal, security-focused SSH implementation.
//
// It contains a server (cmd/gosshd) and a client (cmd/gossh) that are
// wire-compatible with OpenSSH for a conservative subset of features:
// public-key authentication, interactive PTY sessions, and the three
// port-forwarding channels (direct-tcpip, tcpip-forward, SOCKS5).
//
// Cryptographic primitives come from golang.org/x/crypto/ssh. This project
// intentionally does not implement the SSH wire protocol itself.
package gossh
