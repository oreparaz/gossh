package server

import (
	"encoding/binary"
	"errors"
	"strings"
)

// PTYRequest is the parsed RFC-4254 §6.2 pty-req payload.
//
// Only the fields the server actually forwards to the pty are kept:
// Term (for $TERM) and Cols/Rows (for the winsize ioctl). The
// pixel-dimension fields and the termios-modes blob are parsed by
// the RFC but we have no consumer for them — storing them would
// just invite misuse.
type PTYRequest struct {
	Term       string
	Cols, Rows uint32
}

// parseStringRequest reads a single SSH string from req.Payload.
// Used for "exec", "subsystem", "env" (name only).
func parseStringRequest(p []byte) (string, error) {
	if len(p) < 4 {
		return "", errors.New("short payload")
	}
	n := binary.BigEndian.Uint32(p[:4])
	if uint64(n)+4 > uint64(len(p)) {
		return "", errors.New("payload truncated")
	}
	return string(p[4 : 4+n]), nil
}

// parseEnvRequest parses an "env" request (two SSH strings: name, value).
func parseEnvRequest(p []byte) (name, value string, err error) {
	name, rest, err := takeString(p)
	if err != nil {
		return "", "", err
	}
	value, _, err = takeString(rest)
	if err != nil {
		return "", "", err
	}
	return name, value, nil
}

// parsePTYReq parses an RFC-4254 pty-req payload. The pixel-size
// and terminal-modes fields are present in the wire format but we
// ignore them — see PTYRequest doc.
func parsePTYReq(p []byte) (PTYRequest, error) {
	term, p, err := takeString(p)
	if err != nil {
		return PTYRequest{}, err
	}
	if len(p) < 16 {
		return PTYRequest{}, errors.New("pty-req: short payload")
	}
	return PTYRequest{
		Term: term,
		Cols: binary.BigEndian.Uint32(p[0:4]),
		Rows: binary.BigEndian.Uint32(p[4:8]),
	}, nil
}

// parseWindowChange parses a "window-change" payload (four uint32).
// Only Cols/Rows survive; pixel dimensions are discarded.
func parseWindowChange(p []byte) (PTYRequest, error) {
	if len(p) < 16 {
		return PTYRequest{}, errors.New("window-change: short payload")
	}
	return PTYRequest{
		Cols: binary.BigEndian.Uint32(p[0:4]),
		Rows: binary.BigEndian.Uint32(p[4:8]),
	}, nil
}

func takeString(p []byte) (string, []byte, error) {
	if len(p) < 4 {
		return "", nil, errors.New("short string field")
	}
	n := binary.BigEndian.Uint32(p[:4])
	if uint64(n)+4 > uint64(len(p)) {
		return "", nil, errors.New("truncated string field")
	}
	return string(p[4 : 4+n]), p[4+n:], nil
}

// isSafeEnvName returns true if the variable name is on an allowlist
// we propagate to child processes. Anything else is silently dropped.
// OpenSSH uses AcceptEnv; we hard-code the common safe set because
// user-supplied environment is a well-known injection vector.
//
// Names must be non-empty, may only contain [A-Z0-9_], must start
// with a letter or underscore, and must appear in the allowlist.
// The character-set check rules out injection via '=' or shell
// metacharacters in the NAME (the VALUE is always passed verbatim).
func isSafeEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '_' ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9' && i > 0)) {
			return false
		}
	}
	switch name {
	case "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME",
		"LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_PAPER",
		"LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT",
		"LC_IDENTIFICATION", "SSH_ORIGINAL_COMMAND":
		return true
	}
	// Allow LC_* generally.
	return strings.HasPrefix(name, "LC_")
}
