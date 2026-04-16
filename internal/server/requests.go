package server

import (
	"encoding/binary"
	"errors"
	"strings"
)

// PTYRequest is the parsed RFC-4254 §6.2 pty-req payload.
type PTYRequest struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32 // pixel dimensions; usually 0
	TerminalModes []byte
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

// parsePTYReq parses an RFC-4254 pty-req payload.
func parsePTYReq(p []byte) (PTYRequest, error) {
	term, p, err := takeString(p)
	if err != nil {
		return PTYRequest{}, err
	}
	if len(p) < 16 {
		return PTYRequest{}, errors.New("pty-req: short payload")
	}
	cols := binary.BigEndian.Uint32(p[0:4])
	rows := binary.BigEndian.Uint32(p[4:8])
	w := binary.BigEndian.Uint32(p[8:12])
	h := binary.BigEndian.Uint32(p[12:16])
	modes, _, err := takeString(p[16:])
	if err != nil {
		// Some clients omit the modes string entirely.
		modes = ""
	}
	return PTYRequest{
		Term:          term,
		Cols:          cols,
		Rows:          rows,
		Width:         w,
		Height:        h,
		TerminalModes: []byte(modes),
	}, nil
}

// parseWindowChange parses a "window-change" payload (four uint32).
func parseWindowChange(p []byte) (PTYRequest, error) {
	if len(p) < 16 {
		return PTYRequest{}, errors.New("window-change: short payload")
	}
	return PTYRequest{
		Cols:   binary.BigEndian.Uint32(p[0:4]),
		Rows:   binary.BigEndian.Uint32(p[4:8]),
		Width:  binary.BigEndian.Uint32(p[8:12]),
		Height: binary.BigEndian.Uint32(p[12:16]),
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
