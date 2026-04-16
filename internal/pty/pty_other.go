//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package pty

import (
	"errors"
	"os"
	"os/exec"
)

type Session struct {
	Master *os.File
	Cmd    *exec.Cmd
}

func Start(cmd *exec.Cmd, rows, cols uint32) (*Session, error) {
	return nil, errors.New("pty: unsupported platform")
}

func (s *Session) Resize(rows, cols uint32) error { return nil }
func (s *Session) Close() error                   { return nil }
