//go:build linux || darwin || freebsd || netbsd || openbsd

// Package pty wraps the pseudo-terminal allocation and window-size
// management calls, isolating the cgo/syscall surface from the server.
package pty

import (
	"os"
	"os/exec"
	"syscall"

	creackpty "github.com/creack/pty"
)

// Session ties a running child process to its pty master fd.
type Session struct {
	Master *os.File
	Cmd    *exec.Cmd
}

// Start forks cmd attached to a new pseudo-terminal. On return, the
// caller owns the returned Session and must Close it when done.
//
// Rows/cols of 0 are replaced with sensible defaults.
func Start(cmd *exec.Cmd, rows, cols uint32) (*Session, error) {
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	size := &creackpty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	master, err := creackpty.StartWithSize(cmd, size)
	if err != nil {
		return nil, err
	}
	return &Session{Master: master, Cmd: cmd}, nil
}

// Resize updates the pty's window size so the shell re-renders.
func (s *Session) Resize(rows, cols uint32) error {
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	return creackpty.Setsize(s.Master, &creackpty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	})
}

// Close releases the pty master fd. It does not kill the child.
func (s *Session) Close() error {
	if s.Master == nil {
		return nil
	}
	return s.Master.Close()
}
