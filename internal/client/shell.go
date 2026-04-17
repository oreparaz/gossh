package client

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Shell runs an interactive shell through the SSH connection. It puts
// the local stdin into raw mode, forwards window-size changes to the
// remote, and exits with the remote shell's status.
func (c *Client) Shell() (int, error) {
	s, err := c.conn.NewSession()
	if err != nil {
		return -1, err
	}
	defer s.Close()

	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return -1, errors.New("gossh: stdin is not a terminal — use an explicit command or -T")
	}

	// Put local terminal into raw mode so keystrokes pass through.
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return -1, fmt.Errorf("term raw: %w", err)
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	// Request PTY matching our window size.
	w, h, err := term.GetSize(stdinFd)
	if err != nil {
		w, h = 80, 24
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	termName := os.Getenv("TERM")
	if termName == "" {
		termName = "xterm-256color"
	}
	if err := s.RequestPty(termName, h, w, modes); err != nil {
		return -1, fmt.Errorf("request pty: %w", err)
	}

	// Forward SIGWINCH as window-change. signal.Stop alone is not
	// enough to unblock `for range winch`: it un-registers signal
	// delivery but does not close the channel. Add an explicit done
	// channel and select on both so the goroutine actually exits
	// when Shell() returns.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	winchDone := make(chan struct{})
	defer func() {
		signal.Stop(winch)
		close(winchDone)
	}()
	go func() {
		for {
			select {
			case <-winch:
				nw, nh, err := term.GetSize(stdinFd)
				if err == nil {
					_ = s.WindowChange(nh, nw)
				}
			case <-winchDone:
				return
			}
		}
	}()

	s.Stdin = os.Stdin
	s.Stdout = os.Stdout
	s.Stderr = os.Stderr

	if err := s.Shell(); err != nil {
		return -1, fmt.Errorf("start shell: %w", err)
	}
	if err := s.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitStatus(), nil
		}
		return -1, err
	}
	return 0, nil
}

// ExecInteractive runs `command` with a PTY attached to the local
// terminal. Useful for commands like htop that need a tty.
func (c *Client) ExecInteractive(command string) (int, error) {
	s, err := c.conn.NewSession()
	if err != nil {
		return -1, err
	}
	defer s.Close()

	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return -1, errors.New("gossh: stdin is not a terminal")
	}
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return -1, err
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	w, h, err := term.GetSize(stdinFd)
	if err != nil {
		w, h = 80, 24
	}
	termName := os.Getenv("TERM")
	if termName == "" {
		termName = "xterm-256color"
	}
	if err := s.RequestPty(termName, h, w, ssh.TerminalModes{}); err != nil {
		return -1, err
	}
	s.Stdin = os.Stdin
	s.Stdout = os.Stdout
	s.Stderr = os.Stderr
	if err := s.Run(command); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitStatus(), nil
		}
		return -1, err
	}
	return 0, nil
}
