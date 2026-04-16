package server

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/audit"
	"github.com/oscar/gossh/internal/authkeys"
)

// remoteForwards tracks the listeners a single SSH connection has
// opened via tcpip-forward global requests. All listeners are closed
// when the connection closes.
type remoteForwards struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
}

func newRemoteForwards() *remoteForwards {
	return &remoteForwards{listeners: make(map[string]net.Listener)}
}

func keyFor(host string, port uint32) string {
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
}

// add stores l. If there is already a listener for that host/port
// pair, the existing one is closed and replaced.
func (r *remoteForwards) add(host string, port uint32, l net.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := keyFor(host, port)
	if prev, ok := r.listeners[k]; ok {
		_ = prev.Close()
	}
	r.listeners[k] = l
}

// removeKey closes the listener for a given key, returning whether
// one was present.
func (r *remoteForwards) removeKey(host string, port uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := keyFor(host, port)
	l, ok := r.listeners[k]
	if !ok {
		return false
	}
	_ = l.Close()
	delete(r.listeners, k)
	return true
}

// closeAll shuts every listener down.
func (r *remoteForwards) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.listeners {
		_ = l.Close()
	}
	r.listeners = map[string]net.Listener{}
}

// handleRemoteForward processes tcpip-forward / cancel-tcpip-forward
// global requests. Called under handleGlobalRequests.
//
// This replaces the stub in server.go. To reduce churn the dispatcher
// in server.go calls this; the real handler lives here.
func (s *Server) doRemoteForward(ctx context.Context, conn *ssh.ServerConn, fwd *remoteForwards, req *ssh.Request, log *slog.Logger) {
	var body struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &body); err != nil {
		_ = req.Reply(false, nil)
		return
	}

	if req.Type == "cancel-tcpip-forward" {
		ok := fwd.removeKey(body.BindAddr, body.BindPort)
		_ = req.Reply(ok, nil)
		s.audit.Emit(audit.Event{
			Type: audit.TypeTCPIPForwardCancel, Remote: conn.RemoteAddr().String(), User: conn.User(),
			Fields: map[string]interface{}{"host": body.BindAddr, "port": body.BindPort, "ok": ok},
		})
		return
	}

	if hasExt(conn, "no-port-forwarding") {
		s.audit.Emit(audit.Event{
			Type: audit.TypeTCPIPForwardReject, Remote: conn.RemoteAddr().String(), User: conn.User(),
			Fields: map[string]interface{}{"host": body.BindAddr, "port": body.BindPort, "reason": "no-port-forwarding"},
		})
		_ = req.Reply(false, nil)
		return
	}
	if !permitListenAllows(permitOpenFromExt(conn.Permissions, "permitlisten"), body.BindAddr, body.BindPort) {
		log.Warn("tcpip-forward rejected by permitlisten", "host", body.BindAddr, "port", body.BindPort)
		s.audit.Emit(audit.Event{
			Type: audit.TypeTCPIPForwardReject, Remote: conn.RemoteAddr().String(), User: conn.User(),
			Fields: map[string]interface{}{"host": body.BindAddr, "port": body.BindPort, "reason": "permitlisten"},
		})
		_ = req.Reply(false, nil)
		return
	}

	// OpenSSH binds "" and "0.0.0.0" to all interfaces, "localhost" /
	// "127.0.0.1" to loopback. We honour that mapping.
	bindHost := body.BindAddr
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	laddr := net.JoinHostPort(bindHost, strconv.FormatUint(uint64(body.BindPort), 10))
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Info("tcpip-forward listen failed", "addr", laddr, "err", err)
		_ = req.Reply(false, nil)
		return
	}
	actualPort := uint32(l.Addr().(*net.TCPAddr).Port)
	fwd.add(body.BindAddr, body.BindPort, l)
	s.audit.Emit(audit.Event{
		Type: audit.TypeTCPIPForwardBind, Remote: conn.RemoteAddr().String(), User: conn.User(),
		Fields: map[string]interface{}{"host": body.BindAddr, "port": actualPort},
	})

	// Reply with the actual bound port when the client asked for 0.
	if body.BindPort == 0 {
		_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{actualPort}))
	} else {
		_ = req.Reply(true, nil)
	}

	go s.acceptRemoteForward(ctx, conn, body.BindAddr, actualPort, l, log)
}

// permitListenAllows is the -R counterpart of permitOpenAllows; the
// "port of 0" semantics are the same.
func permitListenAllows(list []authkeys.HostPort, host string, port uint32) bool {
	if len(list) == 0 {
		return true
	}
	for _, hp := range list {
		if hp.Host != "*" && hp.Host != host {
			continue
		}
		if hp.Port != 0 && uint32(hp.Port) != port {
			continue
		}
		return true
	}
	return false
}

// acceptRemoteForward runs the accept loop for a -R listener. For
// each inbound connection it opens a forwarded-tcpip channel back to
// the client and splices data across.
func (s *Server) acceptRemoteForward(ctx context.Context, conn *ssh.ServerConn, bindHost string, bindPort uint32, l net.Listener, log *slog.Logger) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			origAddr, origPort := splitHostPort(c.RemoteAddr().String())
			payload := ssh.Marshal(struct {
				ConnectedAddr string
				ConnectedPort uint32
				OrigAddr      string
				OrigPort      uint32
			}{bindHost, bindPort, origAddr, origPort})
			ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				log.Info("forwarded-tcpip open failed", "err", err)
				_ = c.Close()
				return
			}
			go ssh.DiscardRequests(reqs)
			openedAt := time.Now()
			s.audit.Emit(audit.Event{
				Type: audit.TypeForwardedTCPIPOpen, Remote: conn.RemoteAddr().String(), User: conn.User(),
				Fields: map[string]interface{}{"bind_host": bindHost, "bind_port": bindPort, "orig": c.RemoteAddr().String()},
			})
			spliceChannel(ch, c)
			s.audit.Emit(audit.Event{
				Type: audit.TypeForwardedTCPIPClose, Remote: conn.RemoteAddr().String(), User: conn.User(),
				Fields: map[string]interface{}{"bind_host": bindHost, "bind_port": bindPort, "duration_ms": time.Since(openedAt).Milliseconds()},
			})
		}()
		_ = ctx
	}
}

func splitHostPort(s string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, uint32(p)
}
