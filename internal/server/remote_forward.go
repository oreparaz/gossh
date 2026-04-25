package server

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/audit"
)

// remoteForwards tracks the listeners a single SSH connection has
// opened via tcpip-forward global requests. All listeners are closed
// when the connection closes. The chSem field is the per-connection
// channel semaphore; server-initiated forwarded-tcpip channels
// charge against it just like client-initiated channels.
type remoteForwards struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
	closed    bool
	chSem     chan struct{} // per-connection channel cap; shared with handle()
}

func newRemoteForwards(chSem chan struct{}) *remoteForwards {
	return &remoteForwards{
		listeners: make(map[string]net.Listener),
		chSem:     chSem,
	}
}

func keyFor(host string, port uint32) string {
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
}

// add stores l. If there is already a listener for that host/port
// pair, the existing one is closed and replaced. If closeAll has
// already fired, l is closed immediately and not stored — preventing
// the listener from outliving the SSH connection.
func (r *remoteForwards) add(host string, port uint32, l net.Listener) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		_ = l.Close()
		return false
	}
	k := keyFor(host, port)
	if prev, ok := r.listeners[k]; ok {
		_ = prev.Close()
	}
	r.listeners[k] = l
	return true
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

// closeAll shuts every listener down and latches the registry as
// closed so any in-flight add will close its new listener and bail.
func (r *remoteForwards) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
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
	if !permitOpenAllows(permitOpenFromExt(conn.Permissions, "permitlisten"), body.BindAddr, body.BindPort) {
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
		s.audit.Emit(audit.Event{
			Type: audit.TypeTCPIPForwardReject, Remote: conn.RemoteAddr().String(), User: conn.User(),
			Fields: map[string]interface{}{"host": body.BindAddr, "port": body.BindPort, "reason": "listen-fail", "err": err.Error()},
		})
		_ = req.Reply(false, nil)
		return
	}
	actualPort := uint32(l.Addr().(*net.TCPAddr).Port)
	// Key the registry by the *assigned* port. The x/crypto/ssh
	// client switches the local ssh.Listener to the assigned port
	// and sends that port (not the originally-requested 0) in any
	// later cancel-tcpip-forward request; so we must match on it.
	// Two concurrent `-R 0:...` would also collide if we kept the
	// requested port as the key.
	if !fwd.add(body.BindAddr, actualPort, l) {
		// Connection is shutting down; the listener was closed by add.
		_ = req.Reply(false, nil)
		return
	}
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

	go s.acceptRemoteForward(ctx, conn, body.BindAddr, actualPort, l, fwd.chSem, log)
}

// acceptRemoteForward runs the accept loop for a -R listener. For
// each inbound connection it opens a forwarded-tcpip channel back to
// the client and splices data across.
//
// chSem is the per-connection channel semaphore, shared with the
// inbound `session` / `direct-tcpip` dispatch. Charging forwarded-
// tcpip against the same cap prevents a flood of inbound traffic
// on an -R listener from defeating MaxChannelsPerConn (audit #4).
func (s *Server) acceptRemoteForward(ctx context.Context, conn *ssh.ServerConn, bindHost string, bindPort uint32, l net.Listener, chSem chan struct{}, log *slog.Logger) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		// Non-blocking reservation — if the cap is already reached,
		// drop the inbound connection. SSH clients routinely retry.
		select {
		case chSem <- struct{}{}:
		default:
			log.Warn("forwarded-tcpip dropped: per-connection channel cap reached")
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-chSem }()
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
