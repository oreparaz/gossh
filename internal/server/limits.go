package server

import (
	"net"
	"sync"
)

// ipLimiter caps the number of concurrent connections per remote
// address. It is deliberately minimal — no time-based token bucket,
// no global rate. The use case is "refuse obvious DoS from a single
// IP"; operators wanting richer rate limiting should front us with a
// dedicated component (iptables, nftables, a load balancer).
type ipLimiter struct {
	max int
	mu  sync.Mutex
	n   map[string]int
}

func newIPLimiter(max int) *ipLimiter {
	return &ipLimiter{max: max, n: make(map[string]int)}
}

// acquire reserves a slot for addr. It returns a release function and
// true on success, or nil and false when the per-IP cap is reached.
// A max of zero means "unlimited".
func (l *ipLimiter) acquire(addr net.Addr) (func(), bool) {
	if l == nil || l.max == 0 {
		return func() {}, true
	}
	key := ipOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[key] >= l.max {
		return nil, false
	}
	l.n[key]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.n[key] > 0 {
			l.n[key]--
			if l.n[key] == 0 {
				delete(l.n, key)
			}
		}
	}, true
}

func ipOf(addr net.Addr) string {
	if t, ok := addr.(*net.TCPAddr); ok && t.IP != nil {
		return t.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
