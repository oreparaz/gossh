package server

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestIPLimiterZeroMeansUnlimited(t *testing.T) {
	l := newIPLimiter(0)
	var released int32
	for i := 0; i < 100; i++ {
		rel, ok := l.acquire(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
		if !ok {
			t.Fatal("should allow")
		}
		rel()
		atomic.AddInt32(&released, 1)
	}
	if released != 100 {
		t.Fatal("some acquisitions failed")
	}
}

func TestIPLimiterEnforces(t *testing.T) {
	l := newIPLimiter(3)
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}
	rels := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		rel, ok := l.acquire(addr)
		if !ok {
			t.Fatalf("acquire %d", i)
		}
		rels = append(rels, rel)
	}
	if _, ok := l.acquire(addr); ok {
		t.Fatal("4th acquire should have been refused")
	}
	rels[0]()
	if _, ok := l.acquire(addr); !ok {
		t.Fatal("should allow after a release")
	}
	// A different IP is independent.
	other := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 22}
	if _, ok := l.acquire(other); !ok {
		t.Fatal("different IP should not be limited")
	}
}
