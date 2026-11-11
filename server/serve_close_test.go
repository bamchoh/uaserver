package server

import (
	"errors"
	"net"
	"testing"
	"time"
)

// serveAsync runs Serve in a goroutine and returns a channel with its result.
func serveAsync(s *Server, ln net.Listener) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	return done
}

func waitServe(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestServeAfterClose(t *testing.T) {
	s := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitServe(t, serveAsync(s, ln))

	// Serve closes the listener it was given.
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Serve returned %v, want net.ErrClosed", err)
	}
}

func TestCloseRightAfterServe(t *testing.T) {
	// Close right after starting Serve, so Close often runs before Serve
	// has registered the listener.
	for i := 0; i < 20; i++ {
		s := newTestServer(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := serveAsync(s, ln)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		waitServe(t, done)
	}
}
