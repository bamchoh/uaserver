package client_test

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bamchoh/uastack/client"
	"github.com/bamchoh/uastack/server"
	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/uasc"
)

// proxy forwards TCP connections to a server and can cut them.
type proxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []net.Conn
	refuse bool
}

func newProxy(t *testing.T, targetURL string) (*proxy, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, target: targetURL[len("opc.tcp://"):]}
	t.Cleanup(func() { ln.Close(); p.cut() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			refuse := p.refuse
			p.mu.Unlock()
			if refuse {
				c.Close()
				continue
			}
			s, err := net.Dial("tcp", p.target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, s)
			p.mu.Unlock()
			go func() { io.Copy(s, c); s.Close() }()
			go func() { io.Copy(c, s); c.Close() }()
		}
	}()
	return p, "opc.tcp://" + ln.Addr().String()
}

// cut closes all forwarded connections.
func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}

func (p *proxy) setRefuse(v bool) {
	p.mu.Lock()
	p.refuse = v
	p.mu.Unlock()
}

type stateLog struct {
	mu     sync.Mutex
	states []client.ConnState
	ch     chan client.ConnState
}

func newStateLog() *stateLog { return &stateLog{ch: make(chan client.ConnState, 16)} }

func (l *stateLog) record(s client.ConnState, _ error) {
	l.mu.Lock()
	l.states = append(l.states, s)
	l.mu.Unlock()
	l.ch <- s
}

func (l *stateLog) wait(t *testing.T, want client.ConnState) {
	t.Helper()
	timeout := time.After(15 * time.Second)
	for {
		select {
		case s := <-l.ch:
			if s == want {
				return
			}
		case <-timeout:
			t.Fatalf("state %s not reached (states %v)", want, l.states)
		}
	}
}

// expectValue waits for a data change with the value.
func expectValue(t *testing.T, sub *client.Subscription, want int32) client.Notification {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case n, ok := <-sub.Notifications():
			if !ok {
				t.Fatalf("notifications closed while waiting for %d", want)
			}
			for _, dc := range n.DataChanges {
				if dc.Value.Value.Value() == want {
					return n
				}
			}
		case <-timeout:
			t.Fatalf("no notification with value %d", want)
		}
	}
}

func TestReconnectKeepsSession(t *testing.T) {
	ts := startServer(t, true)
	p, url := newProxy(t, ts.url)
	states := newStateLog()
	c, err := client.Dial(ctx(t), url, client.Config{
		SecurityPolicy: uasc.SecurityPolicyBasic256Sha256, AutoAcceptUntrustedCertificates: true,
		Identity: client.UserName("user1", "password1"), AutoReconnect: true,
		ReconnectInterval: 50 * time.Millisecond, OnStateChange: states.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx(t))
	session := c.SessionID()
	sub, err := c.CreateSubscription(ctx(t), client.SubscriptionParams{PublishingInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	items, err := sub.MonitorValues(ctx(t), ts.id("Int"))
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, sub, 1)
	subID := sub.ID()

	p.cut()
	states.wait(t, client.StateReconnecting)
	// The value changes while the client is disconnected.
	if err := ts.srv.AddressSpace().SetValue(ts.id("Int"), ua.NewVariant(int32(2))); err != nil {
		t.Fatal(err)
	}
	states.wait(t, client.StateConnected)
	if c.SessionID() != session || sub.ID() != subID {
		t.Fatal("the session or subscription changed although the server kept them")
	}
	n := expectValue(t, sub, 2)
	if n.DataChanges[0].ClientHandle != items[0].ClientHandle {
		t.Fatal("unexpected client handle")
	}
	if err := c.WriteValue(ctx(t), ts.id("Int"), ua.NewVariant(int32(3))); err != nil {
		t.Fatal(err)
	}
	expectValue(t, sub, 3)
}

func TestReconnectRecreatesSession(t *testing.T) {
	ts := startServer(t, true, func(c *server.Config) { c.MinSessionTimeout = 500 * time.Millisecond })
	p, url := newProxy(t, ts.url)
	states := newStateLog()
	c, err := client.Dial(ctx(t), url, client.Config{
		SecurityPolicy: uasc.SecurityPolicyEccNistP256, AutoAcceptUntrustedCertificates: true,
		Identity: client.UserName("user1", "password1"), AutoReconnect: true,
		SessionTimeout: 500 * time.Millisecond, ReconnectInterval: 50 * time.Millisecond,
		MaxReconnectInterval: 200 * time.Millisecond, OnStateChange: states.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx(t))
	session := c.SessionID()
	sub, err := c.CreateSubscription(ctx(t), client.SubscriptionParams{PublishingInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	items, err := sub.MonitorValues(ctx(t), ts.id("Int"))
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, sub, 1)
	subID := sub.ID()

	// Stay disconnected until the server has dropped the session.
	p.setRefuse(true)
	p.cut()
	states.wait(t, client.StateReconnecting)
	// A request made while disconnected waits for the reconnect.
	readDone := make(chan error, 1)
	go func() {
		_, err := c.ReadValue(ctx(t), ts.id("Int"))
		readDone <- err
	}()
	time.Sleep(1500 * time.Millisecond)
	if err := ts.srv.AddressSpace().SetValue(ts.id("Int"), ua.NewVariant(int32(5))); err != nil {
		t.Fatal(err)
	}
	p.setRefuse(false)
	states.wait(t, client.StateConnected)
	if err := <-readDone; err != nil {
		t.Fatalf("read during the reconnect: %v", err)
	}
	if c.SessionID() == session {
		t.Fatal("the session was not recreated")
	}
	// The subscription and its item are recreated with the same client handle.
	n := expectValue(t, sub, 5)
	if sub.ID() == subID || n.DataChanges[0].ClientHandle != items[0].ClientHandle {
		t.Fatalf("subscription %d (was %d), handle %d", sub.ID(), subID, n.DataChanges[0].ClientHandle)
	}
	if mi := sub.MonitoredItems(); len(mi) != 1 || mi[0].ClientHandle != items[0].ClientHandle {
		t.Fatalf("monitored items %+v", mi)
	}
	if err := c.WriteValue(ctx(t), ts.id("Int"), ua.NewVariant(int32(6))); err != nil {
		t.Fatal(err)
	}
	expectValue(t, sub, 6)

	// Close ends the reconnecting client too.
	p.setRefuse(true)
	p.cut()
	states.wait(t, client.StateReconnecting)
	c.Close(ctx(t))
	if !errors.Is(c.Err(), client.ErrClosed) {
		t.Fatalf("Err after Close: %v", c.Err())
	}
	for range sub.Notifications() {
	}
}
