package client_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/bamchoh/uastack/client"
	"github.com/bamchoh/uastack/server"
	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/uasc"
)

// startExampleServer starts a server with one writable Int32 variable
// "ns=<urn:example>;s=Counter" and returns its URL and a function that stops it.
func startExampleServer() (string, func()) {
	pki, err := os.MkdirTemp("", "uastack-example")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	url := "opc.tcp://" + ln.Addr().String()
	srv, err := server.New(server.Config{
		ApplicationName: "Example Server",
		EndpointURL:     url,
		PKIDir:          pki,
		Security: []server.SecurityConfig{{
			PolicyURI: uasc.SecurityPolicyNone,
			Modes:     []ua.MessageSecurityMode{ua.MessageSecurityModeNone},
		}},
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		log.Fatal(err)
	}
	as := srv.AddressSpace()
	ns := as.RegisterNamespace("urn:example")
	if _, err := as.AddVariable(server.ObjectsFolder, ua.NewStringNodeId(ns, "Counter"),
		ua.NewQualifiedName(ns, "Counter"), ua.NewVariant(int32(1)),
		server.VariableOptions{AccessLevel: server.AccessCurrentRead | server.AccessCurrentWrite}); err != nil {
		log.Fatal(err)
	}
	go srv.Serve(ln)
	return url, func() {
		srv.Close()
		os.RemoveAll(pki)
	}
}

// This example connects to a server without security, then reads and writes a value.
func Example() {
	url, stop := startExampleServer()
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, url, client.Config{}) // SecurityPolicy None, anonymous
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close(ctx)

	ns, err := c.NamespaceIndex(ctx, "urn:example")
	if err != nil {
		log.Fatal(err)
	}
	id := ua.NewStringNodeId(ns, "Counter")

	dv, err := c.ReadValue(ctx, id)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("before:", dv.Value.Value())

	if err := c.WriteValue(ctx, id, ua.NewVariant(int32(42))); err != nil {
		log.Fatal(err)
	}
	dv, err = c.ReadValue(ctx, id)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("after:", dv.Value.Value())
	// Output:
	// before: 1
	// after: 42
}

// This example subscribes to a variable and prints its first data change notification.
func ExampleSubscription_MonitorValues() {
	url, stop := startExampleServer()
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, url, client.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close(ctx)

	ns, err := c.NamespaceIndex(ctx, "urn:example")
	if err != nil {
		log.Fatal(err)
	}
	sub, err := c.CreateSubscription(ctx, client.SubscriptionParams{PublishingInterval: 100 * time.Millisecond})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := sub.MonitorValues(ctx, ua.NewStringNodeId(ns, "Counter")); err != nil {
		log.Fatal(err)
	}
	for n := range sub.Notifications() {
		if n.Err != nil {
			log.Fatal(n.Err)
		}
		if len(n.DataChanges) > 0 {
			fmt.Println("value:", n.DataChanges[0].Value.Value.Value())
			break
		}
	}
	// Output:
	// value: 1
}
