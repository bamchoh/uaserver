package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bamchoh/uastack/client"
	"github.com/bamchoh/uastack/server"
	"github.com/bamchoh/uastack/ua"
	uaid "github.com/bamchoh/uastack/ua/id"
	"github.com/bamchoh/uastack/uacert"
	"github.com/bamchoh/uastack/uasc"
)

const testNS = "urn:client-test"

type testServer struct {
	srv *server.Server
	url string
	ns  uint16
}

func (ts *testServer) id(s string) ua.NodeId { return ua.NewStringNodeId(ts.ns, s) }

func startServer(t *testing.T, autoAccept bool, opts ...func(*server.Config)) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "opc.tcp://" + ln.Addr().String()
	both := []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}
	security := []server.SecurityConfig{{PolicyURI: uasc.SecurityPolicyNone, Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeNone}}}
	for _, p := range uasc.SupportedPolicies()[1:] {
		security = append(security, server.SecurityConfig{PolicyURI: p, Modes: both})
	}
	cfg := server.Config{
		ApplicationURI: "urn:client-test:server",
		ListenAddr:     ln.Addr().String(),
		EndpointURL:    url,
		PKIDir:         t.TempDir(),
		Security:       security,
		UserTokens:     []server.UserTokenType{server.UserTokenAnonymous, server.UserTokenUserName, server.UserTokenCertificate},
		AuthenticateUser: func(user, password string) bool {
			return user == "user1" && password == "password1"
		},
		AutoAcceptUntrustedCertificates: autoAccept,
		Logger:                          log.New(io.Discard, "", 0),
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{srv: srv, url: url}
	as := srv.AddressSpace()
	ts.ns = as.RegisterNamespace(testNS)
	qn := func(s string) ua.QualifiedName { return ua.NewQualifiedName(ts.ns, s) }
	rw := server.VariableOptions{AccessLevel: server.AccessCurrentRead | server.AccessCurrentWrite}
	if _, err := as.AddFolder(server.ObjectsFolder, ts.id("Test"), qn("Test")); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddVariable(ts.id("Test"), ts.id("Int"), qn("Int"), ua.NewVariant(int32(1)), rw); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddVariable(ts.id("Test"), ts.id("Big"), qn("Big"), ua.NewVariant(make([]int32, 10)), rw); err != nil {
		t.Fatal(err)
	}
	i32 := ua.NewNumericNodeId(0, uaid.Int32)
	if _, err := as.AddMethod(ts.id("Test"), ts.id("Add"), qn("Add"),
		[]server.Argument{{Name: "a", DataType: i32}, {Name: "b", DataType: i32}}, []server.Argument{{Name: "sum", DataType: i32}},
		func(_ server.ReadContext, _ ua.NodeId, in []ua.Variant) ([]ua.Variant, ua.StatusCode) {
			return []ua.Variant{ua.NewVariant(in[0].Value().(int32) + in[1].Value().(int32))}, 0
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddFolder(ts.id("Test"), ts.id("Many"), qn("Many")); err != nil {
		t.Fatal(err)
	}
	for i := range 1500 {
		name := "v" + itoa(i)
		if _, err := as.AddVariable(ts.id("Many"), ts.id("Many."+name), qn(name), ua.NewVariant(int32(i)), rw); err != nil {
			t.Fatal(err)
		}
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ts
}

func itoa(i int) string { return big.NewInt(int64(i)).String() }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// userCert creates a user certificate (no application URI) for X509 identities.
func userCert(t *testing.T, curve elliptic.Curve) ([]byte, crypto.Signer) {
	t.Helper()
	var key crypto.Signer
	var err error
	if curve == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TestUser"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

var (
	userCertsOnce sync.Once
	userCerts     map[string]client.Identity
)

func x509Identity(t *testing.T, policy *uasc.SecurityPolicy) client.Identity {
	userCertsOnce.Do(func() {
		userCerts = map[string]client.Identity{}
		for name, curve := range map[string]elliptic.Curve{"rsa": nil, "P-256": elliptic.P256(), "P-384": elliptic.P384()} {
			der, key := userCert(t, curve)
			userCerts[name] = client.X509(der, key)
		}
	})
	if c := policy.CertCurve(); c != nil {
		return userCerts[c.Params().Name]
	}
	return userCerts["rsa"]
}

func TestAllEndpointsAndIdentities(t *testing.T) {
	ts := startServer(t, true)
	eps, err := client.GetEndpoints(ctx(t), ts.url, client.Config{}.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 11 {
		t.Fatalf("got %d endpoints, want 11", len(eps))
	}
	for _, ep := range eps {
		policy := uasc.PolicyByURI(ep.SecurityPolicyUri)
		identities := map[string]client.Identity{
			"Anonymous": client.Anonymous(),
			"UserName":  client.UserName("user1", "password1"),
			"X509":      x509Identity(t, policy),
		}
		for name, id := range identities {
			t.Run(policy.Name+"_"+ep.SecurityMode.String()+"_"+name, func(t *testing.T) {
				c, err := client.DialEndpoint(ctx(t), ts.url, ep, client.Config{
					Identity: id, AutoAcceptUntrustedCertificates: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close(ctx(t))
				want := int32(len(name) + int(ep.SecurityMode))
				if err := c.WriteValue(ctx(t), ts.id("Int"), ua.NewVariant(want)); err != nil {
					t.Fatal(err)
				}
				dv, err := c.ReadValue(ctx(t), ts.id("Int"))
				if err != nil {
					t.Fatal(err)
				}
				if dv.Value.Value() != want {
					t.Fatalf("read %v, want %d", dv.Value, want)
				}
			})
		}
	}
}

func TestWrongPassword(t *testing.T) {
	ts := startServer(t, true)
	for _, p := range []string{uasc.SecurityPolicyNone, uasc.SecurityPolicyBasic256Sha256, uasc.SecurityPolicyEccNistP384} {
		_, err := client.Dial(ctx(t), ts.url, client.Config{
			SecurityPolicy: p, Identity: client.UserName("user1", "wrong"), AutoAcceptUntrustedCertificates: true,
		})
		if !errors.Is(err, ua.StatusBadUserAccessDenied) {
			t.Fatalf("%s: got %v, want BadUserAccessDenied", p, err)
		}
	}
}

func TestServices(t *testing.T) {
	ts := startServer(t, true)
	c, err := client.Dial(ctx(t), ts.url, client.Config{
		SecurityPolicy: uasc.SecurityPolicyBasic256Sha256, AutoAcceptUntrustedCertificates: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx(t))

	ns, err := c.NamespaceIndex(ctx(t), testNS)
	if err != nil || ns != ts.ns {
		t.Fatalf("namespace index %d, %v", ns, err)
	}

	// Translate, browse (with continuation points) and call.
	id, err := c.TranslatePath(ctx(t), ua.NewNumericNodeId(0, uaid.ObjectsFolder), ua.NewQualifiedName(ns, "Test"), ua.NewQualifiedName(ns, "Int"))
	if err != nil || id != ts.id("Int") {
		t.Fatalf("translate: %v, %v", id, err)
	}
	refs, err := c.BrowseChildren(ctx(t), ts.id("Test"))
	if err != nil || len(refs) != 4 {
		t.Fatalf("browse Test: %d refs, %v", len(refs), err)
	}
	resp, err := c.Browse(ctx(t), &ua.BrowseRequest{RequestedMaxReferencesPerNode: 100, NodesToBrowse: []ua.BrowseDescription{{
		NodeId: ts.id("Many"), BrowseDirection: ua.BrowseDirectionForward, ResultMask: uint32(ua.BrowseResultMaskAll),
		ReferenceTypeId: ua.NewNumericNodeId(0, uaid.HierarchicalReferences), IncludeSubtypes: true,
	}}})
	if err != nil || len(resp.Results[0].References) != 100 || resp.Results[0].ContinuationPoint == nil {
		t.Fatalf("paged browse: %v", err)
	}
	refs, err = c.BrowseChildren(ctx(t), ts.id("Many"))
	if err != nil || len(refs) != 1500 {
		t.Fatalf("browse Many: %d refs, %v", len(refs), err)
	}
	out, err := c.CallMethod(ctx(t), ts.id("Test"), ts.id("Add"), ua.NewVariant(int32(2)), ua.NewVariant(int32(40)))
	if err != nil || len(out) != 1 || out[0].Value() != int32(42) {
		t.Fatalf("call: %v, %v", out, err)
	}
	_, err = c.CallMethod(ctx(t), ts.id("Test"), ts.id("Add"), ua.NewVariant("x"), ua.NewVariant(int32(1)))
	if !errors.Is(err, ua.StatusBadTypeMismatch) && !errors.Is(err, ua.StatusBadInvalidArgument) {
		t.Fatalf("call with a bad argument: %v", err)
	}

	// Values larger than one chunk in both directions.
	big := make([]int32, 200_000)
	for i := range big {
		big[i] = int32(i)
	}
	if err := c.WriteValue(ctx(t), ts.id("Big"), ua.NewVariant(big)); err != nil {
		t.Fatal(err)
	}
	dv, err := c.ReadValue(ctx(t), ts.id("Big"))
	if err != nil {
		t.Fatal(err)
	}
	if got := dv.Value.Value().([]int32); len(got) != len(big) || got[len(got)-1] != big[len(big)-1] {
		t.Fatal("big value differs")
	}

	// Errors from individual operations and from the service.
	_, err = c.ReadValue(ctx(t), ts.id("NoSuchNode"))
	if !errors.Is(err, ua.StatusBadNodeIdUnknown) {
		t.Fatalf("read unknown node: %v", err)
	}
	_, err = c.Read(ctx(t), &ua.ReadRequest{})
	if !errors.Is(err, ua.StatusBadNothingToDo) {
		t.Fatalf("empty read: %v", err)
	}
	if err := c.WriteValue(ctx(t), ts.id("Int"), ua.NewVariant("not an int")); !errors.Is(err, ua.StatusBadTypeMismatch) {
		t.Fatalf("write wrong type: %v", err)
	}

	// Registered nodes are usable aliases.
	reg, err := c.RegisterNodes(ctx(t), ts.id("Int"))
	if err != nil || len(reg) != 1 {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.ReadValue(ctx(t), reg[0]); err != nil {
		t.Fatal(err)
	}
	if err := c.UnregisterNodes(ctx(t), reg...); err != nil {
		t.Fatal(err)
	}
}

func TestSubscription(t *testing.T) {
	ts := startServer(t, true)
	c, err := client.Dial(ctx(t), ts.url, client.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx(t))
	sub, err := c.CreateSubscription(ctx(t), client.SubscriptionParams{PublishingInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	items, err := sub.MonitorValues(ctx(t), ts.id("Int"), ts.id("NoSuchNode"))
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Status != 0 || items[1].Status != ua.StatusBadNodeIdUnknown {
		t.Fatalf("monitored item status %s, %s", items[0].Status, items[1].Status)
	}

	// The initial value, then every written value (written slower than the
	// publishing interval, so none is overwritten in the queue of size 1).
	var lastSeq uint32
	expect := func(want int32) {
		t.Helper()
		select {
		case n, ok := <-sub.Notifications():
			if !ok {
				t.Fatal("notifications closed")
			}
			if lastSeq != 0 && n.SequenceNumber != lastSeq+1 {
				t.Fatalf("sequence number %d after %d", n.SequenceNumber, lastSeq)
			}
			lastSeq = n.SequenceNumber
			if len(n.DataChanges) != 1 || n.DataChanges[0].ClientHandle != items[0].ClientHandle {
				t.Fatalf("unexpected notification %+v", n)
			}
			if got := n.DataChanges[0].Value.Value.Value(); got != want {
				t.Fatalf("got value %v, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no notification for %d", want)
		}
	}
	expect(1)
	for v := int32(2); v <= 20; v++ {
		if err := c.WriteValue(ctx(t), ts.id("Int"), ua.NewVariant(v)); err != nil {
			t.Fatal(err)
		}
		expect(v)
	}

	if err := sub.Unmonitor(ctx(t), items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := sub.Delete(ctx(t)); err != nil {
		t.Fatal(err)
	}
	for range sub.Notifications() {
	}

	// Closing the client ends its subscriptions.
	sub2, err := c.CreateSubscription(ctx(t), client.SubscriptionParams{PublishingInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	c.Close(ctx(t))
	var last client.Notification
	for n := range sub2.Notifications() {
		last = n
	}
	if !errors.Is(last.Err, client.ErrClosed) {
		t.Fatalf("last notification error %v, want ErrClosed", last.Err)
	}
}

func TestConnectionLost(t *testing.T) {
	ts := startServer(t, true)
	c, err := client.Dial(ctx(t), ts.url, client.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.CreateSubscription(ctx(t), client.SubscriptionParams{PublishingInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ts.srv.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not notice the closed connection")
	}
	if c.Err() == nil {
		t.Fatal("Err is nil after the connection was lost")
	}
	for range sub.Notifications() {
	}
	if _, err := c.ReadValue(ctx(t), ts.id("Int")); err == nil {
		t.Fatal("read succeeded on a lost connection")
	}
}

func TestSelectEndpoint(t *testing.T) {
	ts := startServer(t, true)
	eps, err := client.GetEndpoints(ctx(t), ts.url, client.Config{}.Limits)
	if err != nil {
		t.Fatal(err)
	}
	best, err := client.SelectEndpoint(eps, "", 0)
	if err != nil || best.SecurityPolicyUri != uasc.SecurityPolicyEccNistP384 || best.SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		t.Fatalf("best endpoint %s %s, %v", best.SecurityPolicyUri, best.SecurityMode, err)
	}
	if _, err := client.SelectEndpoint(eps[:1], uasc.SecurityPolicyBasic256Sha256, ua.MessageSecurityModeSign); err == nil {
		t.Fatal("selected a missing endpoint")
	}
	servers, err := client.FindServers(ctx(t), ts.url, client.Config{}.Limits)
	if err != nil || len(servers) != 1 || servers[0].ApplicationUri != "urn:client-test:server" {
		t.Fatalf("find servers: %+v, %v", servers, err)
	}
}

func TestServerCertificateTrust(t *testing.T) {
	ts := startServer(t, true)
	cfg := client.Config{SecurityPolicy: uasc.SecurityPolicyBasic256Sha256}
	// No trust list configured.
	if _, err := client.Dial(ctx(t), ts.url, cfg); err == nil {
		t.Fatal("connected without a way to trust the server")
	}
	// An empty trust list rejects the certificate and stores it in rejected.
	cfg.PKIDir = t.TempDir()
	_, err := client.Dial(ctx(t), ts.url, cfg)
	if !errors.Is(err, ua.StatusBadCertificateUntrusted) {
		t.Fatalf("got %v, want BadCertificateUntrusted", err)
	}
	rejected, _ := os.ReadDir(filepath.Join(cfg.PKIDir, "rejected", "certs"))
	if len(rejected) != 1 {
		t.Fatalf("%d rejected certificates, want 1", len(rejected))
	}
	// Moving it to trusted makes the connection work, and the client's own
	// certificate was created in the store.
	old := filepath.Join(cfg.PKIDir, "rejected", "certs", rejected[0].Name())
	if err := os.Rename(old, filepath.Join(cfg.PKIDir, "trusted", "certs", rejected[0].Name())); err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(ctx(t), ts.url, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close(ctx(t))
	if _, err := os.Stat(filepath.Join(cfg.PKIDir, "own", "certs", "cert.der")); err != nil {
		t.Fatal(err)
	}
	// A custom check replaces the trust list.
	cfg.PKIDir = ""
	cfg.VerifyServerCertificate = func(chain []*x509.Certificate) error {
		if uacert.CertificateURI(chain[0]) != "urn:client-test:server" {
			return ua.StatusBadCertificateUntrusted
		}
		return nil
	}
	c, err = client.Dial(ctx(t), ts.url, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close(ctx(t))
}

func TestServerRejectsUntrustedClient(t *testing.T) {
	ts := startServer(t, false)
	_, err := client.Dial(ctx(t), ts.url, client.Config{
		SecurityPolicy: uasc.SecurityPolicyBasic256Sha256, AutoAcceptUntrustedCertificates: true,
	})
	if !errors.Is(err, ua.StatusBadSecurityChecksFailed) && !errors.Is(err, ua.StatusBadCertificateUntrusted) {
		t.Fatalf("got %v, want the server to reject the client certificate", err)
	}
}

func TestKeepAlive(t *testing.T) {
	ts := startServer(t, true, func(c *server.Config) { c.MinSessionTimeout = 600 * time.Millisecond })
	dial := func(keepAlive time.Duration) *client.Client {
		c, err := client.Dial(ctx(t), ts.url, client.Config{SessionTimeout: 600 * time.Millisecond, KeepAliveInterval: keepAlive})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(ctx(t)) })
		if c.SessionTimeout() != 600*time.Millisecond {
			t.Fatalf("session timeout %s", c.SessionTimeout())
		}
		return c
	}
	kept, idle := dial(0), dial(-1)
	time.Sleep(2 * time.Second)
	if _, err := kept.ReadValue(ctx(t), ts.id("Int")); err != nil {
		t.Fatalf("session with keep-alive: %v", err)
	}
	if _, err := idle.ReadValue(ctx(t), ts.id("Int")); !errors.Is(err, ua.StatusBadSessionIdInvalid) {
		t.Fatalf("session without keep-alive: got %v, want BadSessionIdInvalid", err)
	}
}
