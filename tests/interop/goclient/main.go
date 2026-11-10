// Command goclient tests the Go client against another OPC UA server (in CI
// the .NET reference server in tests/interop/dotnet-server). It connects to
// every endpoint with anonymous, user name and X509 identities, and for each
// one reads, browses, writes, subscribes and renews nothing but the session.
// It exits with status 1 if any case fails.
//
// Usage: go run ./tests/interop/goclient [-user u -password p -node ns=2;s=Int] opc.tcp://localhost:48600
package main

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
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/bamchoh/uastack/client"
	"github.com/bamchoh/uastack/ua"
	uaid "github.com/bamchoh/uastack/ua/id"
	"github.com/bamchoh/uastack/uasc"
)

func main() {
	user := flag.String("user", "user1", "user name accepted by the server")
	password := flag.String("password", "password1", "password of the user")
	node := flag.String("node", "ns=2;s=Int", "writable Int32 variable")
	only := flag.String("only", "", "run only the cases whose name contains this text")
	verbose := flag.Bool("v", false, "log client diagnostics")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: goclient [flags] <endpoint url>")
		os.Exit(2)
	}
	url := flag.Arg(0)
	writable := ua.MustParseNodeId(*node)
	logger := log.New(os.Stderr, "  ", 0)
	if !*verbose {
		logger = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	eps, err := client.GetEndpoints(ctx, url, client.Config{}.Limits)
	if err != nil {
		fmt.Println("GetEndpoints:", err)
		os.Exit(1)
	}

	userCerts := map[string]client.Identity{}
	for name, curve := range map[string]elliptic.Curve{"rsa": nil, "P-256": elliptic.P256(), "P-384": elliptic.P384()} {
		userCerts[name] = newUserCertificate(curve)
	}

	failed, passed := 0, 0
	for _, ep := range eps {
		p := uasc.PolicyByURI(ep.SecurityPolicyUri)
		if p == nil {
			fmt.Println("skip  unsupported policy", ep.SecurityPolicyUri)
			continue
		}
		x509User := userCerts["rsa"]
		if c := p.CertCurve(); c != nil {
			x509User = userCerts[c.Params().Name]
		}
		type tcase struct {
			name    string
			id      client.Identity
			wantErr ua.StatusCode
		}
		cases := []tcase{{"anonymous", client.Anonymous(), 0}}
		for _, t := range ep.UserIdentityTokens {
			switch t.TokenType {
			case ua.UserTokenTypeUserName:
				cases = append(cases, tcase{"username", client.UserName(*user, *password), 0},
					tcase{"wrong-password", client.UserName(*user, "wrong"), ua.StatusBadUserAccessDenied})
			case ua.UserTokenTypeCertificate:
				cases = append(cases, tcase{"x509", x509User, 0})
			}
		}
		for _, c := range cases {
			name := fmt.Sprintf("%s/%s/%s", p.Name, ep.SecurityMode, c.name)
			if *only != "" && !strings.Contains(name, *only) {
				continue
			}
			err := run(ctx, url, ep, c.id, writable, logger)
			if c.wantErr != 0 {
				if errors.Is(err, c.wantErr) || errors.Is(err, ua.StatusBadIdentityTokenRejected) || errors.Is(err, ua.StatusBadIdentityTokenInvalid) {
					err = nil
				} else {
					err = fmt.Errorf("got %v, want %s", err, c.wantErr)
				}
			}
			if err != nil {
				fmt.Println("FAIL ", name, err)
				failed++
			} else {
				fmt.Println("ok   ", name)
				passed++
			}
		}
	}
	fmt.Printf("%d passed, %d failed\n", passed, failed)
	if failed > 0 || passed == 0 {
		os.Exit(1)
	}
}

func run(ctx context.Context, url string, ep ua.EndpointDescription, id client.Identity, writable ua.NodeId, logger *log.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := client.DialEndpoint(ctx, url, ep, client.Config{
		ApplicationName: "GoInteropClient", Identity: id, AutoAcceptUntrustedCertificates: true, Logger: logger,
	})
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	if _, err := c.ReadValue(ctx, ua.NewNumericNodeId(0, uaid.Server_ServerStatus_CurrentTime)); err != nil {
		return err
	}
	if refs, err := c.BrowseChildren(ctx, ua.NewNumericNodeId(0, uaid.Server)); err != nil {
		return err
	} else if len(refs) == 0 {
		return errors.New("the Server object has no children")
	}
	v := int32(time.Now().UnixNano() % 100000)
	if err := c.WriteValue(ctx, writable, ua.NewVariant(v)); err != nil {
		return err
	}
	dv, err := c.ReadValue(ctx, writable)
	if err != nil {
		return err
	}
	if dv.Value.Value() != v {
		return fmt.Errorf("read back %v, want %d", dv.Value, v)
	}
	sub, err := c.CreateSubscription(ctx, client.SubscriptionParams{PublishingInterval: 100 * time.Millisecond})
	if err != nil {
		return err
	}
	items, err := sub.MonitorValues(ctx, writable)
	if err != nil {
		return err
	}
	if items[0].Status.IsBad() {
		return fmt.Errorf("monitored item: %w", items[0].Status)
	}
	expect := func(want int32) error {
		select {
		case n := <-sub.Notifications():
			if len(n.DataChanges) == 0 || n.DataChanges[0].Value.Value.Value() != want {
				return fmt.Errorf("notification %+v, want value %d", n, want)
			}
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("no notification for %d", want)
		}
	}
	if err := expect(v); err != nil {
		return err
	}
	if err := c.WriteValue(ctx, writable, ua.NewVariant(v+1)); err != nil {
		return err
	}
	if err := expect(v + 1); err != nil {
		return err
	}
	return sub.Delete(ctx)
}

// newUserCertificate creates a user certificate (no application URI).
func newUserCertificate(curve elliptic.Curve) client.Identity {
	var key crypto.Signer
	var err error
	if curve == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	}
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "GoInteropUser", Organization: []string{"opcuasrv"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	return client.X509(der, key)
}
