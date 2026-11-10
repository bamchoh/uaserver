package uasc

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/uacert"
	"github.com/bamchoh/uaserver/uacp"
)

type testCreds struct {
	rsa, p256, p384 *Credential
}

var (
	credsOnce sync.Once
	creds     testCreds
)

func testCredentials(t *testing.T) testCreds {
	t.Helper()
	credsOnce.Do(func() {
		mk := func(curve elliptic.Curve) *Credential {
			var c *Credential
			if curve == nil {
				der, key, err := uacert.CreateSelfSigned("urn:test", "test", []string{"localhost"}, 2048, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				c = &Credential{Certificate: der, PrivateKey: key}
			} else {
				der, key, err := uacert.CreateSelfSignedECC("urn:test", "test", []string{"localhost"}, curve, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				c = &Credential{Certificate: der, PrivateKey: key}
			}
			return c
		}
		creds = testCreds{rsa: mk(nil), p256: mk(elliptic.P256()), p384: mk(elliptic.P384())}
	})
	return creds
}

func (tc testCreds) forPolicy(uri string) *Credential {
	switch uri {
	case SecurityPolicyNone:
		return nil
	case SecurityPolicyEccNistP256:
		return tc.p256
	case SecurityPolicyEccNistP384:
		return tc.p384
	}
	return tc.rsa
}

// startEchoServer serves secure channels that answer a ReadRequest with one
// result per node, holding the node's numeric id.
func startEchoServer(t *testing.T, cfg *Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var id uint32
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			go func(id uint32) {
				defer c.Close()
				uc, err := uacp.Accept(c, uacp.ServerLimits{ReceiveBufferSize: 65535, SendBufferSize: 65535,
					MaxMessageSize: 16 << 20, MaxChunkCount: 4096}, 5*time.Second)
				if err != nil {
					return
				}
				ch := NewChannel(uc, id, cfg)
				_ = ch.Serve(func(r Request) {
					req, ok := r.Body.(*ua.ReadRequest)
					if !ok {
						_ = ch.SendResponse(r.RequestID, &ua.ServiceFault{ResponseHeader: ua.ResponseHeader{
							ServiceResult: ua.StatusBadServiceUnsupported}})
						return
					}
					resp := &ua.ReadResponse{ResponseHeader: ua.ResponseHeader{RequestHandle: req.RequestHeader.RequestHandle}}
					for _, n := range req.NodesToRead {
						resp.Results = append(resp.Results, ua.DataValue{Value: ua.NewVariant(int32(n.NodeId.Numeric))})
					}
					_ = ch.SendResponse(r.RequestID, resp)
				})
			}(id)
		}
	}()
	return "opc.tcp://" + ln.Addr().String()
}

func readN(ctx context.Context, ch *ClientChannel, n int) error {
	req := &ua.ReadRequest{RequestHeader: ua.RequestHeader{RequestHandle: uint32(n)}}
	for i := 0; i < n; i++ {
		req.NodesToRead = append(req.NodesToRead, ua.ReadValueId{NodeId: ua.NewNumericNodeId(0, uint32(i)), AttributeId: 13})
	}
	msg, err := ch.Send(ctx, req)
	if err != nil {
		return err
	}
	resp, ok := msg.(*ua.ReadResponse)
	if !ok {
		return errors.New("unexpected response type")
	}
	if len(resp.Results) != n || resp.ResponseHeader.RequestHandle != uint32(n) {
		return errors.New("unexpected number of results")
	}
	for i, r := range resp.Results {
		if r.Value.Value() != int32(i) {
			return errors.New("unexpected result value")
		}
	}
	return nil
}

func TestClientChannelAllPolicies(t *testing.T) {
	tc := testCredentials(t)
	cfg := &Config{
		Credentials:      tc.forPolicy,
		IsAllowed:        func(string, ua.MessageSecurityMode) bool { return true },
		MinTokenLifetime: 1000, MaxTokenLifetime: 3_600_000,
	}
	url := startEchoServer(t, cfg)
	type tcase struct {
		policy string
		mode   ua.MessageSecurityMode
	}
	cases := []tcase{{SecurityPolicyNone, ua.MessageSecurityModeNone}}
	for _, p := range SupportedPolicies()[1:] {
		cases = append(cases, tcase{p, ua.MessageSecurityModeSign}, tcase{p, ua.MessageSecurityModeSignAndEncrypt})
	}
	for _, c := range cases {
		t.Run(PolicyByURI(c.policy).Name+"_"+c.mode.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := uacp.Dial(ctx, url, uacp.ClientLimits{})
			if err != nil {
				t.Fatal(err)
			}
			cred := tc.forPolicy(c.policy)
			var remote []byte
			if cred != nil {
				remote = cred.Certificate // the echo server uses the same certificates
			}
			ch, err := OpenClientChannel(ctx, conn, ClientConfig{
				SecurityPolicyURI: c.policy, SecurityMode: c.mode, Local: cred, RemoteCertificate: remote,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ch.Close()
			// Small, concurrent and large (multi chunk in both directions) messages.
			var wg sync.WaitGroup
			errs := make(chan error, 20)
			for i := 1; i <= 20; i++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					errs <- readN(ctx, ch, n)
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := readN(ctx, ch, 20000); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientChannelRenewsToken(t *testing.T) {
	tc := testCredentials(t)
	for _, policy := range []string{SecurityPolicyBasic256Sha256, SecurityPolicyEccNistP256} {
		t.Run(PolicyByURI(policy).Name, func(t *testing.T) {
			cfg := &Config{
				Credentials:      tc.forPolicy,
				IsAllowed:        func(string, ua.MessageSecurityMode) bool { return true },
				MinTokenLifetime: 200, MaxTokenLifetime: 200,
			}
			url := startEchoServer(t, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := uacp.Dial(ctx, url, uacp.ClientLimits{})
			if err != nil {
				t.Fatal(err)
			}
			cred := tc.forPolicy(policy)
			ch, err := OpenClientChannel(ctx, conn, ClientConfig{
				SecurityPolicyURI: policy, SecurityMode: ua.MessageSecurityModeSignAndEncrypt,
				Local: cred, RemoteCertificate: cred.Certificate, Lifetime: 200 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ch.Close()
			first := ch.sendTokenID()
			// The token is renewed every 150 ms; the old token would expire
			// after 250 ms, so requests keep working only if renewal works.
			deadline := time.Now().Add(1200 * time.Millisecond)
			for time.Now().Before(deadline) {
				if err := readN(ctx, ch, 3); err != nil {
					t.Fatal(err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if got := ch.sendTokenID(); got < first+4 {
				t.Fatalf("token id %d after 1.2 s, started at %d: token was not renewed", got, first)
			}
		})
	}
}

func TestClientChannelServerError(t *testing.T) {
	tc := testCredentials(t)
	cfg := &Config{
		Credentials:      tc.forPolicy,
		IsAllowed:        func(p string, _ ua.MessageSecurityMode) bool { return p == SecurityPolicyNone },
		MinTokenLifetime: 1000, MaxTokenLifetime: 3_600_000,
	}
	url := startEchoServer(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := uacp.Dial(ctx, url, uacp.ClientLimits{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenClientChannel(ctx, conn, ClientConfig{
		SecurityPolicyURI: SecurityPolicyBasic256Sha256, SecurityMode: ua.MessageSecurityModeSign,
		Local: tc.rsa, RemoteCertificate: tc.rsa.Certificate,
	})
	if !errors.Is(err, ua.StatusBadSecurityModeRejected) {
		t.Fatalf("got %v, want BadSecurityModeRejected", err)
	}
}

func (c *ClientChannel) sendTokenID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendToken.id
}
