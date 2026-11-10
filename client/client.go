// Package client implements an OPC UA client (opc.tcp, UA Binary): secure
// channels with every security policy supported by uasc, sessions with
// anonymous, user name and X509 identities, the Discovery, View, Attribute
// and Method services, and subscriptions.
//
// A minimal example:
//
//	c, err := client.Dial(ctx, "opc.tcp://localhost:4840", client.Config{})
//	if err != nil { ... }
//	defer c.Close(ctx)
//	dv, err := c.ReadValue(ctx, ua.NewNumericNodeId(0, id.Server_ServerStatus_CurrentTime))
package client

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bamchoh/uaserver/ua"
	uaid "github.com/bamchoh/uaserver/ua/id"
	"github.com/bamchoh/uaserver/uacert"
	"github.com/bamchoh/uaserver/uacp"
	"github.com/bamchoh/uaserver/uasc"
)

// Config configures a Client. The zero value connects to the None endpoint
// with an anonymous session.
type Config struct {
	ApplicationURI  string // default "urn:<hostname>:uaclient"
	ApplicationName string // default "Go OPC UA Client"
	ProductURI      string // default "urn:uaclient"

	// SecurityPolicy is the security policy URI (default uasc.SecurityPolicyNone).
	SecurityPolicy string
	// SecurityMode defaults to SignAndEncrypt for secure policies and to None
	// for the None policy.
	SecurityMode ua.MessageSecurityMode

	// Certificate (DER) and PrivateKey are the application instance
	// certificate. If they are not set and the policy needs a certificate,
	// it is loaded from (or created in) PKIDir, or created in memory when
	// PKIDir is empty. ECC policies need an ECC certificate: if Certificate
	// is an RSA certificate, one is created for them.
	Certificate []byte
	PrivateKey  crypto.Signer
	// PKIDir is the certificate store (same layout as the server's): own
	// certificates, and the trusted, issuer and rejected server certificates.
	PKIDir string
	// VerifyServerCertificate decides whether the server certificate is
	// trusted. If nil, the PKIDir trust list is used.
	VerifyServerCertificate func(chain []*x509.Certificate) error
	// AutoAcceptUntrustedCertificates trusts every server certificate
	// (testing only). With a PKIDir, accepted certificates are stored in
	// the trusted directory.
	AutoAcceptUntrustedCertificates bool

	// Identity is the user identity (default Anonymous()).
	Identity Identity
	// SessionName defaults to the application name.
	SessionName string
	// SessionTimeout is the requested session timeout (default 1 minute).
	SessionTimeout time.Duration
	// KeepAliveInterval is how often an idle session is kept alive by
	// reading the server state (default a third of the revised session
	// timeout; negative disables keep-alive).
	KeepAliveInterval time.Duration
	// RequestTimeout applies to calls whose context has no deadline (default 10 s).
	RequestTimeout time.Duration
	// ChannelLifetime is the requested security token lifetime (default 1 hour).
	ChannelLifetime time.Duration
	// Limits are the transport limits sent in the Hello message.
	Limits uacp.ClientLimits
	// LocaleIDs are the preferred locales of the session.
	LocaleIDs []string

	// Logger receives diagnostics (default: discarded).
	Logger *log.Logger
}

func (c *Config) setDefaults() {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	if c.ApplicationName == "" {
		c.ApplicationName = "Go OPC UA Client"
	}
	if c.ApplicationURI == "" {
		c.ApplicationURI = "urn:" + host + ":uaclient"
	}
	if c.ProductURI == "" {
		c.ProductURI = "urn:uaclient"
	}
	if c.SecurityPolicy == "" {
		c.SecurityPolicy = uasc.SecurityPolicyNone
	}
	if c.SecurityMode == ua.MessageSecurityModeInvalid {
		c.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
		if c.SecurityPolicy == uasc.SecurityPolicyNone {
			c.SecurityMode = ua.MessageSecurityModeNone
		}
	}
	if c.Identity == nil {
		c.Identity = Anonymous()
	}
	if c.SessionName == "" {
		c.SessionName = c.ApplicationName
	}
	if c.SessionTimeout == 0 {
		c.SessionTimeout = time.Minute
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 10 * time.Second
	}
	if c.ChannelLifetime == 0 {
		c.ChannelLifetime = time.Hour
	}
	if c.Logger == nil {
		c.Logger = log.New(io.Discard, "", 0)
	}
}

// Client is a connection to an OPC UA server with an activated session. It
// is safe for concurrent use.
type Client struct {
	cfg      Config
	url      string
	endpoint ua.EndpointDescription
	ch       *uasc.ClientChannel
	local    *uasc.Credential // application certificate used on the channel

	sessionID      ua.NodeId
	authToken      ua.NodeId
	sessionTimeout time.Duration
	serverCert     []byte // from CreateSession
	maxRequestSize uint32

	mu          sync.Mutex
	serverNonce []byte

	handle  atomic.Uint32
	lastUse atomic.Int64 // unix nanoseconds of the last request

	subs *subscriptions

	closeOnce sync.Once
	closed    chan struct{}
}

// Dial connects to the server at endpointURL: it reads the server's
// endpoints, picks the one matching the configured security policy and
// mode, opens a secure channel and creates and activates a session.
func Dial(ctx context.Context, endpointURL string, cfg Config) (*Client, error) {
	cfg.setDefaults()
	eps, err := GetEndpoints(ctx, endpointURL, cfg.Limits)
	if err != nil {
		return nil, err
	}
	ep, err := SelectEndpoint(eps, cfg.SecurityPolicy, cfg.SecurityMode)
	if err != nil {
		return nil, err
	}
	return DialEndpoint(ctx, endpointURL, ep, cfg)
}

// DialEndpoint connects to an endpoint returned by GetEndpoints. The
// connection is made to endpointURL (the URL in the endpoint description is
// often not reachable from the client); the security settings come from ep
// and override those in cfg.
func DialEndpoint(ctx context.Context, endpointURL string, ep ua.EndpointDescription, cfg Config) (*Client, error) {
	cfg.setDefaults()
	cfg.SecurityPolicy = ep.SecurityPolicyUri
	cfg.SecurityMode = ep.SecurityMode
	policy := uasc.PolicyByURI(ep.SecurityPolicyUri)
	if policy == nil {
		return nil, fmt.Errorf("client: unsupported security policy %s", ep.SecurityPolicyUri)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.RequestTimeout)
		defer cancel()
	}

	c := &Client{cfg: cfg, url: endpointURL, endpoint: ep, closed: make(chan struct{})}
	c.subs = newSubscriptions(c)
	chCfg := uasc.ClientConfig{
		SecurityPolicyURI: policy.URI, SecurityMode: ep.SecurityMode, Lifetime: cfg.ChannelLifetime,
		Logf: cfg.Logger.Printf,
	}
	if !policy.IsNone() {
		local, err := c.applicationCredential(policy)
		if err != nil {
			return nil, err
		}
		if err := c.verifyServerCertificate(ep); err != nil {
			return nil, err
		}
		c.local = local
		chCfg.Local = local
		chCfg.RemoteCertificate = ep.ServerCertificate
	}
	conn, err := uacp.Dial(ctx, endpointURL, cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	ch, err := uasc.OpenClientChannel(ctx, conn, chCfg)
	if err != nil {
		return nil, fmt.Errorf("client: opening the secure channel: %w", err)
	}
	c.ch = ch
	if err := c.createSession(ctx); err != nil {
		_ = ch.Close()
		return nil, err
	}
	if err := c.activateSession(ctx); err != nil {
		c.closeSession(ctx)
		_ = ch.Close()
		return nil, err
	}
	go c.watchChannel()
	if cfg.KeepAliveInterval >= 0 {
		go c.keepAlive()
	}
	return c, nil
}

// Endpoint returns the endpoint the client is connected to.
func (c *Client) Endpoint() ua.EndpointDescription { return c.endpoint }

// SessionID returns the id of the session.
func (c *Client) SessionID() ua.NodeId { return c.sessionID }

// SessionTimeout returns the session timeout granted by the server.
func (c *Client) SessionTimeout() time.Duration { return c.sessionTimeout }

// Done is closed when the client is closed or its connection is lost.
func (c *Client) Done() <-chan struct{} { return c.closed }

// Err returns why the connection was lost, or nil while it is open.
func (c *Client) Err() error {
	select {
	case <-c.closed:
		if err := c.ch.Err(); err != nil && !errors.Is(err, uasc.ErrChannelClosed) {
			return err
		}
		return uasc.ErrChannelClosed
	default:
		return nil
	}
}

func (c *Client) logf(format string, args ...any) { c.cfg.Logger.Printf(format, args...) }

// Close closes the session (deleting its subscriptions) and the secure channel.
func (c *Client) Close(ctx context.Context) error {
	var err error
	c.closeOnce.Do(func() {
		select {
		case <-c.ch.Done():
		default:
			c.closeSession(ctx)
			err = c.ch.Close()
		}
		close(c.closed)
		c.subs.shutdown(ErrClosed)
	})
	return err
}

// ErrClosed is the error delivered to subscriptions when the client is closed.
var ErrClosed = errors.New("client: closed")

func (c *Client) closeSession(ctx context.Context) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	_, err := c.Send(ctx, &ua.CloseSessionRequest{DeleteSubscriptions: true})
	if err != nil {
		c.logf("client: CloseSession: %v", err)
	}
}

// watchChannel marks the client closed when the secure channel is lost.
func (c *Client) watchChannel() {
	select {
	case <-c.closed:
	case <-c.ch.Done():
		c.closeOnce.Do(func() {
			c.logf("client: connection lost: %v", c.ch.Err())
			close(c.closed)
			c.subs.shutdown(c.ch.Err())
		})
	}
}

// keepAlive reads the server state when the session has been idle, so that
// the session does not time out.
func (c *Client) keepAlive() {
	interval := c.cfg.KeepAliveInterval
	if interval == 0 {
		interval = c.sessionTimeout / 3
	}
	interval = max(interval, 100*time.Millisecond)
	t := time.NewTicker(interval / 2)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
		}
		if time.Since(time.Unix(0, c.lastUse.Load())) < interval {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		_, err := c.ReadValue(ctx, ua.NewNumericNodeId(0, uaid.Server_ServerStatus_State))
		cancel()
		if err != nil {
			c.logf("client: keep-alive: %v", err)
		}
	}
}

// --- requests ---

// Send sends any service request and returns its response. It fills the
// request header (authentication token, handle, timestamp and timeout hint).
// A ServiceFault or a bad ServiceResult is returned as an error that wraps
// the status code: errors.Is(err, ua.StatusBadXxx) works.
func (c *Client) Send(ctx context.Context, req ua.Request) (ua.Response, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.RequestTimeout)
		defer cancel()
	}
	return c.send(ctx, req)
}

// send is Send without the default timeout.
func (c *Client) send(ctx context.Context, req ua.Request) (ua.Response, error) {
	h := req.Header()
	h.AuthenticationToken = c.authToken
	h.Timestamp = time.Now()
	h.RequestHandle = c.handle.Add(1)
	h.TimeoutHint = 0
	if d, ok := ctx.Deadline(); ok {
		h.TimeoutHint = uint32(max(time.Until(d), time.Millisecond) / time.Millisecond)
	}
	c.lastUse.Store(time.Now().UnixNano())
	msg, err := c.ch.Send(ctx, req)
	name := serviceName(req)
	if err != nil {
		return nil, fmt.Errorf("client: %s: %w", name, err)
	}
	resp, ok := msg.(ua.Response)
	if !ok {
		return nil, fmt.Errorf("client: %s: unexpected response %T", name, msg)
	}
	if st := resp.Header().ServiceResult; st.IsBad() {
		return resp, fmt.Errorf("client: %s: %w", name, st)
	}
	return resp, nil
}

func serviceName(req ua.Structure) string {
	return strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%T", req), "*ua."), "Request")
}

// call sends a request and checks the type of the response.
func call[T ua.Response](ctx context.Context, c *Client, req ua.Request) (T, error) {
	var zero T
	resp, err := c.Send(ctx, req)
	if err != nil {
		return zero, err
	}
	r, ok := resp.(T)
	if !ok {
		return zero, fmt.Errorf("client: %s: unexpected response %T", serviceName(req), resp)
	}
	return r, nil
}

// --- certificates ---

// applicationCredential returns the application certificate for a policy.
func (c *Client) applicationCredential(policy *uasc.SecurityPolicy) (*uasc.Credential, error) {
	cfg := &c.cfg
	if cfg.Certificate != nil && cfg.PrivateKey != nil {
		cred := &uasc.Credential{Certificate: cfg.Certificate, PrivateKey: cfg.PrivateKey}
		if certs, err := x509.ParseCertificates(cfg.Certificate); err == nil && len(certs) > 0 &&
			policy.CertificateKeyAllowed(certs[0].PublicKey) {
			return cred, nil
		}
		if !policy.IsECC() {
			return nil, fmt.Errorf("client: the configured certificate cannot be used with %s", policy.Name)
		}
		// An RSA certificate is configured; ECC policies need an ECC one.
	}
	hosts := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append([]string{h}, hosts...)
	}
	var der []byte
	var key crypto.Signer
	var err error
	curve := policy.CertCurve()
	switch {
	case cfg.PKIDir != "" && curve != nil:
		der, key, err = c.store().LoadOrCreateOwnECC(cfg.ApplicationURI, cfg.ApplicationName, hosts, curve)
	case cfg.PKIDir != "":
		der, key, err = c.store().LoadOrCreateOwn(cfg.ApplicationURI, cfg.ApplicationName, hosts)
	default:
		der, key, err = memoryCertificate(cfg.ApplicationURI, cfg.ApplicationName, hosts, curve)
	}
	if err != nil {
		return nil, fmt.Errorf("client: application certificate: %w", err)
	}
	return &uasc.Credential{Certificate: der, PrivateKey: key}, nil
}

// memoryCertificate creates (once per process, application URI and key
// type) a self-signed certificate that is not stored anywhere.
func memoryCertificate(appURI, appName string, hosts []string, curve elliptic.Curve) ([]byte, crypto.Signer, error) {
	name := "rsa"
	if curve != nil {
		name = curve.Params().Name
	}
	k := appURI + "|" + name
	memCertsMu.Lock()
	defer memCertsMu.Unlock()
	if c, ok := memCerts[k]; ok {
		return c.Certificate, c.PrivateKey, nil
	}
	var der []byte
	var key crypto.Signer
	var err error
	if curve != nil {
		der, key, err = uacert.CreateSelfSignedECC(appURI, appName, hosts, curve, 5*365*24*time.Hour)
	} else {
		der, key, err = uacert.CreateSelfSigned(appURI, appName, hosts, 2048, 5*365*24*time.Hour)
	}
	if err != nil {
		return nil, nil, err
	}
	memCerts[k] = &uasc.Credential{Certificate: der, PrivateKey: key}
	return der, key, nil
}

var (
	memCertsMu sync.Mutex
	memCerts   = map[string]*uasc.Credential{}
)

func (c *Client) store() *uacert.Store {
	return &uacert.Store{Root: c.cfg.PKIDir, AutoAccept: c.cfg.AutoAcceptUntrustedCertificates}
}

// verifyServerCertificate checks the endpoint's server certificate.
func (c *Client) verifyServerCertificate(ep ua.EndpointDescription) error {
	chain, err := x509.ParseCertificates(ep.ServerCertificate)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("client: the endpoint has no valid server certificate: %w", ua.StatusBadCertificateInvalid)
	}
	if uri := uacert.CertificateURI(chain[0]); ep.Server.ApplicationUri != "" && uri != ep.Server.ApplicationUri {
		return fmt.Errorf("client: server certificate URI %q does not match the application URI %q: %w",
			uri, ep.Server.ApplicationUri, ua.StatusBadCertificateUriInvalid)
	}
	switch {
	case c.cfg.VerifyServerCertificate != nil:
		err = c.cfg.VerifyServerCertificate(chain)
	case c.cfg.PKIDir != "":
		err = c.store().Validate(chain)
	case c.cfg.AutoAcceptUntrustedCertificates:
		err = nil
	default:
		err = errors.New("no trust list: set PKIDir, VerifyServerCertificate or AutoAcceptUntrustedCertificates")
	}
	if err != nil {
		return fmt.Errorf("client: server certificate %q (%s) is not trusted: %w",
			chain[0].Subject.CommonName, uacert.Thumbprint(chain[0].Raw), err)
	}
	return nil
}

// --- session ---

func (c *Client) createSession(ctx context.Context) error {
	policy := c.ch.SecurityPolicy()
	nonce := uasc.NewNonce(32)
	req := &ua.CreateSessionRequest{
		ClientDescription: ua.ApplicationDescription{
			ApplicationUri:  c.cfg.ApplicationURI,
			ProductUri:      c.cfg.ProductURI,
			ApplicationName: ua.NewLocalizedText(c.cfg.ApplicationName),
			ApplicationType: ua.ApplicationTypeClient,
		},
		EndpointUrl:             c.url,
		SessionName:             c.cfg.SessionName,
		ClientNonce:             nonce,
		RequestedSessionTimeout: float64(c.cfg.SessionTimeout / time.Millisecond),
		MaxResponseMessageSize:  c.cfg.Limits.MaxMessageSize,
	}
	if c.local != nil {
		req.ClientCertificate = c.local.Certificate
		// The server checks that the description matches the certificate.
		if certs, err := x509.ParseCertificates(c.local.Certificate); err == nil {
			if uri := uacert.CertificateURI(certs[0]); uri != "" {
				req.ClientDescription.ApplicationUri = uri
			}
		}
	}
	resp, err := call[*ua.CreateSessionResponse](ctx, c, req)
	if err != nil {
		return err
	}
	c.sessionID = resp.SessionId
	c.authToken = resp.AuthenticationToken
	c.sessionTimeout = time.Duration(resp.RevisedSessionTimeout * float64(time.Millisecond))
	c.serverNonce = resp.ServerNonce
	c.serverCert = resp.ServerCertificate
	c.maxRequestSize = resp.MaxRequestMessageSize

	if !policy.IsNone() {
		if !sameLeaf(resp.ServerCertificate, c.endpoint.ServerCertificate) {
			return fmt.Errorf("client: CreateSession returned a different server certificate: %w", ua.StatusBadCertificateInvalid)
		}
		if len(resp.ServerNonce) < 32 {
			return fmt.Errorf("client: server nonce too short: %w", ua.StatusBadNonceInvalid)
		}
		data := append(append([]byte{}, leaf(c.local.Certificate)...), nonce...)
		pub := c.ch.RemoteCertificate().PublicKey
		if resp.ServerSignature.Algorithm != policy.AsymSignatureAlgorithm ||
			policy.AsymVerify(pub, data, resp.ServerSignature.Signature) != nil {
			return fmt.Errorf("client: invalid server signature: %w", ua.StatusBadApplicationSignatureInvalid)
		}
	}
	// The endpoints must match those returned by GetEndpoints (Part 4, 5.6.2.2).
	found := len(resp.ServerEndpoints) == 0
	for _, ep := range resp.ServerEndpoints {
		if ep.SecurityPolicyUri == c.endpoint.SecurityPolicyUri && ep.SecurityMode == c.endpoint.SecurityMode &&
			sameLeaf(ep.ServerCertificate, c.endpoint.ServerCertificate) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("client: the server endpoints changed between GetEndpoints and CreateSession: %w",
			ua.StatusBadSecurityChecksFailed)
	}
	return nil
}

func (c *Client) activateSession(ctx context.Context) error {
	policy := c.ch.SecurityPolicy()
	c.mu.Lock()
	serverNonce := c.serverNonce
	c.mu.Unlock()
	req := &ua.ActivateSessionRequest{LocaleIds: c.cfg.LocaleIDs}
	if !policy.IsNone() {
		data := append(append([]byte{}, leaf(c.serverCert)...), serverNonce...)
		sig, err := policy.AsymSign(c.local.PrivateKey, data)
		if err != nil {
			return fmt.Errorf("client: signing ActivateSession: %w", err)
		}
		req.ClientSignature = ua.SignatureData{Algorithm: policy.AsymSignatureAlgorithm, Signature: sig}
	}
	tok, tokSig, err := c.cfg.Identity.token(c, serverNonce)
	if err != nil {
		return err
	}
	req.UserIdentityToken = tok
	req.UserTokenSignature = tokSig
	resp, err := call[*ua.ActivateSessionResponse](ctx, c, req)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.serverNonce = resp.ServerNonce
	c.mu.Unlock()
	return nil
}

// leaf returns the first certificate of a DER chain.
func leaf(der []byte) []byte {
	if certs, err := x509.ParseCertificates(der); err == nil && len(certs) > 0 {
		return certs[0].Raw
	}
	return der
}

func sameLeaf(a, b []byte) bool { return string(leaf(a)) == string(leaf(b)) }
