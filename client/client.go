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
	// AutoReconnect reconnects when the connection is lost: the session is
	// activated on a new secure channel, or recreated (with its
	// subscriptions and monitored items) if the server has dropped it.
	// Without it, the client is closed when the connection is lost.
	AutoReconnect bool
	// ReconnectInterval is the first delay before reconnecting (default
	// 500 ms); it doubles after each failed attempt up to MaxReconnectInterval
	// (default 30 s).
	ReconnectInterval    time.Duration
	MaxReconnectInterval time.Duration
	// OnStateChange is called when the connection state changes, with the
	// error that caused the change (nil when connected). It is called from
	// the client's own goroutine and must not block for long.
	OnStateChange func(state ConnState, err error)
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
	if c.ReconnectInterval <= 0 {
		c.ReconnectInterval = 500 * time.Millisecond
	}
	if c.MaxReconnectInterval <= 0 {
		c.MaxReconnectInterval = 30 * time.Second
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
	policy   *uasc.SecurityPolicy
	local    *uasc.Credential // application certificate used on the channel
	// endpointFromSession: endpoint is taken from the first CreateSession response.
	endpointFromSession bool

	// Connection state. ready is closed while a channel with an activated
	// session is installed; it is replaced by an open channel while
	// reconnecting.
	chMu    sync.Mutex
	ch      *uasc.ClientChannel
	ready   chan struct{}
	state   ConnState
	lastErr error

	mu             sync.Mutex // session state
	sessionID      ua.NodeId
	authToken      ua.NodeId
	sessionTimeout time.Duration
	serverCert     []byte // from CreateSession
	serverNonce    []byte
	// eccKey is the server's ephemeral key (nonce form) for encrypting
	// passwords with an ECC user token policy, if one was requested.
	eccKey []byte

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
	if cfg.SecurityPolicy == uasc.SecurityPolicyNone && cfg.SecurityMode == ua.MessageSecurityModeNone {
		// No server certificate to check: take the endpoint description from
		// the CreateSession response and save the GetEndpoints round trip.
		return dial(ctx, endpointURL, ua.EndpointDescription{
			EndpointUrl: endpointURL, SecurityPolicyUri: uasc.SecurityPolicyNone, SecurityMode: ua.MessageSecurityModeNone,
		}, cfg, true)
	}
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
	return dial(ctx, endpointURL, ep, cfg, false)
}

// dial connects to an endpoint. With fromSession, ep is a placeholder for
// the None endpoint and is replaced by the description from CreateSession.
func dial(ctx context.Context, endpointURL string, ep ua.EndpointDescription, cfg Config, fromSession bool) (*Client, error) {
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

	c := &Client{cfg: cfg, url: endpointURL, endpoint: ep, policy: policy, closed: make(chan struct{}), endpointFromSession: fromSession}
	c.subs = newSubscriptions(c)
	if !policy.IsNone() {
		local, err := c.applicationCredential(policy)
		if err != nil {
			return nil, err
		}
		if err := c.verifyServerCertificate(ep); err != nil {
			return nil, err
		}
		c.local = local
	}
	ch, err := c.openChannel(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.createSession(ctx, ch); err != nil {
		_ = ch.Close()
		return nil, err
	}
	if err := c.activateSession(ctx, ch); err != nil {
		c.closeSession(ctx, ch)
		_ = ch.Close()
		return nil, err
	}
	c.ch = ch
	c.ready = make(chan struct{})
	close(c.ready)
	c.state = StateConnected
	go c.supervise(ch)
	if cfg.KeepAliveInterval >= 0 {
		go c.keepAlive()
	}
	return c, nil
}

// dropChannel closes the current channel, so that the connection is
// restored (with AutoReconnect) or reported as lost.
func (c *Client) dropChannel() {
	c.chMu.Lock()
	ch, state := c.ch, c.state
	c.chMu.Unlock()
	if state == StateConnected {
		_ = ch.Close()
	}
}

// openChannel connects and opens a secure channel to the endpoint.
func (c *Client) openChannel(ctx context.Context) (*uasc.ClientChannel, error) {
	chCfg := uasc.ClientConfig{
		SecurityPolicyURI: c.policy.URI, SecurityMode: c.endpoint.SecurityMode, Lifetime: c.cfg.ChannelLifetime,
		Logf: c.cfg.Logger.Printf,
	}
	if !c.policy.IsNone() {
		chCfg.Local = c.local
		chCfg.RemoteCertificate = c.endpoint.ServerCertificate
	}
	conn, err := uacp.Dial(ctx, c.url, c.cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	ch, err := uasc.OpenClientChannel(ctx, conn, chCfg)
	if err != nil {
		return nil, fmt.Errorf("client: opening the secure channel: %w", err)
	}
	return ch, nil
}

// Endpoint returns the endpoint the client is connected to.
func (c *Client) Endpoint() ua.EndpointDescription { return c.endpoint }

// SessionID returns the id of the session. It changes when the session is
// recreated after a reconnect.
func (c *Client) SessionID() ua.NodeId {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// SessionTimeout returns the session timeout granted by the server.
func (c *Client) SessionTimeout() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionTimeout
}

// Done is closed when the client is closed, or when its connection is lost
// and AutoReconnect is off.
func (c *Client) Done() <-chan struct{} { return c.closed }

// Err returns why the client was closed (ErrClosed after Close), or nil
// while it is open.
func (c *Client) Err() error {
	select {
	case <-c.closed:
		c.chMu.Lock()
		defer c.chMu.Unlock()
		if c.lastErr != nil {
			return c.lastErr
		}
		return uasc.ErrChannelClosed
	default:
		return nil
	}
}

// ConnState is the state of the connection.
type ConnState int

const (
	// StateConnected: a secure channel with an activated session is open.
	StateConnected ConnState = iota
	// StateReconnecting: the connection was lost and AutoReconnect is trying
	// to restore it. Requests wait until it is restored or their context ends.
	StateReconnecting
	// StateClosed: the client was closed, or the connection was lost
	// without AutoReconnect.
	StateClosed
)

func (s ConnState) String() string {
	switch s {
	case StateConnected:
		return "Connected"
	case StateReconnecting:
		return "Reconnecting"
	}
	return "Closed"
}

// State returns the connection state.
func (c *Client) State() ConnState {
	c.chMu.Lock()
	defer c.chMu.Unlock()
	return c.state
}

// setState records a state change and reports it.
func (c *Client) setState(state ConnState, err error) {
	c.chMu.Lock()
	changed := c.state != state
	c.state = state
	if err != nil {
		c.lastErr = err
	}
	c.chMu.Unlock()
	if changed && c.cfg.OnStateChange != nil {
		c.cfg.OnStateChange(state, err)
	}
}

// channel returns the current channel, waiting while reconnecting.
func (c *Client) channel(ctx context.Context) (*uasc.ClientChannel, error) {
	for {
		c.chMu.Lock()
		ch, ready := c.ch, c.ready
		c.chMu.Unlock()
		select {
		case <-ready:
			return ch, nil
		default:
		}
		select {
		case <-ready:
		case <-c.closed:
			return nil, c.Err()
		case <-ctx.Done():
			return nil, fmt.Errorf("client: not connected: %w", ctx.Err())
		}
	}
}

func (c *Client) logf(format string, args ...any) { c.cfg.Logger.Printf(format, args...) }

// Close closes the session (deleting its subscriptions) and the secure channel.
func (c *Client) Close(ctx context.Context) error {
	var err error
	c.closeOnce.Do(func() {
		c.chMu.Lock()
		ch, state := c.ch, c.state
		c.chMu.Unlock()
		if state == StateConnected {
			select {
			case <-ch.Done():
			default:
				c.closeSession(ctx, ch)
				err = ch.Close()
			}
		}
		c.subs.shutdown(ErrClosed)
		c.chMu.Lock()
		c.lastErr = ErrClosed
		c.chMu.Unlock()
		close(c.closed)
		c.setState(StateClosed, ErrClosed)
	})
	return err
}

// ErrClosed is the error delivered to subscriptions when the client is closed.
var ErrClosed = errors.New("client: closed")

func (c *Client) closeSession(ctx context.Context, ch *uasc.ClientChannel) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if _, err := c.sendOn(ctx, ch, &ua.CloseSessionRequest{DeleteSubscriptions: true}); err != nil {
		c.logf("client: CloseSession: %v", err)
	}
}

// supervise waits for the channel to be lost, then reconnects or closes the client.
func (c *Client) supervise(ch *uasc.ClientChannel) {
	for {
		select {
		case <-c.closed:
			return
		case <-ch.Done():
		}
		err := ch.Err()
		if err == nil || errors.Is(err, uasc.ErrChannelClosed) {
			err = uasc.ErrChannelClosed
		}
		c.logf("client: connection lost: %v", err)
		if !c.cfg.AutoReconnect {
			c.closeOnce.Do(func() {
				c.subs.shutdown(err)
				c.chMu.Lock()
				c.lastErr = err
				c.chMu.Unlock()
				close(c.closed)
				c.setState(StateClosed, err)
			})
			return
		}
		c.chMu.Lock()
		c.ready = make(chan struct{})
		c.chMu.Unlock()
		c.setState(StateReconnecting, err)
		if ch = c.reconnect(); ch == nil {
			return // closed
		}
	}
}

// reconnect restores the connection, retrying with backoff until it works or
// the client is closed. It returns the new channel, or nil if closed.
func (c *Client) reconnect() *uasc.ClientChannel {
	delay := c.cfg.ReconnectInterval
	for {
		t := time.NewTimer(delay)
		select {
		case <-c.closed:
			t.Stop()
			return nil
		case <-t.C:
		}
		delay = min(delay*2, c.cfg.MaxReconnectInterval)

		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		ch, recreated, err := c.restoreSession(ctx)
		cancel()
		if err != nil {
			c.logf("client: reconnect: %v", err)
			continue
		}
		c.chMu.Lock()
		select {
		case <-c.closed:
			c.chMu.Unlock()
			_ = ch.Close()
			return nil
		default:
		}
		c.ch = ch
		close(c.ready)
		c.chMu.Unlock()
		c.logf("client: reconnected (session recreated: %v)", recreated)
		c.setState(StateConnected, nil)
		ctx, cancel = context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		if recreated {
			c.subs.recreate(ctx)
		} else {
			c.subs.recover(ctx)
		}
		cancel()
		return ch
	}
}

// restoreSession opens a new channel and activates the session on it, or
// creates a new session if the server no longer knows the old one.
func (c *Client) restoreSession(ctx context.Context) (*uasc.ClientChannel, bool, error) {
	ch, err := c.openChannel(ctx)
	if err != nil {
		return nil, false, err
	}
	err = c.activateSession(ctx, ch)
	if err == nil {
		return ch, false, nil
	}
	if !errors.Is(err, ua.StatusBadSessionIdInvalid) && !errors.Is(err, ua.StatusBadSessionClosed) &&
		!errors.Is(err, ua.StatusBadSessionNotActivated) {
		_ = ch.Close()
		return nil, false, err
	}
	c.logf("client: the session is gone (%v); creating a new one", err)
	if err := c.createSession(ctx, ch); err != nil {
		_ = ch.Close()
		return nil, false, err
	}
	if err := c.activateSession(ctx, ch); err != nil {
		c.closeSession(ctx, ch)
		_ = ch.Close()
		return nil, false, err
	}
	return ch, true, nil
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
	failures := 0
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
		}
		if time.Since(time.Unix(0, c.lastUse.Load())) < interval {
			continue
		}
		c.chMu.Lock()
		ch, state := c.ch, c.state
		c.chMu.Unlock()
		if state != StateConnected {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		_, err := c.sendOn(ctx, ch, &ua.ReadRequest{NodesToRead: []ua.ReadValueId{{
			NodeId: ua.NewNumericNodeId(0, uaid.Server_ServerStatus_State), AttributeId: ua.AttributeIdValue,
		}}})
		cancel()
		if err == nil {
			failures = 0
			continue
		}
		c.logf("client: keep-alive: %v", err)
		// A server that stopped answering without closing the connection:
		// drop the channel so that it is reported (and maybe reconnected).
		if errors.Is(err, context.DeadlineExceeded) {
			if failures++; failures >= 2 {
				failures = 0
				_ = ch.Close()
			}
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
	ch, err := c.channel(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: %s: %w", serviceName(req), err)
	}
	return c.sendOn(ctx, ch, req)
}

// sendOn sends a request on a given channel.
func (c *Client) sendOn(ctx context.Context, ch *uasc.ClientChannel, req ua.Request) (ua.Response, error) {
	h := req.Header()
	c.mu.Lock()
	h.AuthenticationToken = c.authToken
	c.mu.Unlock()
	h.Timestamp = time.Now()
	h.RequestHandle = c.handle.Add(1)
	h.TimeoutHint = 0
	if d, ok := ctx.Deadline(); ok {
		h.TimeoutHint = uint32(max(time.Until(d), time.Millisecond) / time.Millisecond)
	}
	c.lastUse.Store(time.Now().UnixNano())
	msg, err := ch.Send(ctx, req)
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
	return callOn[T](ctx, c, nil, req)
}

// callOn is call on a given channel (nil: the current one).
func callOn[T ua.Response](ctx context.Context, c *Client, ch *uasc.ClientChannel, req ua.Request) (T, error) {
	var zero T
	var resp ua.Response
	var err error
	if ch == nil {
		resp, err = c.Send(ctx, req)
	} else {
		resp, err = c.sendOn(ctx, ch, req)
	}
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

func (c *Client) createSession(ctx context.Context, ch *uasc.ClientChannel) error {
	policy := c.policy
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
	req.RequestHeader.AdditionalHeader = c.ecdhRequest()
	if c.local != nil {
		req.ClientCertificate = c.local.Certificate
		// The server checks that the description matches the certificate.
		if certs, err := x509.ParseCertificates(c.local.Certificate); err == nil {
			if uri := uacert.CertificateURI(certs[0]); uri != "" {
				req.ClientDescription.ApplicationUri = uri
			}
		}
	}
	c.mu.Lock()
	c.authToken = ua.NodeId{} // CreateSession has no session yet
	c.mu.Unlock()
	resp, err := callOn[*ua.CreateSessionResponse](ctx, c, ch, req)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sessionID = resp.SessionId
	c.authToken = resp.AuthenticationToken
	c.sessionTimeout = time.Duration(resp.RevisedSessionTimeout * float64(time.Millisecond))
	c.serverNonce = resp.ServerNonce
	c.serverCert = resp.ServerCertificate
	c.mu.Unlock()
	if err := c.ecdhResponse(&resp.ResponseHeader); err != nil {
		return err
	}

	if !policy.IsNone() {
		if !sameLeaf(resp.ServerCertificate, c.endpoint.ServerCertificate) {
			return fmt.Errorf("client: CreateSession returned a different server certificate: %w", ua.StatusBadCertificateInvalid)
		}
		if len(resp.ServerNonce) < 32 {
			return fmt.Errorf("client: server nonce too short: %w", ua.StatusBadNonceInvalid)
		}
		data := append(append([]byte{}, leaf(c.local.Certificate)...), nonce...)
		pub := ch.RemoteCertificate().PublicKey
		if resp.ServerSignature.Algorithm != policy.AsymSignatureAlgorithm ||
			policy.AsymVerify(pub, data, resp.ServerSignature.Signature) != nil {
			return fmt.Errorf("client: invalid server signature: %w", ua.StatusBadApplicationSignatureInvalid)
		}
	}
	if c.endpointFromSession {
		c.endpointFromSession = false
		for _, ep := range resp.ServerEndpoints {
			if ep.SecurityPolicyUri == uasc.SecurityPolicyNone && ep.SecurityMode == ua.MessageSecurityModeNone {
				ep.EndpointUrl = c.url
				c.endpoint = ep
				return nil
			}
		}
		return fmt.Errorf("client: the server has no None endpoint: %w", ua.StatusBadSecurityPolicyRejected)
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

func (c *Client) activateSession(ctx context.Context, ch *uasc.ClientChannel) error {
	policy := c.policy
	c.mu.Lock()
	serverNonce, serverCert := c.serverNonce, c.serverCert
	c.mu.Unlock()
	req := &ua.ActivateSessionRequest{LocaleIds: c.cfg.LocaleIDs}
	req.RequestHeader.AdditionalHeader = c.ecdhRequest()
	if !policy.IsNone() {
		data := append(append([]byte{}, leaf(serverCert)...), serverNonce...)
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
	resp, err := callOn[*ua.ActivateSessionResponse](ctx, c, ch, req)
	if err != nil {
		return err
	}
	if err := c.ecdhResponse(&resp.ResponseHeader); err != nil {
		c.logf("client: %v", err) // only needed for a later activation
	}
	c.mu.Lock()
	c.serverNonce = resp.ServerNonce
	c.mu.Unlock()
	return nil
}

// ecdhPolicy returns the ECC policy that secures the user name token, or nil
// if the identity needs no ephemeral key.
func (c *Client) ecdhPolicy() *uasc.SecurityPolicy {
	if _, ok := c.cfg.Identity.(userName); !ok {
		return nil
	}
	p, err := c.tokenPolicy(ua.UserTokenTypeUserName)
	if err != nil {
		return nil
	}
	if sp := c.tokenSecurity(p); sp != nil && sp.IsECC() {
		return sp
	}
	return nil
}

// ecdhRequest returns the AdditionalHeader asking for an ephemeral key
// (Part 4, 7.41.2.3), or a null header if none is needed.
func (c *Client) ecdhRequest() ua.ExtensionObject {
	sp := c.ecdhPolicy()
	if sp == nil {
		return ua.ExtensionObject{}
	}
	return ua.NewAdditionalHeader(ua.KeyValuePair{
		Key: ua.NewQualifiedName(0, ua.AdditionalParameterECDHPolicyUri), Value: ua.NewVariant(sp.URI),
	})
}

// ecdhResponse stores the server's ephemeral key after checking its signature.
func (c *Client) ecdhResponse(h *ua.ResponseHeader) error {
	sp := c.ecdhPolicy()
	if sp == nil {
		return nil
	}
	v, ok := ua.AdditionalParameter(h.AdditionalHeader, ua.AdditionalParameterECDHKey)
	if !ok {
		return nil // keep the previous key
	}
	if st, ok := v.Value().(ua.StatusCode); ok {
		return fmt.Errorf("client: the server cannot provide an ephemeral key: %w", st)
	}
	eo, _ := v.Value().(ua.ExtensionObject)
	key, ok := eo.Value.(*ua.EphemeralKeyType)
	if !ok || len(key.PublicKey) == 0 {
		return fmt.Errorf("client: invalid ECDHKey from the server: %w", ua.StatusBadDecodingError)
	}
	c.mu.Lock()
	serverCert := c.serverCert
	c.mu.Unlock()
	cert, err := x509.ParseCertificate(leaf(serverCert))
	if err != nil || sp.AsymVerify(cert.PublicKey, key.PublicKey, key.Signature) != nil {
		return fmt.Errorf("client: invalid ECDHKey signature: %w", ua.StatusBadSecurityChecksFailed)
	}
	c.mu.Lock()
	c.eccKey = key.PublicKey
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
