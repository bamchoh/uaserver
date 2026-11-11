// Package server implements an OPC UA server (opc.tcp, UA Binary) with
// secure channels, sessions, the standard address space and the
// Discovery, Session, View, Attribute, Method, MonitoredItem and
// Subscription service sets.
package server

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/uacp"
	"github.com/bamchoh/uastack/uasc"
)

// UserTokenType selects the user identity tokens offered by the server.
type UserTokenType int

const (
	UserTokenAnonymous UserTokenType = iota
	UserTokenUserName
	UserTokenCertificate
)

// SecurityConfig enables a security policy with a set of modes.
type SecurityConfig struct {
	PolicyURI string
	Modes     []ua.MessageSecurityMode
}

// Identity describes the user of a session.
type Identity struct {
	Type        UserTokenType
	UserName    string
	Certificate *x509.Certificate

	eccKeyUsed bool // the password was encrypted for the session's ephemeral key
}

// Config configures a Server.
type Config struct {
	ApplicationURI   string
	ApplicationName  string
	ProductURI       string
	ManufacturerName string
	ProductName      string
	SoftwareVersion  string
	BuildNumber      string

	// ListenAddr is the TCP listen address, e.g. ":4840".
	ListenAddr string
	// EndpointURL is the advertised URL, e.g. "opc.tcp://myhost:4840".
	EndpointURL string
	// Hostnames are put into the generated certificate.
	Hostnames []string

	Security   []SecurityConfig
	UserTokens []UserTokenType
	// AuthenticateUser validates user name tokens. If nil, user name tokens are rejected.
	AuthenticateUser func(user, password string) bool
	// AuthenticateCertificate validates X509 user tokens after the certificate
	// has been checked against the trust list. If nil, all trusted certificates are accepted.
	AuthenticateCertificate func(cert *x509.Certificate) bool

	// PKIDir is the root of the certificate store (default "pki").
	PKIDir string
	// AutoAcceptUntrustedCertificates trusts all client certificates (testing only).
	AutoAcceptUntrustedCertificates bool

	MaxSessions          int
	MaxSessionTimeout    time.Duration
	MinSessionTimeout    time.Duration
	MaxSubscriptions     int // per session
	MaxMonitoredItems    int // per subscription
	MaxOperationsPerCall int
	MaxContinuationPts   int
	// MinPublishingInterval is the shortest publishing interval granted to a
	// subscription (default 10 ms).
	MinPublishingInterval time.Duration
	// MinSamplingInterval is the polling interval for values whose changes
	// cannot be observed: variables with OnRead and attributes other than
	// Value (default 50 ms). Values stored with SetValue or written by
	// clients are reported as soon as they change.
	MinSamplingInterval time.Duration

	Logger *log.Logger
}

func (c *Config) setDefaults() {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	if c.ApplicationName == "" {
		c.ApplicationName = "Go OPC UA Server"
	}
	if c.ApplicationURI == "" {
		c.ApplicationURI = "urn:" + host + ":opcuasrv"
	}
	if c.ProductURI == "" {
		c.ProductURI = "urn:opcuasrv"
	}
	if c.ManufacturerName == "" {
		c.ManufacturerName = "opcuasrv"
	}
	if c.ProductName == "" {
		c.ProductName = c.ApplicationName
	}
	if c.SoftwareVersion == "" {
		c.SoftwareVersion = "0.1.0"
	}
	if c.BuildNumber == "" {
		c.BuildNumber = "1"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":4840"
	}
	if c.EndpointURL == "" {
		_, port, _ := net.SplitHostPort(c.ListenAddr)
		if port == "" {
			port = "4840"
		}
		c.EndpointURL = "opc.tcp://" + host + ":" + port
	}
	if len(c.Hostnames) == 0 {
		c.Hostnames = []string{host, "localhost", "127.0.0.1"}
		if u, err := url.Parse(c.EndpointURL); err == nil && u.Hostname() != host {
			c.Hostnames = append(c.Hostnames, u.Hostname())
		}
	}
	if len(c.Security) == 0 {
		c.Security = []SecurityConfig{{PolicyURI: uasc.SecurityPolicyNone, Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeNone}}}
	}
	if len(c.UserTokens) == 0 {
		c.UserTokens = []UserTokenType{UserTokenAnonymous}
	}
	if c.PKIDir == "" {
		c.PKIDir = "pki"
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 100
	}
	if c.MaxSessionTimeout == 0 {
		c.MaxSessionTimeout = time.Hour
	}
	if c.MinSessionTimeout == 0 {
		c.MinSessionTimeout = 10 * time.Second
	}
	if c.MaxSubscriptions == 0 {
		c.MaxSubscriptions = 100
	}
	if c.MaxMonitoredItems == 0 {
		c.MaxMonitoredItems = 10000
	}
	if c.MaxOperationsPerCall == 0 {
		c.MaxOperationsPerCall = 10000
	}
	if c.MaxContinuationPts == 0 {
		c.MaxContinuationPts = 10
	}
	if c.MinPublishingInterval == 0 {
		c.MinPublishingInterval = 10 * time.Millisecond
	}
	if c.MinSamplingInterval == 0 {
		c.MinSamplingInterval = 50 * time.Millisecond
	}
	if c.Logger == nil {
		c.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
}

// Server is an OPC UA server.
type Server struct {
	cfg Config
	as  *AddressSpace
	pki *CertificateStore
	// rsaCred is the RSA application certificate (RSA policies, user token
	// encryption). eccCreds holds the ECC certificates by ECC policy URI.
	rsaCred   *uasc.Credential
	eccCreds  map[string]*uasc.Credential
	endpoints []ua.EndpointDescription
	chCfg     *uasc.Config
	startTime time.Time

	nextChannelID atomic.Uint32
	nextSubID     atomic.Uint32

	mu       sync.Mutex
	ln       net.Listener
	channels map[uint32]*uasc.Channel
	sessions *sessionManager
	monitors *monitorIndex
	closed   chan struct{}
	wg       sync.WaitGroup
	state    atomic.Int32
}

// New creates a server: it loads (or creates) the application certificate and
// builds the standard address space.
func New(cfg Config) (*Server, error) {
	cfg.setDefaults()
	s := &Server{
		cfg: cfg, channels: map[uint32]*uasc.Channel{}, closed: make(chan struct{}),
		startTime: time.Now(),
		pki:       &CertificateStore{Root: cfg.PKIDir, AutoAccept: cfg.AutoAcceptUntrustedCertificates},
	}
	s.nextChannelID.Store(uint32(time.Now().Unix() & 0xFFFF))
	needRSA := false
	s.eccCreds = map[string]*uasc.Credential{}
	for _, sc := range cfg.Security {
		p := uasc.PolicyByURI(sc.PolicyURI)
		if p == nil {
			return nil, fmt.Errorf("server: unsupported security policy %s", sc.PolicyURI)
		}
		switch {
		case p.IsECC():
			der, key, err := s.pki.LoadOrCreateOwnECC(cfg.ApplicationURI, cfg.ApplicationName, cfg.Hostnames, p.CertCurve())
			if err != nil {
				return nil, fmt.Errorf("server: ECC certificate: %w", err)
			}
			s.eccCreds[p.URI] = &uasc.Credential{Certificate: der, PrivateKey: key}
		case !p.IsNone():
			needRSA = true
		}
	}
	for _, t := range cfg.UserTokens {
		if t != UserTokenAnonymous {
			needRSA = true // user tokens are secured with the RSA certificate
		}
	}
	if needRSA {
		der, key, err := s.pki.LoadOrCreateOwn(cfg.ApplicationURI, cfg.ApplicationName, cfg.Hostnames)
		if err != nil {
			return nil, fmt.Errorf("server: certificate: %w", err)
		}
		s.rsaCred = &uasc.Credential{Certificate: der, PrivateKey: key}
	}
	s.as = newAddressSpace(cfg.ApplicationURI)
	s.monitors = newMonitorIndex()
	s.as.onChange = s.valueChanged
	if err := loadNS0(s.as); err != nil {
		return nil, err
	}
	s.setupServerObject()
	s.endpoints = s.buildEndpoints()
	s.sessions = newSessionManager(s)
	s.chCfg = &uasc.Config{
		Credentials:       s.credential,
		IsAllowed:         s.isAllowed,
		VerifyCertificate: s.pki.Validate,
		MinTokenLifetime:  10_000,
		MaxTokenLifetime:  3_600_000,
		Logf:              s.logf,
	}
	return s, nil
}

// AddressSpace returns the server address space.
func (s *Server) AddressSpace() *AddressSpace { return s.as }

// CertificateStore returns the PKI store.
func (s *Server) CertificateStore() *CertificateStore { return s.pki }

// Endpoints returns the endpoint descriptions.
func (s *Server) Endpoints() []ua.EndpointDescription { return s.endpoints }

// Config returns the effective configuration.
func (s *Server) Config() Config { return s.cfg }

func (s *Server) logf(format string, args ...any) { s.cfg.Logger.Printf(format, args...) }

// credential returns the certificate and key used with a security policy.
// The None policy uses the RSA certificate (it secures user tokens).
func (s *Server) credential(policyURI string) *uasc.Credential {
	if p := uasc.PolicyByURI(policyURI); p != nil && p.IsECC() {
		return s.eccCreds[policyURI]
	}
	return s.rsaCred
}

// serverCertificate returns the DER certificate advertised for a policy.
func (s *Server) serverCertificate(policyURI string) []byte {
	if c := s.credential(policyURI); c != nil {
		return c.Certificate
	}
	return nil
}

// rsaKey returns the RSA private key, or nil.
func (s *Server) rsaKey() *rsa.PrivateKey {
	if s.rsaCred == nil {
		return nil
	}
	k, _ := s.rsaCred.PrivateKey.(*rsa.PrivateKey)
	return k
}

func (s *Server) isAllowed(policy string, mode ua.MessageSecurityMode) bool {
	for _, sc := range s.cfg.Security {
		if sc.PolicyURI != policy {
			continue
		}
		for _, m := range sc.Modes {
			if m == mode {
				return true
			}
		}
	}
	return false
}

func (s *Server) applicationDescription() ua.ApplicationDescription {
	return ua.ApplicationDescription{
		ApplicationUri:  s.cfg.ApplicationURI,
		ProductUri:      s.cfg.ProductURI,
		ApplicationName: ua.NewLocalizedText(s.cfg.ApplicationName),
		ApplicationType: ua.ApplicationTypeServer,
		DiscoveryUrls:   []string{s.cfg.EndpointURL},
	}
}

func (s *Server) buildEndpoints() []ua.EndpointDescription {
	var eps []ua.EndpointDescription
	// The strongest RSA policy offered secures user tokens on None and ECC
	// endpoints (user tokens are encrypted/signed with RSA algorithms).
	strongest := ""
	best := byte(0)
	for _, sc := range s.cfg.Security {
		if p := uasc.PolicyByURI(sc.PolicyURI); !p.IsNone() && !p.IsECC() && p.SecurityLevel >= best {
			strongest, best = p.URI, p.SecurityLevel
		}
	}
	if strongest == "" && s.rsaCred != nil {
		strongest = uasc.SecurityPolicyBasic256Sha256
	}
	for _, sc := range s.cfg.Security {
		p := uasc.PolicyByURI(sc.PolicyURI)
		for _, m := range sc.Modes {
			var tokens []ua.UserTokenPolicy
			for _, t := range s.cfg.UserTokens {
				if tp, ok := s.userTokenPolicy(t, p, strongest); ok {
					tokens = append(tokens, tp)
				}
			}
			ep := ua.EndpointDescription{
				EndpointUrl:         s.cfg.EndpointURL,
				Server:              s.applicationDescription(),
				SecurityMode:        m,
				SecurityPolicyUri:   p.URI,
				UserIdentityTokens:  tokens,
				TransportProfileUri: uasc.TransportProfileUaTcp,
				SecurityLevel:       uasc.SecurityLevel(p.URI, m),
			}
			ep.ServerCertificate = s.serverCertificate(p.URI)
			eps = append(eps, ep)
		}
	}
	return eps
}

// userTokenPolicy returns the user token policy offered on an endpoint. It
// returns false if the token type cannot be offered on the endpoint.
func (s *Server) userTokenPolicy(t UserTokenType, channelPolicy *uasc.SecurityPolicy, strongest string) (ua.UserTokenPolicy, bool) {
	if t == UserTokenAnonymous {
		return ua.UserTokenPolicy{PolicyId: "Anonymous", TokenType: ua.UserTokenTypeAnonymous}, true
	}
	tokenPolicy := ""
	suffix := ""
	if channelPolicy.IsECC() {
		// User tokens use the channel's ECC policy (clients only pick token
		// policies of the same key family): passwords are sent as an
		// EccEncryptedSecret and user certificates must be ECC.
	} else if channelPolicy.IsNone() {
		tokenPolicy = strongest
		suffix = "_" + uasc.PolicyByURI(strongest).Name
	}
	switch t {
	case UserTokenUserName:
		return ua.UserTokenPolicy{PolicyId: "UserName" + suffix, TokenType: ua.UserTokenTypeUserName, SecurityPolicyUri: tokenPolicy}, true
	case UserTokenCertificate:
		return ua.UserTokenPolicy{PolicyId: "Certificate" + suffix, TokenType: ua.UserTokenTypeCertificate, SecurityPolicyUri: tokenPolicy}, true
	}
	return ua.UserTokenPolicy{}, false
}

// ListenAndServe starts listening and serves until Close is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln. It returns nil after Close, including
// when Close was called before Serve; ln is closed in that case.
func (s *Server) Serve(ln net.Listener) error {
	// Register ln under the lock that Close holds while closing s.ln, so a
	// Close that happens before or during this call always stops the loop.
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	default:
	}
	s.ln = ln
	// Add before Close can reach wg.Wait (it takes s.mu first).
	s.wg.Add(1)
	s.mu.Unlock()
	s.logf("OPC UA server listening on %s (%s)", ln.Addr(), s.cfg.EndpointURL)
	for _, ep := range s.endpoints {
		s.logf("  endpoint: %s [%s, %s]", ep.EndpointUrl, uasc.PolicyByURI(ep.SecurityPolicyUri).Name, ep.SecurityMode)
	}
	go s.sessions.run()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(c)
		}()
	}
}

// Close stops the server, closing all channels and sessions.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
	}
	close(s.closed)
	s.mu.Lock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	chans := make([]*uasc.Channel, 0, len(s.channels))
	for _, c := range s.channels {
		chans = append(chans, c)
	}
	s.mu.Unlock()
	for _, c := range chans {
		c.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	uc, err := uacp.Accept(c, uacp.ServerLimits{
		ReceiveBufferSize: 65535, SendBufferSize: 65535, MaxMessageSize: 16 * 1024 * 1024, MaxChunkCount: 4096,
	}, 10*time.Second)
	if err != nil {
		return
	}
	id := s.nextChannelID.Add(1)
	ch := uasc.NewChannel(uc, id, s.chCfg)
	s.mu.Lock()
	s.channels[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.channels, id)
		s.mu.Unlock()
		s.sessions.channelClosed(ch)
	}()
	err = ch.Serve(func(req uasc.Request) {
		go s.dispatch(ch, req)
	})
	if err != nil {
		s.logf("channel %d (%s): %v", id, c.RemoteAddr(), err)
	}
}

func requestHeaderOf(s ua.Structure) *ua.RequestHeader {
	if r, ok := s.(ua.Request); ok {
		return r.Header()
	}
	return nil
}

func respHeader(req *ua.RequestHeader, status ua.StatusCode) ua.ResponseHeader {
	h := ua.ResponseHeader{Timestamp: time.Now(), ServiceResult: status}
	if req != nil {
		h.RequestHandle = req.RequestHandle
	}
	return h
}

func fault(req *ua.RequestHeader, status ua.StatusCode) ua.Structure {
	return &ua.ServiceFault{ResponseHeader: respHeader(req, status)}
}

func (s *Server) send(ch *uasc.Channel, reqID uint32, hdr *ua.RequestHeader, resp ua.Structure) {
	if resp == nil {
		return
	}
	err := ch.SendResponse(reqID, resp)
	if errors.Is(err, uasc.ErrResponseTooLarge) {
		err = ch.SendResponse(reqID, fault(hdr, ua.StatusBadResponseTooLarge))
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		s.logf("channel %d: send: %v", ch.ID(), err)
	}
}

func (s *Server) dispatch(ch *uasc.Channel, req uasc.Request) {
	hdr := requestHeaderOf(req.Body)
	defer func() {
		if r := recover(); r != nil {
			s.logf("panic while handling %T: %v", req.Body, r)
			s.send(ch, req.RequestID, hdr, fault(hdr, ua.StatusBadInternalError))
		}
	}()

	// Services that do not require a session.
	switch r := req.Body.(type) {
	case *ua.GetEndpointsRequest:
		s.send(ch, req.RequestID, hdr, s.getEndpoints(r))
		return
	case *ua.FindServersRequest:
		s.send(ch, req.RequestID, hdr, s.findServers(r))
		return
	case *ua.FindServersOnNetworkRequest:
		s.send(ch, req.RequestID, hdr, &ua.FindServersOnNetworkResponse{ResponseHeader: respHeader(hdr, 0), LastCounterResetTime: s.startTime})
		return
	case *ua.CreateSessionRequest:
		s.send(ch, req.RequestID, hdr, s.sessions.createSession(ch, r))
		return
	case *ua.ActivateSessionRequest:
		s.send(ch, req.RequestID, hdr, s.sessions.activateSession(ch, r))
		return
	}
	if hdr == nil {
		s.send(ch, req.RequestID, hdr, fault(hdr, ua.StatusBadServiceUnsupported))
		return
	}
	sess, status := s.sessions.lookup(ch, hdr.AuthenticationToken, req.Body)
	if status != 0 {
		s.send(ch, req.RequestID, hdr, fault(hdr, status))
		return
	}

	var resp ua.Structure
	switch r := req.Body.(type) {
	case *ua.CloseSessionRequest:
		s.sessions.closeSession(sess, r.DeleteSubscriptions)
		resp = &ua.CloseSessionResponse{ResponseHeader: respHeader(hdr, 0)}
	case *ua.CancelRequest:
		resp = &ua.CancelResponse{ResponseHeader: respHeader(hdr, 0)}
	case *ua.BrowseRequest:
		resp = s.browse(sess, r)
	case *ua.BrowseNextRequest:
		resp = s.browseNext(sess, r)
	case *ua.TranslateBrowsePathsToNodeIdsRequest:
		resp = s.translateBrowsePaths(sess, r)
	case *ua.RegisterNodesRequest:
		resp = s.registerNodes(r)
	case *ua.UnregisterNodesRequest:
		resp = s.unregisterNodes(r)
	case *ua.ReadRequest:
		resp = s.read(sess, r)
	case *ua.WriteRequest:
		resp = s.write(sess, r)
	case *ua.CallRequest:
		resp = s.call(sess, r)
	case *ua.CreateSubscriptionRequest:
		resp = s.createSubscription(sess, r)
	case *ua.ModifySubscriptionRequest:
		resp = s.modifySubscription(sess, r)
	case *ua.SetPublishingModeRequest:
		resp = s.setPublishingMode(sess, r)
	case *ua.DeleteSubscriptionsRequest:
		resp = s.deleteSubscriptions(sess, r)
	case *ua.TransferSubscriptionsRequest:
		resp = s.transferSubscriptions(sess, r)
	case *ua.CreateMonitoredItemsRequest:
		resp = s.createMonitoredItems(sess, r)
	case *ua.ModifyMonitoredItemsRequest:
		resp = s.modifyMonitoredItems(sess, r)
	case *ua.SetMonitoringModeRequest:
		resp = s.setMonitoringMode(sess, r)
	case *ua.DeleteMonitoredItemsRequest:
		resp = s.deleteMonitoredItems(sess, r)
	case *ua.RepublishRequest:
		resp = s.republish(sess, r)
	case *ua.PublishRequest:
		// Publish responses are sent asynchronously by the subscription engine.
		sess.queuePublish(ch, req.RequestID, r)
		return
	default:
		resp = fault(hdr, ua.StatusBadServiceUnsupported)
	}
	s.send(ch, req.RequestID, hdr, resp)
}

// --- discovery services ---

// endpointsFor returns the endpoint descriptions with the host part of the
// URL replaced by the host the client used to reach the server.
func (s *Server) endpointsFor(requestURL string) []ua.EndpointDescription {
	eps := make([]ua.EndpointDescription, len(s.endpoints))
	copy(eps, s.endpoints)
	ru, err := url.Parse(requestURL)
	if err != nil || ru.Hostname() == "" {
		return eps
	}
	for i := range eps {
		eu, err := url.Parse(eps[i].EndpointUrl)
		if err != nil {
			continue
		}
		if !strings.EqualFold(eu.Hostname(), ru.Hostname()) {
			eu.Host = net.JoinHostPort(ru.Hostname(), eu.Port())
			eps[i].EndpointUrl = eu.String()
			srv := eps[i].Server
			srv.DiscoveryUrls = []string{eu.String()}
			eps[i].Server = srv
		}
	}
	return eps
}

func (s *Server) getEndpoints(r *ua.GetEndpointsRequest) ua.Structure {
	eps := s.endpointsFor(r.EndpointUrl)
	if len(r.ProfileUris) > 0 {
		ok := false
		for _, p := range r.ProfileUris {
			if p == uasc.TransportProfileUaTcp {
				ok = true
			}
		}
		if !ok {
			eps = []ua.EndpointDescription{}
		}
	}
	return &ua.GetEndpointsResponse{ResponseHeader: respHeader(&r.RequestHeader, 0), Endpoints: eps}
}

func (s *Server) findServers(r *ua.FindServersRequest) ua.Structure {
	app := s.applicationDescription()
	if eps := s.endpointsFor(r.EndpointUrl); len(eps) > 0 {
		app.DiscoveryUrls = []string{eps[0].EndpointUrl}
	}
	servers := []ua.ApplicationDescription{app}
	if len(r.ServerUris) > 0 {
		found := false
		for _, u := range r.ServerUris {
			if u == s.cfg.ApplicationURI {
				found = true
			}
		}
		if !found {
			servers = []ua.ApplicationDescription{}
		}
	}
	return &ua.FindServersResponse{ResponseHeader: respHeader(&r.RequestHeader, 0), Servers: servers}
}
