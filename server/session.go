package server

import (
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"sync"
	"time"

	"opcuasrv/ua"
	"opcuasrv/uasc"
)

// Session is a client session.
type Session struct {
	srv       *Server
	ID        ua.NodeId
	authToken ua.NodeId
	Name      string
	Client    ua.ApplicationDescription
	timeout   time.Duration

	mu          sync.Mutex
	channel     *uasc.Channel
	clientCert  *x509.Certificate
	serverNonce []byte
	activated   bool
	closed      bool
	lastSeen    time.Time
	identity    Identity
	localeIDs   []string

	browseCPs map[string]*browseCP
	cpCounter uint64

	subs         map[uint32]*subscription
	publishQueue []*publishReq
}

// Identity returns the user identity of the session.
func (s *Session) Identity() Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identity
}

type sessionManager struct {
	srv      *Server
	mu       sync.Mutex
	byToken  map[ua.NodeId]*Session
	sessions map[ua.NodeId]*Session
}

func newSessionManager(s *Server) *sessionManager {
	return &sessionManager{srv: s, byToken: map[ua.NodeId]*Session{}, sessions: map[ua.NodeId]*Session{}}
}

// run expires sessions and publish requests.
func (m *sessionManager) run() {
	defer m.srv.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-m.srv.closed:
			m.mu.Lock()
			all := make([]*Session, 0, len(m.sessions))
			for _, s := range m.sessions {
				all = append(all, s)
			}
			m.mu.Unlock()
			for _, s := range all {
				m.closeSession(s, true)
			}
			return
		case now := <-t.C:
			m.mu.Lock()
			var expired []*Session
			all := make([]*Session, 0, len(m.sessions))
			for _, s := range m.sessions {
				s.mu.Lock()
				if now.Sub(s.lastSeen) > s.timeout {
					expired = append(expired, s)
				}
				s.mu.Unlock()
				all = append(all, s)
			}
			m.mu.Unlock()
			for _, s := range expired {
				m.srv.logf("session %q timed out", s.Name)
				m.closeSession(s, true)
			}
			for _, s := range all {
				s.expirePublishRequests(now)
			}
		}
	}
}

func (m *sessionManager) channelClosed(ch *uasc.Channel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		s.mu.Lock()
		if s.channel == ch {
			// The session survives until its timeout so the client can reconnect.
			s.channel = nil
			s.publishQueue = nil
		}
		s.mu.Unlock()
	}
}

func (m *sessionManager) createSession(ch *uasc.Channel, r *ua.CreateSessionRequest) ua.Structure {
	hdr := &r.RequestHeader
	s := m.srv
	policy := ch.SecurityPolicy()

	var clientCert *x509.Certificate
	if len(r.ClientCertificate) > 0 {
		certs, err := x509.ParseCertificates(r.ClientCertificate)
		if err != nil || len(certs) == 0 {
			return fault(hdr, ua.StatusBadCertificateInvalid)
		}
		clientCert = certs[0]
	}
	if !policy.IsNone() {
		if clientCert == nil || string(clientCert.Raw) != string(ch.RemoteCertificateDER()) {
			return fault(hdr, ua.StatusBadCertificateInvalid)
		}
		if len(r.ClientNonce) < policy.NonceLength {
			return fault(hdr, ua.StatusBadNonceInvalid)
		}
		if uri := CertificateURI(clientCert); uri != r.ClientDescription.ApplicationUri {
			return fault(hdr, ua.StatusBadCertificateUriInvalid)
		}
	}
	if r.ClientDescription.ApplicationType == ua.ApplicationTypeServer {
		return fault(hdr, ua.StatusBadInvalidArgument)
	}

	m.mu.Lock()
	if len(m.sessions) >= s.cfg.MaxSessions {
		m.mu.Unlock()
		return fault(hdr, ua.StatusBadTooManySessions)
	}
	m.mu.Unlock()

	timeout := time.Duration(r.RequestedSessionTimeout * float64(time.Millisecond))
	if timeout < s.cfg.MinSessionTimeout {
		timeout = s.cfg.MinSessionTimeout
	}
	if timeout > s.cfg.MaxSessionTimeout {
		timeout = s.cfg.MaxSessionTimeout
	}
	nonce := uasc.NewNonce(32)
	sess := &Session{
		srv:       s,
		ID:        ua.NewGuidNodeId(1, ua.NewGuid()),
		authToken: ua.NewByteStringNodeId(0, uasc.NewNonce(32)),
		Name:      r.SessionName,
		Client:    r.ClientDescription,
		timeout:   timeout,
		channel:   ch, clientCert: clientCert, serverNonce: nonce, lastSeen: time.Now(),
		browseCPs: map[string]*browseCP{}, subs: map[uint32]*subscription{},
	}
	if sess.Name == "" {
		sess.Name = sess.ID.String()
	}

	var sig ua.SignatureData
	if !policy.IsNone() && clientCert != nil {
		data := append(append([]byte{}, clientCert.Raw...), r.ClientNonce...)
		b, err := policy.AsymSign(s.key, data)
		if err != nil {
			return fault(hdr, ua.StatusBadInternalError)
		}
		sig = ua.SignatureData{Algorithm: policy.AsymSignatureAlgorithm, Signature: b}
	}

	m.mu.Lock()
	m.sessions[sess.ID] = sess
	m.byToken[sess.authToken] = sess
	m.mu.Unlock()
	s.logf("session %q created (%s)", sess.Name, ch.RemoteAddr())

	return &ua.CreateSessionResponse{
		ResponseHeader:        respHeader(hdr, 0),
		SessionId:             sess.ID,
		AuthenticationToken:   sess.authToken,
		RevisedSessionTimeout: float64(timeout / time.Millisecond),
		ServerNonce:           nonce,
		ServerCertificate:     s.cert,
		ServerEndpoints:       s.endpointsFor(r.EndpointUrl),
		ServerSignature:       sig,
		MaxRequestMessageSize: 0,
	}
}

func (m *sessionManager) activateSession(ch *uasc.Channel, r *ua.ActivateSessionRequest) ua.Structure {
	hdr := &r.RequestHeader
	s := m.srv
	m.mu.Lock()
	sess := m.byToken[hdr.AuthenticationToken]
	m.mu.Unlock()
	if sess == nil {
		return fault(hdr, ua.StatusBadSessionIdInvalid)
	}
	policy := ch.SecurityPolicy()

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return fault(hdr, ua.StatusBadSessionIdInvalid)
	}
	if sess.channel != ch {
		// Re-binding to a new channel requires the same client certificate.
		if !policy.IsNone() || sess.clientCert != nil {
			if sess.clientCert == nil || string(sess.clientCert.Raw) != string(ch.RemoteCertificateDER()) {
				return fault(hdr, ua.StatusBadSecureChannelIdInvalid)
			}
		}
	}
	if !policy.IsNone() {
		if sess.clientCert == nil {
			return fault(hdr, ua.StatusBadApplicationSignatureInvalid)
		}
		pub, ok := sess.clientCert.PublicKey.(*rsa.PublicKey)
		if !ok || r.ClientSignature.Algorithm != policy.AsymSignatureAlgorithm {
			return fault(hdr, ua.StatusBadApplicationSignatureInvalid)
		}
		data := append(append([]byte{}, s.cert...), sess.serverNonce...)
		if err := policy.AsymVerify(pub, data, r.ClientSignature.Signature); err != nil {
			return fault(hdr, ua.StatusBadApplicationSignatureInvalid)
		}
	}

	ep := s.endpointForChannel(ch)
	identity, status := s.validateIdentity(ch, ep, sess.serverNonce, r.UserIdentityToken, r.UserTokenSignature)
	if status != 0 {
		s.logf("session %q: identity rejected: %s", sess.Name, status)
		return fault(hdr, status)
	}
	if sess.activated && sess.channel != ch && identity != sess.identity {
		// Transferring a session to another channel requires the same user.
		if identity.Type != sess.identity.Type || identity.UserName != sess.identity.UserName {
			return fault(hdr, ua.StatusBadUserAccessDenied)
		}
	}
	if sess.channel != ch {
		sess.publishQueue = nil
	}
	sess.channel = ch
	sess.identity = identity
	sess.activated = true
	sess.lastSeen = time.Now()
	sess.localeIDs = r.LocaleIds
	sess.serverNonce = uasc.NewNonce(32)
	s.logf("session %q activated (user: %s)", sess.Name, identityString(identity))

	return &ua.ActivateSessionResponse{
		ResponseHeader: respHeader(hdr, 0),
		ServerNonce:    sess.serverNonce,
	}
}

func identityString(i Identity) string {
	switch i.Type {
	case UserTokenUserName:
		return i.UserName
	case UserTokenCertificate:
		if i.Certificate != nil {
			return "cert:" + i.Certificate.Subject.CommonName
		}
	}
	return "anonymous"
}

func (s *Server) endpointForChannel(ch *uasc.Channel) *ua.EndpointDescription {
	for i := range s.endpoints {
		ep := &s.endpoints[i]
		if ep.SecurityPolicyUri == ch.SecurityPolicy().URI && ep.SecurityMode == ch.SecurityMode() {
			return ep
		}
	}
	return nil
}

func (s *Server) validateIdentity(ch *uasc.Channel, ep *ua.EndpointDescription, serverNonce []byte,
	tok ua.ExtensionObject, tokSig ua.SignatureData) (Identity, ua.StatusCode) {
	if ep == nil {
		return Identity{}, ua.StatusBadSecurityPolicyRejected
	}
	findPolicy := func(policyID string, t ua.UserTokenType) *ua.UserTokenPolicy {
		for i := range ep.UserIdentityTokens {
			p := &ep.UserIdentityTokens[i]
			if p.TokenType == t && (p.PolicyId == policyID || policyID == "") {
				return p
			}
		}
		return nil
	}
	tokenSecurity := func(p *ua.UserTokenPolicy) *uasc.SecurityPolicy {
		if p.SecurityPolicyUri != "" {
			return uasc.PolicyByURI(p.SecurityPolicyUri)
		}
		return ch.SecurityPolicy()
	}

	switch t := tok.Value.(type) {
	case nil:
		if findPolicy("", ua.UserTokenTypeAnonymous) == nil {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		return Identity{Type: UserTokenAnonymous}, 0

	case *ua.AnonymousIdentityToken:
		if findPolicy(t.PolicyId, ua.UserTokenTypeAnonymous) == nil {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		return Identity{Type: UserTokenAnonymous}, 0

	case *ua.UserNameIdentityToken:
		p := findPolicy(t.PolicyId, ua.UserTokenTypeUserName)
		if p == nil {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		sp := tokenSecurity(p)
		if sp == nil {
			return Identity{}, ua.StatusBadSecurityPolicyRejected
		}
		password := t.Password
		if !sp.IsNone() {
			if t.EncryptionAlgorithm != sp.AsymEncryptionAlgorithm {
				return Identity{}, ua.StatusBadIdentityTokenInvalid
			}
			pt, err := sp.AsymDecrypt(s.key, t.Password)
			if err != nil || len(pt) < 4 {
				return Identity{}, ua.StatusBadIdentityTokenInvalid
			}
			n := int(binary.LittleEndian.Uint32(pt[:4]))
			if n > len(pt)-4 || n < len(serverNonce) {
				return Identity{}, ua.StatusBadIdentityTokenInvalid
			}
			secret := pt[4 : 4+n]
			nonce := secret[len(secret)-len(serverNonce):]
			if subtle.ConstantTimeCompare(nonce, serverNonce) != 1 {
				return Identity{}, ua.StatusBadIdentityTokenInvalid
			}
			password = secret[:len(secret)-len(serverNonce)]
		} else if t.EncryptionAlgorithm != "" {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		if s.cfg.AuthenticateUser == nil || !s.cfg.AuthenticateUser(t.UserName, string(password)) {
			return Identity{}, ua.StatusBadUserAccessDenied
		}
		return Identity{Type: UserTokenUserName, UserName: t.UserName}, 0

	case *ua.X509IdentityToken:
		p := findPolicy(t.PolicyId, ua.UserTokenTypeCertificate)
		if p == nil {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		sp := tokenSecurity(p)
		if sp == nil || sp.IsNone() {
			return Identity{}, ua.StatusBadSecurityPolicyRejected
		}
		cert, err := x509.ParseCertificate(t.CertificateData)
		if err != nil {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return Identity{}, ua.StatusBadIdentityTokenInvalid
		}
		data := append(append([]byte{}, s.cert...), serverNonce...)
		if tokSig.Algorithm != sp.AsymSignatureAlgorithm || sp.AsymVerify(pub, data, tokSig.Signature) != nil {
			return Identity{}, ua.StatusBadUserSignatureInvalid
		}
		if err := s.pki.Validate([]*x509.Certificate{cert}); err != nil {
			return Identity{}, ua.StatusBadIdentityTokenRejected
		}
		if s.cfg.AuthenticateCertificate != nil && !s.cfg.AuthenticateCertificate(cert) {
			return Identity{}, ua.StatusBadUserAccessDenied
		}
		return Identity{Type: UserTokenCertificate, Certificate: cert}, 0
	}
	return Identity{}, ua.StatusBadIdentityTokenInvalid
}

// lookup finds the session for a request and checks it may be used on ch.
func (m *sessionManager) lookup(ch *uasc.Channel, token ua.NodeId, req ua.Structure) (*Session, ua.StatusCode) {
	m.mu.Lock()
	sess := m.byToken[token]
	m.mu.Unlock()
	if sess == nil {
		return nil, ua.StatusBadSessionIdInvalid
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return nil, ua.StatusBadSessionIdInvalid
	}
	if sess.channel != ch {
		return nil, ua.StatusBadSecureChannelIdInvalid
	}
	if !sess.activated {
		if _, ok := req.(*ua.CloseSessionRequest); !ok {
			return nil, ua.StatusBadSessionNotActivated
		}
	}
	sess.lastSeen = time.Now()
	return sess, 0
}

func (m *sessionManager) closeSession(sess *Session, deleteSubs bool) {
	m.mu.Lock()
	delete(m.sessions, sess.ID)
	delete(m.byToken, sess.authToken)
	m.mu.Unlock()

	sess.mu.Lock()
	if sess.closed {
		sess.mu.Unlock()
		return
	}
	sess.closed = true
	subs := make([]*subscription, 0, len(sess.subs))
	for _, sub := range sess.subs {
		subs = append(subs, sub)
	}
	sess.subs = map[uint32]*subscription{}
	pending := sess.publishQueue
	sess.publishQueue = nil
	sess.mu.Unlock()

	// Subscriptions are always deleted: transfer to other sessions is not supported.
	_ = deleteSubs
	for _, sub := range subs {
		sub.stop()
	}
	for _, p := range pending {
		p.respond(fault(&p.req.RequestHeader, ua.StatusBadSessionClosed))
	}
	m.srv.logf("session %q closed", sess.Name)
}
