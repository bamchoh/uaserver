package uasc

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/uacp"
)

// ClientConfig configures the client side of a secure channel.
type ClientConfig struct {
	SecurityPolicyURI string
	SecurityMode      ua.MessageSecurityMode
	// Local is the client application certificate and key. It is required
	// for every policy except None.
	Local *Credential
	// RemoteCertificate is the server certificate (DER) of the endpoint. It
	// is required for every policy except None. The caller must have checked
	// that it is trusted.
	RemoteCertificate []byte
	// Lifetime is the requested security token lifetime (default 1 hour).
	// Tokens are renewed after 75% of the lifetime granted by the server.
	Lifetime time.Duration
	// Logf is an optional logger.
	Logf func(format string, args ...any)
}

// ErrChannelClosed is returned for requests on a closed channel.
var ErrChannelClosed = errors.New("uasc: secure channel closed")

// ClientChannel is the client side of a secure channel. It is safe for
// concurrent use; requests are matched to responses by request id.
type ClientChannel struct {
	conn   *uacp.Conn
	cfg    ClientConfig
	policy *SecurityPolicy
	mode   ua.MessageSecurityMode

	local      *Credential
	localLeaf  []byte // DER of the client leaf certificate
	remoteCert *x509.Certificate
	remotePub  crypto.PublicKey

	nextReqID atomic.Uint32

	mu         sync.Mutex
	id         uint32
	tokens     []*token // tokens accepted for receiving, newest last
	sendToken  *token
	recvSeq    recvSeq
	pending    map[uint32]chan<- clientResult
	chunks     map[uint32][][]byte
	chunkBytes map[uint32]int
	err        error

	sendMu  sync.Mutex
	sendSeq sendSeq

	closeOnce sync.Once
	closed    chan struct{}
}

type clientResult struct {
	msg ua.Structure
	err error
}

// OpenClientChannel opens a secure channel on a connection returned by
// uacp.Dial. On error the connection is closed.
func OpenClientChannel(ctx context.Context, conn *uacp.Conn, cfg ClientConfig) (*ClientChannel, error) {
	c, err := newClientChannel(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	go c.readLoop()
	if err := c.openToken(ctx, ua.SecurityTokenRequestTypeIssue); err != nil {
		c.shutdown(err)
		return nil, err
	}
	go c.renewLoop()
	return c, nil
}

func newClientChannel(conn *uacp.Conn, cfg ClientConfig) (*ClientChannel, error) {
	if cfg.SecurityPolicyURI == "" {
		cfg.SecurityPolicyURI = SecurityPolicyNone
	}
	policy := PolicyByURI(cfg.SecurityPolicyURI)
	if policy == nil {
		return nil, fmt.Errorf("uasc: unsupported security policy %s", cfg.SecurityPolicyURI)
	}
	mode := cfg.SecurityMode
	if mode == ua.MessageSecurityModeInvalid {
		mode = ua.MessageSecurityModeSignAndEncrypt
		if policy.IsNone() {
			mode = ua.MessageSecurityModeNone
		}
	}
	if policy.IsNone() != (mode == ua.MessageSecurityModeNone) {
		return nil, fmt.Errorf("uasc: security mode %s cannot be used with %s", mode, policy.Name)
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = time.Hour
	}
	c := &ClientChannel{
		conn: conn, cfg: cfg, policy: policy, mode: mode,
		recvSeq: recvSeq{legacy: !policy.IsECC()}, sendSeq: sendSeq{legacy: !policy.IsECC()},
		pending: map[uint32]chan<- clientResult{}, chunks: map[uint32][][]byte{}, chunkBytes: map[uint32]int{},
		closed: make(chan struct{}),
	}
	if !policy.IsNone() {
		if cfg.Local == nil || cfg.Local.PrivateKey == nil {
			return nil, fmt.Errorf("uasc: %s needs a client certificate", policy.Name)
		}
		leafs, err := x509.ParseCertificates(cfg.Local.Certificate)
		if err != nil || len(leafs) == 0 {
			return nil, fmt.Errorf("uasc: invalid client certificate: %v", err)
		}
		if !policy.CertificateKeyAllowed(leafs[0].PublicKey) {
			return nil, fmt.Errorf("uasc: the client certificate key cannot be used with %s", policy.Name)
		}
		certs, err := x509.ParseCertificates(cfg.RemoteCertificate)
		if err != nil || len(certs) == 0 {
			return nil, fmt.Errorf("uasc: invalid server certificate: %v", err)
		}
		if !policy.CertificateKeyAllowed(certs[0].PublicKey) {
			return nil, fmt.Errorf("uasc: the server certificate key cannot be used with %s", policy.Name)
		}
		c.local = cfg.Local
		c.localLeaf = leafs[0].Raw
		c.remoteCert = certs[0]
		c.remotePub = certs[0].PublicKey
	}
	c.nextReqID.Store(0)
	return c, nil
}

// ID returns the secure channel id assigned by the server.
func (c *ClientChannel) ID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

// SecurityPolicy returns the channel's security policy.
func (c *ClientChannel) SecurityPolicy() *SecurityPolicy { return c.policy }

// SecurityMode returns the channel's message security mode.
func (c *ClientChannel) SecurityMode() ua.MessageSecurityMode { return c.mode }

// RemoteCertificate returns the server certificate, or nil for the None policy.
func (c *ClientChannel) RemoteCertificate() *x509.Certificate { return c.remoteCert }

// Done is closed when the channel is closed.
func (c *ClientChannel) Done() <-chan struct{} { return c.closed }

// Err returns why the channel was closed, or nil while it is open.
func (c *ClientChannel) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *ClientChannel) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

// shutdown closes the connection and fails all pending requests with err.
func (c *ClientChannel) shutdown(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = ErrChannelClosed
		}
		c.mu.Lock()
		c.err = err
		pending := c.pending
		c.pending = map[uint32]chan<- clientResult{}
		c.mu.Unlock()
		close(c.closed)
		_ = c.conn.Close()
		for _, ch := range pending {
			ch <- clientResult{err: err}
		}
	})
}

// Close sends a CloseSecureChannel request and closes the connection.
func (c *ClientChannel) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}
	req := &ua.CloseSecureChannelRequest{RequestHeader: ua.RequestHeader{Timestamp: time.Now()}}
	e := ua.NewEncoder(64)
	e.WriteNodeId(req.BinaryEncodingID())
	req.Encode(e)
	err := c.sendChunks(uacp.MsgClose, c.newRequestID(), e.Bytes())
	c.shutdown(ErrChannelClosed)
	return err
}

func (c *ClientChannel) newRequestID() uint32 {
	for {
		if id := c.nextReqID.Add(1); id != 0 {
			return id
		}
	}
}

// register adds a pending request; it fails if the channel is closed.
func (c *ClientChannel) register(reqID uint32) (<-chan clientResult, error) {
	ch := make(chan clientResult, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	c.pending[reqID] = ch
	return ch, nil
}

func (c *ClientChannel) unregister(reqID uint32) {
	c.mu.Lock()
	delete(c.pending, reqID)
	delete(c.chunks, reqID)
	delete(c.chunkBytes, reqID)
	c.mu.Unlock()
}

// deliver hands a result to the waiting request, if it is still waiting.
func (c *ClientChannel) deliver(reqID uint32, r clientResult) {
	c.mu.Lock()
	ch, ok := c.pending[reqID]
	delete(c.pending, reqID)
	c.mu.Unlock()
	if ok {
		ch <- r
	} else {
		c.logf("uasc: dropped response for request %d (not waiting)", reqID)
	}
}

func (c *ClientChannel) wait(ctx context.Context, reqID uint32, ch <-chan clientResult) (ua.Structure, error) {
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-ctx.Done():
		c.unregister(reqID)
		return nil, ctx.Err()
	}
}

// Send sends a service request and waits for its response. The caller fills
// the request header. A ServiceFault is returned as a response, not as an error.
func (c *ClientChannel) Send(ctx context.Context, req ua.Structure) (ua.Structure, error) {
	e := ua.NewEncoder(1024)
	e.WriteNodeId(req.BinaryEncodingID())
	req.Encode(e)
	reqID := c.newRequestID()
	ch, err := c.register(reqID)
	if err != nil {
		return nil, err
	}
	if err := c.sendChunks(uacp.MsgMessage, reqID, e.Bytes()); err != nil {
		c.unregister(reqID)
		return nil, err
	}
	return c.wait(ctx, reqID, ch)
}

// sendChunks sends a MSG or CLO message, split into chunks.
func (c *ClientChannel) sendChunks(msgType string, reqID uint32, body []byte) error {
	if c.conn.PeerMaxMessage > 0 && uint32(len(body)) > c.conn.PeerMaxMessage {
		return ua.StatusBadRequestTooLarge
	}
	maxBody := maxChunkBody(c.policy, c.mode, int(c.conn.SendBufferSize))
	n := max((len(body)+maxBody-1)/maxBody, 1)
	if c.conn.PeerMaxChunks > 0 && uint32(n) > c.conn.PeerMaxChunks {
		return ua.StatusBadRequestTooLarge
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	tok, id, closedErr := c.sendToken, c.id, c.err
	c.mu.Unlock()
	if closedErr != nil {
		return closedErr
	}
	for i := 0; i < n; i++ {
		start := i * maxBody
		end := min(start+maxBody, len(body))
		ct := byte(uacp.ChunkIntermediate)
		if i == n-1 {
			ct = uacp.ChunkFinal
		}
		chunk, err := sealSym(c.policy, c.mode, msgType, ct, id, tok.id, &tok.local, c.sendSeq.next(), reqID, body[start:end])
		if err != nil {
			return err
		}
		if _, err := c.conn.Write(chunk); err != nil {
			c.shutdown(err)
			return err
		}
	}
	return nil
}

// --- security tokens ---

// openToken issues or renews the security token.
func (c *ClientChannel) openToken(ctx context.Context, reqType ua.SecurityTokenRequestType) error {
	var nonce []byte
	var eph *ecdh.PrivateKey
	switch {
	case c.policy.IsECC():
		k, n, err := c.policy.NewEphemeralKey()
		if err != nil {
			return err
		}
		eph, nonce = k, n
	case c.policy.IsNone():
		nonce = []byte{}
	default:
		nonce = NewNonce(c.policy.NonceLength)
	}
	hdr := ua.RequestHeader{Timestamp: time.Now()}
	if d, ok := ctx.Deadline(); ok {
		hdr.TimeoutHint = uint32(max(time.Until(d), 0) / time.Millisecond)
	}
	req := &ua.OpenSecureChannelRequest{
		RequestHeader:     hdr,
		RequestType:       reqType,
		SecurityMode:      c.mode,
		ClientNonce:       nonce,
		RequestedLifetime: uint32(c.cfg.Lifetime / time.Millisecond),
	}
	body := ua.NewEncoder(256)
	body.WriteNodeId(req.BinaryEncodingID())
	req.Encode(body)

	reqID := c.newRequestID()
	ch, err := c.register(reqID)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()
	var remoteCert []byte
	if c.remoteCert != nil {
		remoteCert = c.remoteCert.Raw
	}
	out, err := sealAsym(c.policy, id, c.local, remoteCert, c.remotePub, c.sendSeq.next(), reqID,
		body.Bytes(), int(c.conn.SendBufferSize))
	if err == nil {
		_, err = c.conn.Write(out)
	}
	c.sendMu.Unlock()
	if err != nil {
		c.unregister(reqID)
		return err
	}

	msg, err := c.wait(ctx, reqID, ch)
	if err != nil {
		return err
	}
	resp, ok := msg.(*ua.OpenSecureChannelResponse)
	if !ok {
		if f, ok := msg.(*ua.ServiceFault); ok {
			return fmt.Errorf("uasc: OpenSecureChannel failed: %w", f.ResponseHeader.ServiceResult)
		}
		return fmt.Errorf("uasc: unexpected response %T to OpenSecureChannel", msg)
	}
	if st := resp.ResponseHeader.ServiceResult; st.IsBad() {
		return fmt.Errorf("uasc: OpenSecureChannel failed: %w", st)
	}
	st := resp.SecurityToken
	if st.ChannelId == 0 || (id != 0 && st.ChannelId != id) {
		return secErr(ua.StatusBadSecureChannelIdInvalid, "server returned an invalid channel id")
	}
	if st.RevisedLifetime == 0 {
		return secErr(ua.StatusBadSecurityChecksFailed, "server returned a zero token lifetime")
	}
	tok := &token{id: st.TokenId, created: time.Now(), lifetime: time.Duration(st.RevisedLifetime) * time.Millisecond}
	switch {
	case c.policy.IsECC():
		serverKey, err := c.policy.ParseNonce(resp.ServerNonce)
		if err != nil {
			return secErr(ua.StatusBadNonceInvalid, "server nonce is not a valid ephemeral key")
		}
		secret, err := eph.ECDH(serverKey)
		if err != nil {
			return secErr(ua.StatusBadNonceInvalid, "key agreement failed")
		}
		signOnly := c.mode == ua.MessageSecurityModeSign
		tok.local, tok.remote = c.policy.DeriveECCKeys(secret, nonce, resp.ServerNonce, signOnly)
	case !c.policy.IsNone():
		if len(resp.ServerNonce) < c.policy.NonceLength {
			return secErr(ua.StatusBadNonceInvalid, "server nonce too short")
		}
		// Client keys: secret=ServerNonce, seed=ClientNonce. Server keys: the reverse.
		tok.local = c.policy.DeriveKeys(resp.ServerNonce, nonce)
		tok.remote = c.policy.DeriveKeys(nonce, resp.ServerNonce)
	}

	c.mu.Lock()
	c.id = st.ChannelId
	// Keep the previous token for receiving until the server switches to
	// the new one; send with the new token right away (Part 6, 6.7.4).
	if n := len(c.tokens); n > 0 {
		c.tokens = c.tokens[n-1:]
	}
	c.tokens = append(c.tokens, tok)
	c.sendToken = tok
	c.mu.Unlock()
	return nil
}

// renewLoop renews the security token after 75% of its lifetime.
func (c *ClientChannel) renewLoop() {
	for {
		c.mu.Lock()
		tok := c.sendToken
		c.mu.Unlock()
		t := time.NewTimer(time.Until(tok.created.Add(tok.lifetime * 3 / 4)))
		select {
		case <-c.closed:
			t.Stop()
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), max(tok.lifetime/4, 5*time.Second))
		err := c.openToken(ctx, ua.SecurityTokenRequestTypeRenew)
		cancel()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
			}
			c.logf("uasc: renewing the security token failed: %v", err)
			c.shutdown(fmt.Errorf("uasc: token renewal failed: %w", err))
			return
		}
	}
}

func (c *ClientChannel) findToken(id uint32) *token {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for i, t := range c.tokens {
		if t.id != id {
			continue
		}
		if t.expired(now) {
			return nil
		}
		// The server switched to the newer token: drop the older ones.
		if i > 0 {
			c.tokens = c.tokens[i:]
		}
		return t
	}
	return nil
}

// --- receiving ---

func (c *ClientChannel) readLoop() {
	for {
		ch, err := c.conn.ReadChunk()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				err = ErrChannelClosed
			}
			c.shutdown(err)
			return
		}
		switch ch.Type {
		case uacp.MsgOpen:
			err = c.handleOpen(ch)
		case uacp.MsgMessage:
			err = c.handleMessage(ch)
		case uacp.MsgError:
			err = uacp.ParseError(ch)
		default:
			err = fmt.Errorf("uasc: unexpected message type %s", ch.Type)
		}
		if err != nil {
			c.shutdown(err)
			return
		}
	}
}

func (c *ClientChannel) handleOpen(ch *uacp.Chunk) error {
	if ch.ChunkType != uacp.ChunkFinal {
		return secErr(ua.StatusBadTcpMessageTypeInvalid, "chunked OPN responses are not supported")
	}
	data := ch.Data
	h, err := parseAsymHeader(data)
	if err != nil {
		return err
	}
	if h.policyURI != c.policy.URI {
		return secErr(ua.StatusBadSecurityPolicyRejected, "server changed the security policy")
	}
	c.mu.Lock()
	id := c.id
	c.mu.Unlock()
	if id != 0 && h.channelID != id {
		return secErr(ua.StatusBadSecureChannelIdInvalid, "channel id mismatch")
	}
	if !c.policy.IsNone() {
		thumb := sha1.Sum(c.localLeaf)
		if string(h.thumbprint) != string(thumb[:]) {
			return secErr(ua.StatusBadSecurityChecksFailed, "receiver certificate thumbprint mismatch")
		}
		chain, err := x509.ParseCertificates(h.senderCert)
		if err != nil || len(chain) == 0 || string(chain[0].Raw) != string(c.remoteCert.Raw) {
			return secErr(ua.StatusBadCertificateInvalid, "server certificate differs from the endpoint's")
		}
	}
	plain, err := openAsym(c.policy, c.local, c.remotePub, data, h.end)
	if err != nil {
		return err
	}
	if len(plain) < 8 {
		return secErr(ua.StatusBadDecodingError, "message too short")
	}
	seq := binary.LittleEndian.Uint32(plain[0:4])
	reqID := binary.LittleEndian.Uint32(plain[4:8])
	if err := c.checkSeq(seq); err != nil {
		return err
	}
	c.deliver(reqID, decodeResponse(plain[8:]))
	return nil
}

func (c *ClientChannel) checkSeq(seq uint32) error {
	c.mu.Lock()
	ok := c.recvSeq.check(seq)
	c.mu.Unlock()
	if !ok {
		return secErr(ua.StatusBadSequenceNumberInvalid, "invalid sequence number")
	}
	return nil
}

func (c *ClientChannel) handleMessage(ch *uacp.Chunk) error {
	data := ch.Data
	if len(data) < 24 {
		return secErr(ua.StatusBadDecodingError, "message too short")
	}
	channelID := binary.LittleEndian.Uint32(data[8:12])
	tokenID := binary.LittleEndian.Uint32(data[12:16])
	if channelID != c.ID() {
		return secErr(ua.StatusBadSecureChannelIdInvalid, "channel id mismatch")
	}
	tok := c.findToken(tokenID)
	if tok == nil {
		return secErr(ua.StatusBadSecureChannelTokenUnknown, "unknown security token")
	}
	seq, reqID, body, err := openSym(c.policy, c.mode, &tok.remote, data)
	if err != nil {
		return err
	}
	if err := c.checkSeq(seq); err != nil {
		return err
	}

	switch ch.ChunkType {
	case uacp.ChunkAbort:
		d := ua.NewDecoder(body)
		code, reason := d.ReadStatusCode(), d.ReadString()
		if code == 0 {
			code = ua.StatusBadUnexpectedError
		}
		c.unregisterChunks(reqID)
		c.deliver(reqID, clientResult{err: fmt.Errorf("uasc: server aborted the response: %w (%s)", code, reason)})
		return nil
	case uacp.ChunkIntermediate:
		c.mu.Lock()
		if _, waiting := c.pending[reqID]; !waiting {
			c.mu.Unlock()
			return nil // the caller gave up; drop the chunks
		}
		c.chunks[reqID] = append(c.chunks[reqID], append([]byte(nil), body...))
		c.chunkBytes[reqID] += len(body)
		tooLarge := (c.conn.MaxChunkCount > 0 && uint32(len(c.chunks[reqID])) >= c.conn.MaxChunkCount) ||
			(c.conn.MaxMessageSize > 0 && uint32(c.chunkBytes[reqID]) > c.conn.MaxMessageSize)
		c.mu.Unlock()
		if tooLarge {
			c.unregisterChunks(reqID)
			c.deliver(reqID, clientResult{err: ua.StatusBadResponseTooLarge})
		}
		return nil
	}
	c.mu.Lock()
	prev, ok := c.chunks[reqID]
	total := c.chunkBytes[reqID]
	delete(c.chunks, reqID)
	delete(c.chunkBytes, reqID)
	c.mu.Unlock()
	if ok {
		full := make([]byte, 0, total+len(body))
		for _, p := range prev {
			full = append(full, p...)
		}
		body = append(full, body...)
	}
	c.deliver(reqID, decodeResponse(body))
	return nil
}

func (c *ClientChannel) unregisterChunks(reqID uint32) {
	c.mu.Lock()
	delete(c.chunks, reqID)
	delete(c.chunkBytes, reqID)
	c.mu.Unlock()
}

func decodeResponse(body []byte) clientResult {
	d := ua.NewDecoder(body)
	typeID := d.ReadNodeId()
	msg := ua.NewStructureByEncodingID(typeID)
	if d.Err() != nil || msg == nil {
		return clientResult{err: fmt.Errorf("uasc: unknown response type %s: %w", typeID, ua.StatusBadDecodingError)}
	}
	d.ReadStruct(msg)
	if d.Err() != nil {
		return clientResult{err: fmt.Errorf("uasc: decoding %T: %w", msg, ua.StatusBadDecodingError)}
	}
	return clientResult{msg: msg}
}
