// Package uasc implements the server side of the OPC UA Secure Conversation
// protocol (Part 6, 6.7): secure channel establishment, token renewal,
// message signing/encryption and chunking.
package uasc

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"opcuasrv/ua"
	"opcuasrv/uacp"
)

// Config holds the server side settings of a secure channel.
type Config struct {
	// Certificate is the DER encoded application instance certificate.
	Certificate []byte
	PrivateKey  *rsa.PrivateKey
	// IsAllowed reports whether an endpoint offers the policy/mode combination.
	IsAllowed func(policyURI string, mode ua.MessageSecurityMode) bool
	// VerifyCertificate validates the client certificate (chain). It returns nil
	// if the certificate is trusted, or an error (preferably a ua.StatusCode).
	VerifyCertificate func(chain []*x509.Certificate) error
	// Token lifetime limits in milliseconds.
	MinTokenLifetime uint32
	MaxTokenLifetime uint32
	// Logf is an optional logger.
	Logf func(format string, args ...any)
}

type token struct {
	id       uint32
	created  time.Time
	lifetime time.Duration
	local    Keys // keys used by the server to secure messages it sends
	remote   Keys // keys used by the client to secure messages it sends
}

func (t *token) expired(now time.Time) bool {
	return now.After(t.created.Add(t.lifetime + t.lifetime/4))
}

// Channel is a server side secure channel.
type Channel struct {
	conn *uacp.Conn
	cfg  *Config
	id   uint32

	policy     *SecurityPolicy
	mode       ua.MessageSecurityMode
	remoteCert *x509.Certificate
	remoteDER  []byte // as sent by the client (may contain a chain)
	remotePub  *rsa.PublicKey

	mu          sync.Mutex
	tokens      []*token // tokens accepted for receiving, newest last
	sendToken   *token
	nextTokenID uint32
	lastRecvSeq uint32
	haveRecvSeq bool

	sendMu  sync.Mutex
	sendSeq uint32

	chunks     map[uint32][][]byte
	chunkBytes map[uint32]int

	closeOnce sync.Once
	closed    chan struct{}
}

// Request is a decoded service request received on a channel.
type Request struct {
	RequestID uint32
	Body      ua.Structure
}

// NewChannel creates a server side channel on an accepted connection.
func NewChannel(conn *uacp.Conn, id uint32, cfg *Config) *Channel {
	return &Channel{
		conn: conn, cfg: cfg, id: id, nextTokenID: 1, sendSeq: 0,
		chunks: map[uint32][][]byte{}, chunkBytes: map[uint32]int{}, closed: make(chan struct{}),
		policy: PolicyByURI(SecurityPolicyNone),
	}
}

// ID returns the secure channel id.
func (c *Channel) ID() uint32 { return c.id }

// SecurityPolicy returns the negotiated policy.
func (c *Channel) SecurityPolicy() *SecurityPolicy { return c.policy }

// SecurityMode returns the negotiated message security mode.
func (c *Channel) SecurityMode() ua.MessageSecurityMode { return c.mode }

// RemoteCertificate returns the client certificate, or nil for the None policy.
func (c *Channel) RemoteCertificate() *x509.Certificate { return c.remoteCert }

// RemoteCertificateDER returns the leaf client certificate in DER form.
func (c *Channel) RemoteCertificateDER() []byte {
	if c.remoteCert == nil {
		return nil
	}
	return c.remoteCert.Raw
}

// EndpointURL returns the URL sent by the client in the Hello message.
func (c *Channel) EndpointURL() string { return c.conn.EndpointURL }

// RemoteAddr returns the client network address.
func (c *Channel) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Done is closed when the channel is closed.
func (c *Channel) Done() <-chan struct{} { return c.closed }

// Close closes the channel and the underlying connection.
func (c *Channel) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

func (c *Channel) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

// fail sends an ERR message and closes the channel.
func (c *Channel) fail(code ua.StatusCode, reason string) error {
	c.sendMu.Lock()
	c.conn.SendError(code, reason)
	c.sendMu.Unlock()
	c.Close()
	return fmt.Errorf("uasc: %s: %s", code, reason)
}

// Serve reads messages until the channel is closed. The first message must
// be an OpenSecureChannel request. handle is called for every service request;
// it must not block for long (start a goroutine for slow requests).
func (c *Channel) Serve(handle func(Request)) error {
	defer c.Close()
	first := true
	for {
		deadline := time.Now().Add(60 * time.Second)
		c.mu.Lock()
		if n := len(c.tokens); n > 0 {
			t := c.tokens[n-1]
			deadline = t.created.Add(t.lifetime + t.lifetime/4)
		}
		c.mu.Unlock()
		_ = c.conn.SetReadDeadline(deadline)
		ch, err := c.conn.ReadChunk()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return c.fail(ua.StatusBadSecureChannelTokenUnknown, "security token expired")
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if first && ch.Type != uacp.MsgOpen {
			return c.fail(ua.StatusBadTcpMessageTypeInvalid, "expected OPN")
		}
		switch ch.Type {
		case uacp.MsgOpen:
			if err := c.handleOpen(ch, first); err != nil {
				return err
			}
			first = false
		case uacp.MsgMessage, uacp.MsgClose:
			req, done, err := c.handleSymmetric(ch)
			if err != nil {
				return err
			}
			if !done {
				continue
			}
			if ch.Type == uacp.MsgClose {
				return nil
			}
			if _, ok := req.Body.(*ua.CloseSecureChannelRequest); ok {
				return nil
			}
			handle(req)
		default:
			return c.fail(ua.StatusBadTcpMessageTypeInvalid, "unexpected message type "+ch.Type)
		}
	}
}

// --- asymmetric (OPN) ---

func (c *Channel) handleOpen(ch *uacp.Chunk, first bool) error {
	if ch.ChunkType != uacp.ChunkFinal {
		return c.fail(ua.StatusBadTcpMessageTypeInvalid, "chunked OPN is not supported")
	}
	data := ch.Data
	d := ua.NewDecoder(data[uacp.HeaderSize:])
	channelID := d.ReadUint32()
	policyURI := d.ReadString()
	senderCert := d.ReadByteString()
	thumbprint := d.ReadByteString()
	if d.Err() != nil {
		return c.fail(ua.StatusBadDecodingError, "malformed security header")
	}
	hdrEnd := uacp.HeaderSize + d.Pos()

	if first {
		if channelID != 0 {
			return c.fail(ua.StatusBadTcpSecureChannelUnknown, "unexpected channel id")
		}
	} else if channelID != c.id {
		return c.fail(ua.StatusBadTcpSecureChannelUnknown, "channel id mismatch")
	}

	policy := PolicyByURI(policyURI)
	if policy == nil {
		return c.fail(ua.StatusBadSecurityPolicyRejected, "unsupported security policy")
	}
	if !first && policy.URI != c.policy.URI {
		return c.fail(ua.StatusBadSecurityPolicyRejected, "security policy changed")
	}

	var plain []byte
	if policy.IsNone() {
		plain = data[hdrEnd:]
	} else {
		if c.cfg.PrivateKey == nil {
			return c.fail(ua.StatusBadSecurityPolicyRejected, "server has no certificate")
		}
		ownThumb := sha1.Sum(c.cfg.Certificate)
		if string(thumbprint) != string(ownThumb[:]) {
			return c.fail(ua.StatusBadSecurityChecksFailed, "receiver certificate thumbprint mismatch")
		}
		chain, err := x509.ParseCertificates(senderCert)
		if err != nil || len(chain) == 0 {
			return c.fail(ua.StatusBadCertificateInvalid, "invalid client certificate")
		}
		pub, ok := chain[0].PublicKey.(*rsa.PublicKey)
		if !ok {
			return c.fail(ua.StatusBadCertificateInvalid, "client certificate is not RSA")
		}
		if bits := pub.N.BitLen(); bits < policy.MinAsymKeyBits || bits > policy.MaxAsymKeyBits {
			return c.fail(ua.StatusBadCertificatePolicyCheckFailed, "client key length not allowed by policy")
		}
		if !first && string(chain[0].Raw) != string(c.remoteCert.Raw) {
			return c.fail(ua.StatusBadSecurityChecksFailed, "client certificate changed")
		}
		if first && c.cfg.VerifyCertificate != nil {
			if err := c.cfg.VerifyCertificate(chain); err != nil {
				code := ua.StatusBadSecurityChecksFailed
				var sc ua.StatusCode
				if errors.As(err, &sc) {
					code = sc
				}
				c.logf("uasc: rejected client certificate %q: %v", chain[0].Subject.CommonName, err)
				return c.fail(code, "client certificate rejected")
			}
		}
		pt, err := policy.AsymDecrypt(c.cfg.PrivateKey, data[hdrEnd:])
		if err != nil {
			return c.fail(ua.StatusBadSecurityChecksFailed, "decryption failed")
		}
		sigLen := pub.Size()
		if len(pt) < 8+sigLen+1 {
			return c.fail(ua.StatusBadSecurityChecksFailed, "message too short")
		}
		signed := make([]byte, 0, hdrEnd+len(pt))
		signed = append(signed, data[:hdrEnd]...)
		signed = append(signed, pt[:len(pt)-sigLen]...)
		if err := policy.AsymVerify(pub, signed, pt[len(pt)-sigLen:]); err != nil {
			return c.fail(ua.StatusBadSecurityChecksFailed, "invalid signature")
		}
		pt = pt[:len(pt)-sigLen]
		padLen := int(pt[len(pt)-1])
		sizeBytes := 1
		if c.cfg.PrivateKey.Size() > 256 {
			padLen = int(pt[len(pt)-2]) | int(pt[len(pt)-1])<<8
			sizeBytes = 2
		}
		if len(pt) < 8+padLen+sizeBytes {
			return c.fail(ua.StatusBadSecurityChecksFailed, "invalid padding")
		}
		plain = pt[:len(pt)-padLen-sizeBytes]
		if first {
			c.remoteDER = senderCert
			c.remoteCert = chain[0]
			c.remotePub = pub
		}
	}
	if len(plain) < 8 {
		return c.fail(ua.StatusBadDecodingError, "message too short")
	}
	seq := binary.LittleEndian.Uint32(plain[0:4])
	reqID := binary.LittleEndian.Uint32(plain[4:8])
	if err := c.checkSeq(seq, first); err != nil {
		return err
	}
	bd := ua.NewDecoder(plain[8:])
	typeID := bd.ReadNodeId()
	req := &ua.OpenSecureChannelRequest{}
	if typeID != req.BinaryEncodingID() {
		return c.fail(ua.StatusBadTcpMessageTypeInvalid, "expected OpenSecureChannelRequest")
	}
	bd.ReadStruct(req)
	if bd.Err() != nil {
		return c.fail(ua.StatusBadDecodingError, "malformed OpenSecureChannelRequest")
	}

	if first && req.RequestType != ua.SecurityTokenRequestTypeIssue {
		return c.fail(ua.StatusBadSecurityChecksFailed, "first request must be Issue")
	}
	if !first && req.RequestType != ua.SecurityTokenRequestTypeRenew {
		return c.fail(ua.StatusBadSecurityChecksFailed, "expected Renew")
	}
	if !first && req.SecurityMode != c.mode {
		return c.fail(ua.StatusBadSecurityModeRejected, "security mode changed")
	}
	if req.SecurityMode == ua.MessageSecurityModeInvalid ||
		(policy.IsNone() != (req.SecurityMode == ua.MessageSecurityModeNone)) ||
		(c.cfg.IsAllowed != nil && !c.cfg.IsAllowed(policy.URI, req.SecurityMode)) {
		return c.fail(ua.StatusBadSecurityModeRejected, "security mode not allowed")
	}
	if !policy.IsNone() && len(req.ClientNonce) < policy.NonceLength {
		return c.fail(ua.StatusBadNonceInvalid, "client nonce too short")
	}

	lifetime := req.RequestedLifetime
	if lifetime == 0 || lifetime > c.cfg.MaxTokenLifetime {
		lifetime = c.cfg.MaxTokenLifetime
	}
	if lifetime < c.cfg.MinTokenLifetime {
		lifetime = c.cfg.MinTokenLifetime
	}

	var serverNonce []byte
	tok := &token{created: time.Now(), lifetime: time.Duration(lifetime) * time.Millisecond}
	if !policy.IsNone() {
		serverNonce = NewNonce(policy.NonceLength)
		// Client keys: secret=ServerNonce, seed=ClientNonce. Server keys: the reverse.
		tok.remote = policy.DeriveKeys(serverNonce, req.ClientNonce)
		tok.local = policy.DeriveKeys(req.ClientNonce, serverNonce)
	}

	c.mu.Lock()
	tok.id = c.nextTokenID
	c.nextTokenID++
	if first {
		c.policy = policy
		c.mode = req.SecurityMode
		c.sendToken = tok
	}
	// Keep at most the current and the new token.
	now := time.Now()
	kept := c.tokens[:0]
	for _, t := range c.tokens {
		if !t.expired(now) {
			kept = append(kept, t)
		}
	}
	if len(kept) > 1 {
		kept = kept[len(kept)-1:]
	}
	c.tokens = append(kept, tok)
	c.mu.Unlock()

	resp := &ua.OpenSecureChannelResponse{
		ResponseHeader: ua.ResponseHeader{
			Timestamp:     time.Now(),
			RequestHandle: req.RequestHeader.RequestHandle,
		},
		ServerProtocolVersion: 0,
		SecurityToken: ua.ChannelSecurityToken{
			ChannelId:       c.id,
			TokenId:         tok.id,
			CreatedAt:       tok.created,
			RevisedLifetime: lifetime,
		},
		ServerNonce: serverNonce,
	}
	if serverNonce == nil {
		resp.ServerNonce = []byte{}
	}
	return c.sendAsymmetric(reqID, resp)
}

func (c *Channel) checkSeq(seq uint32, first bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.haveRecvSeq || first {
		c.lastRecvSeq = seq
		c.haveRecvSeq = true
		return nil
	}
	expected := c.lastRecvSeq + 1
	// Sequence numbers may wrap around after 4294966271 (UInt32.MaxValue - 1024).
	if seq != expected && !(c.lastRecvSeq > 4294966271 && seq < 1024) {
		return c.fail(ua.StatusBadSequenceNumberInvalid, "invalid sequence number")
	}
	c.lastRecvSeq = seq
	return nil
}

func (c *Channel) nextSendSeq() uint32 {
	c.sendSeq++
	if c.sendSeq > 4294966271 {
		c.sendSeq = 1
	}
	return c.sendSeq
}

func (c *Channel) sendAsymmetric(reqID uint32, msg ua.Structure) error {
	body := ua.NewEncoder(512)
	body.WriteNodeId(msg.BinaryEncodingID())
	msg.Encode(body)

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	hdr := ua.NewEncoder(2048)
	hdr.WriteRaw([]byte("OPNF"))
	hdr.WriteUint32(0) // size placeholder
	hdr.WriteUint32(c.id)
	hdr.WriteString(c.policy.URI)
	if c.policy.IsNone() {
		hdr.WriteByteString(nil)
		hdr.WriteByteString(nil)
	} else {
		hdr.WriteByteString(c.cfg.Certificate)
		thumb := sha1.Sum(c.remoteCert.Raw)
		hdr.WriteByteString(thumb[:])
	}

	plain := ua.NewEncoder(body.Len() + 512)
	plain.WriteUint32(c.nextSendSeq())
	plain.WriteUint32(reqID)
	plain.WriteRaw(body.Bytes())

	var out []byte
	if c.policy.IsNone() {
		out = append(hdr.Bytes(), plain.Bytes()...)
	} else {
		pub := c.remotePub
		pb := c.policy.AsymPlainBlockSize(pub)
		sigLen := c.cfg.PrivateKey.Size()
		sizeBytes := 1
		if pub.Size() > 256 {
			sizeBytes = 2
		}
		n := plain.Len() + sizeBytes + sigLen
		pad := (pb - n%pb) % pb
		for i := 0; i < pad; i++ {
			plain.WriteUint8(byte(pad))
		}
		plain.WriteUint8(byte(pad))
		if sizeBytes == 2 {
			plain.WriteUint8(byte(pad >> 8))
		}
		blocks := (plain.Len() + sigLen) / pb
		total := hdr.Len() + blocks*pub.Size()
		if total > int(c.conn.SendBufferSize) {
			return fmt.Errorf("uasc: OPN response exceeds send buffer")
		}
		hb := hdr.Bytes()
		binary.LittleEndian.PutUint32(hb[4:], uint32(total))
		signed := append(append([]byte{}, hb...), plain.Bytes()...)
		sig, err := c.policy.AsymSign(c.cfg.PrivateKey, signed)
		if err != nil {
			return err
		}
		plain.WriteRaw(sig)
		enc, err := c.policy.AsymEncrypt(pub, plain.Bytes())
		if err != nil {
			return err
		}
		out = append(hb, enc...)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	_, err := c.conn.Write(out)
	return err
}

// --- symmetric (MSG / CLO) ---

func (c *Channel) findToken(id uint32) *token {
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
		// The client switched to a newer token: use it for sending too.
		if t != c.sendToken && t.id > c.sendToken.id {
			c.sendToken = t
			c.tokens = c.tokens[i:]
		}
		return t
	}
	return nil
}

func (c *Channel) handleSymmetric(ch *uacp.Chunk) (Request, bool, error) {
	data := ch.Data
	if len(data) < 24 {
		return Request{}, false, c.fail(ua.StatusBadDecodingError, "message too short")
	}
	channelID := binary.LittleEndian.Uint32(data[8:12])
	tokenID := binary.LittleEndian.Uint32(data[12:16])
	if channelID != c.id {
		return Request{}, false, c.fail(ua.StatusBadTcpSecureChannelUnknown, "channel id mismatch")
	}
	tok := c.findToken(tokenID)
	if tok == nil {
		return Request{}, false, c.fail(ua.StatusBadSecureChannelTokenUnknown, "unknown security token")
	}
	end := len(data)
	if c.mode == ua.MessageSecurityModeSignAndEncrypt {
		if err := c.policy.SymDecrypt(tok.remote.EncryptionKey, tok.remote.IV, data[16:]); err != nil {
			return Request{}, false, c.fail(ua.StatusBadSecurityChecksFailed, "decryption failed")
		}
	}
	if c.mode != ua.MessageSecurityModeNone {
		sl := c.policy.SymSignatureLength
		if end < 24+sl {
			return Request{}, false, c.fail(ua.StatusBadSecurityChecksFailed, "message too short")
		}
		if err := c.policy.SymVerify(tok.remote.SigningKey, data[:end-sl], data[end-sl:end]); err != nil {
			return Request{}, false, c.fail(ua.StatusBadSecurityChecksFailed, "invalid signature")
		}
		end -= sl
	}
	if c.mode == ua.MessageSecurityModeSignAndEncrypt {
		pad := int(data[end-1])
		if end-1-pad < 24 {
			return Request{}, false, c.fail(ua.StatusBadSecurityChecksFailed, "invalid padding")
		}
		end = end - 1 - pad
	}
	seq := binary.LittleEndian.Uint32(data[16:20])
	reqID := binary.LittleEndian.Uint32(data[20:24])
	if err := c.checkSeq(seq, false); err != nil {
		return Request{}, false, err
	}
	body := data[24:end]

	switch ch.ChunkType {
	case uacp.ChunkAbort:
		delete(c.chunks, reqID)
		delete(c.chunkBytes, reqID)
		return Request{}, false, nil
	case uacp.ChunkIntermediate:
		c.chunks[reqID] = append(c.chunks[reqID], body)
		c.chunkBytes[reqID] += len(body)
		if (c.conn.MaxChunkCount > 0 && uint32(len(c.chunks[reqID])) >= c.conn.MaxChunkCount) ||
			(c.conn.MaxMessageSize > 0 && uint32(c.chunkBytes[reqID]) > c.conn.MaxMessageSize) {
			return Request{}, false, c.fail(ua.StatusBadRequestTooLarge, "request too large")
		}
		if len(c.chunks) > 64 {
			return Request{}, false, c.fail(ua.StatusBadTcpNotEnoughResources, "too many pending requests")
		}
		return Request{}, false, nil
	}
	if prev, ok := c.chunks[reqID]; ok {
		total := c.chunkBytes[reqID] + len(body)
		if c.conn.MaxMessageSize > 0 && uint32(total) > c.conn.MaxMessageSize {
			return Request{}, false, c.fail(ua.StatusBadRequestTooLarge, "request too large")
		}
		full := make([]byte, 0, total)
		for _, p := range prev {
			full = append(full, p...)
		}
		body = append(full, body...)
		delete(c.chunks, reqID)
		delete(c.chunkBytes, reqID)
	}

	d := ua.NewDecoder(body)
	typeID := d.ReadNodeId()
	msg := ua.NewStructureByEncodingID(typeID)
	if msg == nil || d.Err() != nil {
		c.logf("uasc: unsupported service %s", typeID)
		_ = c.SendResponse(reqID, &ua.ServiceFault{ResponseHeader: ua.ResponseHeader{
			Timestamp: time.Now(), ServiceResult: ua.StatusBadServiceUnsupported}})
		return Request{}, false, nil
	}
	d.ReadStruct(msg)
	if d.Err() != nil {
		return Request{}, false, c.fail(ua.StatusBadDecodingError, "malformed request")
	}
	return Request{RequestID: reqID, Body: msg}, true, nil
}

// ErrResponseTooLarge is returned by SendResponse when the peer limits are exceeded.
var ErrResponseTooLarge = errors.New("uasc: response too large")

// SendResponse encodes and sends a service response, splitting it into chunks.
func (c *Channel) SendResponse(reqID uint32, msg ua.Structure) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	e := ua.NewEncoder(1024)
	e.WriteNodeId(msg.BinaryEncodingID())
	msg.Encode(e)
	body := e.Bytes()

	if c.conn.PeerMaxMessage > 0 && uint32(len(body)) > c.conn.PeerMaxMessage {
		return ErrResponseTooLarge
	}
	maxBody := c.maxChunkBody()
	nChunks := (len(body) + maxBody - 1) / maxBody
	if nChunks == 0 {
		nChunks = 1
	}
	if c.conn.PeerMaxChunks > 0 && uint32(nChunks) > c.conn.PeerMaxChunks {
		return ErrResponseTooLarge
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	tok := c.sendToken
	c.mu.Unlock()
	for i := 0; i < nChunks; i++ {
		start := i * maxBody
		end := min(start+maxBody, len(body))
		ct := byte(uacp.ChunkIntermediate)
		if i == nChunks-1 {
			ct = uacp.ChunkFinal
		}
		chunk, err := c.buildSymmetricChunk(ct, tok, reqID, body[start:end])
		if err != nil {
			return err
		}
		if _, err := c.conn.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (c *Channel) maxChunkBody() int {
	size := int(c.conn.SendBufferSize)
	switch c.mode {
	case ua.MessageSecurityModeSign:
		return size - 24 - c.policy.SymSignatureLength
	case ua.MessageSecurityModeSignAndEncrypt:
		bs := c.policy.SymBlockSize
		encRegion := (size - 16) / bs * bs
		return encRegion - 8 - c.policy.SymSignatureLength - 1
	}
	return size - 24
}

func (c *Channel) buildSymmetricChunk(chunkType byte, tok *token, reqID uint32, body []byte) ([]byte, error) {
	e := ua.NewEncoder(len(body) + 64)
	e.WriteRaw([]byte{'M', 'S', 'G', chunkType})
	e.WriteUint32(0)
	e.WriteUint32(c.id)
	e.WriteUint32(tok.id)
	e.WriteUint32(c.nextSendSeq())
	e.WriteUint32(reqID)
	e.WriteRaw(body)
	switch c.mode {
	case ua.MessageSecurityModeNone:
		b := e.Bytes()
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		return b, nil
	case ua.MessageSecurityModeSign:
		sl := c.policy.SymSignatureLength
		b := e.Bytes()
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)+sl))
		sig := c.policy.SymSign(tok.local.SigningKey, b)
		return append(b, sig...), nil
	}
	sl := c.policy.SymSignatureLength
	bs := c.policy.SymBlockSize
	n := (e.Len() - 16) + 1 + sl
	pad := (bs - n%bs) % bs
	for i := 0; i <= pad; i++ { // padding bytes plus the PaddingSize byte
		e.WriteUint8(byte(pad))
	}
	b := e.Bytes()
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)+sl))
	b = append(b, c.policy.SymSign(tok.local.SigningKey, b)...)
	if err := c.policy.SymEncrypt(tok.local.EncryptionKey, tok.local.IV, b[16:]); err != nil {
		return nil, err
	}
	return b, nil
}
