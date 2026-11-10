package uasc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"github.com/bamchoh/uastack/ua"
)

// This file holds the message framing shared by the server and the client
// side of a secure channel: building and opening asymmetric (OPN) and
// symmetric (MSG/CLO) chunks, and the sequence number rules.

// secError is a protocol error with the status code to report to the peer.
type secError struct {
	code   ua.StatusCode
	reason string
}

func (e *secError) Error() string { return fmt.Sprintf("uasc: %s: %s", e.code, e.reason) }
func (e *secError) Unwrap() error { return e.code }

func secErr(code ua.StatusCode, reason string) error { return &secError{code, reason} }

// asymHeader is the security header of an OPN chunk.
type asymHeader struct {
	channelID  uint32
	policyURI  string
	senderCert []byte
	thumbprint []byte
	end        int // offset of the (possibly encrypted) sequence header
}

func parseAsymHeader(data []byte) (asymHeader, error) {
	d := ua.NewDecoder(data[8:])
	h := asymHeader{
		channelID:  d.ReadUint32(),
		policyURI:  d.ReadString(),
		senderCert: d.ReadByteString(),
		thumbprint: d.ReadByteString(),
	}
	if d.Err() != nil {
		return h, secErr(ua.StatusBadDecodingError, "malformed security header")
	}
	h.end = 8 + d.Pos()
	return h, nil
}

// openAsym verifies and decrypts an OPN chunk and returns its plaintext,
// starting with the sequence header. local is the receiver's credential and
// senderPub the public key of the sender's certificate (both unused for None).
func openAsym(policy *SecurityPolicy, local *Credential, senderPub crypto.PublicKey, data []byte, hdrEnd int) ([]byte, error) {
	if policy.IsNone() {
		return data[hdrEnd:], nil
	}
	sigLen := policy.AsymSignatureLength(senderPub)
	if policy.IsECC() {
		// ECC: the message is signed but not encrypted and has no padding.
		if len(data) < hdrEnd+8+sigLen {
			return nil, secErr(ua.StatusBadSecurityChecksFailed, "message too short")
		}
		if err := policy.AsymVerify(senderPub, data[:len(data)-sigLen], data[len(data)-sigLen:]); err != nil {
			return nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid signature")
		}
		return data[hdrEnd : len(data)-sigLen], nil
	}
	rsaKey, _ := local.PrivateKey.(*rsa.PrivateKey)
	pt, err := policy.AsymDecrypt(rsaKey, data[hdrEnd:])
	if err != nil {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "decryption failed")
	}
	if len(pt) < 8+sigLen+1 {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "message too short")
	}
	signed := make([]byte, 0, hdrEnd+len(pt))
	signed = append(signed, data[:hdrEnd]...)
	signed = append(signed, pt[:len(pt)-sigLen]...)
	if err := policy.AsymVerify(senderPub, signed, pt[len(pt)-sigLen:]); err != nil {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid signature")
	}
	pt = pt[:len(pt)-sigLen]
	padLen := int(pt[len(pt)-1])
	sizeBytes := 1
	if rsaKey.Size() > 256 {
		padLen = int(pt[len(pt)-2]) | int(pt[len(pt)-1])<<8
		sizeBytes = 2
	}
	if len(pt) < 8+padLen+sizeBytes {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid padding")
	}
	return pt[:len(pt)-padLen-sizeBytes], nil
}

// sealAsym builds an OPN chunk. local is the sender's credential, remoteCert
// the receiver's leaf certificate (DER) and remotePub its public key.
func sealAsym(policy *SecurityPolicy, channelID uint32, local *Credential, remoteCert []byte,
	remotePub crypto.PublicKey, seq, reqID uint32, body []byte, maxSize int) ([]byte, error) {
	hdr := ua.NewEncoder(2048)
	hdr.WriteRaw([]byte("OPNF"))
	hdr.WriteUint32(0) // size placeholder
	hdr.WriteUint32(channelID)
	hdr.WriteString(policy.URI)
	if policy.IsNone() {
		hdr.WriteByteString(nil)
		hdr.WriteByteString(nil)
	} else {
		hdr.WriteByteString(local.Certificate)
		thumb := sha1.Sum(remoteCert)
		hdr.WriteByteString(thumb[:])
	}

	plain := ua.NewEncoder(len(body) + 512)
	plain.WriteUint32(seq)
	plain.WriteUint32(reqID)
	plain.WriteRaw(body)

	var out []byte
	switch {
	case policy.IsNone():
		out = append(hdr.Bytes(), plain.Bytes()...)
	case policy.IsECC():
		// Signed, not encrypted, no padding.
		sigLen := policy.AsymSignatureLength(local.PrivateKey.Public())
		hb := hdr.Bytes()
		total := len(hb) + plain.Len() + sigLen
		if total > maxSize {
			return nil, fmt.Errorf("uasc: OPN message exceeds the send buffer")
		}
		binary.LittleEndian.PutUint32(hb[4:], uint32(total))
		out = append(hb, plain.Bytes()...)
		sig, err := policy.AsymSign(local.PrivateKey, out)
		if err != nil {
			return nil, err
		}
		out = append(out, sig...)
	default:
		pub, ok := remotePub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("uasc: %s needs an RSA peer certificate", policy.Name)
		}
		pb := policy.AsymPlainBlockSize(pub)
		sigLen := policy.AsymSignatureLength(local.PrivateKey.Public())
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
		if total > maxSize {
			return nil, fmt.Errorf("uasc: OPN message exceeds the send buffer")
		}
		hb := hdr.Bytes()
		binary.LittleEndian.PutUint32(hb[4:], uint32(total))
		signed := append(append([]byte{}, hb...), plain.Bytes()...)
		sig, err := policy.AsymSign(local.PrivateKey, signed)
		if err != nil {
			return nil, err
		}
		plain.WriteRaw(sig)
		enc, err := policy.AsymEncrypt(pub, plain.Bytes())
		if err != nil {
			return nil, err
		}
		out = append(hb, enc...)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// openSym verifies and decrypts a MSG/CLO chunk in place with the sender's
// keys and returns the sequence number, request id and body.
func openSym(policy *SecurityPolicy, mode ua.MessageSecurityMode, keys *Keys, data []byte) (seq, reqID uint32, body []byte, err error) {
	if len(data) < 24 {
		return 0, 0, nil, secErr(ua.StatusBadDecodingError, "message too short")
	}
	end := len(data)
	if mode == ua.MessageSecurityModeSignAndEncrypt {
		if err := policy.SymDecrypt(keys.EncryptionKey, keys.IV, data[16:]); err != nil {
			return 0, 0, nil, secErr(ua.StatusBadSecurityChecksFailed, "decryption failed")
		}
	}
	if mode != ua.MessageSecurityModeNone {
		sl := policy.SymSignatureLength
		if end < 24+sl {
			return 0, 0, nil, secErr(ua.StatusBadSecurityChecksFailed, "message too short")
		}
		if err := policy.SymVerify(keys.SigningKey, data[:end-sl], data[end-sl:end]); err != nil {
			return 0, 0, nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid signature")
		}
		end -= sl
	}
	if mode == ua.MessageSecurityModeSignAndEncrypt {
		pad := int(data[end-1])
		if end-1-pad < 24 {
			return 0, 0, nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid padding")
		}
		end = end - 1 - pad
	}
	seq = binary.LittleEndian.Uint32(data[16:20])
	reqID = binary.LittleEndian.Uint32(data[20:24])
	return seq, reqID, data[24:end], nil
}

// sealSym builds a MSG or CLO chunk secured with the sender's keys.
func sealSym(policy *SecurityPolicy, mode ua.MessageSecurityMode, msgType string, chunkType byte,
	channelID, tokenID uint32, keys *Keys, seq, reqID uint32, body []byte) ([]byte, error) {
	e := ua.NewEncoder(len(body) + 64)
	e.WriteRaw([]byte{msgType[0], msgType[1], msgType[2], chunkType})
	e.WriteUint32(0)
	e.WriteUint32(channelID)
	e.WriteUint32(tokenID)
	e.WriteUint32(seq)
	e.WriteUint32(reqID)
	e.WriteRaw(body)
	switch mode {
	case ua.MessageSecurityModeNone:
		b := e.Bytes()
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		return b, nil
	case ua.MessageSecurityModeSign:
		sl := policy.SymSignatureLength
		b := e.Bytes()
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)+sl))
		sig := policy.SymSign(keys.SigningKey, b)
		return append(b, sig...), nil
	}
	sl := policy.SymSignatureLength
	bs := policy.SymBlockSize
	n := (e.Len() - 16) + 1 + sl
	pad := (bs - n%bs) % bs
	for i := 0; i <= pad; i++ { // padding bytes plus the PaddingSize byte
		e.WriteUint8(byte(pad))
	}
	b := e.Bytes()
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)+sl))
	b = append(b, policy.SymSign(keys.SigningKey, b)...)
	if err := policy.SymEncrypt(keys.EncryptionKey, keys.IV, b[16:]); err != nil {
		return nil, err
	}
	return b, nil
}

// maxChunkBody returns the largest body that fits into one symmetric chunk.
func maxChunkBody(policy *SecurityPolicy, mode ua.MessageSecurityMode, bufferSize int) int {
	switch mode {
	case ua.MessageSecurityModeSign:
		return bufferSize - 24 - policy.SymSignatureLength
	case ua.MessageSecurityModeSignAndEncrypt:
		bs := policy.SymBlockSize
		encRegion := (bufferSize - 16) / bs * bs
		return encRegion - 8 - policy.SymSignatureLength - 1
	}
	return bufferSize - 24
}

// recvSeq checks received sequence numbers (Part 6, 6.7.2.4).
type recvSeq struct {
	legacy bool // RSA and None policies use legacy sequence numbers
	have   bool
	last   uint32
}

func (r *recvSeq) check(seq uint32) bool {
	if !r.have {
		// Non legacy (ECC) sequence numbers must start at 0.
		if !r.legacy && seq != 0 {
			return false
		}
		r.last, r.have = seq, true
		return true
	}
	ok := seq == r.last+1 && r.last != 0xFFFFFFFF
	if !ok {
		if r.legacy {
			// Legacy numbers wrap after UInt32.MaxValue - 1024 to a value below 1024.
			ok = r.last > 4294966271 && seq < 1024
		} else {
			// Non legacy numbers wrap from UInt32.MaxValue to 0.
			ok = r.last == 0xFFFFFFFF && seq == 0
		}
	}
	if ok {
		r.last = seq
	}
	return ok
}

// sendSeq produces sequence numbers for sent chunks.
type sendSeq struct {
	legacy bool
	v      uint32 // next number (non legacy) or last sent number (legacy)
}

func (s *sendSeq) next() uint32 {
	if !s.legacy {
		v := s.v // starts at 0 and wraps from UInt32.MaxValue to 0
		s.v++
		return v
	}
	s.v++
	if s.v > 4294966271 {
		s.v = 1
	}
	return s.v
}
