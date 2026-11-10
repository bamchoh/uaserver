package uasc

import (
	"crypto/ecdh"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/bamchoh/uaserver/ua"
)

// This file implements the EccEncryptedSecret format (Part 4, 7.41.2.3),
// used to send passwords on endpoints with an ECC user token policy.
//
// The receiver (the server) hands out a signed ephemeral key in the
// ECDHKey additional header. The sender creates its own ephemeral key,
// derives an AES key from the ECDH secret, encrypts the secret and signs the
// whole structure with its application certificate.

// eccEncryptedSecretTypeID is the DataType id of EccEncryptedSecret.
var eccEncryptedSecretTypeID = ua.NewNumericNodeId(0, 17546)

var secretLabel = []byte("opcua-secret")

// ErrUnsupportedPolicy is returned for operations a policy does not support.
var ErrUnsupportedPolicy = errors.New("uasc: operation not supported by the security policy")

// SignEphemeralKey signs an ephemeral public key (nonce form) with the
// server's application key, as sent in the ECDHKey additional header.
func (p *SecurityPolicy) SignEphemeralKey(cred *Credential, publicKey []byte) ([]byte, error) {
	return p.AsymSign(cred.PrivateKey, publicKey)
}

// secretKeys derives the AES key and IV of an EccEncryptedSecret.
func (p *SecurityPolicy) secretKeys(priv *ecdh.PrivateKey, remote []byte, senderNonce, receiverNonce []byte) (key, iv []byte, err error) {
	pub, err := p.ParseNonce(remote)
	if err != nil {
		return nil, nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, ErrSecurity
	}
	n := p.SymEncryptionKeyLength + p.SymBlockSize
	salt := binary.LittleEndian.AppendUint16(nil, uint16(n))
	salt = append(salt, secretLabel...)
	salt = append(salt, senderNonce...)
	salt = append(salt, receiverNonce...)
	b := hkdf(p.symHash, shared, salt, n)
	return b[:p.SymEncryptionKeyLength], b[p.SymEncryptionKeyLength:], nil
}

// secretPadding returns the number of padding bytes (Part 4, 7.41.2.3).
func secretPadding(blockSize, secretLen, dataLen int) int {
	dataLen += 2 // the padding size
	pad := 0
	if dataLen%blockSize != 0 {
		pad = blockSize - dataLen%blockSize
	}
	if pad+secretLen < blockSize {
		pad += blockSize
	}
	return pad
}

// EncryptSecretECC encodes secret as an EccEncryptedSecret for the receiver's
// ephemeral key (receiverKey, nonce form). nonce is the receiver's session
// nonce. sender signs the structure; its certificate is included unless
// omitCertificate is set (allowed when the receiver knows it from a secure
// channel).
func (p *SecurityPolicy) EncryptSecretECC(sender *Credential, omitCertificate bool, receiverKey, nonce, secret []byte) ([]byte, error) {
	if !p.IsECC() {
		return nil, ErrUnsupportedPolicy
	}
	if sender == nil || sender.PrivateKey == nil {
		return nil, fmt.Errorf("uasc: an EccEncryptedSecret needs the sender's ECC certificate")
	}
	certs, err := x509.ParseCertificates(sender.Certificate)
	if err != nil || len(certs) == 0 || !p.CertificateKeyAllowed(certs[0].PublicKey) {
		return nil, fmt.Errorf("uasc: the sender certificate cannot be used with %s", p.Name)
	}
	eph, senderNonce, err := p.NewEphemeralKey()
	if err != nil {
		return nil, err
	}
	key, iv, err := p.secretKeys(eph, receiverKey, senderNonce, receiverKey)
	if err != nil {
		return nil, fmt.Errorf("uasc: invalid receiver ephemeral key: %w", err)
	}

	e := ua.NewEncoder(512 + len(secret))
	e.WriteNodeId(eccEncryptedSecretTypeID)
	e.WriteUint8(1) // binary body
	lengthPos := e.Len()
	e.WriteUint32(0)
	e.WriteString(p.URI)
	if omitCertificate {
		e.WriteByteString(nil)
	} else {
		e.WriteByteString(sender.Certificate)
	}
	e.WriteDateTime(time.Now())
	e.WriteUint16(uint16(len(senderNonce) + len(receiverKey) + 8))
	e.WriteByteString(senderNonce)
	e.WriteByteString(receiverKey)
	start := e.Len()
	e.WriteByteString(nonce)
	e.WriteByteString(secret)
	pad := secretPadding(p.SymBlockSize, len(secret), e.Len()-start)
	for range pad {
		e.WriteUint8(byte(pad))
	}
	e.WriteUint8(byte(pad))
	e.WriteUint8(0)
	end := e.Len()
	sigLen := p.AsymSignatureLength(sender.PrivateKey.Public())

	b := append(e.Bytes(), make([]byte, sigLen)...)
	binary.LittleEndian.PutUint32(b[lengthPos:], uint32(len(b)-lengthPos-4))
	if err := p.SymEncrypt(key, iv, b[start:end]); err != nil {
		return nil, err
	}
	sig, err := p.AsymSign(sender.PrivateKey, b[:end])
	if err != nil {
		return nil, err
	}
	copy(b[end:], sig)
	return b, nil
}

// DecryptSecretECC decodes an EccEncryptedSecret sent to the ephemeral key
// receiverKey. senderCert is used when the structure does not contain the
// sender certificate; otherwise the contained certificate must be the same
// one. The structure's nonce must equal expectedNonce.
func (p *SecurityPolicy) DecryptSecretECC(data []byte, receiverKey *ecdh.PrivateKey, senderCert *x509.Certificate, expectedNonce []byte) ([]byte, error) {
	if !p.IsECC() {
		return nil, ErrUnsupportedPolicy
	}
	d := ua.NewDecoder(data)
	if d.ReadNodeId() != eccEncryptedSecretTypeID || d.ReadUint8() != 1 {
		return nil, secErr(ua.StatusBadDataTypeIdUnknown, "not an EccEncryptedSecret")
	}
	length := int(d.ReadUint32())
	if d.Err() != nil || length != d.Remaining() {
		return nil, secErr(ua.StatusBadDecodingError, "invalid EccEncryptedSecret length")
	}
	if d.ReadString() != p.URI {
		return nil, secErr(ua.StatusBadSecurityPolicyRejected, "EccEncryptedSecret uses another security policy")
	}
	if certData := d.ReadByteString(); len(certData) > 0 {
		chain, err := x509.ParseCertificates(certData)
		if err != nil || len(chain) == 0 {
			return nil, secErr(ua.StatusBadCertificateInvalid, "invalid sender certificate")
		}
		if senderCert != nil && string(chain[0].Raw) != string(senderCert.Raw) {
			return nil, secErr(ua.StatusBadCertificateInvalid, "the sender certificate is not the session's certificate")
		}
		senderCert = chain[0]
	}
	if senderCert == nil || !p.CertificateKeyAllowed(senderCert.PublicKey) {
		return nil, secErr(ua.StatusBadCertificateInvalid, "no usable sender certificate")
	}
	signingTime := d.ReadDateTime()
	if time.Since(signingTime) > time.Hour || time.Until(signingTime) > 5*time.Minute {
		return nil, secErr(ua.StatusBadInvalidTimestamp, "EccEncryptedSecret signing time out of range")
	}
	keyDataLen := int(d.ReadUint16())
	senderNonce := d.ReadByteString()
	receiverNonce := d.ReadByteString()
	if d.Err() != nil || keyDataLen != len(senderNonce)+len(receiverNonce)+8 {
		return nil, secErr(ua.StatusBadDecodingError, "invalid EccEncryptedSecret key data")
	}
	if string(receiverNonce) != string(receiverKey.PublicKey().Bytes()[1:]) {
		return nil, secErr(ua.StatusBadNonceInvalid, "EccEncryptedSecret was encrypted for another ephemeral key")
	}
	start := d.Pos()
	sigLen := p.AsymSignatureLength(senderCert.PublicKey)
	end := len(data) - sigLen
	if end <= start || (end-start)%p.SymBlockSize != 0 {
		return nil, secErr(ua.StatusBadDecodingError, "invalid EccEncryptedSecret size")
	}
	if err := p.AsymVerify(senderCert.PublicKey, data[:end], data[end:]); err != nil {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "invalid EccEncryptedSecret signature")
	}
	key, iv, err := p.secretKeys(receiverKey, senderNonce, senderNonce, receiverNonce)
	if err != nil {
		return nil, secErr(ua.StatusBadNonceInvalid, "invalid sender ephemeral key")
	}
	plain := append([]byte(nil), data[start:end]...)
	if err := p.SymDecrypt(key, iv, plain); err != nil {
		return nil, secErr(ua.StatusBadSecurityChecksFailed, "decryption failed")
	}
	pd := ua.NewDecoder(plain)
	nonce := pd.ReadByteString()
	secret := pd.ReadByteString()
	pad := int(pd.ReadUint8())
	bad := 0
	for range pad {
		bad |= int(pd.ReadUint8()) ^ pad
	}
	bad |= int(pd.ReadUint8()) // high byte of the padding size
	if pd.Err() != nil || bad != 0 || pd.Remaining() != 0 {
		return nil, secErr(ua.StatusBadDecodingError, "invalid EccEncryptedSecret padding")
	}
	if subtle.ConstantTimeCompare(nonce, expectedNonce) != 1 {
		return nil, secErr(ua.StatusBadNonceInvalid, "EccEncryptedSecret nonce mismatch")
	}
	return secret, nil
}
