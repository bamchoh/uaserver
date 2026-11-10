package client

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/uasc"
)

// Identity is the user identity of a session: Anonymous(), UserName(...) or
// X509(...).
type Identity interface {
	// token builds the identity token for ActivateSession.
	token(c *Client, serverNonce []byte) (ua.ExtensionObject, ua.SignatureData, error)
}

// Anonymous returns the anonymous identity.
func Anonymous() Identity { return anonymous{} }

// UserName returns a user name and password identity. On secure policies
// the password is encrypted with the server certificate.
func UserName(user, password string) Identity { return userName{user, password} }

// X509 returns an identity that proves possession of a user certificate
// (DER) by signing with its private key.
func X509(certificate []byte, key crypto.Signer) Identity { return x509Identity{certificate, key} }

type anonymous struct{}

func (anonymous) token(c *Client, _ []byte) (ua.ExtensionObject, ua.SignatureData, error) {
	p, err := c.tokenPolicy(ua.UserTokenTypeAnonymous)
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, err
	}
	return ua.NewExtensionObject(&ua.AnonymousIdentityToken{PolicyId: p.PolicyId}), ua.SignatureData{}, nil
}

type userName struct{ user, password string }

func (u userName) token(c *Client, serverNonce []byte) (ua.ExtensionObject, ua.SignatureData, error) {
	p, err := c.tokenPolicy(ua.UserTokenTypeUserName)
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, err
	}
	sp := c.tokenSecurity(p)
	if sp == nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: user token policy %q uses the unsupported security policy %s",
			p.PolicyId, p.SecurityPolicyUri)
	}
	tok := &ua.UserNameIdentityToken{PolicyId: p.PolicyId, UserName: u.user}
	if sp.IsNone() {
		// Sent in clear text; only acceptable on an encrypted channel or for testing.
		tok.Password = []byte(u.password)
		return ua.NewExtensionObject(tok), ua.SignatureData{}, nil
	}
	if sp.IsECC() {
		return u.eccToken(c, tok, sp, serverNonce)
	}
	cert, err := x509.ParseCertificate(leaf(c.currentServerCert()))
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: the server has no certificate to encrypt the password with")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: the server certificate is not an RSA certificate")
	}
	// Length (4 bytes, little endian) | password | server nonce (Part 4, 7.36.2.2).
	secret := make([]byte, 4, 4+len(u.password)+len(serverNonce))
	binary.LittleEndian.PutUint32(secret, uint32(len(u.password)+len(serverNonce)))
	secret = append(append(secret, u.password...), serverNonce...)
	enc, err := sp.AsymEncrypt(pub, secret)
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: encrypting the password: %w", err)
	}
	tok.Password = enc
	tok.EncryptionAlgorithm = sp.AsymEncryptionAlgorithm
	return ua.NewExtensionObject(tok), ua.SignatureData{}, nil
}

// eccToken encrypts the password as an EccEncryptedSecret for the server's
// ephemeral key (Part 4, 7.41.2.3).
func (u userName) eccToken(c *Client, tok *ua.UserNameIdentityToken, sp *uasc.SecurityPolicy, serverNonce []byte) (ua.ExtensionObject, ua.SignatureData, error) {
	c.mu.Lock()
	key := c.eccKey
	c.mu.Unlock()
	if key == nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: the server sent no ephemeral key to encrypt the password: %w",
			ua.StatusBadIdentityTokenInvalid)
	}
	// The secret is signed with an ECC application certificate. On a secure
	// channel with that certificate the server already knows it.
	cred := c.local
	omit := c.endpoint.SecurityMode != ua.MessageSecurityModeNone
	if cred == nil || !sp.CertificateKeyAllowed(cred.PrivateKey.Public()) {
		var err error
		if cred, err = c.applicationCredential(sp); err != nil {
			return ua.ExtensionObject{}, ua.SignatureData{}, err
		}
		omit = false
	}
	enc, err := sp.EncryptSecretECC(cred, omit, key, serverNonce, []byte(u.password))
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: encrypting the password: %w", err)
	}
	tok.Password = enc
	return ua.NewExtensionObject(tok), ua.SignatureData{}, nil
}

type x509Identity struct {
	cert []byte
	key  crypto.Signer
}

func (x x509Identity) token(c *Client, serverNonce []byte) (ua.ExtensionObject, ua.SignatureData, error) {
	p, err := c.tokenPolicy(ua.UserTokenTypeCertificate)
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, err
	}
	sp := c.tokenSecurity(p)
	if sp == nil || sp.IsNone() {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: user token policy %q has no usable security policy", p.PolicyId)
	}
	if x.key == nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: X509 identity without a private key")
	}
	if !sp.CertificateKeyAllowed(x.key.Public()) {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: the user certificate key cannot be used with %s", sp.Name)
	}
	data := append(append([]byte{}, leaf(c.currentServerCert())...), serverNonce...)
	sig, err := sp.AsymSign(x.key, data)
	if err != nil {
		return ua.ExtensionObject{}, ua.SignatureData{}, fmt.Errorf("client: signing the user token: %w", err)
	}
	tok := &ua.X509IdentityToken{PolicyId: p.PolicyId, CertificateData: x.cert}
	return ua.NewExtensionObject(tok), ua.SignatureData{Algorithm: sp.AsymSignatureAlgorithm, Signature: sig}, nil
}

// tokenPolicy finds the endpoint's user token policy for a token type.
func (c *Client) tokenPolicy(t ua.UserTokenType) (*ua.UserTokenPolicy, error) {
	for i := range c.endpoint.UserIdentityTokens {
		p := &c.endpoint.UserIdentityTokens[i]
		if p.TokenType == t {
			return p, nil
		}
	}
	return nil, fmt.Errorf("client: the endpoint does not accept %s identity tokens: %w", t, ua.StatusBadIdentityTokenInvalid)
}

// tokenSecurity returns the security policy that secures a user token.
func (c *Client) tokenSecurity(p *ua.UserTokenPolicy) *uasc.SecurityPolicy {
	if p.SecurityPolicyUri != "" {
		return uasc.PolicyByURI(p.SecurityPolicyUri)
	}
	return c.policy
}

func (c *Client) currentServerCert() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverCert
}
