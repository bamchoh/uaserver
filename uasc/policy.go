package uasc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"opcuasrv/ua"
)

// Security policy URIs.
const (
	SecurityPolicyNone                = "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityPolicyBasic256Sha256      = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	SecurityPolicyAes128Sha256RsaOaep = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	SecurityPolicyAes256Sha256RsaPss  = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
	AlgorithmRsaSha256                = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgorithmRsaPssSha256             = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256"
	AlgorithmRsaOaep                  = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	AlgorithmRsaOaepSha256            = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
	TransportProfileUaTcp             = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
)

// ErrSecurity is returned when a signature or decryption check fails.
var ErrSecurity = errors.New("uasc: security checks failed")

// SecurityPolicy describes the algorithms of a security policy (Part 7).
type SecurityPolicy struct {
	URI  string
	Name string
	// SecurityLevel is a relative measure of the policy strength used in endpoint descriptions.
	SecurityLevel byte

	NonceLength int

	// Symmetric algorithms.
	SymSigningKeyLength    int
	SymEncryptionKeyLength int
	SymBlockSize           int
	SymSignatureLength     int

	// Asymmetric algorithms.
	MinAsymKeyBits          int
	MaxAsymKeyBits          int
	AsymSignatureAlgorithm  string
	AsymEncryptionAlgorithm string

	oaepHash func() hash.Hash
	pss      bool
}

// IsNone reports whether the policy is the None policy.
func (p *SecurityPolicy) IsNone() bool { return p.URI == SecurityPolicyNone }

var policies = map[string]*SecurityPolicy{
	SecurityPolicyNone: {URI: SecurityPolicyNone, Name: "None"},
	SecurityPolicyBasic256Sha256: {
		URI: SecurityPolicyBasic256Sha256, Name: "Basic256Sha256", SecurityLevel: 3,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 32, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaep,
		oaepHash: sha1.New,
	},
	SecurityPolicyAes128Sha256RsaOaep: {
		URI: SecurityPolicyAes128Sha256RsaOaep, Name: "Aes128_Sha256_RsaOaep", SecurityLevel: 2,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 16, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaep,
		oaepHash: sha1.New,
	},
	SecurityPolicyAes256Sha256RsaPss: {
		URI: SecurityPolicyAes256Sha256RsaPss, Name: "Aes256_Sha256_RsaPss", SecurityLevel: 4,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 32, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaPssSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaepSha256,
		oaepHash: sha256.New, pss: true,
	},
}

// PolicyByURI returns the security policy for a URI, or nil if unsupported.
func PolicyByURI(uri string) *SecurityPolicy { return policies[uri] }

// SupportedPolicies returns the URIs of all supported policies.
func SupportedPolicies() []string {
	return []string{SecurityPolicyNone, SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep, SecurityPolicyAes256Sha256RsaPss}
}

// --- asymmetric ---

// AsymPlainBlockSize returns the plaintext block size for RSA encryption with key pub.
func (p *SecurityPolicy) AsymPlainBlockSize(pub *rsa.PublicKey) int {
	return pub.Size() - 2*p.oaepHash().Size() - 2
}

// AsymEncrypt encrypts data (whose length is a multiple of the plain block size) block by block.
func (p *SecurityPolicy) AsymEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	pb := p.AsymPlainBlockSize(pub)
	out := make([]byte, 0, (len(data)+pb-1)/pb*pub.Size())
	for off := 0; off < len(data); off += pb {
		end := min(off+pb, len(data))
		c, err := rsa.EncryptOAEP(p.oaepHash(), rand.Reader, pub, data[off:end], nil)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	return out, nil
}

// AsymDecrypt decrypts data block by block with priv.
func (p *SecurityPolicy) AsymDecrypt(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	cb := priv.Size()
	if len(data)%cb != 0 {
		return nil, ErrSecurity
	}
	out := make([]byte, 0, len(data))
	for off := 0; off < len(data); off += cb {
		pt, err := rsa.DecryptOAEP(p.oaepHash(), nil, priv, data[off:off+cb], nil)
		if err != nil {
			return nil, ErrSecurity
		}
		out = append(out, pt...)
	}
	return out, nil
}

// AsymSign signs data with priv.
func (p *SecurityPolicy) AsymSign(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	if p.pss {
		return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
}

// AsymVerify verifies a signature made with AsymSign.
func (p *SecurityPolicy) AsymVerify(pub *rsa.PublicKey, data, sig []byte) error {
	h := sha256.Sum256(data)
	var err error
	if p.pss {
		err = rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	} else {
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	}
	if err != nil {
		return ErrSecurity
	}
	return nil
}

// --- symmetric ---

// SymSign computes the HMAC-SHA256 of data.
func (p *SecurityPolicy) SymSign(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// SymVerify checks an HMAC-SHA256 signature.
func (p *SecurityPolicy) SymVerify(key, data, sig []byte) error {
	if !hmac.Equal(p.SymSign(key, data), sig) {
		return ErrSecurity
	}
	return nil
}

// SymEncrypt encrypts data in place with AES-CBC (len(data) must be a multiple of the block size).
func (p *SecurityPolicy) SymEncrypt(key, iv, data []byte) error {
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	if len(data)%b.BlockSize() != 0 {
		return fmt.Errorf("uasc: data not block aligned")
	}
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(data, data)
	return nil
}

// SymDecrypt decrypts data in place with AES-CBC.
func (p *SecurityPolicy) SymDecrypt(key, iv, data []byte) error {
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	if len(data)%b.BlockSize() != 0 {
		return ErrSecurity
	}
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(data, data)
	return nil
}

// Keys holds a derived symmetric key set.
type Keys struct {
	SigningKey    []byte
	EncryptionKey []byte
	IV            []byte
}

// DeriveKeys derives a key set with P_SHA256(secret, seed) (Part 6, 6.7.5).
func (p *SecurityPolicy) DeriveKeys(secret, seed []byte) Keys {
	n := p.SymSigningKeyLength + p.SymEncryptionKeyLength + p.SymBlockSize
	b := pSHA256(secret, seed, n)
	return Keys{
		SigningKey:    b[:p.SymSigningKeyLength],
		EncryptionKey: b[p.SymSigningKeyLength : p.SymSigningKeyLength+p.SymEncryptionKeyLength],
		IV:            b[p.SymSigningKeyLength+p.SymEncryptionKeyLength:],
	}
}

func pSHA256(secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	a := seed
	for len(out) < length {
		m := hmac.New(sha256.New, secret)
		m.Write(a)
		a = m.Sum(nil)
		m = hmac.New(sha256.New, secret)
		m.Write(a)
		m.Write(seed)
		out = m.Sum(out)
	}
	return out[:length]
}

// NewNonce returns a random nonce of n bytes.
func NewNonce(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// SecurityLevel computes the endpoint security level for a policy and mode.
func SecurityLevel(policyURI string, mode ua.MessageSecurityMode) byte {
	p := PolicyByURI(policyURI)
	if p == nil || mode == ua.MessageSecurityModeNone {
		return 0
	}
	if mode == ua.MessageSecurityModeSignAndEncrypt {
		return p.SecurityLevel * 10
	}
	return p.SecurityLevel
}
