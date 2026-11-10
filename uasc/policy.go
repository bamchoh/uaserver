package uasc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/bamchoh/uastack/ua"
)

// Security policy URIs.
const (
	SecurityPolicyNone                = "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityPolicyBasic256Sha256      = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	SecurityPolicyAes128Sha256RsaOaep = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	SecurityPolicyAes256Sha256RsaPss  = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
	SecurityPolicyEccNistP256         = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256"
	SecurityPolicyEccNistP384         = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384"
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

	// NonceLength is the length of the secure channel nonce. For ECC
	// policies the nonce is an ephemeral public key (X|Y).
	NonceLength int

	// Symmetric algorithms.
	SymSigningKeyLength    int
	SymEncryptionKeyLength int
	SymBlockSize           int
	SymSignatureLength     int

	// Asymmetric algorithms.
	MinAsymKeyBits          int
	MaxAsymKeyBits          int
	AsymSignatureAlgorithm  string // empty for ECDSA (the .NET stack sends null)
	AsymEncryptionAlgorithm string // empty for ECC (no asymmetric encryption)

	oaepHash func() hash.Hash
	pss      bool
	symHash  func() hash.Hash
	asymHash crypto.Hash

	// ECC policies.
	ecdhCurve  ecdh.Curve
	certCurves []elliptic.Curve // curves allowed for certificates
}

// IsNone reports whether the policy is the None policy.
func (p *SecurityPolicy) IsNone() bool { return p.URI == SecurityPolicyNone }

// IsECC reports whether the policy uses elliptic curve cryptography.
func (p *SecurityPolicy) IsECC() bool { return p.ecdhCurve != nil }

// CertCurve returns the curve of the application certificate used with an
// ECC policy, or nil for RSA policies.
func (p *SecurityPolicy) CertCurve() elliptic.Curve {
	if len(p.certCurves) == 0 {
		return nil
	}
	return p.certCurves[0]
}

var policies = map[string]*SecurityPolicy{
	SecurityPolicyNone: {URI: SecurityPolicyNone, Name: "None"},
	SecurityPolicyBasic256Sha256: {
		URI: SecurityPolicyBasic256Sha256, Name: "Basic256Sha256", SecurityLevel: 3,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 32, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaep,
		oaepHash: sha1.New, symHash: sha256.New, asymHash: crypto.SHA256,
	},
	SecurityPolicyAes128Sha256RsaOaep: {
		URI: SecurityPolicyAes128Sha256RsaOaep, Name: "Aes128_Sha256_RsaOaep", SecurityLevel: 2,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 16, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaep,
		oaepHash: sha1.New, symHash: sha256.New, asymHash: crypto.SHA256,
	},
	SecurityPolicyAes256Sha256RsaPss: {
		URI: SecurityPolicyAes256Sha256RsaPss, Name: "Aes256_Sha256_RsaPss", SecurityLevel: 4,
		NonceLength: 32, SymSigningKeyLength: 32, SymEncryptionKeyLength: 32, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 2048, MaxAsymKeyBits: 4096,
		AsymSignatureAlgorithm: AlgorithmRsaPssSha256, AsymEncryptionAlgorithm: AlgorithmRsaOaepSha256,
		oaepHash: sha256.New, pss: true, symHash: sha256.New, asymHash: crypto.SHA256,
	},
	// ECC policies (Part 7; parameters as in the .NET stack's SecurityPolicyInfo).
	SecurityPolicyEccNistP256: {
		URI: SecurityPolicyEccNistP256, Name: "ECC_nistP256", SecurityLevel: 3,
		NonceLength: 64, SymSigningKeyLength: 32, SymEncryptionKeyLength: 16, SymBlockSize: 16, SymSignatureLength: 32,
		MinAsymKeyBits: 256, MaxAsymKeyBits: 384,
		symHash: sha256.New, asymHash: crypto.SHA256,
		ecdhCurve: ecdh.P256(), certCurves: []elliptic.Curve{elliptic.P256(), elliptic.P384()},
	},
	SecurityPolicyEccNistP384: {
		URI: SecurityPolicyEccNistP384, Name: "ECC_nistP384", SecurityLevel: 5,
		NonceLength: 96, SymSigningKeyLength: 48, SymEncryptionKeyLength: 32, SymBlockSize: 16, SymSignatureLength: 48,
		MinAsymKeyBits: 384, MaxAsymKeyBits: 384,
		symHash: sha512.New384, asymHash: crypto.SHA384,
		ecdhCurve: ecdh.P384(), certCurves: []elliptic.Curve{elliptic.P384()},
	},
}

// PolicyByURI returns the security policy for a URI, or nil if unsupported.
func PolicyByURI(uri string) *SecurityPolicy { return policies[uri] }

// SupportedPolicies returns the URIs of all supported policies.
func SupportedPolicies() []string {
	return []string{SecurityPolicyNone, SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep,
		SecurityPolicyAes256Sha256RsaPss, SecurityPolicyEccNistP256, SecurityPolicyEccNistP384}
}

// --- asymmetric ---

// CertificateKeyAllowed reports whether a certificate public key may be used with the policy.
func (p *SecurityPolicy) CertificateKeyAllowed(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return !p.IsECC() && bits >= p.MinAsymKeyBits && bits <= p.MaxAsymKeyBits
	case *ecdsa.PublicKey:
		for _, c := range p.certCurves {
			if k.Curve == c {
				return true
			}
		}
	}
	return false
}

// AsymSignatureLength returns the length of a signature made with the key of pub.
func (p *SecurityPolicy) AsymSignatureLength(pub crypto.PublicKey) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.Size()
	case *ecdsa.PublicKey:
		return 2 * coordLen(k.Curve)
	}
	return 0
}

func coordLen(c elliptic.Curve) int { return (c.Params().BitSize + 7) / 8 }

// AsymPlainBlockSize returns the plaintext block size for RSA encryption with key pub.
func (p *SecurityPolicy) AsymPlainBlockSize(pub *rsa.PublicKey) int {
	return pub.Size() - 2*p.oaepHash().Size() - 2
}

// AsymEncrypt encrypts data (whose length is a multiple of the plain block size) block by block.
func (p *SecurityPolicy) AsymEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	if p.oaepHash == nil {
		return nil, fmt.Errorf("uasc: %s has no asymmetric encryption", p.Name)
	}
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
	if p.oaepHash == nil || priv == nil {
		return nil, ErrSecurity
	}
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

func (p *SecurityPolicy) digest(data []byte) []byte {
	h := p.asymHash.New()
	h.Write(data)
	return h.Sum(nil)
}

// AsymSign signs data with an RSA or ECDSA private key. ECDSA signatures use
// the fixed length r|s format (IEEE P1363) used by OPC UA.
func (p *SecurityPolicy) AsymSign(key crypto.Signer, data []byte) ([]byte, error) {
	h := p.digest(data)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if p.pss {
			return rsa.SignPSS(rand.Reader, k, p.asymHash, h, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.SignPKCS1v15(rand.Reader, k, p.asymHash, h)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, h)
		if err != nil {
			return nil, err
		}
		n := coordLen(k.Curve)
		sig := make([]byte, 2*n)
		r.FillBytes(sig[:n])
		s.FillBytes(sig[n:])
		return sig, nil
	}
	return nil, fmt.Errorf("uasc: unsupported private key %T", key)
}

// AsymVerify verifies a signature made with AsymSign.
func (p *SecurityPolicy) AsymVerify(pub crypto.PublicKey, data, sig []byte) error {
	h := p.digest(data)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		var err error
		if p.pss {
			err = rsa.VerifyPSS(k, p.asymHash, h, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		} else {
			err = rsa.VerifyPKCS1v15(k, p.asymHash, h, sig)
		}
		if err == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		n := coordLen(k.Curve)
		if len(sig) == 2*n {
			r := new(big.Int).SetBytes(sig[:n])
			s := new(big.Int).SetBytes(sig[n:])
			if ecdsa.Verify(k, h, r, s) {
				return nil
			}
		}
	}
	return ErrSecurity
}

// --- ECC key exchange ---

// NewEphemeralKey creates an ephemeral ECDH key and returns it with its nonce encoding (X|Y).
func (p *SecurityPolicy) NewEphemeralKey() (*ecdh.PrivateKey, []byte, error) {
	k, err := p.ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k, k.PublicKey().Bytes()[1:], nil // strip the 0x04 uncompressed point prefix
}

// ParseNonce decodes a peer's ephemeral public key from its nonce encoding (X|Y).
func (p *SecurityPolicy) ParseNonce(nonce []byte) (*ecdh.PublicKey, error) {
	if len(nonce) != p.NonceLength {
		return nil, ErrSecurity
	}
	k, err := p.ecdhCurve.NewPublicKey(append([]byte{4}, nonce...))
	if err != nil {
		return nil, ErrSecurity
	}
	return k, nil
}

// DeriveECCKeys derives the client and server key sets from an ECDH secret
// with HKDF (Part 6, 6.8.1). With signOnly only signing keys are derived.
func (p *SecurityPolicy) DeriveECCKeys(secret, clientNonce, serverNonce []byte, signOnly bool) (client, server Keys) {
	n := p.SymSigningKeyLength
	if !signOnly {
		n += p.SymEncryptionKeyLength + p.SymBlockSize
	}
	salt := func(label string, a, b []byte) []byte {
		s := binary.LittleEndian.AppendUint16(nil, uint16(n))
		s = append(s, label...)
		s = append(s, a...)
		return append(s, b...)
	}
	split := func(b []byte) Keys {
		k := Keys{SigningKey: b[:p.SymSigningKeyLength]}
		if !signOnly {
			e := p.SymSigningKeyLength + p.SymEncryptionKeyLength
			k.EncryptionKey = b[p.SymSigningKeyLength:e]
			k.IV = b[e : e+p.SymBlockSize]
		}
		return k
	}
	client = split(hkdf(p.symHash, secret, salt("opcua-client", clientNonce, serverNonce), n))
	server = split(hkdf(p.symHash, secret, salt("opcua-server", serverNonce, clientNonce), n))
	return client, server
}

// hkdf implements RFC 5869 with the salt also used as the expand info, as
// the OPC UA stacks do.
func hkdf(h func() hash.Hash, secret, salt []byte, length int) []byte {
	m := hmac.New(h, salt)
	m.Write(secret)
	prk := m.Sum(nil)
	out := make([]byte, 0, length+64)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		m = hmac.New(h, prk)
		m.Write(t)
		m.Write(salt)
		m.Write([]byte{counter})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// --- symmetric ---

// SymSign computes the HMAC (SHA256 or SHA384) of data.
func (p *SecurityPolicy) SymSign(key, data []byte) []byte {
	m := hmac.New(p.symHash, key)
	m.Write(data)
	return m.Sum(nil)
}

// SymVerify checks an HMAC signature.
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
