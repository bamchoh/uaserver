package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"opcuasrv/ua"
)

// CertificateStore manages the application instance certificate and the
// trust lists, using the same directory layout as the .NET stack:
//
//	<root>/own/certs, <root>/own/private, <root>/trusted/certs,
//	<root>/issuer/certs, <root>/rejected/certs
type CertificateStore struct {
	Root string
	// AutoAccept trusts unknown client certificates automatically (for testing only).
	AutoAccept bool
	mu         sync.Mutex
}

// Thumbprint returns the upper case hex SHA1 thumbprint of a DER certificate.
func Thumbprint(der []byte) string {
	s := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

func (s *CertificateStore) dir(parts ...string) string {
	return filepath.Join(append([]string{s.Root}, parts...)...)
}

// LoadOrCreateOwn loads the application certificate or creates a self-signed
// one if none exists, it expired or its application URI does not match.
func (s *CertificateStore) LoadOrCreateOwn(appURI, appName string, hosts []string) ([]byte, *rsa.PrivateKey, error) {
	certPath := s.dir("own", "certs", "cert.der")
	keyPath := s.dir("own", "private", "key.pem")
	if der, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			cert, err1 := x509.ParseCertificate(der)
			key, err2 := parseKey(keyPEM)
			if err1 == nil && err2 == nil && time.Now().Before(cert.NotAfter) && certHasURI(cert, appURI) {
				return der, key, nil
			}
		}
	}
	der, key, err := CreateSelfSigned(appURI, appName, hosts, 2048, 5*365*24*time.Hour)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, der, 0o644); err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	for _, d := range []string{"trusted", "issuer", "rejected"} {
		_ = os.MkdirAll(s.dir(d, "certs"), 0o755)
	}
	return der, key, nil
}

func parseKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("server: invalid key file")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("server: key is not RSA")
	}
	return rk, nil
}

func certHasURI(c *x509.Certificate, uri string) bool {
	for _, u := range c.URIs {
		if u.String() == uri {
			return true
		}
	}
	return false
}

// CertificateURI returns the application URI from the subject alternative name.
func CertificateURI(c *x509.Certificate) string {
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	return ""
}

// CreateSelfSigned creates a self-signed OPC UA application instance certificate.
func CreateSelfSigned(appURI, appName string, hosts []string, bits int, validity time.Duration) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(appURI)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: appName, Organization: []string{appName}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func (s *CertificateStore) readDir(name string) []*x509.Certificate {
	entries, err := os.ReadDir(s.dir(name, "certs"))
	if err != nil {
		return nil
	}
	var out []*x509.Certificate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(s.dir(name, "certs", e.Name()))
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(b); blk != nil {
			b = blk.Bytes
		}
		if cs, err := x509.ParseCertificates(b); err == nil {
			out = append(out, cs...)
		}
	}
	return out
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9 ._-]`)

// Reject stores a certificate in the rejected directory.
func (s *CertificateStore) Reject(c *x509.Certificate) {
	name := unsafeFileChars.ReplaceAllString(c.Subject.CommonName, "_")
	p := s.dir("rejected", "certs", fmt.Sprintf("%s [%s].der", name, Thumbprint(c.Raw)))
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, c.Raw, 0o644)
}

// Trust stores a certificate in the trusted directory.
func (s *CertificateStore) Trust(c *x509.Certificate) error {
	name := unsafeFileChars.ReplaceAllString(c.Subject.CommonName, "_")
	p := s.dir("trusted", "certs", fmt.Sprintf("%s [%s].der", name, Thumbprint(c.Raw)))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, c.Raw, 0o644)
}

// Validate checks a certificate chain sent by a client. The trust list is
// re-read on every call so that certificates moved from rejected to trusted
// take effect without a restart.
func (s *CertificateStore) Validate(chain []*x509.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(chain) == 0 {
		return ua.StatusBadCertificateInvalid
	}
	leaf := chain[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return ua.StatusBadCertificateTimeInvalid
	}
	if CertificateURI(leaf) == "" {
		return ua.StatusBadCertificateUriInvalid
	}
	trusted := s.readDir("trusted")
	for _, t := range trusted {
		if string(t.Raw) == string(leaf.Raw) {
			return nil
		}
	}
	roots := x509.NewCertPool()
	haveRoots := false
	for _, t := range trusted {
		if t.IsCA {
			roots.AddCert(t)
			haveRoots = true
		}
	}
	if haveRoots {
		inter := x509.NewCertPool()
		for _, c := range s.readDir("issuer") {
			inter.AddCert(c)
		}
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: now}); err == nil {
			return nil
		}
	}
	if s.AutoAccept {
		return s.Trust(leaf)
	}
	s.Reject(leaf)
	return ua.StatusBadCertificateUntrusted
}
