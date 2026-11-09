package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"opcuasrv/ua"
)

// newUserCert creates a self-signed certificate without an application URI,
// as typically used for X509 user identity tokens.
func newUserCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TestUser"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateUserCertificate(t *testing.T) {
	store := &CertificateStore{Root: t.TempDir()}
	cert := newUserCert(t)

	// Unknown user certificates are rejected and stored in the rejected directory.
	if err := store.ValidateUser(cert); err != ua.StatusBadCertificateUntrusted {
		t.Fatalf("untrusted user cert: got %v", err)
	}
	if len(store.readDir("rejected")) != 1 {
		t.Fatal("rejected certificate was not stored")
	}

	if err := store.Trust(cert); err != nil {
		t.Fatal(err)
	}
	// A trusted user certificate needs no application URI ...
	if err := store.ValidateUser(cert); err != nil {
		t.Fatalf("trusted user cert: got %v", err)
	}
	// ... but an application instance certificate does.
	if err := store.Validate([]*x509.Certificate{cert}); err != ua.StatusBadCertificateUriInvalid {
		t.Fatalf("application cert without URI: got %v", err)
	}
}
