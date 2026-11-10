package server

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"time"

	"github.com/bamchoh/uastack/uacert"
)

// CertificateStore is the certificate store used by the server. It is an
// alias of uacert.Store, which is shared with the client.
type CertificateStore = uacert.Store

// Thumbprint returns the upper case hex SHA1 thumbprint of a DER certificate.
func Thumbprint(der []byte) string { return uacert.Thumbprint(der) }

// CertificateURI returns the application URI from the subject alternative name.
func CertificateURI(c *x509.Certificate) string { return uacert.CertificateURI(c) }

// CreateSelfSigned creates a self-signed RSA OPC UA application instance certificate.
func CreateSelfSigned(appURI, appName string, hosts []string, bits int, validity time.Duration) ([]byte, crypto.Signer, error) {
	return uacert.CreateSelfSigned(appURI, appName, hosts, bits, validity)
}

// CreateSelfSignedECC creates a self-signed ECDSA OPC UA application instance certificate.
func CreateSelfSignedECC(appURI, appName string, hosts []string, curve elliptic.Curve, validity time.Duration) ([]byte, crypto.Signer, error) {
	return uacert.CreateSelfSignedECC(appURI, appName, hosts, curve, validity)
}
