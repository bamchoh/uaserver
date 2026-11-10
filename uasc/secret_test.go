package uasc

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/bamchoh/uaserver/ua"
)

func TestEccEncryptedSecretRoundTrip(t *testing.T) {
	tc := testCredentials(t)
	for _, uri := range []string{SecurityPolicyEccNistP256, SecurityPolicyEccNistP384} {
		p := PolicyByURI(uri)
		sender := tc.forPolicy(uri)
		cert, _ := x509.ParseCertificate(sender.Certificate)
		receiver, receiverKey, err := p.NewEphemeralKey()
		if err != nil {
			t.Fatal(err)
		}
		nonce := NewNonce(32)
		for _, secret := range []string{"", "pw", "password1", "a much longer password than one AES block"} {
			for _, omit := range []bool{false, true} {
				data, err := p.EncryptSecretECC(sender, omit, receiverKey, nonce, []byte(secret))
				if err != nil {
					t.Fatal(err)
				}
				got, err := p.DecryptSecretECC(data, receiver, cert, nonce)
				if err != nil || string(got) != secret {
					t.Fatalf("%s %q omit=%v: got %q, %v", p.Name, secret, omit, got, err)
				}
			}
		}
		data, _ := p.EncryptSecretECC(sender, false, receiverKey, nonce, []byte("password1"))
		if _, err := p.DecryptSecretECC(data, receiver, cert, NewNonce(32)); !errors.Is(err, ua.StatusBadNonceInvalid) {
			t.Fatalf("%s: wrong nonce: %v", p.Name, err)
		}
		tampered := append([]byte(nil), data...)
		tampered[len(tampered)-p.AsymSignatureLength(cert.PublicKey)-3] ^= 1
		if _, err := p.DecryptSecretECC(tampered, receiver, cert, nonce); !errors.Is(err, ua.StatusBadSecurityChecksFailed) {
			t.Fatalf("%s: tampered: %v", p.Name, err)
		}
		other, _, _ := p.NewEphemeralKey()
		if _, err := p.DecryptSecretECC(data, other, cert, nonce); !errors.Is(err, ua.StatusBadNonceInvalid) {
			t.Fatalf("%s: other receiver key: %v", p.Name, err)
		}
	}
}
