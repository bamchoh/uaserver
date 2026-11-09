package uasc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	stdhkdf "crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

// The OPC UA key derivation is HKDF with the salt also used as info.
func TestHKDFMatchesStandardLibrary(t *testing.T) {
	secret := bytes.Repeat([]byte{0x0b}, 32)
	salt := []byte("\x50\x00opcua-client and some nonces")
	for _, h := range []func() hash.Hash{sha256.New, sha512.New384} {
		want, err := stdhkdf.Key(h, secret, salt, string(salt), 80)
		if err != nil {
			t.Fatal(err)
		}
		if got := hkdf(h, secret, salt, 80); !bytes.Equal(got, want) {
			t.Fatalf("hkdf mismatch:\n got %x\nwant %x", got, want)
		}
	}
}

func TestECDSASignatureFormat(t *testing.T) {
	for _, uri := range []string{SecurityPolicyEccNistP256, SecurityPolicyEccNistP384} {
		p := PolicyByURI(uri)
		key, err := ecdsa.GenerateKey(p.CertCurve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("data to sign")
		sig, err := p.AsymSign(key, data)
		if err != nil {
			t.Fatal(err)
		}
		// Fixed length r|s (IEEE P1363), not ASN.1 DER.
		if want := p.AsymSignatureLength(&key.PublicKey); len(sig) != want {
			t.Fatalf("%s: signature length %d, want %d", p.Name, len(sig), want)
		}
		if err := p.AsymVerify(&key.PublicKey, data, sig); err != nil {
			t.Fatalf("%s: verify: %v", p.Name, err)
		}
		sig[3] ^= 1
		if p.AsymVerify(&key.PublicKey, data, sig) == nil {
			t.Fatalf("%s: tampered signature verified", p.Name)
		}
	}
}

func TestCertificateKeyAllowed(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if !PolicyByURI(SecurityPolicyEccNistP256).CertificateKeyAllowed(&p256.PublicKey) ||
		!PolicyByURI(SecurityPolicyEccNistP256).CertificateKeyAllowed(&p384.PublicKey) ||
		PolicyByURI(SecurityPolicyEccNistP384).CertificateKeyAllowed(&p256.PublicKey) ||
		PolicyByURI(SecurityPolicyBasic256Sha256).CertificateKeyAllowed(&p256.PublicKey) {
		t.Fatal("unexpected certificate key policy check")
	}
}

// Both sides of the ECDH exchange must derive the same key sets.
func TestECCKeyExchange(t *testing.T) {
	for _, uri := range []string{SecurityPolicyEccNistP256, SecurityPolicyEccNistP384} {
		p := PolicyByURI(uri)
		clientKey, clientNonce, err := p.NewEphemeralKey()
		if err != nil {
			t.Fatal(err)
		}
		serverKey, serverNonce, err := p.NewEphemeralKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(clientNonce) != p.NonceLength {
			t.Fatalf("%s: nonce length %d", p.Name, len(clientNonce))
		}
		// Server side.
		cpub, err := p.ParseNonce(clientNonce)
		if err != nil {
			t.Fatal(err)
		}
		s1, _ := serverKey.ECDH(cpub)
		sClient, sServer := p.DeriveECCKeys(s1, clientNonce, serverNonce, false)
		// Client side.
		spub, err := p.ParseNonce(serverNonce)
		if err != nil {
			t.Fatal(err)
		}
		s2, _ := clientKey.ECDH(spub)
		cClient, cServer := p.DeriveECCKeys(s2, clientNonce, serverNonce, false)

		if !bytes.Equal(sClient.SigningKey, cClient.SigningKey) || !bytes.Equal(sServer.EncryptionKey, cServer.EncryptionKey) {
			t.Fatalf("%s: key sets differ", p.Name)
		}
		if bytes.Equal(sClient.SigningKey, sServer.SigningKey) {
			t.Fatalf("%s: client and server keys must differ", p.Name)
		}
		if len(sClient.SigningKey) != p.SymSigningKeyLength || len(sClient.EncryptionKey) != p.SymEncryptionKeyLength || len(sClient.IV) != 16 {
			t.Fatalf("%s: key lengths", p.Name)
		}
		// Sign only derives a shorter key block, so the signing key differs.
		signOnly, _ := p.DeriveECCKeys(s1, clientNonce, serverNonce, true)
		if signOnly.EncryptionKey != nil || bytes.Equal(signOnly.SigningKey, sClient.SigningKey) {
			t.Fatalf("%s: sign only keys", p.Name)
		}
		if len(p.SymSign(sClient.SigningKey, []byte("x"))) != p.SymSignatureLength {
			t.Fatalf("%s: HMAC length", p.Name)
		}
		if _, err := p.ParseNonce(clientNonce[1:]); err == nil {
			t.Fatalf("%s: short nonce accepted", p.Name)
		}
	}
}
