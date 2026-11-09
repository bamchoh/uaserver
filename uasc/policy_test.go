package uasc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAsymmetricRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range SupportedPolicies()[1:] {
		p := PolicyByURI(uri)
		if p.IsECC() {
			continue // covered by ecc_test.go
		}
		pb := p.AsymPlainBlockSize(&key.PublicKey)
		data := bytes.Repeat([]byte{0x5A}, pb*3)
		enc, err := p.AsymEncrypt(&key.PublicKey, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) != 3*key.Size() {
			t.Fatalf("%s: cipher length %d", p.Name, len(enc))
		}
		dec, err := p.AsymDecrypt(key, enc)
		if err != nil || !bytes.Equal(dec, data) {
			t.Fatalf("%s: decrypt failed: %v", p.Name, err)
		}
		sig, err := p.AsymSign(key, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.AsymVerify(&key.PublicKey, data, sig); err != nil {
			t.Fatalf("%s: verify: %v", p.Name, err)
		}
		data[0] ^= 1
		if p.AsymVerify(&key.PublicKey, data, sig) == nil {
			t.Fatalf("%s: tampered data verified", p.Name)
		}
	}
}

func TestSymmetricRoundTrip(t *testing.T) {
	for _, uri := range SupportedPolicies()[1:] {
		p := PolicyByURI(uri)
		if p.IsECC() {
			continue // covered by ecc_test.go
		}
		k := p.DeriveKeys(NewNonce(32), NewNonce(32))
		if len(k.SigningKey) != p.SymSigningKeyLength || len(k.EncryptionKey) != p.SymEncryptionKeyLength || len(k.IV) != p.SymBlockSize {
			t.Fatalf("%s: key lengths", p.Name)
		}
		data := bytes.Repeat([]byte{1, 2, 3, 4}, 16)
		buf := append([]byte{}, data...)
		if err := p.SymEncrypt(k.EncryptionKey, k.IV, buf); err != nil {
			t.Fatal(err)
		}
		if err := p.SymDecrypt(k.EncryptionKey, k.IV, buf); err != nil || !bytes.Equal(buf, data) {
			t.Fatalf("%s: symmetric round trip failed", p.Name)
		}
		if p.SymVerify(k.SigningKey, data, p.SymSign(k.SigningKey, data)) != nil {
			t.Fatalf("%s: hmac", p.Name)
		}
	}
}

// P_SHA256 must be deterministic and depend on the seed.
func TestPSHA256Deterministic(t *testing.T) {
	a := pSHA256([]byte("secret"), []byte("seed"), 80)
	b := pSHA256([]byte("secret"), []byte("seed"), 80)
	if !bytes.Equal(a, b) || len(a) != 80 {
		t.Fatal("pSHA256 not deterministic")
	}
	if bytes.Equal(a[:32], pSHA256([]byte("secret"), []byte("seeD"), 32)) {
		t.Fatal("pSHA256 ignores seed")
	}
}
