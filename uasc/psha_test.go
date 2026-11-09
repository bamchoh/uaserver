package uasc

import (
	"encoding/hex"
	"testing"
)

// TLS 1.2 PRF (P_SHA256) test vector; the TLS label is part of the seed.
func TestPSHA256Vector(t *testing.T) {
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	seed = append([]byte("test label"), seed...)
	got := hex.EncodeToString(pSHA256(secret, seed, 16))
	if got != "e3f229ba727be17b8d122620557cd453" {
		t.Fatalf("got %s", got)
	}
}
