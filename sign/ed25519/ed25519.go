package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// SignVerify describes sign and verify for specific curve and msg
func SignVerify(msg string) (bool, error) {

	// https://github.com/golang/crypto/blob/master/ed25519/ed25519_test.go
	public, private, _ := ed25519.GenerateKey(rand.Reader)

	message := []byte("test message")
	sig := ed25519.Sign(private, message)
	if !ed25519.Verify(public, message, sig) {
		return false, fmt.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if ed25519.Verify(public, wrongMessage, sig) {
		return false, fmt.Errorf("signature of different message accepted")
	}

	return true, nil
}
