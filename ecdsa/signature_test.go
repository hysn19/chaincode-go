package signature_test

import (
	"crypto/elliptic"
	"fmt"
	"signature"
	"testing"
)

func testSignGeneration(t *testing.T, c elliptic.Curve, tag string) {
	msg := "hello, world"
	val, err := signature.Sign(c, msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("Verify: ", val)
}

func testSignASN1Generation(t *testing.T, c elliptic.Curve, tag string) {
	msg := "hello, world"
	val, err := signature.SignASN1(c, msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("Verify: ", val)
}

func TestSign(t *testing.T) {
	// testSignGeneration
	// testSignGeneration(t, elliptic.P224(), "p224")
	// if testing.Short() {
	// 	return
	// }
	testSignGeneration(t, elliptic.P256(), "p256")
	// testSignGeneration(t, elliptic.P384(), "p384")
	// testSignGeneration(t, elliptic.P521(), "p521")

	// testSignASN1Generation
	// testSignASN1Generation(t, elliptic.P521(), "p224")
	// if testing.Short() {
	// 	return
	// }
	// testSignASN1Generation(t, elliptic.P521(), "p256")
	// testSignASN1Generation(t, elliptic.P521(), "p384")
	// testSignASN1Generation(t, elliptic.P521(), "p521")
}
