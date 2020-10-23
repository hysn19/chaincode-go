package secp256r1_test

import (
	"crypto/elliptic"
	"fmt"
	"secp256r1"
	"testing"
)

func testGeneration(t *testing.T, c elliptic.Curve, tag string) {
	msg := "hello, world"
	val, err := secp256r1.SignVerify(c, msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("#", tag, " sign-verify: ", val)
}

func testASN1Generation(t *testing.T, c elliptic.Curve, tag string) {
	msg := "hello, world"
	val, err := secp256r1.SignVerifyASN1(c, msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("#", tag, " sign-verify(asn1): ", val)
}

func TestSign(t *testing.T) {
	testGeneration(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testGeneration(t, elliptic.P256(), "p256")
	testGeneration(t, elliptic.P384(), "p384")
	testGeneration(t, elliptic.P521(), "p521")

	testASN1Generation(t, elliptic.P521(), "p224")
	if testing.Short() {
		return
	}
	testASN1Generation(t, elliptic.P521(), "p256")
	testASN1Generation(t, elliptic.P521(), "p384")
	testASN1Generation(t, elliptic.P521(), "p521")
}
