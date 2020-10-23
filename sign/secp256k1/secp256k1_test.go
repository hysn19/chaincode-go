package secp256k1_test

import (
	"fmt"
	"secp256k1"
	"testing"
)

func testGeneration(t *testing.T, tag string) {
	msg := "hello, world"
	val, err := secp256k1.SignVerify(msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("#secp256k1 sign-verify: ", val)
}

func TestSign(t *testing.T) {
	testGeneration(t, "s256")
}
