package ed25519_test

import (
	"ed25519"
	"fmt"
	"testing"
)

func testGeneration(t *testing.T, tag string) {
	msg := "hello, world"
	val, err := ed25519.SignVerify(msg)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	fmt.Println("#ed25519 sign-verify: ", val)
}

func TestSign(t *testing.T) {
	testGeneration(t, "ed25519")
}
