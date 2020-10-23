package secp256k1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// ECDSASignature represents an ECDSA signature.
type ECDSASignature struct {
	R, S *big.Int
}

// EDSignState describes basic details of what makes up a simple asset
type EDSignState struct {
	MarshalledKey string `json:"marshalledKey"`
	Signatrue     string `json:"signatrue"`
}

// SignVerify describes sign and verify for specific curve and msg
func SignVerify(msg string) (bool, error) {

	// ## https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/secp256_test.go
	testpubkey, testseckey := generateKeyPair()
	// testmsg := csprngEntropy(32)
	testmsg, err := generateRandomBytes(32)
	if err != nil {
		return false, fmt.Errorf("can`t generate random bytes: %s", err)
	}
	testsig, err := secp256k1.Sign(testmsg, testseckey)
	if err != nil {
		return false, fmt.Errorf("can`t sign the argument: %s", err)
	}

	// fmt.Printf("testmsg   : %s%x\n", "0x", testmsg)
	// fmt.Printf("testsig   : %s%x\n", "0x", testsig)
	// fmt.Printf("testpubkey: %s%x\n", "0x", testpubkey)

	pubkey, err := crypto.UnmarshalPubkey(testpubkey)
	if err != nil {
		return false, fmt.Errorf("can`t unmarshal pubkey: error(%s)", err)
	}
	testpubkeyc := crypto.FromECDSAPub(pubkey)
	// fmt.Printf("testpubkeyc: %s%x\n", "0x", testpubkeyc)

	compactSigCheck(testsig)
	if len(testpubkey) != 65 {
		return false, fmt.Errorf("pubkey length mismatch: want: 65 have: %d", len(testpubkey))
	}
	if len(testseckey) != 32 {
		return false, fmt.Errorf("seckey length mismatch: want: 32 have: %d", len(testseckey))
	}
	if len(testsig) != 65 {
		return false, fmt.Errorf("sig length mismatch: want: 65 have: %d", len(testsig))
	}
	recid := int(testsig[64])
	if recid > 4 || recid < 0 {
		return false, fmt.Errorf("sig recid mismatch: want: within 0 to 4 have: %d", int(testsig[64]))
	}

	// ## https://github.com/ethereum/go-ethereum/blob/master/crypto/signature_test.go
	// testmsg := hexutil.MustDecode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	// testsig := hexutil.MustDecode("0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
	// testpubkey := hexutil.MustDecode("0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
	// testpubkeyc := hexutil.MustDecode("0x02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a")

	sig := testsig[:len(testsig)-1] // remove recovery id
	if !secp256k1.VerifySignature(testpubkey, testmsg, sig) {
		return false, fmt.Errorf("can't verify signature with uncompressed key")
	}
	if !secp256k1.VerifySignature(testpubkeyc, testmsg, sig) {
		return false, fmt.Errorf("can't verify signature with compressed key")
	}

	if secp256k1.VerifySignature(nil, testmsg, sig) {
		return false, fmt.Errorf("signature valid with no key")
	}
	if secp256k1.VerifySignature(testpubkey, nil, sig) {
		return false, fmt.Errorf("signature valid with no message")
	}
	if secp256k1.VerifySignature(testpubkey, testmsg, nil) {
		return false, fmt.Errorf("nil signature valid")
	}
	if secp256k1.VerifySignature(testpubkey, testmsg, append(common.CopyBytes(sig), 1, 2, 3)) {
		return false, fmt.Errorf("signature valid with extra bytes at the end")
	}
	if secp256k1.VerifySignature(testpubkey, testmsg, sig[:len(sig)-2]) {
		return false, fmt.Errorf("signature valid even though it's incomplete")
	}

	return true, nil
}

// highest bit of signature ECDSA s value must be 0, in the 33th byte
func compactSigCheck(sig []byte) {
	var b = int(sig[32])
	if b < 0 {
		fmt.Printf("highest bit is negative: %d", b)
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		fmt.Printf("highest bit: %d bit >> 7: %d", b, b>>7)
	}
	if (b & 0x80) == 0x80 {
		fmt.Printf("highest bit: %d bit & 0x80: %d", b, b&0x80)
	}
}

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}

func csprngEntropy(n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return buf
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
