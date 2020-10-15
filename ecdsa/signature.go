package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"encoding/asn1"
	b64 "encoding/base64"
	"encoding/json"

	"github.com/mitchellh/mapstructure"
)

// ECDSASignature represents an ECDSA signature.
type ECDSASignature struct {
	R, S *big.Int
}

// Sign message a new sign to the world state with given details.
func Sign(c elliptic.Curve, msg string) (bool, error) {
	privatekey := new(ecdsa.PrivateKey)
	privatekey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(msg))
	r := big.NewInt(0)
	s := big.NewInt(0)

	// sign
	r, s, serr := ecdsa.Sign(rand.Reader, privatekey, hash[:])
	if serr != nil {
		return false, serr
	}

	sig, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return false, err
	}

	// base64 encode
	b64sig := b64.StdEncoding.EncodeToString(sig)
	fmt.Printf("b64 signature : %s\n", b64sig)

	marshalledKey, err := json.Marshal(privatekey.PublicKey)
	if err != nil {
		panic(err)
	}
	b64MarshalledKey := b64.URLEncoding.EncodeToString(marshalledKey)
	fmt.Printf("b64 pubkey : %s\n", b64MarshalledKey)

	// base64 decode
	marshalledKey, merr := b64.URLEncoding.DecodeString(b64MarshalledKey)
	if merr != nil {
		return false, merr
	}

	der, err := b64.StdEncoding.DecodeString(b64sig)

	// verify
	var unmarshalledKey ecdsa.PublicKey
	unmarshalledKey = UnmarshalECCPublicKey(marshalledKey)

	esig := &ECDSASignature{}
	_, err = asn1.Unmarshal(der, esig)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(&unmarshalledKey, hash[:], esig.R, esig.S)

	return valid, nil
}

// SignASN1 message a new sign to the world state with given details.
func SignASN1(c elliptic.Curve, msg string) (bool, error) {
	privatekey := new(ecdsa.PrivateKey)
	privatekey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(rand.Reader, privatekey, hash[:])
	if err != nil {
		return false, err
	}

	b64Sign := b64.URLEncoding.EncodeToString(sig)
	fmt.Printf("signature: %s\n", b64Sign)

	marshalledKey, err := json.Marshal(privatekey.PublicKey)
	if err != nil {
		panic(err)
	}
	b64MarshalledKey := b64.URLEncoding.EncodeToString(marshalledKey)
	fmt.Printf("marshalledKey: %s\n", b64MarshalledKey)

	// b64Sign := "MEYCIQDz43T2VU-cIN8mE4GFnEAwX9ZuoT_cqZU41VB133Ib2wIhAMbi85xmAlZ2n0o_S8G6yY4VGU_LfHpfPvmbqqXY5HvJ"
	// b64MarshalledKey := "eyJDdXJ2ZSI6eyJQIjoxMTU3OTIwODkyMTAzNTYyNDg3NjI2OTc0NDY5NDk0MDc1NzM1MzAwODYxNDM0MTUyOTAzMTQxOTU1MzM2MzEzMDg4NjcwOTc4NTM5NTEsIk4iOjExNTc5MjA4OTIxMDM1NjI0ODc2MjY5NzQ0Njk0OTQwNzU3MzUyOTk5Njk1NTIyNDEzNTc2MDM0MjQyMjI1OTA2MTA2ODUxMjA0NDM2OSwiQiI6NDEwNTgzNjM3MjUxNTIxNDIxMjkzMjYxMjk3ODAwNDcyNjg0MDkxMTQ0NDEwMTU5OTM3MjU1NTQ4MzUyNTYzMTQwMzk0Njc0MDEyOTEsIkd4Ijo0ODQzOTU2MTI5MzkwNjQ1MTc1OTA1MjU4NTI1Mjc5NzkxNDIwMjc2Mjk0OTUyNjA0MTc0Nzk5NTg0NDA4MDcxNzA4MjQwNDYzNTI4NiwiR3kiOjM2MTM0MjUwOTU2NzQ5Nzk1Nzk4NTg1MTI3OTE5NTg3ODgxOTU2NjExMTA2NjcyOTg1MDE1MDcxODc3MTk4MjUzNTY4NDE0NDA1MTA5LCJCaXRTaXplIjoyNTYsIk5hbWUiOiJQLTI1NiJ9LCJYIjoyNDYyNDQxOTI5NTk1NDQ5NzQ3NTk3NjIyNjM2NTI3MDIwMTcxMzkyMzEwMTI3MDUxMjkwOTYwOTM5NDY3NDgzNjU2NzY5MTYyMTc3NSwiWSI6MTQ3MjA3MzcyNDYwMDA1MDUwMTMxOTk3Njc0NjE1NTU4ODEzODMyNDk0OTI0MzAwOTEzMzI1NDI5MzY0NzI0ODAwOTM5MTA2OTE5NTV9"

	marshalledKey, merr := b64.URLEncoding.DecodeString(b64MarshalledKey)
	if merr != nil {
		return false, merr
	}

	var unmarshalledKey ecdsa.PublicKey
	unmarshalledKey = UnmarshalECCPublicKey(marshalledKey)
	usig, derr := b64.URLEncoding.DecodeString(b64Sign)
	if derr != nil {
		return false, derr
	}

	valid := ecdsa.VerifyASN1(&unmarshalledKey, hash[:], usig)
	fmt.Println("signature verified:", valid)

	return valid, nil
}

//UnmarshalECCPublicKey extract ECC public key from marshaled objects
func UnmarshalECCPublicKey(object []byte) (pub ecdsa.PublicKey) {
	var public ecdsa.PublicKey

	type retrieve struct {
		CurveParams *elliptic.CurveParams `json:"Curve"`
		MyX         *big.Int              `json:"X"`
		MyY         *big.Int              `json:"Y"`
	}

	rt := new(retrieve)

	errmarsh := json.Unmarshal(object, &rt)
	if errmarsh != nil {
		fmt.Println("err at UnmarshalECCPublicKey()")
		panic(errmarsh)
	}

	public.Curve = rt.CurveParams
	public.X = rt.MyX
	public.Y = rt.MyY
	mapstructure.Decode(public, &pub)

	// fmt.Println("Unmarshalled ECC public key : ", pub)
	return
}
