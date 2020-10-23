package secp256r1

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

// EDSignState describes basic details of what makes up a simple asset
type EDSignState struct {
	MarshalledKey string `json:"marshalledKey"`
	Signatrue     string `json:"signatrue"`
}

// SignVerify describes sign and verify for specific curve and msg
func SignVerify(c elliptic.Curve, msg string) (bool, error) {
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
	// fmt.Printf("b64 signature : %s\n", b64sig)

	marshalledKey, err := json.Marshal(privatekey.PublicKey)
	if err != nil {
		panic(err)
	}
	b64MarshalledKey := b64.URLEncoding.EncodeToString(marshalledKey)
	// fmt.Printf("b64 pubkey : %s\n", b64MarshalledKey)

	edsign := EDSignState{
		MarshalledKey: b64MarshalledKey,
		Signatrue:     b64sig,
	}
	edsignJSON, err := json.Marshal(edsign)
	if err != nil {
		return false, err
	}

	var edsign1 EDSignState
	err = json.Unmarshal(edsignJSON, &edsign1)
	if err != nil {
		return false, err
	}

	// base64 decode
	der, err := b64.StdEncoding.DecodeString(edsign1.Signatrue)

	marshalledKey, merr := b64.URLEncoding.DecodeString(edsign1.MarshalledKey)
	if merr != nil {
		return false, merr
	}

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

// SignVerifyASN1 describes sign and verify for specific curve and msg
func SignVerifyASN1(c elliptic.Curve, msg string) (bool, error) {

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
	// fmt.Printf("signature: %s\n", b64Sign)

	marshalledKey, err := json.Marshal(privatekey.PublicKey)
	if err != nil {
		panic(err)
	}
	b64MarshalledKey := b64.URLEncoding.EncodeToString(marshalledKey)
	// fmt.Printf("marshalledKey: %s\n", b64MarshalledKey)

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
