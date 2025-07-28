package photoproof

import (
	"fmt"

	"github.com/drakstik/PhotoGnark_V1/src/image"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// An Identity Transformation is essentially a normal signature verification.
type IdentityTransformation struct {
	PublicKey signature.PublicKey
	Signature []byte
	Img       image.Image
}

//----------------------------------------------------------------------------------------------------

func NewIdentity(img image.Image, sk signature.Signer) (IdentityTransformation, error) {
	signature, err := img.Sign(sk)
	if err != nil {
		return IdentityTransformation{}, err
	}

	pk := sk.Public()

	return IdentityTransformation{
		PublicKey: pk,
		Signature: signature,
		Img:       img,
	}, err
}

// TODO
func (idT IdentityTransformation) ToFr(sk signature.Signer, public_key []byte) (TransformationCircuit, error) {
	digsig, err := idT.Img.Sign(sk)

	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	eddsa_digSig.Assign(1, digsig)
	eddsa_PK.Assign(1, public_key)

	// Return a pointer here
	circuit := &IdentityCircuit{
		PublicKey:       eddsa_PK,
		EdDSA_Signature: eddsa_digSig,
		ImgBytes:        idT.Img.PixelBytes,
	}

	return circuit, err
}

// TODO
func (idT IdentityTransformation) VerifySignature(img image.Image) (bool, error) {
	// Instantiate MIMC BN254 hash function, to be used in signing the image
	hFunc := hash.MIMC_BN254.New()

	output, err := idT.PublicKey.Verify(idT.Signature, img.PixelBytes, hFunc)
	if err != nil {
		fmt.Println("funct (idT) Edit(): ERROR during normal signature verification.")
		fmt.Print(err.Error())
		return output, err
	}

	return output, err
}

func (idT IdentityTransformation) GetType() string {
	return "id"
}
