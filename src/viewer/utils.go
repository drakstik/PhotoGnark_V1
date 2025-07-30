package viewer

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/drakstik/PhotoGnark_V1/src/camera"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

func RecreateWitness(photo camera.Photograph, sk signature.Signer) (witness.Witness, error) {

	img := photo.Img

	// Create a new Identity Transformation
	transformation, err := photoproof.NewIdentity(img, sk)
	if err != nil {
		return nil, fmt.Errorf("ERROR: NewIdentity() while verifying proof.")
	}

	circuit, err := transformation.ToFr(sk, sk.Public().Bytes())
	if err != nil {
		return nil, fmt.Errorf("ERROR: img.ToBigEndian() while verifying proof..")
	}

	//Create the secret witness from the circuit
	secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("ERROR: frontend.NewWitness() while verifying proof...\n" + err.Error())
		return nil, err
	}

	known_witness, err := secret_witness.Public()
	if err != nil {
		return nil, fmt.Errorf("ERROR: secret_witness.Public() while verifying proof..")
	}

	return known_witness, err
}

func CompareWitnesses(witness_1 witness.Witness, witness_2 witness.Witness) bool {
	known_witness_binaries, _ := witness_1.MarshalBinary()
	public_witness_binaries, _ := witness_2.MarshalBinary()

	return bytes.Equal(known_witness_binaries, public_witness_binaries)
}
