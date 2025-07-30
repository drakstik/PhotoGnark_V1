package viewer

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/drakstik/PhotoGnark_V1/src/camera"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

type User struct {
	sk signature.Signer
}

func NewUser() (User, error) {
	sk, err := photoproof.NewSecretKey()
	if err != nil {
		return User{}, err
	}

	return User{sk: sk}, err
}

// Wrapper for Gnark's proof verification.
// There are two options for verification showcased below for educational purposes:
//  1. OPTION 1: Compare recreated_witness and public_witness first, then verify with the Public_Witness
//  2. OPTION 2: Use the recreated_witness in groth16.Verify
func (user User) VerifyPhotograph(photo camera.Photograph) (bool, error) {
	// Recreate the wintess
	recreated_witness, err := RecreateWitness(photo, user.sk)
	if err != nil {
		return false, fmt.Errorf("ERROR: user.GetWitness(photo) while verifying proof..")
	}

	// OPTION 1: Compare recreated_witness and public_witness
	// if CompareWitnesses(photo.Proof.Public_Witness, recreated_witness) {
	// 	err := groth16.Verify(photo.Proof.Gnark_Proof, photo.Proof.Gnark_Keys.VerifyingKey, photo.Proof.Public_Witness)
	// 	if err != nil {
	// 		fmt.Println("ERROR: VerifyGnarkProof failed.")
	// 		return false, fmt.Errorf(err.Error())
	// 	}
	// }

	// OPTION 2: use the recreated_witness in groth16.Verify
	err = groth16.Verify(photo.Proof.Gnark_Proof, photo.Proof.Gnark_Keys.VerifyingKey, recreated_witness)
	if err != nil {
		fmt.Println("ERROR: VerifyGnarkProof failed.")
		return false, fmt.Errorf(err.Error())
	}

	return true, err
}
