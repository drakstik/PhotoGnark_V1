package photoproof

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type Proof struct {
	Signature     []byte
	PublicKey     signature.PublicKey
	PCD_Proof     groth16.Proof
	PublicWitness witness.Witness
	VeriKey       groth16.VerifyingKey
}

func NewSecretKey() (signature.Signer, error) {
	// 1. Generate a secret key using ceddsa.
	sk, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	if err != nil {
		fmt.Println("func NewSecretKey(): Error while generating secret key using ceddsa...")
		fmt.Print(err.Error())
		return nil, err
	}

	return sk, nil
}
