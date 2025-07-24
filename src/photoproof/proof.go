package photoproof

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type PCD_Keys struct {
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
}

type Proof struct {
	Signature     []byte
	PublicKey     signature.PublicKey
	PCD_Keys      map[string]PCD_Keys
	PCD_Proofs    map[string]groth16.Proof
	PCD_Witnesses map[string]witness.Witness
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
