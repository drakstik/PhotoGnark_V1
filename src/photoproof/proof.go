package photoproof

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/drakstik/PhotoGnark_V1/src/image"
)

type PCD_Keys struct {
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
}

type Gnark_Proof struct {
	Gnark_Keys     PCD_Keys
	Gnark_Proof    groth16.Proof
	Public_Witness witness.Witness
}

// This function can be used to generate a new secret key. Used only by camera.
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

// This function can be used to prove the originality of an image,
// given a camera's secret key and PCD keys (which represent Permissible Transformations).
// Used only by camera.
func Prove_Originality(img image.Image, sk signature.Signer, PCD_Keys map[string]PCD_Keys) (Gnark_Proof, error) {

	// Create a new Identity Transformation
	transformation, err := NewIdentity(img, sk)
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: NewIdentity() while taking a random photo.")
	}

	// Turn the transformation into a Gnark circuit
	circuit, err := transformation.ToFr(sk, sk.Public().Bytes())
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: transformation.ToFr() while taking a random photo.")
	}

	fmt.Println("Creating image's circuit Witness...")
	// Create the secret witness from the circuit
	secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: frontend.NewWitness() while taking a random photo.")
	}

	fmt.Println("Compiling image circuit into constraint system...")
	// Set the security parameter and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: frontend.Compile() while taking a random photo.")
	}

	fmt.Println("Proving compliance predicate...")
	// Prove the secret witness adheres to the compliance predicate, using the given proving key
	proof, err := groth16.Prove(compliance_predicate, PCD_Keys["id_Fr"].ProvingKey, secret_witness)
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: frontend.Prove() failed inside the camera.")
	}

	public_witness, err := secret_witness.Public()
	if err != nil {
		return Gnark_Proof{}, fmt.Errorf("ERROR: secret_witness.Public() while taking a random photo.")
	}

	gnark_proof := Gnark_Proof{
		Gnark_Keys:     PCD_Keys["id_Fr"],
		Gnark_Proof:    proof,
		Public_Witness: public_witness,
	}

	return gnark_proof, err

}
