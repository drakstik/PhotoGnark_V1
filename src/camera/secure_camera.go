package camera

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/drakstik/PhotoGnark_V1/src/image"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

type SecureCamera struct {
	secretKey     signature.Signer
	Photographs   []Photograph
	PermissibleTr []photoproof.Transformation
	PCD_Keys      map[string]photoproof.PCD_Keys
}

// Create a SecureCamera with permissible transformations
func NewCamera(permissible []photoproof.Transformation) SecureCamera {

	// Simulating a camera's secret key. NOT SECURE! Only for demo.
	sk, err := photoproof.NewSecretKey()
	if err != nil {
		return SecureCamera{}
	}

	pcd_keys, err := photoproof.Generator(sk, permissible)
	if err != nil {
		return SecureCamera{}
	}

	camera := SecureCamera{
		secretKey:     sk,
		Photographs:   []Photograph{},
		PermissibleTr: permissible,
		PCD_Keys:      pcd_keys,
	}

	return camera
}

// TODO: rewrite so
func (camera SecureCamera) take_random_photo() (Photograph, error) {
	img, err := image.NewImage("random")
	if err != nil {
		return Photograph{}, err
	}

	sig, err := img.Sign(camera.secretKey)
	if err != nil {
		return Photograph{}, err
	}

	pk := camera.secretKey.Public()

	pcd_proofs := make(map[string]groth16.Proof)
	pcd_witnesses := make(map[string]witness.Witness)

	// For each transformation, create a proof.
	for i := 0; i < len(camera.PermissibleTr); i++ {
		FrTransformation, err := camera.PermissibleTr[i].ToFr(camera.secretKey)
		if err != nil {
			return Photograph{}, err
		}

		circuit, ok := FrTransformation.(frontend.Circuit)
		if !ok {
			fmt.Println("take_random_photo(): ERROR while asserting " + FrTransformation.GetType() + " into frontend.Circuit.")
			return Photograph{}, err
		}

		// Create the secret witness from the circuit
		secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
		if err != nil {
			return Photograph{}, err
		}

		// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
		compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			fmt.Println("take_random_photo(): ERROR while compiling " + FrTransformation.GetType() + " into compliance predicate.")
			return Photograph{}, err
		}

		proving_key := camera.PCD_Keys[FrTransformation.GetType()].ProvingKey

		// Prove the secret witness adheres to the compliance predicate, using the given proving key
		pcd_proof, err := groth16.Prove(compliance_predicate, proving_key, secret_witness)
		if err != nil {
			fmt.Println("take_random_photo(): ERROR while proving " + FrTransformation.GetType() + " into groth16.Proof.")
			return Photograph{}, err
		}

		// Create a public witness
		publicWitness, err := secret_witness.Public()
		if err != nil {
			fmt.Println("take_random_photo(): ERROR while creating public witness for " + FrTransformation.GetType() + ".")
			return Photograph{}, err
		}

		pcd_proofs[FrTransformation.GetType()] = pcd_proof
		pcd_witnesses[FrTransformation.GetType()] = publicWitness
	}

	proof := []photoproof.Proof{photoproof.Proof{
		Signature:     sig,
		PublicKey:     pk,
		PCD_Keys:      camera.PCD_Keys, // All images have the camera's pcd_keys.
		PCD_Proofs:    pcd_proofs,
		PCD_Witnesses: pcd_witnesses,
	}}

	photo := Photograph{
		Img:   img,
		Proof: proof,
	}

	// Save photo in the camera
	camera.Photographs[len(camera.Photographs)-1] = photo

	return photo, err
}
