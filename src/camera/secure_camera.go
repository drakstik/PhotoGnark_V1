package camera

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
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

	fmt.Println("Generating a new camera...")
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
func (camera *SecureCamera) Take_Random_Photo() (Photograph, error) {
	img, err := image.NewImage("random")
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: NewImage() while taking a random photo.")
	}

	// Create a new Identity Transformation
	transformation, err := photoproof.NewIdentity(img, camera.secretKey)
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: NewIdentity() while taking a random photo.")
	}

	// Turn the transformation into a Gnark circuit
	circuit, err := transformation.ToFr(camera.secretKey, camera.secretKey.Public().Bytes())
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: transformation.ToFr() while taking a random photo.")
	}

	fmt.Println("Creating image's circuit Witness...")
	// Create the secret witness from the circuit
	secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: frontend.NewWitness() while taking a random photo.")
	}

	fmt.Println("Compiling image circuit into constraint system...")
	// Set the security parameter and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: frontend.Compile() while taking a random photo.")
	}

	// Get the proving key for the Identity Transformation
	proving_key := camera.PCD_Keys["id_Fr"].ProvingKey

	fmt.Println("Proving compliance predicate...")
	// Prove the secret witness adheres to the compliance predicate, using the given proving key
	proof, err := groth16.Prove(compliance_predicate, proving_key, secret_witness)
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: frontend.Prove() failed inside the camera.")
	}

	public_witness, err := secret_witness.Public()
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: secret_witness.Public() while taking a random photo.")
	}

	gnark_proof := photoproof.Gnark_Proof{
		Gnark_Keys:     camera.PCD_Keys,
		Gnark_Proof:    proof,
		Public_Witness: public_witness,
	}

	return Photograph{
		Img:   img,
		Proof: gnark_proof,
	}, err
}
