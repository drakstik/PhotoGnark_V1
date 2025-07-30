package camera

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
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

// This function takes a random image, proves its originality and stores
// the image and proof as a photograph in the camera.
// Also returns the photograph, for testing purposes.
func (camera *SecureCamera) Take_Random_Photo() (Photograph, error) {
	img, err := image.NewImage("random")
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: NewImage() failed while taking a random photo.")
	}

	gnark_proof, err := photoproof.Prove_Originality(img, camera.secretKey, camera.PCD_Keys)
	if err != nil {
		return Photograph{}, fmt.Errorf("ERROR: Prove_Originality() failed while taking a random photo.")
	}

	photo := Photograph{
		Img:   img,
		Proof: gnark_proof,
	}

	camera.Photographs = append(camera.Photographs, photo)

	return photo, err
}
