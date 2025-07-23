package examples

import (
	"fmt"

	"github.com/drakstik/PhotoGnark_V1/src/image"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
	"github.com/drakstik/PhotoGnark_V1/src/transformations"
)

// This tests NewImage("random"), NewSecretKey(), NewIdentity(), Identity.Edit()
func Test_Identity_Transformation() {
	img, err := image.NewImage("random")
	if err != nil {
		return
	}

	img2, err := image.NewImage("random")
	if err != nil {
		return
	}

	// Simulating a camera's secret key
	sk, err := photoproof.NewSecretKey()
	if err != nil {
		return
	}

	id, err := transformations.NewIdentity(img, sk)
	if err != nil {
		return
	}

	should_be_true, err := id.Edit(img)
	if err != nil {
		return
	}

	should_be_false, err := id.Edit(img2)
	if err != nil {
		return
	}

	fmt.Println(should_be_true)
	fmt.Println(should_be_false)
}
