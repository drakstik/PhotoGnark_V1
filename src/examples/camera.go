package examples

import (
	"github.com/drakstik/PhotoGnark_V1/src/camera"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

// This tests NewCamera(), Generator(), GeneratePCD_Keys()
func Test_New_Camera(permissible_transformations []string) camera.SecureCamera {
	permissible := []photoproof.Transformation{}

	for i := 0; i < len(permissible_transformations); i++ {
		if permissible_transformations[i] == "id" {

			permissible = append(permissible, photoproof.IdentityTransformation{})

		}
	}

	camera := camera.NewCamera(permissible)

	return camera
}
