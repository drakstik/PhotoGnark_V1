package examples

import (
	"github.com/drakstik/PhotoGnark_V1/src/camera"
)

// This tests NewCamera(), Generator(), GeneratePCD_Keys() and Take_Random_Photo()
func Test_Take_Photo() camera.Photograph {
	cam := Test_New_Camera([]string{"id"})

	photo, err := cam.Take_Random_Photo()
	if err != nil {
		return camera.Photograph{}
	}

	return photo

}
