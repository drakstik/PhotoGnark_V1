package camera

import (
	"github.com/drakstik/PhotoGnark_V1/src/image"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

type Photograph struct {
	Img   image.Image
	Proof photoproof.Gnark_Proof
}
