package examples

import (
	"github.com/drakstik/PhotoGnark_V1/src/viewer"
)

func Test_Viewer() (bool, error) {
	photo := Test_Take_Photo()
	viewer_app_user, _ := viewer.NewUser()
	return viewer_app_user.VerifyPhotograph(photo)
}
