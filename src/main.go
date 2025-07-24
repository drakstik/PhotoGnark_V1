package main

import "github.com/drakstik/PhotoGnark_V1/src/examples"

func main() {
	examples.Test_Identity_Transformation()

	// Only testing Identity transformation as permissible
	examples.Test_New_Camera([]string{"id"})
}
