package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
)

// This function sets PCD_Keys for each permissible transformation in the camera.
func Generator(sk signature.Signer, trs []Transformation) (map[string]PCD_Keys, error) {

	m := map[string]PCD_Keys{}

	for i := 0; i < len(trs); i++ {

		trType := trs[i].GetType()

		// TODO: Add more transformations.
		if trType == "id" {
			// Assert the type of transformation to be IdentityTransformation
			tr, ok := trs[i].(IdentityTransformation)
			if !ok {
				return map[string]PCD_Keys{}, fmt.Errorf("Generator(): ERROR while asserting " + trType + " into frontend.Circuit.")
			}

			// Set public key of transformation
			tr.PublicKey = sk.Public()

			// Set transformation with public key into camera
			trs[i] = tr

			FrTransformation, err := tr.ToFr(sk)
			if err != nil {
				return nil, err
			}

			// Generate PCD_Keys for this permissible transformation
			newM, err := FrTransformation.GeneratePCD_Keys(sk, trs[i].GetType(), m)
			if err != nil {
				return map[string]PCD_Keys{}, fmt.Errorf("Generator() - ERROR while generating PCD_Keys.")
			}

			// Set new M
			m = newM

		} else {
			return map[string]PCD_Keys{}, fmt.Errorf("Generator() - Please define permissible transformation list of names, at least \"id\".")
		}
	}

	return m, nil
}
