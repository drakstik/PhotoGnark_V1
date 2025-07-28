package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/signature"
)

// Generates PCD_Keys for each given Transformation.
// Leverages interface Transformation to apply the same Generator function to various Transformations.
func Generator(sk signature.Signer, trs []Transformation) (map[string]PCD_Keys, error) {

	m := map[string]PCD_Keys{}

	for i := range trs {

		tr := trs[i]

		FrTransformation, err := tr.ToFr(sk, sk.Public().Bytes())
		if err != nil {
			return nil, err
		}

		// Generate PCD_Keys for this permissible transformation
		pcd_keys, err := FrTransformation.GeneratePCD_Keys(sk)
		if err != nil {
			return map[string]PCD_Keys{}, fmt.Errorf("Generator() - ERROR while generating PCD_Keys; TrType: " + tr.GetType())
		}

		// Set new M
		m[FrTransformation.GetType()] = pcd_keys
	}

	return m, nil
}
