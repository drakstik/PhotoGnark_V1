package photoproof

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
)

type Transformation interface {
	GetType() string
	ToFr(sk signature.Signer) (TransformationCircuit, error)
}

type TransformationCircuit interface {
	GetType() string
	Define(api frontend.API) error
	GeneratePCD_Keys(sk signature.Signer, trType string, m map[string]PCD_Keys) (map[string]PCD_Keys, error)
}
