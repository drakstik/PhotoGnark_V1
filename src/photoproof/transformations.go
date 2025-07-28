package photoproof

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
)

type Transformation interface {
	GetType() string
	ToFr(sk signature.Signer, public_key []byte) (TransformationCircuit, error)
}

type TransformationCircuit interface {
	GetType() string
	Define(api frontend.API) error
	GeneratePCD_Keys(sk signature.Signer) (PCD_Keys, error)
}
