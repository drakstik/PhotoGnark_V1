# Introduction

This repo contains the source code of **PhotoGnark**, a Golang implementation of [PhotoProof](https://ieeexplore.ieee.org/document/7546506) that leverages the Gnark library for Zero Knowledge functionality.

# PhotoProof
To achieve image authentication that allows for permissible transformations, we propose PhotoProof, a cryptographic scheme that combines a digital signature scheme and the typical Zero-Knowledge algorithms commonly known as the Generator, Prover and Verifier schemes to define permissible transformations for images taken with a Secure Camera, as originally proposed in the paper by Assa Naveh and Eran Tromer, from Tel Aviv University. 

### What is Image Authentication anyways?

To understand what an authentic image is, we must start by defining what a Secure Camera is... A Secure Camera is a camera that can securely take an image and sign the image. This means that the Secure Camera is immune to hardware tempering, side channels and *image injection* attacks. An image is **original** if its ZK-SNARK proof was signed by a Secure Camera using a secure signature scheme. 

An image is said to have a **permissible provenance** if it has proveably undergone *only* permissible transformations, as defined by circuits and a constraint system (aka compliance predicate).

An image *t_n* is **authentic** when it has a permissible provenance and is an original image O (*O,t1,t2,t3,...t_n*) .

### What is a Pixel?

To understand an image, we must define a pixel. A *pixel* has an array of size 3, where each index contains a number from 0 to 255 (aka 1 byte or in Golang it's a uint8). Each uint8 represents red, green and blue (i.e. \[R,G,B\]). This array can also be represented as *packed* into a single uint32. 

A pixel also has its location as a Row, Column or Index as a field `Loc`.

```
package image

import "github.com/consensys/gnark/frontend"

type PixelLocation struct {
	Row uint64
	Col uint64
	Idx uint64
}

type Pixel struct {
	RGB    [3]uint8
	Packed uint32
	Loc    PixelLocation
}
```

A pixel can be made into a Gnark-struct, which is a struct that is made of `frontend.Variable` fields and is digestable by a Gnark circuit during compiling & key generation, proving and verification steps. This can be done using the `ToFr()` function ('Fr' is often used in the codebase to represent an object that is compatible with Gnark's [frontend api](github.com/consensys/gnark/frontend)).

```
type FrPixelLoc struct {
	Row frontend.Variable //secret
	Col frontend.Variable //secret
	Idx frontend.Variable //secret
}

type FrPixel struct {
	RGB    frontend.Variable //secret
	Packed frontend.Variable //secret
	Loc    FrPixelLoc        //secret
}
```

### What is an Image?

An image is an N\*N  array of pixels and the pixels encoded as a Big-Endian byte slice. 

```

const (
	N  = 1080
	N2 = N * N // Number of pixels in an image.
)

type Image struct {
	Pixels     [N2]Pixel
	PixelBytes []byte
}
```

An image can also be made into an FrImage using the function `ToFr()`. 

```
type FrImage struct {
	Pixels   [N2]FrPixel // Secret
	ImgBytes []byte
}

func (img Image) ToFr() (frImg FrImage) {

	output := FrImage{}

	for i := 0; i < N*N; i++ {
		pxl := img.Pixels[i]
		output.Pixels[pxl.Loc.Idx] = pxl.ToFr()
	}

	return output
}
```

### What is a Transformation?

Image transformations are functions that take an image and some parameters as input, and output a new image by changing pixel values. Here's how we define a Transformation interface:

```
type Transformation interface {
	GetType() string // To get the transformation type
	ToFr(sk signature.Signer) (TransformationCircuit, error) // Explained further down
}
```

To represent an image that has not undergone any transformations, we define the *Identity Transformation* as an eddsa signature scheme using 
- a MIMC BN254 hash function, 
- a secret key (for creating the signature from an image's bytes) and 
- a public key (for verifying the image's bytes signature).

*Remark:* Our ZK-SNARKs implementation uses Gnark's *groth16* over the BN254 elliptic curve constructions. 

This means that an Identity Transformation is simply the signature verification process of those image bytes. 

```
package photoproof

import (
	"github.com/drakstik/PhotoGnark_V1/src/image"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type IdentityTransformation struct {
	PublicKey signature.PublicKey
	Signature []byte
	Img       image.Image
}

func NewIdentity(img image.Image, sk signature.Signer) (IdentityTransformation, error)

func (idT IdentityTransformation) VerifySignature(img image.Image) (bool, error)
```





### Permissible Transformations

A set of transformations are defined as permissible by an administrator. This allows for administrators to create their own definition for Image Authenticity. For example, an admin can set increasing all pixels by a value less than 5 as a permissible transformation, which would mean that the image would retain its authenticity even if it is altered by increasing all pixel values by 3, according to the admin.

Permissible transformations' fields can be made public by the admin or kept private, depending on their definitions of Image Authenticity. Gnark `circuits`, which represent transformations that Gnark can handle, have fields that are [frontend.Variable](https://github.com/consensys/gnark/frontend) or objects from [Gnark's eddsa package](https://github.com/consensys/gnark/std/signature/eddsa). 

The Identity Transformation can be expressed as a Gnark circuit (let's call it an *Identity Circuit* to borrow Gnark's language), allowing for fast verification times and secret fields. This means that if the public wants to edit or verify an image, they just need the proving and verifying keys, alongside the image in question and the scheme itself. All this without having to reveal the signature, public key, image bytes or previous transformations. 
```
type IdentityCircuit struct {
	PublicKey       eddsa.PublicKey   `gnark:",public"`
	EdDSA_Signature eddsa.Signature   `gnark:",public"`
	ImgBytes        frontend.Variable // Image as Big Endian bytes;
}
```

We use a ToFr() function to turn a `Transformation` into a `TransformationCircuit`.

```
func (idT IdentityTransformation) ToFr(sk signature.Signer, public_key []bytes) (TransformationCircuit, error)
```

All TransformationCircuits are Gnark circuits which implement the Define() function:
```
type TransformationCircuit interface {
	GetType() string
	Define(api frontend.API) error
	GeneratePCD_Keys(sk signature.Signer, trType string, m map[string]PCD_Keys) (map[string]PCD_Keys, error) // Explained further down.
}
```

To conclude, Transformations, such as the Identity Transformation can be used to derive a Gnark circuit, proof and keys that can be used by a prover to permissibly edit the image and verifier to verify an image originated from a Secure Camera and only underwent permissible transformations. Here's how the IdentityCircuit is "defined" as a Gnark circuit (see [here](https://docs.gnark.consensys.io/HowTo/write/standard_library) for documentation references on circuit definition and signature verification within a circuit):

```
func (circuit IdentityCircuit) Define(api frontend.API) error {
	// set the twisted edwards curve to use
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	// hash function
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// tip: gnark profiles enable circuit developers to measure the number of constraints
	// generated by a part of the (or the entire) circuit, using pprof.
	// see github.com/consensys/gnark/profile

	// verify the EdDSA signature
	eddsa.Verify(curve, circuit.EdDSA_Signature, circuit.ImgBytes, circuit.PublicKey, &mimc)

	// tip: api.Println behaves like go fmt.Println but accepts frontend.Variable
	// that are resolved at Proving time
	api.Println("message", circuit.ImgBytes)

	return err
}
```

*Remark:* The Identity Transformation and its circuit will be used as a backbone to allow further editors to apply permissible transformations, because it proves Originality from a Secure Camera and is the first node in thproving permissible provenance. 

### PCD Keys

`PCD_Keys` contain one key for proving image authentication for editors `groth16.ProvingKey` and one verification key for viewers `groth16.VerifyingKey`. 

Together, the keys with the proof `groth16.Proof` and witness `witness.Witness`, make up our `PCD_Proof`, which is attached to each photograph our camera will take and every permissibly edited image.

```
package photoproof

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type PCD_Keys struct {
	ProvingKey   groth16.ProvingKey
	VerifyingKey groth16.VerifyingKey
}

type PCD_Proof struct {
	PCD_Keys      map[string]PCD_Keys
	PCD_Proofs    groth16.Proof
	PCD_Witnesses witness.Witness
}
```

The camera may have multiple PCD Keys and embeds them in each photograph as a map of PCD_Keys with string keys to represent the various permissible transformations in our library.

```
package camera

import (
	"github.com/drakstik/PhotoGnark_V1/src/image"
	"github.com/drakstik/PhotoGnark_V1/src/photoproof"
)

type Photograph struct {
	Img           image.Image
	Proof         photoproof.PCD_Proof
}
```


### Generator
Gnark circuits can be used to generate PCD Keys. The Identity Circuit, for example, can generate a set of system keys called `PCD_Keys` in our implementation, where PCD stands for *Proof-Carrying Data* (11. A. Chiesa and E. Tromer, “Proof-carrying data and hearsay arguments from signature cards.” in ICS, vol. 10, 2010, pp. 310–331.). 

Our generator function takes advantage of Go's Interfaces, which allow us to to delegate key generation to each Transformation & Circuit type. This is why the TransformationCirctuit interface (introduced earlier) has the function `GeneratePCD_Keys()`. Here's how GeneratePCD_Keys works in the IdentityCirctui:

```
// GeneratePCD_Keys implements TransformationCircuit.
func (circuit IdentityCircuit) GeneratePCD_Keys(sk signature.Signer) (PCD_Keys, error) {

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("generatePCD_Keys(): ERROR while compiling constraint system for " + circuit.GetType())
		return PCD_Keys{}, err
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		fmt.Println("generatePCD_Keys(): ERROR while generating PCD Keys from the constraint system for" + circuit.GetType())
		return PCD_Keys{}, err
	}

	pcd_keys := PCD_Keys{
		ProvingKey:   provingKey,
		VerifyingKey: verifyingKey,
	}

	return pcd_keys, err
}
```



### The Prover
Proving 

### The Verifier
