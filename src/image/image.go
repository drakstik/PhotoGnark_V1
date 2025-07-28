package image

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

const (
	// N must be a constant, not a variable, because N is used in the definition of the image size and
	// circuits do not change once compiled. N is also used to set array size, which is set at compile time and is meant
	// to remain unchangeable.
	N  = 16
	N2 = N * N // Number of pixels in an image.
)

type Image struct {
	Pixels     [N2]Pixel
	PixelBytes []byte
}

type FrImage struct {
	Pixels   [N2]FrPixel // Secret
	ImgBytes []byte
}

// ---------------------------------------------------------------------------------------

func NewImage(flag string) (Image, error) {
	newImage := Image{Pixels: [N2]Pixel{}}

	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			if flag == "black" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col
				black := [3]uint8{0, 0, 0}

				blackPixel := Pixel{
					RGB:    black,
					Packed: Pack(black),
					Loc:    PixelLocation{Row: uint64(row), Col: uint64(col), Idx: uint64(idx)},
				}

				newImage.Pixels[blackPixel.Loc.Idx] = blackPixel
			}

			if flag == "white" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col
				white := [3]uint8{255, 255, 255}

				whitePixel := Pixel{
					RGB:    white,
					Packed: Pack(white),
					Loc:    PixelLocation{Row: uint64(row), Col: uint64(col), Idx: uint64(idx)},
				}

				newImage.Pixels[whitePixel.Loc.Idx] = whitePixel
			}

			if flag == "random" {
				// Generate a random number between 0 and 255
				n1, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}
				n2, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}
				n3, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}

				random := [3]uint8{uint8(n1.Int64()), uint8(n2.Int64()), uint8(n3.Int64())}

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				randomPixel := Pixel{
					RGB:    random,
					Packed: Pack(random),
					Loc:    PixelLocation{Row: uint64(row), Col: uint64(col), Idx: uint64(idx)},
				}

				newImage.Pixels[randomPixel.Loc.Idx] = randomPixel
			}
		}
	}

	b, err := newImage.ToBigEndian()
	if err != nil {
		return Image{}, err
	}

	newImage.PixelBytes = b

	return newImage, err
}

// ----------------------------------------------------------------------------------------

func (img Image) PrintImage() {
	fmt.Println("RGB Image: ")
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			currentIdx := row*N + col
			pxl := img.Pixels[currentIdx]
			fmt.Printf("(%3d, %3d, %3d) ", pxl.RGB[0], pxl.RGB[1], pxl.RGB[2])
		}
		fmt.Println() // New line after each row
	}
}

func (img Image) ToFr() (frImg FrImage) {

	output := FrImage{}

	for i := 0; i < N*N; i++ {
		pxl := img.Pixels[i]
		output.Pixels[pxl.Loc.Idx] = pxl.ToFr()
	}

	return output
}

// Return the JSON encoded version of an image's pixels as bytes.
func (img Image) ToByte() ([]byte, error) {
	pixel_bytes, err := json.Marshal(img.Pixels)
	if err != nil {
		fmt.Println("Error while encoding image: " + err.Error())
		return []byte{}, err
	}

	return pixel_bytes, err
}

// Interprets pixel bytes as the bytes of a big-endian unsigned integer, sets z to that value, and return z value as a big endian slice.
// If this step is skipped, you get this error:
// "runtime error: slice bounds out of range".
// This step is required to define an image into something that Gnark circuits understand.
func (img Image) ToBigEndian() ([]byte, error) {

	// Define the picture as a "z value of a field element (fr.element)" that's converted into a big endian
	img_bytes, err := img.ToByte() // Encode image into bytes using JSON
	if err != nil {
		return []byte{}, err
	}

	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(img_bytes)                 // Set the image bytes as the z value for the fr.Element
	big_endian_bytes_Image := msgFr.Marshal() // Convert z value to a big endian slice

	return big_endian_bytes_Image, err
}

// Simple digital signature of the image's PixelBytes.
func (img Image) Sign(secretKey signature.Signer) ([]byte, error) {

	// 3. Instantiate MIMC BN254 hash function, to be used in signing the image
	hFunc := hash.MIMC_BN254.New()

	// 4. Sign the image (must first turn the image into a Big Endian)
	signature, err := secretKey.Sign(img.PixelBytes, hFunc)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}

	return signature, err
}
