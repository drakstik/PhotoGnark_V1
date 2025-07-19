package image

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const (
	// N must be a constant, not a variable, because N is used in the definition of the image transformation circuits;
	// and circuits do not change once compiled. N is also used to set array size, which is set at compile time and is meant
	// to remain unchangeable.
	N  = 1
	N2 = N * N // Number of pixels in an image.
)

type ImagePacked struct {
	Pixels [N * N]PixelPacked
}

type ImageRGB struct {
	Pixels [N * N]PixelRGB
}

type FrImage struct {
	Pixels [N * N]frontend.Variable // Secret
}

// ---------------------------------------------------------------------------------------

func NewImageRGB(flag string) (ImageRGB, error) {
	newImage := ImageRGB{Pixels: [N * N]PixelRGB{}}

	if flag == "" {
		return newImage, nil
	}

	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			if flag == "black" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				blackPixel := PixelRGB{
					R:   0,
					G:   0,
					B:   0,
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = blackPixel
			}

			if flag == "white" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				whitePixel := PixelRGB{
					R:   255,
					G:   255,
					B:   255,
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = whitePixel
			}

			if flag == "random" {
				// Generate a random number between 0 and 255
				n, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return ImageRGB{}, err
				}

				randomR := uint8(n.Int64())
				randomG := uint8(n.Int64())
				randomB := uint8(n.Int64())

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				randomPixel := PixelRGB{
					R:   randomR,
					G:   randomG,
					B:   randomB,
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = randomPixel
			}
		}
	}

	return newImage, nil
}

func NewImagePacked(flag string) (ImagePacked, error) {
	newImage := ImagePacked{Pixels: [N * N]PixelPacked{}}

	if flag == "" {
		return newImage, nil
	}

	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			if flag == "black" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				blackPixel := PixelPacked{
					RGB: uint32(0)<<16 | uint32(0)<<8 | uint32(0),
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = blackPixel
			}

			if flag == "white" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				whitePixel := PixelPacked{
					RGB: uint32(255)<<16 | uint32(255)<<8 | uint32(255),
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = whitePixel
			}

			if flag == "random" {
				// Generate a random number between 0 and 255
				n, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return ImagePacked{}, err
				}

				randomR := uint8(n.Int64())
				randomG := uint8(n.Int64())
				randomB := uint8(n.Int64())

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				randomPixel := PixelPacked{
					RGB: uint32(randomR)<<16 | uint32(randomG)<<8 | uint32(randomB),
					row: uint64(row),
					col: uint64(col),
					idx: uint64(idx),
				}

				newImage.Pixels[idx] = randomPixel
			}
		}
	}

	return newImage, nil
}

// TODO
func (img ImageRGB) ToImagePacked() (ImagePacked, error)

// TODO
func (img ImagePacked) ToImageRGB() (ImageRGB, error)

// ----------------------------------------------------------------------------------------

func (img ImageRGB) PrintImage() {
	fmt.Println("RGB Image: ")
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			currentIdx := row*N + col
			pxl := img.Pixels[currentIdx]
			fmt.Printf("(%3d, %3d, %3d) ", pxl.R, pxl.G, pxl.B)
		}
		fmt.Println() // New line after each row
	}
}

func (img ImagePacked) PrintImage() {
	fmt.Println("Packed Image: ")
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			currentIdx := row*N + col
			pxl := img.Pixels[currentIdx]
			pxlPacked := pxl.Unpack()
			fmt.Printf("(%3d, %3d, %3d) ", pxlPacked.R, pxlPacked.G, pxlPacked.B)
		}
		fmt.Println() // New line after each row
	}
}

func (img ImagePacked) AddPixelRGB(pxl PixelRGB) {
	img.Pixels[pxl.idx] = pxl.Pack()
}

func (img ImagePacked) AddPixelPacked(pxl PixelPacked) {
	img.Pixels[pxl.idx] = pxl
}

func (img ImageRGB) AddPixelRGB(pxl PixelRGB) {
	img.Pixels[pxl.idx] = pxl
}

func (img ImageRGB) AddPixelPacked(pxl PixelPacked) {
	img.Pixels[pxl.idx] = pxl.Unpack()
}

func (img FrImage) AddPixelRGB(pxl PixelRGB) {
	img.Pixels[pxl.idx] = frontend.Variable(pxl.Pack().RGB)
}

func (img FrImage) AddPixelPacked(pxl PixelPacked) {
	img.Pixels[pxl.idx] = frontend.Variable(pxl.RGB)
}
