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

// ---------------------------------------------------------------

type FrPixelLoc struct {
	Row frontend.Variable `gnark:",inherit"` //secret
	Col frontend.Variable `gnark:",inherit"` //secret
	Idx frontend.Variable `gnark:",inherit"` //secret
}

type FrPixel struct {
	RGB    frontend.Variable `gnark:",inherit"` //secret
	Packed frontend.Variable `gnark:",inherit"` //secret
	Loc    FrPixelLoc        `gnark:",inherit"` //secret
}

// ---------------------------------------------------------------------------------------

func (pxl Pixel) ToFr() (frPxl FrPixel) {
	loc := FrPixelLoc{
		Row: pxl.Loc.Row,
		Col: pxl.Loc.Col,
		Idx: pxl.Loc.Idx,
	}

	return FrPixel{
		RGB:    pxl.RGB,
		Packed: pxl.Packed,
		Loc:    loc,
	}
}

//--------------------------------------------------------------------------------------------------------------

func NewPixel(rgb [3]uint8, loc PixelLocation) Pixel {
	return Pixel{RGB: rgb, Packed: Pack(rgb), Loc: loc}
}

func NewPixel_p(packed uint32, loc PixelLocation) Pixel {
	return Pixel{RGB: Unpack(packed), Packed: packed, Loc: loc}
}

func Pack(rgb [3]uint8) uint32 {
	return uint32(rgb[0])<<16 | uint32(rgb[1])<<8 | uint32(rgb[2])
}

func Unpack(packed uint32) [3]uint8 {
	return [3]uint8{uint8((packed >> 16) & 0xFF), uint8((packed >> 8) & 0xFF), uint8(packed & 0xFF)}
}
