package image

type PixelRGB struct {
	R   uint8
	G   uint8
	B   uint8
	row uint64
	col uint64
	idx uint64
}

type PixelPacked struct {
	RGB uint32
	row uint64
	col uint64
	idx uint64
}

// TODO
type FrPixelRGB struct {
}

// TODO
type FrPixelPacked struct {
}

func (pixel PixelRGB) Pack() PixelPacked {
	rgb := uint32(pixel.R)<<16 | uint32(pixel.G)<<8 | uint32(pixel.B)
	return PixelPacked{
		RGB: rgb,
		row: pixel.row,
		col: pixel.col,
		idx: pixel.idx,
	}
}

func (packed PixelPacked) Unpack() PixelRGB {
	return PixelRGB{
		R:   uint8((packed.RGB >> 16) & 0xFF),
		G:   uint8((packed.RGB >> 8) & 0xFF),
		B:   uint8(packed.RGB & 0xFF),
		row: packed.row,
		col: packed.col,
		idx: packed.idx,
	}
}
