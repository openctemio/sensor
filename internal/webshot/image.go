package webshot

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
)

// The picture leaves the task as fresh pixels only: decoded and encoded
// again, so no chunk, comment, profile or trailing bytes of what the browser
// wrote survive (the platform decodes and re-encodes once more).

// Bounds the platform also enforces (RFC-081): an image over them is
// dropped there, so it is never sent.
const (
	maxImageBytes  = 1 << 20
	maxImageWidth  = 1920
	maxImageHeight = 2400
)

var errImage = errors.New("webshot: the screenshot is not a usable image")

// encoded is a re-encoded screenshot.
type encoded struct {
	MediaType string
	Data      []byte
	Width     int
	Height    int
}

// reencode decodes a PNG from the browser and encodes it again within the
// size cap: PNG when it fits, else JPEG at falling quality. limit is the
// byte cap (at most maxImageBytes).
func reencode(raw []byte, limit int) (*encoded, error) {
	if limit <= 0 || limit > maxImageBytes {
		limit = maxImageBytes
	}
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, fmt.Errorf("%w: not a PNG", errImage)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errImage, err)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxImageWidth || cfg.Height > maxImageHeight {
		return nil, fmt.Errorf("%w: %dx%d is out of bounds", errImage, cfg.Width, cfg.Height)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errImage, err)
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err == nil && buf.Len() <= limit {
		return &encoded{MediaType: "image/png", Data: buf.Bytes(), Width: cfg.Width, Height: cfg.Height}, nil
	}
	for _, q := range []int{85, 70, 50} {
		buf.Reset()
		if err := jpeg.Encode(&buf, opaque(img), &jpeg.Options{Quality: q}); err != nil {
			return nil, fmt.Errorf("%w: %v", errImage, err)
		}
		if buf.Len() <= limit {
			return &encoded{MediaType: "image/jpeg", Data: buf.Bytes(), Width: cfg.Width, Height: cfg.Height}, nil
		}
	}
	return nil, fmt.Errorf("%w: over %d bytes at every quality", errImage, limit)
}

// opaque is the image as JPEG can hold it (no alpha): what the browser
// renders is opaque already, so this only changes the color model.
func opaque(img image.Image) image.Image {
	if _, ok := img.(*image.RGBA); ok {
		return img
	}
	b := img.Bounds()
	out := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			out.Set(x, y, img.At(x, y))
		}
	}
	return out
}
