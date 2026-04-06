// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"encoding/binary"
	"image/gif"
	"image/jpeg"
	"image/png"
)

// JpegScanner analyzes JPEG files
type JpegScanner struct{}

func NewJpegScanner() *JpegScanner { return &JpegScanner{} }

func (s *JpegScanner) Name() string                                  { return "ScanJpeg" }
func (s *JpegScanner) Init(config map[string]interface{}) error       { return nil }
func (s *JpegScanner) Flavors() []string                              { return []string{"image/jpeg"} }
func (s *JpegScanner) Priority() int                                  { return 5 }

func (s *JpegScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"width":  cfg.Width,
		"height": cfg.Height,
	}

	// Parse EXIF segments (APP1 markers)
	var segments []interface{}
	offset := 2 // Skip SOI marker (FF D8)
	for offset+4 < len(file) {
		if file[offset] != 0xFF {
			break
		}
		marker := file[offset+1]
		segLen := int(binary.BigEndian.Uint16(file[offset+2:]))

		segName := jpegMarkerName(marker)
		if segName != "" {
			segments = append(segments, segName)
		}

		// Check for trailing data after EOI
		if marker == 0xD9 { // EOI
			if offset+2 < len(file) {
				trailingSize := len(file) - offset - 2
				result["trailingData"] = trailingSize
				if trailingSize > 0 {
					result["hasTrailingData"] = true
				}
			}
			break
		}

		offset += 2 + segLen
	}

	if len(segments) > 0 {
		result["segments"] = segments
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

func jpegMarkerName(marker byte) string {
	switch {
	case marker == 0xE0:
		return "APP0/JFIF"
	case marker == 0xE1:
		return "APP1/EXIF"
	case marker >= 0xE2 && marker <= 0xEF:
		return "APP" + string(rune('0'+marker-0xE0))
	case marker == 0xFE:
		return "COM"
	case marker == 0xDB:
		return "DQT"
	case marker == 0xC0:
		return "SOF0"
	case marker == 0xC4:
		return "DHT"
	case marker == 0xDA:
		return "SOS"
	default:
		return ""
	}
}

// GifScanner analyzes GIF files
type GifScanner struct{}

func NewGifScanner() *GifScanner { return &GifScanner{} }

func (s *GifScanner) Name() string                                  { return "ScanGif" }
func (s *GifScanner) Init(config map[string]interface{}) error       { return nil }
func (s *GifScanner) Flavors() []string                              { return []string{"image/gif"} }
func (s *GifScanner) Priority() int                                  { return 5 }

func (s *GifScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	g, err := gif.DecodeAll(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"frames": len(g.Image),
	}

	if len(g.Image) > 0 {
		bounds := g.Image[0].Bounds()
		result["width"] = bounds.Dx()
		result["height"] = bounds.Dy()
	}

	if len(g.Image) > 1 {
		result["animated"] = true
	}

	// Version
	version := "GIF89a"
	if len(file) >= 6 {
		version = string(file[:6])
	}
	result["version"] = version

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// BmpEofScanner detects trailing data after BMP files
type BmpEofScanner struct{}

func NewBmpEofScanner() *BmpEofScanner { return &BmpEofScanner{} }

func (s *BmpEofScanner) Name() string                                  { return "ScanBmpEof" }
func (s *BmpEofScanner) Init(config map[string]interface{}) error       { return nil }
func (s *BmpEofScanner) Flavors() []string                              { return []string{"image/bmp"} }
func (s *BmpEofScanner) Priority() int                                  { return 5 }

func (s *BmpEofScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if len(file) < 14 || file[0] != 'B' || file[1] != 'M' {
		return nil, nil
	}

	// BMP file size is at offset 2 (4 bytes, little-endian)
	declaredSize := binary.LittleEndian.Uint32(file[2:6])
	actualSize := uint32(len(file))

	result := map[string]interface{}{
		"declaredSize": declaredSize,
		"actualSize":   actualSize,
	}

	if actualSize > declaredSize {
		trailingSize := actualSize - declaredSize
		result["hasTrailingData"] = true
		result["trailingDataSize"] = trailingSize

		// Extract trailing data for further analysis
		return &ScanResult{
			Scanner: s.Name(),
			Data:    result,
			Files: []ExtractedFile{
				{Name: metadata.Name + ".trailing", Content: file[declaredSize:]},
			},
		}, nil
	}

	result["hasTrailingData"] = false
	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// PngEofScanner detects trailing data after the IEND chunk in PNG files
type PngEofScanner struct{}

func NewPngEofScanner() *PngEofScanner { return &PngEofScanner{} }

func (s *PngEofScanner) Name() string                                  { return "ScanPngEof" }
func (s *PngEofScanner) Init(config map[string]interface{}) error       { return nil }
func (s *PngEofScanner) Flavors() []string                              { return []string{"image/png"} }
func (s *PngEofScanner) Priority() int                                  { return 5 }

func (s *PngEofScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// PNG signature is 8 bytes
	if len(file) < 8 {
		return nil, nil
	}

	cfg, err := png.DecodeConfig(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"width":  cfg.Width,
		"height": cfg.Height,
	}

	// Find IEND chunk
	iendMarker := []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82} // IEND + CRC
	iendIdx := bytes.Index(file, iendMarker)
	if iendIdx >= 0 {
		iendEnd := iendIdx + len(iendMarker)
		if iendEnd < len(file) {
			trailingSize := len(file) - iendEnd
			result["hasTrailingData"] = true
			result["trailingDataSize"] = trailingSize

			return &ScanResult{
				Scanner: s.Name(),
				Data:    result,
				Files: []ExtractedFile{
					{Name: metadata.Name + ".trailing", Content: file[iendEnd:]},
				},
			}, nil
		}
	}

	result["hasTrailingData"] = false
	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}
