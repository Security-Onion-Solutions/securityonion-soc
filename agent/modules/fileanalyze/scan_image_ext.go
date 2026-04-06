// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LsbScanner detects LSB (Least Significant Bit) steganography in images
type LsbScanner struct{}

func NewLsbScanner() *LsbScanner { return &LsbScanner{} }

func (s *LsbScanner) Name() string                                  { return "ScanLsb" }
func (s *LsbScanner) Init(config map[string]interface{}) error       { return nil }
func (s *LsbScanner) Flavors() []string                              { return []string{"image/png", "image/bmp"} }
func (s *LsbScanner) Priority() int                                  { return 7 }

func (s *LsbScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	img, _, err := image.Decode(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds()
	totalPixels := bounds.Dx() * bounds.Dy()
	if totalPixels == 0 {
		return nil, nil
	}

	// Extract LSBs from each color channel
	var lsbBits []byte
	maxBits := totalPixels * 3 // RGB channels
	if maxBits > 8192 {
		maxBits = 8192 // Sample first 1KB of LSB data
	}

	bitCount := 0
	var currentByte byte
	var bytePos int

	for y := bounds.Min.Y; y < bounds.Max.Y && bitCount < maxBits; y++ {
		for x := bounds.Min.X; x < bounds.Max.X && bitCount < maxBits; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			for _, channel := range []uint32{r, g, b} {
				if bitCount >= maxBits {
					break
				}
				bit := byte(channel>>8) & 1
				currentByte = (currentByte << 1) | bit
				bytePos++
				if bytePos == 8 {
					lsbBits = append(lsbBits, currentByte)
					currentByte = 0
					bytePos = 0
				}
				bitCount++
			}
		}
	}

	// Analyze LSB data for signs of hidden content
	result := map[string]interface{}{
		"pixelsSampled": totalPixels,
	}

	if len(lsbBits) > 0 {
		// Check entropy of LSB data — random/high entropy suggests steganography
		ent := shannonEntropy(lsbBits)
		result["lsbEntropy"] = math_round(ent, 3)

		// Check for readable ASCII in LSB data
		printableCount := 0
		for _, b := range lsbBits {
			if b >= 0x20 && b <= 0x7E {
				printableCount++
			}
		}
		printableRatio := float64(printableCount) / float64(len(lsbBits))
		result["printableRatio"] = math_round(printableRatio, 3)

		// If high printable ratio, likely contains text
		if printableRatio > 0.7 {
			result["suspectedSteganography"] = true
			result["hiddenTextSample"] = extractPrintable(lsbBits, 200)
		}

		// Check for known file signatures in LSB data
		lsbTypes := IdentifyType(lsbBits)
		for _, t := range lsbTypes {
			if t != "*" {
				result["suspectedSteganography"] = true
				result["embeddedType"] = t
				break
			}
		}
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

func math_round(val float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int(val*pow+0.5)) / pow
}

func extractPrintable(data []byte, maxLen int) string {
	var sb strings.Builder
	for _, b := range data {
		if sb.Len() >= maxLen {
			break
		}
		if b >= 0x20 && b <= 0x7E {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// OcrScanner extracts text from images using Tesseract
type OcrScanner struct {
	timeout int
}

func NewOcrScanner() *OcrScanner {
	return &OcrScanner{timeout: 60}
}

func (s *OcrScanner) Name() string { return "ScanOcr" }

func (s *OcrScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *OcrScanner) Flavors() []string {
	return []string{"image/jpeg", "image/png", "image/bmp", "image/gif", "image/tiff"}
}

func (s *OcrScanner) Priority() int { return 8 }

func (s *OcrScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "ocr-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tesseract", tmpFile.Name(), "stdout", "--psm", "3")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tesseract failed: %w", err)
	}

	text := strings.TrimSpace(string(output))
	if text == "" {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"hasText": false,
			},
		}, nil
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"hasText":    true,
			"textLength": len(text),
			"text":       truncateString(text, 2000),
		},
	}, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// QrScanner detects and decodes QR codes in images
type QrScanner struct {
	timeout int
}

func NewQrScanner() *QrScanner {
	return &QrScanner{timeout: 30}
}

func (s *QrScanner) Name() string { return "ScanQr" }

func (s *QrScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *QrScanner) Flavors() []string {
	return []string{"image/jpeg", "image/png", "image/bmp", "image/gif"}
}

func (s *QrScanner) Priority() int { return 8 }

func (s *QrScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "qr-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zbarimg", "--quiet", "--raw", tmpFile.Name())
	output, err := cmd.Output()
	if err != nil {
		// No QR code found is not an error
		return nil, nil
	}

	text := strings.TrimSpace(string(output))
	if text == "" {
		return nil, nil
	}

	var codes []interface{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			codes = append(codes, line)
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"codes": codes,
			"count": len(codes),
		},
	}, nil
}

// TranscodeScanner converts images to PNG for consistent downstream analysis
type TranscodeScanner struct {
	timeout int
}

func NewTranscodeScanner() *TranscodeScanner {
	return &TranscodeScanner{timeout: 30}
}

func (s *TranscodeScanner) Name() string { return "ScanTranscode" }

func (s *TranscodeScanner) Init(config map[string]interface{}) error { return nil }

func (s *TranscodeScanner) Flavors() []string {
	return []string{"image/bmp", "image/gif"}
}

func (s *TranscodeScanner) Priority() int { return 4 } // Before other image scanners

func (s *TranscodeScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	img, format, err := image.Decode(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"sourceFormat":  format,
			"transcodedTo":  "png",
			"transcodedSize": buf.Len(),
		},
		Files: []ExtractedFile{
			{Name: metadata.Name + ".png", Content: buf.Bytes()},
		},
	}, nil
}
