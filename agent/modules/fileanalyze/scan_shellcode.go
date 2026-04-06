// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Base64PeScanner detects PE files encoded in base64
type Base64PeScanner struct{}

func NewBase64PeScanner() *Base64PeScanner {
	return &Base64PeScanner{}
}

func (s *Base64PeScanner) Name() string { return "ScanBase64PE" }

func (s *Base64PeScanner) Init(config map[string]interface{}) error { return nil }

func (s *Base64PeScanner) Flavors() []string { return []string{"*"} }

func (s *Base64PeScanner) Priority() int { return 10 } // Low priority, runs after others

func (s *Base64PeScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// Look for base64-encoded MZ header: TVqQ (base64 of MZ\x90\x00) or TVpQ, TVro, etc.
	mzBase64Prefixes := []string{"TVqQ", "TVpQ", "TVro", "TVoA"}

	content := string(file)
	var extracted []ExtractedFile

	for _, prefix := range mzBase64Prefixes {
		idx := bytes.Index(file, []byte(prefix))
		if idx == -1 {
			continue
		}

		// Try to find the end of the base64 block
		end := idx
		for end < len(content) && isBase64Char(content[end]) {
			end++
		}

		if end-idx < 100 { // Too short to be a PE
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(content[idx:end])
		if err != nil {
			continue
		}

		// Verify MZ header
		if len(decoded) > 2 && decoded[0] == 'M' && decoded[1] == 'Z' {
			extracted = append(extracted, ExtractedFile{
				Name:    "decoded_pe.exe",
				Content: decoded,
			})

			return &ScanResult{
				Scanner: s.Name(),
				Data: map[string]interface{}{
					"found":       true,
					"offset":      idx,
					"decodedSize": len(decoded),
				},
				Files: extracted,
			}, nil
		}
	}

	return nil, nil // No base64 PE found
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
}

// DonutScanner detects Donut shellcode loaders
type DonutScanner struct{}

func NewDonutScanner() *DonutScanner {
	return &DonutScanner{}
}

func (s *DonutScanner) Name() string { return "ScanDonut" }

func (s *DonutScanner) Init(config map[string]interface{}) error { return nil }

func (s *DonutScanner) Flavors() []string { return []string{"*"} }

func (s *DonutScanner) Priority() int { return 10 }

// Donut loader magic bytes
var donutMagic = []byte("DONUT_INSTANCE")

func (s *DonutScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if bytes.Contains(file, donutMagic) {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"detected": true,
				"type":     "donut_loader",
			},
		}, nil
	}

	return nil, nil
}

// SwfScanner analyzes SWF (Flash) files
type SwfScanner struct{}

func NewSwfScanner() *SwfScanner {
	return &SwfScanner{}
}

func (s *SwfScanner) Name() string { return "ScanSwf" }

func (s *SwfScanner) Init(config map[string]interface{}) error { return nil }

func (s *SwfScanner) Flavors() []string {
	return []string{"application/x-shockwave-flash"}
}

func (s *SwfScanner) Priority() int { return 5 }

func (s *SwfScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if len(file) < 8 {
		return nil, nil
	}

	result := make(map[string]interface{})
	var extracted []ExtractedFile

	sig := string(file[:3])
	switch sig {
	case "FWS":
		result["compression"] = "none"
	case "CWS":
		result["compression"] = "zlib"
		// Decompress zlib-compressed SWF
		reader, err := zlib.NewReader(bytes.NewReader(file[8:]))
		if err == nil {
			decompressed, err := io.ReadAll(io.LimitReader(reader, DEFAULT_MAX_FILE_SIZE))
			reader.Close()
			if err == nil {
				// Reconstruct uncompressed SWF
				header := make([]byte, 8)
				copy(header, file[:8])
				header[0] = 'F' // Mark as uncompressed
				full := append(header, decompressed...)
				extracted = append(extracted, ExtractedFile{
					Name:    metadata.Name + ".decompressed",
					Content: full,
				})
			}
		}
	case "ZWS":
		result["compression"] = "lzma"
		// LZMA decompression of SWF
		if len(file) > 17 {
			reader := flate.NewReader(bytes.NewReader(file[17:]))
			decompressed, err := io.ReadAll(io.LimitReader(reader, DEFAULT_MAX_FILE_SIZE))
			reader.Close()
			if err == nil && len(decompressed) > 0 {
				extracted = append(extracted, ExtractedFile{
					Name:    metadata.Name + ".decompressed",
					Content: decompressed,
				})
			}
		}
	default:
		return nil, nil
	}

	// SWF version
	result["version"] = int(file[3])

	// File length (uncompressed)
	if len(file) >= 8 {
		result["fileLength"] = binary.LittleEndian.Uint32(file[4:8])
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
		Files:   extracted,
	}, nil
}

// UpxScanner attempts to unpack UPX-packed binaries
type UpxScanner struct {
	timeout int
}

func NewUpxScanner() *UpxScanner {
	return &UpxScanner{timeout: 60}
}

func (s *UpxScanner) Name() string { return "ScanUpx" }

func (s *UpxScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *UpxScanner) Flavors() []string {
	return []string{"application/x-dosexec", "application/x-elf"}
}

func (s *UpxScanner) Priority() int { return 8 } // After PE/ELF scanners

func (s *UpxScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// Quick check for UPX markers
	if !bytes.Contains(file, []byte("UPX!")) && !bytes.Contains(file, []byte("UPX0")) {
		return nil, nil
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "upx-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	// Create output path
	outPath := tmpPath + ".unpacked"
	defer os.Remove(outPath)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "upx", "-d", "-o", outPath, tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"detected":  true,
				"unpacked":  false,
				"error":     fmt.Sprintf("upx failed: %s", string(output)),
			},
		}, nil
	}

	// Read unpacked file
	unpacked, err := os.ReadFile(outPath)
	if err != nil {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"detected": true,
				"unpacked": false,
			},
		}, nil
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"detected":     true,
			"unpacked":     true,
			"packedSize":   len(file),
			"unpackedSize": len(unpacked),
		},
		Files: []ExtractedFile{
			{Name: metadata.Name + ".unpacked", Content: unpacked},
		},
	}, nil
}
