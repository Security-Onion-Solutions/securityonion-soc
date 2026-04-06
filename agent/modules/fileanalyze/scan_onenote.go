// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// OneNote file header GUID: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
var onenoteHeaderGUID = []byte{
	0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
	0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
}

// Embedded file GUID used in OneNote to embed objects
var onenoteEmbeddedFileGUID = []byte{
	0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
	0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
}

type OnenoteScanner struct{}

func NewOnenoteScanner() *OnenoteScanner {
	return &OnenoteScanner{}
}

func (s *OnenoteScanner) Name() string { return "ScanOnenote" }

func (s *OnenoteScanner) Init(config map[string]interface{}) error { return nil }

func (s *OnenoteScanner) Flavors() []string {
	return []string{"application/onenote", "application/msonenote"}
}

func (s *OnenoteScanner) Priority() int { return 5 }

func (s *OnenoteScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// Verify OneNote header
	if len(file) < 16 || !bytes.HasPrefix(file, onenoteHeaderGUID) {
		return nil, nil
	}

	// Search for embedded file GUIDs
	var extracted []ExtractedFile
	embeddedCount := 0

	searchFrom := 0
	for {
		idx := bytes.Index(file[searchFrom:], onenoteEmbeddedFileGUID)
		if idx == -1 {
			break
		}
		pos := searchFrom + idx
		searchFrom = pos + len(onenoteEmbeddedFileGUID)

		// After the GUID, there's a size field (4 bytes, little-endian)
		sizeOffset := pos + len(onenoteEmbeddedFileGUID) + 4 // Skip 4 bytes of reserved data
		if sizeOffset+4 > len(file) {
			continue
		}

		size := binary.LittleEndian.Uint32(file[sizeOffset:])
		dataOffset := sizeOffset + 4

		if size == 0 || size > uint32(DEFAULT_MAX_FILE_SIZE) || dataOffset+int(size) > len(file) {
			continue
		}

		embeddedCount++
		data := file[dataOffset : dataOffset+int(size)]
		extracted = append(extracted, ExtractedFile{
			Name:    fmt.Sprintf("embedded_%d.bin", embeddedCount),
			Content: data,
		})
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"embeddedObjects": embeddedCount,
		},
		Files: extracted,
	}, nil
}
