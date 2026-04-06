// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"encoding/binary"
)

// TNEF magic signature
var tnefSignature = []byte{0x78, 0x9F, 0x3E, 0x22}

type TnefScanner struct{}

func NewTnefScanner() *TnefScanner {
	return &TnefScanner{}
}

func (s *TnefScanner) Name() string { return "ScanTnef" }

func (s *TnefScanner) Init(config map[string]interface{}) error { return nil }

func (s *TnefScanner) Flavors() []string {
	return []string{"application/ms-tnef", "application/vnd.ms-tnef"}
}

func (s *TnefScanner) Priority() int { return 5 }

func (s *TnefScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if len(file) < 6 || !bytes.HasPrefix(file, tnefSignature) {
		return nil, nil
	}

	var extracted []ExtractedFile
	var attachmentNames []interface{}

	// Parse TNEF structure
	// Format: signature(4) + legacy_key(2) + attributes...
	offset := 6

	for offset < len(file)-9 {
		if offset+9 > len(file) {
			break
		}

		// Each attribute: level(1) + type(2) + name(2) + length(4) + data(length) + checksum(2)
		level := file[offset]
		offset++

		if level != 1 && level != 2 {
			break
		}

		if offset+8 > len(file) {
			break
		}

		attrType := binary.LittleEndian.Uint16(file[offset:])
		_ = attrType
		offset += 2

		attrName := binary.LittleEndian.Uint16(file[offset:])
		offset += 2

		dataLen := binary.LittleEndian.Uint32(file[offset:])
		offset += 4

		if int(dataLen) < 0 || offset+int(dataLen) > len(file) {
			break
		}

		attrData := file[offset : offset+int(dataLen)]
		offset += int(dataLen)

		// Skip checksum
		if offset+2 > len(file) {
			break
		}
		offset += 2

		// Attachment rendering data (attAttachRenddata = 0x9002)
		// Attachment data (attAttachData = 0x800F)
		// Attachment title/filename (attAttachTitle = 0x8010)
		if level == 2 {
			switch attrName {
			case 0x8010: // attAttachTitle - filename
				name := string(bytes.TrimRight(attrData, "\x00"))
				if name != "" {
					attachmentNames = append(attachmentNames, name)
				}
			case 0x800F: // attAttachData
				fileName := "attachment"
				if len(attachmentNames) > 0 {
					fileName = attachmentNames[len(attachmentNames)-1].(string)
				}
				if int64(len(attrData)) <= DEFAULT_MAX_FILE_SIZE {
					extracted = append(extracted, ExtractedFile{
						Name:    fileName,
						Content: attrData,
					})
				}
			}
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"attachments":    attachmentNames,
			"numAttachments": len(attachmentNames),
		},
		Files: extracted,
	}, nil
}
