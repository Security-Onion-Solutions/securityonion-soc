// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"encoding/hex"
)

const DEFAULT_HEADER_FOOTER_SIZE = 50

type HeaderScanner struct {
	size int
}

func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{size: DEFAULT_HEADER_FOOTER_SIZE}
}

func (s *HeaderScanner) Name() string { return "ScanHeader" }

func (s *HeaderScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["size"]; ok {
			s.size = int(v.(float64))
		}
	}
	return nil
}

func (s *HeaderScanner) Flavors() []string { return []string{"*"} }

func (s *HeaderScanner) Priority() int { return 5 }

func (s *HeaderScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	headerSize := s.size
	if headerSize > len(file) {
		headerSize = len(file)
	}

	footerStart := len(file) - s.size
	if footerStart < 0 {
		footerStart = 0
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"header": hex.EncodeToString(file[:headerSize]),
			"footer": hex.EncodeToString(file[footerStart:]),
		},
	}, nil
}
