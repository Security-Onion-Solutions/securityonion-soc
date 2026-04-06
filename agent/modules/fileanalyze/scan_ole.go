// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"io"

	"github.com/richardlehane/mscfb"
)

type OleScanner struct{}

func NewOleScanner() *OleScanner {
	return &OleScanner{}
}

func (s *OleScanner) Name() string { return "ScanOle" }

func (s *OleScanner) Init(config map[string]interface{}) error { return nil }

func (s *OleScanner) Flavors() []string {
	return []string{"application/x-ole", "application/vnd.ms-excel", "application/msword"}
}

func (s *OleScanner) Priority() int { return 5 }

func (s *OleScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	doc, err := mscfb.New(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	var streams []interface{}
	var extracted []ExtractedFile

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		streams = append(streams, entry.Name)

		if entry.Size > 0 && entry.Size < DEFAULT_MAX_FILE_SIZE {
			data, readErr := io.ReadAll(entry)
			if readErr == nil && len(data) > 0 {
				extracted = append(extracted, ExtractedFile{
					Name:    entry.Name,
					Content: data,
				})
			}
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"streams":    streams,
			"numStreams": len(streams),
		},
		Files: extracted,
	}, nil
}
