// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

type HashScanner struct{}

func NewHashScanner() *HashScanner {
	return &HashScanner{}
}

func (s *HashScanner) Name() string { return "ScanHash" }

func (s *HashScanner) Init(config map[string]interface{}) error { return nil }

func (s *HashScanner) Flavors() []string { return []string{"*"} }

func (s *HashScanner) Priority() int { return 5 }

func (s *HashScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	md5sum := md5.Sum(file)
	sha1sum := sha1.Sum(file)
	sha256sum := sha256.Sum256(file)

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"md5":    hex.EncodeToString(md5sum[:]),
			"sha1":   hex.EncodeToString(sha1sum[:]),
			"sha256": hex.EncodeToString(sha256sum[:]),
		},
	}, nil
}
