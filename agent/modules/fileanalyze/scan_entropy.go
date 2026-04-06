// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"math"
)

type EntropyScanner struct{}

func NewEntropyScanner() *EntropyScanner {
	return &EntropyScanner{}
}

func (s *EntropyScanner) Name() string { return "ScanEntropy" }

func (s *EntropyScanner) Init(config map[string]interface{}) error { return nil }

func (s *EntropyScanner) Flavors() []string { return []string{"*"} }

func (s *EntropyScanner) Priority() int { return 5 }

func (s *EntropyScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if len(file) == 0 {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"entropy": 0.0,
			},
		}, nil
	}

	var freq [256]float64
	for _, b := range file {
		freq[b]++
	}

	length := float64(len(file))
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := count / length
			entropy -= p * math.Log2(p)
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"entropy": math.Round(entropy*1000) / 1000,
		},
	}, nil
}
