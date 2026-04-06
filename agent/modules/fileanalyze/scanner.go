// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"sort"
	"strings"
)

type FileMetadata struct {
	Name     string
	Size     int64
	Depth    int
	ParentID string
}

type ScanResult struct {
	Scanner string                 `json:"scanner"`
	Data    map[string]interface{} `json:"data"`
	Files   []ExtractedFile        `json:"files,omitempty"`
}

type ExtractedFile struct {
	Name    string
	Content []byte
}

type Scanner interface {
	Name() string
	Init(config map[string]interface{}) error
	Scan(file []byte, metadata FileMetadata) (*ScanResult, error)
	Flavors() []string // File types this scanner handles, "*" for all
	Priority() int     // Lower runs first
}

type ScannerRegistry struct {
	scanners []Scanner
}

func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{}
}

func (r *ScannerRegistry) Register(s Scanner) {
	r.scanners = append(r.scanners, s)
	sort.Slice(r.scanners, func(i, j int) bool {
		return r.scanners[i].Priority() < r.scanners[j].Priority()
	})
}

func (r *ScannerRegistry) ScannersForFlavor(flavor string) []Scanner {
	var result []Scanner
	for _, s := range r.scanners {
		for _, f := range s.Flavors() {
			if f == "*" || strings.EqualFold(f, flavor) {
				result = append(result, s)
				break
			}
		}
	}
	return result
}
