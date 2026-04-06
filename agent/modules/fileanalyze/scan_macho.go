// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"debug/macho"
)

type MachoScanner struct{}

func NewMachoScanner() *MachoScanner {
	return &MachoScanner{}
}

func (s *MachoScanner) Name() string { return "ScanMacho" }

func (s *MachoScanner) Init(config map[string]interface{}) error { return nil }

func (s *MachoScanner) Flavors() []string {
	return []string{"application/x-mach-binary"}
}

func (s *MachoScanner) Priority() int { return 5 }

func (s *MachoScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	f, err := macho.NewFile(bytes.NewReader(file))
	if err != nil {
		// Try as fat/universal binary
		return s.scanFat(file, metadata)
	}
	defer f.Close()

	return s.scanSingle(f)
}

func (s *MachoScanner) scanSingle(f *macho.File) (*ScanResult, error) {
	result := make(map[string]interface{})

	result["cpu"] = f.Cpu.String()
	result["type"] = f.Type.String()
	result["byteOrder"] = f.ByteOrder.String()

	// Sections
	var sections []interface{}
	for _, sec := range f.Sections {
		sections = append(sections, map[string]interface{}{
			"name":    sec.Name,
			"segment": sec.Seg,
			"size":    sec.Size,
		})
	}
	result["sections"] = sections

	// Load commands
	var loads []interface{}
	for _, load := range f.Loads {
		loads = append(loads, load.Raw())
	}
	result["loadCommands"] = len(f.Loads)

	// Imported libraries
	libs, err := f.ImportedLibraries()
	if err == nil && len(libs) > 0 {
		var libList []interface{}
		for _, lib := range libs {
			libList = append(libList, lib)
		}
		result["libraries"] = libList
	}

	// Imported symbols
	symbols, err := f.ImportedSymbols()
	if err == nil && len(symbols) > 0 {
		var symList []interface{}
		for i, sym := range symbols {
			if i >= 100 {
				break
			}
			symList = append(symList, sym)
		}
		result["importedSymbols"] = symList
		result["importedSymbolCount"] = len(symbols)
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}

func (s *MachoScanner) scanFat(file []byte, metadata FileMetadata) (*ScanResult, error) {
	fat, err := macho.NewFatFile(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}
	defer fat.Close()

	var arches []interface{}
	for _, arch := range fat.Arches {
		arches = append(arches, map[string]interface{}{
			"cpu":    arch.Cpu.String(),
			"subcpu": arch.SubCpu,
		})
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"isFat":  true,
			"arches": arches,
		},
	}, nil
}
