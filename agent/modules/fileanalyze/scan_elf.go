// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"debug/elf"
)

type ElfScanner struct{}

func NewElfScanner() *ElfScanner {
	return &ElfScanner{}
}

func (s *ElfScanner) Name() string { return "ScanElf" }

func (s *ElfScanner) Init(config map[string]interface{}) error { return nil }

func (s *ElfScanner) Flavors() []string {
	return []string{"application/x-elf"}
}

func (s *ElfScanner) Priority() int { return 5 }

func (s *ElfScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	f, err := elf.NewFile(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]interface{})

	// Basic info
	result["class"] = f.Class.String()
	result["byteOrder"] = f.ByteOrder.String()
	result["osAbi"] = f.OSABI.String()
	result["type"] = f.Type.String()
	result["machine"] = f.Machine.String()

	// Sections
	var sections []interface{}
	for _, sec := range f.Sections {
		sections = append(sections, map[string]interface{}{
			"name":  sec.Name,
			"type":  sec.Type.String(),
			"size":  sec.Size,
			"flags": sec.Flags.String(),
		})
	}
	result["sections"] = sections

	// Program headers (segments)
	var segments []interface{}
	for _, prog := range f.Progs {
		segments = append(segments, map[string]interface{}{
			"type":  prog.Type.String(),
			"flags": prog.Flags.String(),
		})
	}
	result["segments"] = segments

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
		for _, sym := range symbols {
			symList = append(symList, sym.Name)
		}
		// Limit to first 100 symbols
		if len(symList) > 100 {
			symList = symList[:100]
		}
		result["importedSymbols"] = symList
		result["importedSymbolCount"] = len(symbols)
	}

	// Check for suspicious characteristics
	var suspicious []interface{}

	// Check if statically linked (no dynamic section)
	hasDynamic := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			hasDynamic = true
			break
		}
	}
	if !hasDynamic {
		result["isStatic"] = true
	}

	// Check for writable+executable segments (W^X violation)
	for _, prog := range f.Progs {
		if prog.Flags&elf.PF_W != 0 && prog.Flags&elf.PF_X != 0 {
			suspicious = append(suspicious, "WX_SEGMENT")
			break
		}
	}

	// Check for no RELRO
	hasRelro := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	if !hasRelro && hasDynamic {
		suspicious = append(suspicious, "NO_RELRO")
	}

	// Check for suspicious symbols
	suspiciousSymbols := []string{
		"ptrace", "dlopen", "dlsym", "mprotect",
		"execve", "fork", "system", "popen",
	}
	if symbols != nil {
		for _, sym := range symbols {
			for _, susp := range suspiciousSymbols {
				if sym.Name == susp {
					suspicious = append(suspicious, "IMPORT_"+susp)
				}
			}
		}
	}

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}
