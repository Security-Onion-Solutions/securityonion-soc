// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"math"
	"time"
)

type PeScanner struct{}

func NewPeScanner() *PeScanner {
	return &PeScanner{}
}

func (s *PeScanner) Name() string { return "ScanPe" }

func (s *PeScanner) Init(config map[string]interface{}) error { return nil }

func (s *PeScanner) Flavors() []string {
	return []string{"application/x-dosexec"}
}

func (s *PeScanner) Priority() int { return 5 }

func (s *PeScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	f, err := pe.NewFile(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]interface{})

	// Machine type
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		result["machine"] = "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		result["machine"] = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		result["machine"] = "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		result["machine"] = "arm64"
	default:
		result["machine"] = f.Machine
	}

	// Characteristics
	var characteristics []interface{}
	if f.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
		characteristics = append(characteristics, "EXECUTABLE_IMAGE")
	}
	if f.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		characteristics = append(characteristics, "DLL")
	}
	if f.Characteristics&pe.IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
		characteristics = append(characteristics, "LARGE_ADDRESS_AWARE")
	}
	if f.Characteristics&pe.IMAGE_FILE_SYSTEM != 0 {
		characteristics = append(characteristics, "SYSTEM")
	}
	result["characteristics"] = characteristics

	// Determine if 32 or 64 bit
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		result["bits"] = 32
		result["imageBase"] = oh.ImageBase
		result["entryPoint"] = oh.AddressOfEntryPoint
		result["subsystem"] = subsystemName(oh.Subsystem)
		result["dllCharacteristics"] = parseDllCharacteristics(oh.DllCharacteristics)
	case *pe.OptionalHeader64:
		result["bits"] = 64
		result["imageBase"] = oh.ImageBase
		result["entryPoint"] = oh.AddressOfEntryPoint
		result["subsystem"] = subsystemName(oh.Subsystem)
		result["dllCharacteristics"] = parseDllCharacteristics(oh.DllCharacteristics)
	}

	// Timestamp
	timestamp := time.Unix(int64(f.TimeDateStamp), 0).UTC()
	result["compiledAt"] = timestamp.Format(time.RFC3339)

	// Sections
	var sections []interface{}
	for _, sec := range f.Sections {
		sections = append(sections, map[string]interface{}{
			"name":           sec.Name,
			"virtualSize":    sec.VirtualSize,
			"virtualAddress": sec.VirtualAddress,
			"rawSize":        sec.Size,
			"entropy":        sectionEntropy(sec, file),
		})
	}
	result["sections"] = sections

	// Imports
	imports, err := f.ImportedSymbols()
	if err == nil && len(imports) > 0 {
		dllMap := make(map[string][]interface{})
		for _, imp := range imports {
			// Format is "DLL:function"
			parts := splitImport(imp)
			if len(parts) == 2 {
				dllMap[parts[0]] = append(dllMap[parts[0]], parts[1])
			}
		}

		var importList []interface{}
		for dll, funcs := range dllMap {
			importList = append(importList, map[string]interface{}{
				"dll":       dll,
				"functions": funcs,
			})
		}
		result["imports"] = importList
	}

	// Imported libraries
	libs, err := f.ImportedLibraries()
	if err == nil && len(libs) > 0 {
		var libList []interface{}
		for _, lib := range libs {
			libList = append(libList, lib)
		}
		result["libraries"] = libList
	}

	// Check for suspicious imports
	var suspicious []interface{}
	suspiciousAPIs := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
		"CreateRemoteThread", "NtUnmapViewOfSection",
		"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
		"URLDownloadToFile", "WinExec", "ShellExecute",
		"InternetOpen", "HttpSendRequest",
		"CryptEncrypt", "CryptDecrypt",
		"RegSetValue", "RegCreateKey",
	}
	if imports != nil {
		for _, imp := range imports {
			for _, api := range suspiciousAPIs {
				if bytes.Contains([]byte(imp), []byte(api)) {
					suspicious = append(suspicious, api)
				}
			}
		}
	}
	if len(suspicious) > 0 {
		result["suspicious"] = deduplicateSlice(suspicious)
	}

	// Check for packer indicators
	result["isPacked"] = isPacked(f, file)

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}

func splitImport(imp string) []string {
	for i := len(imp) - 1; i >= 0; i-- {
		if imp[i] == ':' {
			return []string{imp[:i], imp[i+1:]}
		}
	}
	return []string{imp}
}

func subsystemName(sub uint16) string {
	switch sub {
	case 1:
		return "NATIVE"
	case 2:
		return "WINDOWS_GUI"
	case 3:
		return "WINDOWS_CUI"
	case 7:
		return "POSIX_CUI"
	case 9:
		return "WINDOWS_CE_GUI"
	case 10:
		return "EFI_APPLICATION"
	default:
		return "UNKNOWN"
	}
}

func parseDllCharacteristics(chars uint16) []interface{} {
	var result []interface{}
	if chars&0x0020 != 0 {
		result = append(result, "HIGH_ENTROPY_VA")
	}
	if chars&0x0040 != 0 {
		result = append(result, "DYNAMIC_BASE")
	}
	if chars&0x0100 != 0 {
		result = append(result, "NX_COMPAT")
	}
	if chars&0x0400 != 0 {
		result = append(result, "NO_SEH")
	}
	if chars&0x4000 != 0 {
		result = append(result, "GUARD_CF")
	}
	return result
}

func sectionEntropy(sec *pe.Section, file []byte) float64 {
	data, err := sec.Data()
	if err != nil || len(data) == 0 {
		return 0
	}
	return shannonEntropy(data)
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := count / length
			entropy -= p * log2(p)
		}
	}
	return entropy
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log2(x)
}

// isPacked checks for common packer indicators
func isPacked(f *pe.File, data []byte) bool {
	// Check for known packer section names
	packerSections := []string{".upx", "UPX0", "UPX1", ".aspack", ".adata", ".nsp0", ".nsp1"}
	for _, sec := range f.Sections {
		for _, packer := range packerSections {
			if sec.Name == packer {
				return true
			}
		}
	}

	// Check for high entropy in code section (>7.0 suggests packing)
	for _, sec := range f.Sections {
		if sec.Name == ".text" || sec.Name == ".code" {
			secData, err := sec.Data()
			if err == nil && len(secData) > 0 {
				ent := shannonEntropy(secData)
				if ent > 7.0 {
					return true
				}
			}
		}
	}

	// Check for small import table (packers typically have very few imports)
	imports, _ := f.ImportedLibraries()
	if len(imports) > 0 && len(imports) <= 2 {
		// Very few imports combined with high overall entropy
		_ = binary.LittleEndian // keep import
		return false            // Need more signals
	}

	return false
}
