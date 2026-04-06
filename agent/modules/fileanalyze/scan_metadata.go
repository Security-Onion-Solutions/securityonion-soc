// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// LnkScanner parses Windows LNK (shortcut) files
type LnkScanner struct{}

func NewLnkScanner() *LnkScanner { return &LnkScanner{} }

func (s *LnkScanner) Name() string                                  { return "ScanLNK" }
func (s *LnkScanner) Init(config map[string]interface{}) error       { return nil }
func (s *LnkScanner) Flavors() []string                              { return []string{"application/x-ms-shortcut"} }
func (s *LnkScanner) Priority() int                                  { return 5 }

// LNK magic: 4C 00 00 00
var lnkMagic = []byte{0x4C, 0x00, 0x00, 0x00}

func (s *LnkScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if len(file) < 76 || !bytes.HasPrefix(file, lnkMagic) {
		return nil, nil
	}

	result := make(map[string]interface{})

	// Link flags at offset 20
	if len(file) >= 24 {
		flags := binary.LittleEndian.Uint32(file[20:24])
		var flagList []interface{}
		if flags&0x01 != 0 {
			flagList = append(flagList, "HasLinkTargetIDList")
		}
		if flags&0x02 != 0 {
			flagList = append(flagList, "HasLinkInfo")
		}
		if flags&0x04 != 0 {
			flagList = append(flagList, "HasName")
		}
		if flags&0x08 != 0 {
			flagList = append(flagList, "HasRelativePath")
		}
		if flags&0x10 != 0 {
			flagList = append(flagList, "HasWorkingDir")
		}
		if flags&0x20 != 0 {
			flagList = append(flagList, "HasArguments")
		}
		if flags&0x40 != 0 {
			flagList = append(flagList, "HasIconLocation")
		}
		result["flags"] = flagList
	}

	// File attributes at offset 24
	if len(file) >= 28 {
		attrs := binary.LittleEndian.Uint32(file[24:28])
		if attrs&0x01 != 0 {
			result["isReadonly"] = true
		}
		if attrs&0x02 != 0 {
			result["isHidden"] = true
		}
		if attrs&0x04 != 0 {
			result["isSystem"] = true
		}
		if attrs&0x20 != 0 {
			result["isArchive"] = true
		}
	}

	// Try to extract readable strings that might contain target paths/commands
	readableStrings := extractReadableStrings(file[76:], 8)
	var suspicious []interface{}
	for _, s := range readableStrings {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "powershell") || strings.Contains(lower, "cmd.exe") ||
			strings.Contains(lower, "wscript") || strings.Contains(lower, "mshta") ||
			strings.Contains(lower, "certutil") || strings.Contains(lower, "bitsadmin") {
			suspicious = append(suspicious, s)
		}
	}
	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// ManifestScanner parses XML manifests (Windows application manifests)
type ManifestScanner struct{}

func NewManifestScanner() *ManifestScanner { return &ManifestScanner{} }

func (s *ManifestScanner) Name() string                                  { return "ScanManifest" }
func (s *ManifestScanner) Init(config map[string]interface{}) error       { return nil }
func (s *ManifestScanner) Flavors() []string                              { return []string{"application/x-manifest"} }
func (s *ManifestScanner) Priority() int                                  { return 5 }

func (s *ManifestScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	result := make(map[string]interface{})

	// Extract assembly identity
	type AssemblyIdentity struct {
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
		Type    string `xml:"type,attr"`
	}

	type Assembly struct {
		Identity AssemblyIdentity `xml:"assemblyIdentity"`
	}

	var asm Assembly
	if err := xml.Unmarshal(file, &asm); err == nil {
		if asm.Identity.Name != "" {
			result["assemblyName"] = asm.Identity.Name
			result["assemblyVersion"] = asm.Identity.Version
		}
	}

	// Check for elevation requirements
	if strings.Contains(content, "requireAdministrator") {
		result["requiresAdmin"] = true
	} else if strings.Contains(content, "highestAvailable") {
		result["requestsHighest"] = true
	}

	// Check for DPI awareness
	if strings.Contains(content, "dpiAware") {
		result["dpiAware"] = true
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// JarManifestScanner parses Java JAR manifest files
type JarManifestScanner struct{}

func NewJarManifestScanner() *JarManifestScanner { return &JarManifestScanner{} }

func (s *JarManifestScanner) Name() string                                  { return "ScanJarManifest" }
func (s *JarManifestScanner) Init(config map[string]interface{}) error       { return nil }
func (s *JarManifestScanner) Flavors() []string                              { return []string{"application/x-jar-manifest"} }
func (s *JarManifestScanner) Priority() int                                  { return 5 }

func (s *JarManifestScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	result := make(map[string]interface{})
	attrs := make(map[string]interface{})

	for _, line := range strings.Split(string(file), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			attrs[key] = value
		}
	}

	result["attributes"] = attrs

	if v, ok := attrs["Main-Class"]; ok {
		result["mainClass"] = v
	}
	if v, ok := attrs["Manifest-Version"]; ok {
		result["manifestVersion"] = v
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// UrlScanner parses .url (Windows internet shortcut) files
type UrlScanner struct{}

func NewUrlScanner() *UrlScanner { return &UrlScanner{} }

func (s *UrlScanner) Name() string                                  { return "ScanUrl" }
func (s *UrlScanner) Init(config map[string]interface{}) error       { return nil }
func (s *UrlScanner) Flavors() []string                              { return []string{"application/x-url"} }
func (s *UrlScanner) Priority() int                                  { return 5 }

func (s *UrlScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	result := make(map[string]interface{})

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		case "url":
			result["url"] = value
		case "iconfile":
			result["iconFile"] = value
		case "iconindex":
			result["iconIndex"] = value
		}
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// IqyScanner parses IQY (Internet Query) files — often used in phishing
type IqyScanner struct{}

func NewIqyScanner() *IqyScanner { return &IqyScanner{} }

func (s *IqyScanner) Name() string                                  { return "ScanIqy" }
func (s *IqyScanner) Init(config map[string]interface{}) error       { return nil }
func (s *IqyScanner) Flavors() []string                              { return []string{"application/x-iqy"} }
func (s *IqyScanner) Priority() int                                  { return 5 }

var iqyURLPattern = regexp.MustCompile(`(?i)^https?://`)

func (s *IqyScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	lines := strings.Split(string(file), "\n")
	result := make(map[string]interface{})
	var urls []interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if iqyURLPattern.MatchString(line) {
			urls = append(urls, line)
		}
	}

	if len(urls) > 0 {
		result["urls"] = urls
		result["suspicious"] = true
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// VstoScanner parses VSTO (Visual Studio Tools for Office) deployment manifests
type VstoScanner struct{}

func NewVstoScanner() *VstoScanner { return &VstoScanner{} }

func (s *VstoScanner) Name() string                                  { return "ScanVsto" }
func (s *VstoScanner) Init(config map[string]interface{}) error       { return nil }
func (s *VstoScanner) Flavors() []string                              { return []string{"application/x-vsto"} }
func (s *VstoScanner) Priority() int                                  { return 5 }

func (s *VstoScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	result := make(map[string]interface{})

	// VSTO files are XML deployment manifests
	if strings.Contains(content, "vstov4:customization") || strings.Contains(content, "asmv1:assembly") {
		result["type"] = "vsto_deployment"
	}

	// Extract deployment URL
	urlPattern := regexp.MustCompile(`(?i)codebase\s*=\s*["']([^"']+)["']`)
	if matches := urlPattern.FindStringSubmatch(content); len(matches) > 1 {
		result["codebaseUrl"] = matches[1]
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// ExiftoolScanner extracts metadata via exiftool CLI
type ExiftoolScanner struct {
	timeout int
}

func NewExiftoolScanner() *ExiftoolScanner {
	return &ExiftoolScanner{timeout: 30}
}

func (s *ExiftoolScanner) Name() string { return "ScanExiftool" }

func (s *ExiftoolScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *ExiftoolScanner) Flavors() []string {
	return []string{
		"image/jpeg", "image/png", "image/gif", "image/tiff", "image/bmp",
		"application/pdf", "application/x-dosexec",
		"video/mp4", "audio/mpeg",
	}
}

func (s *ExiftoolScanner) Priority() int { return 9 } // Run late, after format-specific scanners

func (s *ExiftoolScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "exif-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "exiftool", "-j", tmpFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("exiftool failed: %w", err)
	}

	// Parse JSON output
	var parsed []map[string]interface{}
	if err := json.Unmarshal(output, &parsed); err != nil {
		return nil, err
	}

	if len(parsed) == 0 {
		return &ScanResult{Scanner: s.Name(), Data: map[string]interface{}{}}, nil
	}

	// Remove internal fields
	data := parsed[0]
	delete(data, "SourceFile")
	delete(data, "Directory")
	delete(data, "FileName")

	return &ScanResult{Scanner: s.Name(), Data: data}, nil
}
