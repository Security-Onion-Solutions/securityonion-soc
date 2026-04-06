// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/apex/log"
)

// SevenZipScanner extracts 7z, RAR, ISO, DMG, VHD, MSI, and other formats via 7z CLI
type SevenZipScanner struct {
	limit   int
	timeout int
}

func NewSevenZipScanner() *SevenZipScanner {
	return &SevenZipScanner{
		limit:   DEFAULT_ARCHIVE_LIMIT,
		timeout: 150,
	}
}

func (s *SevenZipScanner) Name() string { return "ScanSevenZip" }

func (s *SevenZipScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["limit"]; ok {
			s.limit = int(v.(float64))
		}
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *SevenZipScanner) Flavors() []string {
	return []string{
		"application/x-7z-compressed",
		"application/x-rar",
		"application/x-iso9660-image",
		"application/x-apple-diskimage",
		"application/vnd.ms-msi",
		"application/x-msi",
	}
}

func (s *SevenZipScanner) Priority() int { return 5 }

func (s *SevenZipScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// Write input to temp file
	tmpFile, err := os.CreateTemp("", "7z-input-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	// Create temp dir for extraction
	extractDir, err := os.MkdirTemp("", "7z-extract-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create extract dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "7z", "x", "-y", "-o"+extractDir, tmpFile.Name())
	cmd.Env = append(os.Environ(), "LANG=C")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("7z extraction failed: %w (output: %s)", err, string(output))
	}

	// Collect extracted files
	var extracted []ExtractedFile
	var filenames []interface{}
	count := 0

	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if count >= s.limit {
			return filepath.SkipAll
		}

		relPath, _ := filepath.Rel(extractDir, path)
		filenames = append(filenames, relPath)

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			log.WithField("file", relPath).WithError(readErr).Debug("Failed to read extracted file")
			return nil
		}

		if int64(len(data)) > DEFAULT_MAX_FILE_SIZE {
			log.WithField("file", relPath).Debug("Extracted file exceeds max size, skipping")
			return nil
		}

		extracted = append(extracted, ExtractedFile{
			Name:    filepath.Base(path),
			Content: data,
		})
		count++
		return nil
	})
	if err != nil {
		log.WithError(err).Warn("Error walking 7z extraction output")
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"files":     filenames,
			"extracted": count,
		},
		Files: extracted,
	}, nil
}

// LzmaScanner decompresses LZMA/XZ files via 7z or xz CLI
type LzmaScanner struct {
	timeout int
}

func NewLzmaScanner() *LzmaScanner {
	return &LzmaScanner{timeout: 120}
}

func (s *LzmaScanner) Name() string { return "ScanLzma" }

func (s *LzmaScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *LzmaScanner) Flavors() []string {
	return []string{"application/x-lzma", "application/x-xz"}
}

func (s *LzmaScanner) Priority() int { return 5 }

func (s *LzmaScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "lzma-input-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	extractDir, err := os.MkdirTemp("", "lzma-extract-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(extractDir)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "7z", "x", "-y", "-o"+extractDir, tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("lzma decompression failed: %w (output: %s)", err, string(output))
	}

	var extracted []ExtractedFile
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if int64(len(data)) <= DEFAULT_MAX_FILE_SIZE {
			extracted = append(extracted, ExtractedFile{
				Name:    filepath.Base(path),
				Content: data,
			})
		}
		return nil
	})
	if err != nil {
		log.WithError(err).Warn("Error walking lzma extraction output")
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"decompressedFiles": len(extracted),
		},
		Files: extracted,
	}, nil
}
