// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"path/filepath"

	"github.com/apex/log"
)

const DEFAULT_ARCHIVE_LIMIT = 1000
const DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024 // 256MB per extracted file

type ZipScanner struct {
	limit       int
	maxFileSize int64
}

func NewZipScanner() *ZipScanner {
	return &ZipScanner{
		limit:       DEFAULT_ARCHIVE_LIMIT,
		maxFileSize: DEFAULT_MAX_FILE_SIZE,
	}
}

func (s *ZipScanner) Name() string { return "ScanZip" }

func (s *ZipScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["limit"]; ok {
			s.limit = int(v.(float64))
		}
	}
	return nil
}

func (s *ZipScanner) Flavors() []string {
	return []string{"application/zip", "application/java-archive", "application/vnd.openxmlformats-officedocument"}
}

func (s *ZipScanner) Priority() int { return 5 }

func (s *ZipScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	var extracted []ExtractedFile
	var filenames []interface{}
	count := 0

	for _, f := range reader.File {
		if count >= s.limit {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}

		filenames = append(filenames, f.Name)

		rc, err := f.Open()
		if err != nil {
			log.WithField("file", f.Name).WithError(err).Debug("Failed to open zip entry")
			continue
		}

		data, err := io.ReadAll(io.LimitReader(rc, s.maxFileSize))
		rc.Close()
		if err != nil {
			log.WithField("file", f.Name).WithError(err).Debug("Failed to read zip entry")
			continue
		}

		extracted = append(extracted, ExtractedFile{
			Name:    filepath.Base(f.Name),
			Content: data,
		})
		count++
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"total":    len(reader.File),
			"files":    filenames,
			"extracted": count,
		},
		Files: extracted,
	}, nil
}

// GzipScanner decompresses gzip files
type GzipScanner struct {
	maxFileSize int64
}

func NewGzipScanner() *GzipScanner {
	return &GzipScanner{maxFileSize: DEFAULT_MAX_FILE_SIZE}
}

func (s *GzipScanner) Name() string { return "ScanGzip" }

func (s *GzipScanner) Init(config map[string]interface{}) error { return nil }

func (s *GzipScanner) Flavors() []string {
	return []string{"application/gzip", "application/x-gzip"}
}

func (s *GzipScanner) Priority() int { return 5 }

func (s *GzipScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader, err := gzip.NewReader(bytes.NewReader(file))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, s.maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	name := metadata.Name
	if reader.Name != "" {
		name = reader.Name
	} else if ext := filepath.Ext(name); ext == ".gz" {
		name = name[:len(name)-len(ext)]
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"decompressedSize": len(data),
		},
		Files: []ExtractedFile{
			{Name: name, Content: data},
		},
	}, nil
}

// Bzip2Scanner decompresses bzip2 files
type Bzip2Scanner struct {
	maxFileSize int64
}

func NewBzip2Scanner() *Bzip2Scanner {
	return &Bzip2Scanner{maxFileSize: DEFAULT_MAX_FILE_SIZE}
}

func (s *Bzip2Scanner) Name() string { return "ScanBzip2" }

func (s *Bzip2Scanner) Init(config map[string]interface{}) error { return nil }

func (s *Bzip2Scanner) Flavors() []string {
	return []string{"application/x-bzip2"}
}

func (s *Bzip2Scanner) Priority() int { return 5 }

func (s *Bzip2Scanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader := bzip2.NewReader(bytes.NewReader(file))
	data, err := io.ReadAll(io.LimitReader(reader, s.maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress bzip2: %w", err)
	}

	name := metadata.Name
	if ext := filepath.Ext(name); ext == ".bz2" {
		name = name[:len(name)-len(ext)]
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"decompressedSize": len(data),
		},
		Files: []ExtractedFile{
			{Name: name, Content: data},
		},
	}, nil
}

// TarScanner extracts tar archives
type TarScanner struct {
	limit       int
	maxFileSize int64
}

func NewTarScanner() *TarScanner {
	return &TarScanner{
		limit:       DEFAULT_ARCHIVE_LIMIT,
		maxFileSize: DEFAULT_MAX_FILE_SIZE,
	}
}

func (s *TarScanner) Name() string { return "ScanTar" }

func (s *TarScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["limit"]; ok {
			s.limit = int(v.(float64))
		}
	}
	return nil
}

func (s *TarScanner) Flavors() []string {
	return []string{"application/x-tar"}
}

func (s *TarScanner) Priority() int { return 5 }

func (s *TarScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader := tar.NewReader(bytes.NewReader(file))
	var extracted []ExtractedFile
	var filenames []interface{}
	count := 0

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}
		if count >= s.limit {
			break
		}

		filenames = append(filenames, header.Name)

		data, err := io.ReadAll(io.LimitReader(reader, s.maxFileSize))
		if err != nil {
			log.WithField("file", header.Name).WithError(err).Debug("Failed to read tar entry")
			continue
		}

		extracted = append(extracted, ExtractedFile{
			Name:    filepath.Base(header.Name),
			Content: data,
		})
		count++
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

// ZlibScanner decompresses zlib streams
type ZlibScanner struct {
	maxFileSize int64
}

func NewZlibScanner() *ZlibScanner {
	return &ZlibScanner{maxFileSize: DEFAULT_MAX_FILE_SIZE}
}

func (s *ZlibScanner) Name() string { return "ScanZlib" }

func (s *ZlibScanner) Init(config map[string]interface{}) error { return nil }

func (s *ZlibScanner) Flavors() []string {
	return []string{"application/zlib"}
}

func (s *ZlibScanner) Priority() int { return 5 }

func (s *ZlibScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader, err := zlib.NewReader(bytes.NewReader(file))
	if err != nil {
		return nil, fmt.Errorf("failed to open zlib: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, s.maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress zlib: %w", err)
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"decompressedSize": len(data),
		},
		Files: []ExtractedFile{
			{Name: metadata.Name + ".decompressed", Content: data},
		},
	}, nil
}
