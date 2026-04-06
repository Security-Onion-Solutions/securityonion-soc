// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
)

type Pipeline struct {
	registry     *ScannerRegistry
	resultWriter *ResultWriter
	maxDepth     int
}

func NewPipeline(registry *ScannerRegistry, resultWriter *ResultWriter, maxDepth int) *Pipeline {
	return &Pipeline{
		registry:     registry,
		resultWriter: resultWriter,
		maxDepth:     maxDepth,
	}
}

func (p *Pipeline) ProcessFile(filePath string, hash string, depth int) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	metadata := FileMetadata{
		Name:  filepath.Base(filePath),
		Size:  info.Size(),
		Depth: depth,
	}

	// Identify file types for flavor-based scanner dispatch
	types := IdentifyType(data)
	scanResults := make(map[string]interface{})

	// Collect all matching scanners (deduplicated)
	seen := make(map[string]bool)
	var matchedScanners []Scanner
	for _, typ := range types {
		for _, scanner := range p.registry.ScannersForFlavor(typ) {
			if !seen[scanner.Name()] {
				seen[scanner.Name()] = true
				matchedScanners = append(matchedScanners, scanner)
			}
		}
	}

	for _, scanner := range matchedScanners {
		result, err := scanner.Scan(data, metadata)
		if err != nil {
			log.WithFields(log.Fields{
				"scanner": scanner.Name(),
				"file":    filePath,
			}).WithError(err).Warn("Scanner failed")
			continue
		}
		if result != nil {
			scanResults[result.Scanner] = result.Data

			// Handle extracted files from archive scanners
			if len(result.Files) > 0 && depth < p.maxDepth {
				for _, extracted := range result.Files {
					p.processExtracted(extracted, hash, depth+1)
				}
			}
		}
	}

	fileResult := &FileResult{
		Timestamp: time.Now().UTC(),
		File: FileInfo{
			Name:  metadata.Name,
			Size:  metadata.Size,
			Hash:  hash,
			Depth: depth,
		},
		Scanners: scanResults,
		Event: map[string]interface{}{
			"module": "fileanalyze",
		},
	}

	return p.resultWriter.Write(fileResult)
}

func (p *Pipeline) processExtracted(file ExtractedFile, parentHash string, depth int) {
	tmpDir, err := os.MkdirTemp("", "fileanalyze-")
	if err != nil {
		log.WithError(err).Error("Failed to create temp dir for extracted file")
		return
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, file.Name)
	if err := os.WriteFile(tmpPath, file.Content, 0600); err != nil {
		log.WithError(err).Error("Failed to write extracted file")
		return
	}

	hash, err := hashFile(tmpPath)
	if err != nil {
		log.WithError(err).Error("Failed to hash extracted file")
		return
	}

	if err := p.ProcessFile(tmpPath, hash, depth); err != nil {
		log.WithFields(log.Fields{
			"file":  file.Name,
			"depth": depth,
		}).WithError(err).Warn("Failed to process extracted file")
	}
}
