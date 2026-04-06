// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
)

const DEFAULT_YARA_RULES_PATH = "/opt/so/conf/strelka/rules/compiled/rules.compiled"
const DEFAULT_YARA_TIMEOUT = 120

type YaraScanner struct {
	rulesPath string
	compiled  bool
	timeout   int
}

func NewYaraScanner() *YaraScanner {
	return &YaraScanner{
		rulesPath: DEFAULT_YARA_RULES_PATH,
		compiled:  true,
		timeout:   DEFAULT_YARA_TIMEOUT,
	}
}

func (s *YaraScanner) Name() string { return "ScanYara" }

func (s *YaraScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["rulesPath"]; ok {
			s.rulesPath = v.(string)
		}
		if v, ok := config["compiled"]; ok {
			s.compiled = v.(bool)
		}
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}

	// Verify rules file exists
	if _, err := os.Stat(s.rulesPath); os.IsNotExist(err) {
		log.WithField("rulesPath", s.rulesPath).Warn("YARA rules file not found, scanner will be inactive")
	}

	return nil
}

func (s *YaraScanner) Flavors() []string { return []string{"*"} }

func (s *YaraScanner) Priority() int { return 5 }

func (s *YaraScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if _, err := os.Stat(s.rulesPath); os.IsNotExist(err) {
		return nil, nil
	}

	// Write file to temp location for yara CLI
	tmpFile, err := os.CreateTemp("", "yara-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	args := []string{"-s"} // Show matching strings
	if s.compiled {
		args = append(args, "-C") // Use compiled rules
	}

	// If rulesPath is a directory, scan with all rule files
	info, err := os.Stat(s.rulesPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		// Find all .yar/.yara/.compiled files in directory
		entries, err := os.ReadDir(s.rulesPath)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			ext := filepath.Ext(entry.Name())
			if ext == ".yar" || ext == ".yara" || ext == ".compiled" {
				args = append(args, filepath.Join(s.rulesPath, entry.Name()))
			}
		}
	} else {
		args = append(args, s.rulesPath)
	}

	args = append(args, tmpFile.Name())

	cmd := exec.CommandContext(ctx, "yara", args...)
	output, err := cmd.Output()
	if err != nil {
		// Exit code 1 means no matches (not an error)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return &ScanResult{
				Scanner: s.Name(),
				Data: map[string]interface{}{
					"matches": []interface{}{},
				},
			}, nil
		}
		return nil, fmt.Errorf("yara execution failed: %w", err)
	}

	matches := parseYaraOutput(string(output))

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"matches": matches,
		},
	}, nil
}

func parseYaraOutput(output string) []interface{} {
	var matches []interface{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// YARA output format: "rule_name file_path"
		// With -s flag, matching strings follow as: "0x0:$string_name: matched_data"
		if strings.HasPrefix(line, "0x") {
			// This is a matching string detail line, skip for now
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			matches = append(matches, parts[0])
		}
	}

	if matches == nil {
		matches = []interface{}{}
	}

	return matches
}
