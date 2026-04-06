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

const DEFAULT_PASSWORDS_PATH = "/etc/strelka/passwords.dat"

// EncryptedZipScanner attempts to crack encrypted zip files using 7z with a password list
type EncryptedZipScanner struct {
	passwordsPath string
	timeout       int
}

func NewEncryptedZipScanner() *EncryptedZipScanner {
	return &EncryptedZipScanner{
		passwordsPath: DEFAULT_PASSWORDS_PATH,
		timeout:       150,
	}
}

func (s *EncryptedZipScanner) Name() string { return "ScanEncryptedZip" }

func (s *EncryptedZipScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["passwordsPath"]; ok {
			s.passwordsPath = v.(string)
		}
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *EncryptedZipScanner) Flavors() []string {
	return []string{"application/zip-encrypted"}
}

func (s *EncryptedZipScanner) Priority() int { return 6 } // After regular zip scanner

func (s *EncryptedZipScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	passwords, err := loadPasswords(s.passwordsPath)
	if err != nil {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"cracked":      false,
				"error":        "password list not found",
				"passwordFile": s.passwordsPath,
			},
		}, nil
	}

	// Write file to temp
	tmpFile, err := os.CreateTemp("", "enc-zip-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	extractDir, err := os.MkdirTemp("", "enc-zip-extract-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(extractDir)

	// Try each password
	for _, password := range passwords {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
		cmd := exec.CommandContext(ctx, "7z", "x", "-y", "-p"+password, "-o"+extractDir, tmpFile.Name())
		output, err := cmd.CombinedOutput()
		cancel()

		if err == nil {
			// Successfully cracked
			var extracted []ExtractedFile
			var filenames []interface{}

			filepath.Walk(extractDir, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil || info.IsDir() {
					return nil
				}
				relPath, _ := filepath.Rel(extractDir, path)
				filenames = append(filenames, relPath)

				data, readErr := os.ReadFile(path)
				if readErr == nil && int64(len(data)) <= DEFAULT_MAX_FILE_SIZE {
					extracted = append(extracted, ExtractedFile{
						Name:    filepath.Base(path),
						Content: data,
					})
				}
				return nil
			})

			return &ScanResult{
				Scanner: s.Name(),
				Data: map[string]interface{}{
					"cracked":  true,
					"password": password,
					"files":    filenames,
				},
				Files: extracted,
			}, nil
		}

		_ = output
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"cracked":        false,
			"passwordsTried": len(passwords),
		},
	}, nil
}

// EncryptedDocScanner attempts to crack encrypted Office documents
type EncryptedDocScanner struct {
	passwordsPath string
	timeout       int
}

func NewEncryptedDocScanner() *EncryptedDocScanner {
	return &EncryptedDocScanner{
		passwordsPath: DEFAULT_PASSWORDS_PATH,
		timeout:       150,
	}
}

func (s *EncryptedDocScanner) Name() string { return "ScanEncryptedDoc" }

func (s *EncryptedDocScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["passwordsPath"]; ok {
			s.passwordsPath = v.(string)
		}
		if v, ok := config["timeout"]; ok {
			s.timeout = int(v.(float64))
		}
	}
	return nil
}

func (s *EncryptedDocScanner) Flavors() []string {
	return []string{"application/encrypted-doc"}
}

func (s *EncryptedDocScanner) Priority() int { return 6 }

func (s *EncryptedDocScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	passwords, err := loadPasswords(s.passwordsPath)
	if err != nil {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"cracked": false,
				"error":   "password list not found",
			},
		}, nil
	}

	// Write to temp
	tmpFile, err := os.CreateTemp("", "enc-doc-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(file); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	// Use john to attempt password extraction and cracking
	// First, extract hash from the document
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)
	defer cancel()

	// Try using office2john.py to extract hash, then john to crack
	hashCmd := exec.CommandContext(ctx, "python3", "-c",
		fmt.Sprintf("import sys; sys.path.insert(0,'/opt/john/run'); import office2john; office2john.process_file('%s')", tmpFile.Name()))
	hashOutput, err := hashCmd.Output()
	if err != nil {
		log.WithError(err).Debug("office2john extraction failed")
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"cracked": false,
				"error":   "hash extraction failed",
			},
		}, nil
	}

	hashStr := strings.TrimSpace(string(hashOutput))
	if hashStr == "" {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"cracked": false,
				"error":   "no hash extracted",
			},
		}, nil
	}

	// Write hash to temp file for john
	hashFile, err := os.CreateTemp("", "doc-hash-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(hashFile.Name())

	hashFile.WriteString(hashStr + "\n")
	hashFile.Close()

	// Run john with wordlist
	johnCmd := exec.CommandContext(ctx, "john",
		"--wordlist="+s.passwordsPath,
		hashFile.Name())
	johnCmd.Run()

	// Check if cracked
	showCmd := exec.CommandContext(ctx, "john", "--show", hashFile.Name())
	showOutput, err := showCmd.Output()
	if err == nil {
		lines := strings.Split(string(showOutput), "\n")
		for _, line := range lines {
			if strings.Contains(line, ":") && !strings.HasPrefix(line, "0 password") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) >= 2 && parts[1] != "" {
					return &ScanResult{
						Scanner: s.Name(),
						Data: map[string]interface{}{
							"cracked":  true,
							"password": parts[1],
						},
					}, nil
				}
			}
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"cracked":        false,
			"passwordsTried": len(passwords),
		},
	}, nil
}

func loadPasswords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var passwords []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pw := strings.TrimSpace(scanner.Text())
		if pw != "" && !strings.HasPrefix(pw, "#") {
			passwords = append(passwords, pw)
		}
	}
	return passwords, scanner.Err()
}
