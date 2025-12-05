// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestRulesetSourceValidate tests the RulesetSource.Validate method
func TestRulesetSourceValidate(t *testing.T) {
	tests := []struct {
		name        string
		source      *RulesetSource
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid URL source",
			source: &RulesetSource{
				Name:       "ETOPEN",
				SourceType: "url",
				SourcePath: "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
				License:    "MIT",
				Enabled:    util.Ptr(true),
			},
			expectError: false,
		},
		{
			name: "Valid directory source",
			source: &RulesetSource{
				Name:       "local",
				SourceType: "directory",
				SourcePath: "/opt/rules",
				License:    "Custom",
				Enabled:    util.Ptr(true),
			},
			expectError: false,
		},
		{
			name: "Valid elasticsearch source",
			source: &RulesetSource{
				Name:       "custom",
				SourceType: "elasticsearch",
				SourcePath: "so_detection.ruleset:__custom__",
				License:    "Unknown",
				Enabled:    util.Ptr(true),
			},
			expectError: false,
		},
		{
			name: "Missing name",
			source: &RulesetSource{
				Name:       "",
				SourceType: "url",
				SourcePath: "https://example.com/rules.tar.gz",
				License:    "MIT",
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "Missing sourceType",
			source: &RulesetSource{
				Name:       "test",
				SourceType: "",
				SourcePath: "https://example.com/rules.tar.gz",
				License:    "MIT",
			},
			expectError: true,
			errorMsg:    "sourceType is required",
		},
		{
			name: "Invalid sourceType",
			source: &RulesetSource{
				Name:       "test",
				SourceType: "invalid",
				SourcePath: "https://example.com/rules.tar.gz",
				License:    "MIT",
			},
			expectError: true,
			errorMsg:    "invalid sourceType",
		},
		{
			name: "Missing sourcePath",
			source: &RulesetSource{
				Name:       "test",
				SourceType: "url",
				SourcePath: "",
				License:    "MIT",
			},
			expectError: true,
			errorMsg:    "sourcePath is required",
		},
		{
			name: "Missing license",
			source: &RulesetSource{
				Name:       "test",
				SourceType: "url",
				SourcePath: "https://example.com/rules.tar.gz",
				License:    "",
			},
			expectError: true,
			errorMsg:    "license is required",
		},
		{
			name: "Missing enabled",
			source: &RulesetSource{
				Name:       "test",
				SourceType: "url",
				SourcePath: "https://example.com/rules.tar.gz",
				License:    "MIT",
				Enabled:    nil,
			},
			expectError: true,
			errorMsg:    "enabled is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.source.Validate()
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetRulesetSourcesFromConfig tests parsing ruleset sources from configuration
func TestGetRulesetSourcesFromConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]interface{}
		field         string
		dflt          []*RulesetSource
		expectError   bool
		expectedCount int
	}{
		{
			name: "Parse valid single source",
			config: map[string]interface{}{
				"rulesetSources": []interface{}{
					map[string]interface{}{
						"name":       "ETOPEN",
						"sourceType": "url",
						"sourcePath": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
						"license":    "MIT",
						"enabled":    true,
					},
				},
			},
			field:         "rulesetSources",
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "Parse multiple sources",
			config: map[string]interface{}{
				"rulesetSources": []interface{}{
					map[string]interface{}{
						"name":       "ETOPEN",
						"sourceType": "url",
						"sourcePath": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
						"license":    "MIT",
						"enabled":    true,
					},
					map[string]interface{}{
						"name":       "local",
						"sourceType": "directory",
						"sourcePath": "/opt/rules",
						"license":    "Custom",
						"enabled":    false,
					},
				},
			},
			field:         "rulesetSources",
			expectError:   false,
			expectedCount: 2,
		},
		{
			name:          "Missing field with defaults",
			config:        map[string]interface{}{},
			field:         "rulesetSources",
			dflt:          []*RulesetSource{{Name: "default", SourceType: "url", SourcePath: "http://example.com", License: "MIT"}},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name:        "Missing field without defaults",
			config:      map[string]interface{}{},
			field:       "rulesetSources",
			dflt:        nil,
			expectError: true,
		},
		{
			name: "Invalid source - missing name",
			config: map[string]interface{}{
				"rulesetSources": []interface{}{
					map[string]interface{}{
						"sourceType": "url",
						"sourcePath": "https://example.com/rules.tar.gz",
						"license":    "MIT",
					},
				},
			},
			field:       "rulesetSources",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources, err := GetRulesetSourcesFromConfig(tt.config, tt.field, tt.dflt)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(sources))
			}
		})
	}
}

// TestNewRulesetManager tests RulesetManager creation
func TestNewRulesetManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "ruleset")}

	source1 := &RulesetSource{
		Name:       "ETOPEN",
		SourceType: "url",
		SourcePath: "https://example.com/rules.tar.gz",
		License:    "MIT",
		Enabled:    util.Ptr(true),
	}

	source2 := &RulesetSource{
		Name:       "local",
		SourceType: "directory",
		SourcePath: "/opt/rules",
		License:    "Custom",
		Enabled:    util.Ptr(true),
	}

	sources := []*RulesetSource{source1, source2}
	rm := NewRulesetManager(iom, logger, sources...)

	assert.NotNil(t, rm)
	assert.Equal(t, iom, rm.ioManager)
	assert.Equal(t, logger, rm.logger)
	assert.Len(t, rm.GetSources(), 2)
	assert.Equal(t, "ETOPEN", rm.GetSources()[0].Name)
	assert.Equal(t, "local", rm.GetSources()[1].Name)
}

// TestShouldExcludeFile tests file exclusion logic
func TestShouldExcludeFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "ruleset")}
	rm := NewRulesetManager(iom, logger)

	tests := []struct {
		name            string
		filename        string
		excludePatterns []string
		expected        bool
	}{
		{
			name:            "No exclusions",
			filename:        "test.rules",
			excludePatterns: []string{},
			expected:        false,
		},
		{
			name:            "Match exact filename",
			filename:        "test.rules",
			excludePatterns: []string{"test.rules"},
			expected:        true,
		},
		{
			name:            "Match wildcard pattern",
			filename:        "botcc.rules",
			excludePatterns: []string{"botcc*", "deleted*"},
			expected:        true,
		},
		{
			name:            "No match",
			filename:        "emerging-malware.rules",
			excludePatterns: []string{"botcc*", "deleted*"},
			expected:        false,
		},
		{
			name:            "Match one of multiple patterns",
			filename:        "deleted.rules",
			excludePatterns: []string{"botcc*", "deleted*", "compromised*"},
			expected:        true,
		},
		{
			name:            "Match file in subdirectory by basename",
			filename:        "/nsm/rules/suricata/retired.rules",
			excludePatterns: []string{"*retired*"},
			expected:        true,
		},
		{
			name:            "Match file in deep subdirectory",
			filename:        "rules/emerging/botcc.rules",
			excludePatterns: []string{"botcc*"},
			expected:        true,
		},
		{
			name:            "No match for file in subdirectory",
			filename:        "/nsm/rules/emerging-malware.rules",
			excludePatterns: []string{"botcc*", "deleted*"},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.shouldExcludeFile(tt.filename, tt.excludePatterns)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestVerifyContentHash tests hash verification
func TestVerifyContentHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "ruleset")}
	rm := NewRulesetManager(iom, logger)

	content := []byte("test content")

	tests := []struct {
		name         string
		content      []byte
		expectedHash string
		expectError  bool
	}{
		{
			name:         "Valid MD5 hash",
			content:      content,
			expectedHash: "9473fdd0d880a43c21b7778d34872157", // MD5 of "test content"
			expectError:  false,
		},
		{
			name:         "Valid SHA256 hash",
			content:      content,
			expectedHash: "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72", // SHA256 of "test content"
			expectError:  false,
		},
		{
			name:         "Invalid MD5 hash",
			content:      content,
			expectedHash: "00000000000000000000000000000000",
			expectError:  true,
		},
		{
			name:         "Invalid SHA256 hash",
			content:      content,
			expectedHash: "0000000000000000000000000000000000000000000000000000000000000000",
			expectError:  true,
		},
		{
			name:         "Invalid hash format",
			content:      content,
			expectedHash: "not-a-hash",
			expectError:  true,
		},
		{
			name:         "Empty hash (no verification)",
			content:      content,
			expectedHash: "",
			expectError:  false,
		},
		{
			name:         "Case insensitive MD5",
			content:      content,
			expectedHash: "9473FDD0D880A43C21B7778D34872157", // Uppercase
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.verifyContentHash(tt.content, tt.expectedHash)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestQueryElasticsearch tests querying Elasticsearch for user-created rules
func TestQueryElasticsearch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	iom := mock.NewMockIOManager(ctrl)
	detStore := servermock.NewMockDetectionstore(ctrl)
	logger := &nidsLogger{log.WithField("test", "ruleset")}
	rm := NewRulesetManager(iom, logger)

	source := &RulesetSource{
		Name:       "custom",
		SourceType: "elasticsearch",
		SourcePath: "so_detection.ruleset:__custom__",
		License:    "Unknown",
		Enabled:    util.Ptr(true),
	}

	// Mock existing detections from ES
	existingDetections := map[string]*model.Detection{
		"1001": {
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Custom Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Ruleset:   "__custom__",
			Engine:    model.EngineNameSuricata,
		},
		"1002": {
			PublicID:  "1002",
			Content:   "alert tcp any any -> any any (msg:\"Custom Rule 2\"; sid:1002;)",
			IsEnabled: false,
			Ruleset:   "__custom__",
			Engine:    model.EngineNameSuricata,
		},
	}

	// Mock GetAllDetections call
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(existingDetections, nil)

	detections, err := rm.queryElasticsearch(ctx, detStore, source)

	assert.NoError(t, err)
	assert.Len(t, detections, 2)
	// Map iteration order is non-deterministic, so check both IDs are present
	publicIDs := []string{detections[0].PublicID, detections[1].PublicID}
	assert.ElementsMatch(t, []string{"1001", "1002"}, publicIDs)
}

// TestSyncAllWithEnabledAndDisabledSources tests SyncAll with mixed enabled/disabled sources
func TestSyncAllWithEnabledAndDisabledSources(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	iom := mock.NewMockIOManager(ctrl)
	detStore := servermock.NewMockDetectionstore(ctrl)
	logger := &nidsLogger{log.WithField("test", "ruleset")}

	// Create an enabled elasticsearch source
	enabledSource := &RulesetSource{
		Name:       "custom",
		SourceType: "elasticsearch",
		SourcePath: "so_detection.ruleset:__custom__",
		License:    "Unknown",
		Enabled:    util.Ptr(true),
	}

	// Create a disabled source
	disabledSource := &RulesetSource{
		Name:       "disabled",
		SourceType: "url",
		SourcePath: "https://example.com/rules.tar.gz",
		License:    "MIT",
		Enabled:    util.Ptr(false),
	}

	rm := NewRulesetManager(iom, logger, enabledSource, disabledSource)

	// Mock GetAllDetections for enabled source
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": {
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
			Engine:    model.EngineNameSuricata,
			Ruleset:   "__custom__",
			IsEnabled: true,
		},
	}, nil)

	results := rm.SyncAll(ctx, detStore)

	// Should have one result (enabled source only)
	assert.Len(t, results, 1)
	assert.Contains(t, results, "custom")
	assert.NotContains(t, results, "disabled")

	// Verify the result for enabled source
	result := results["custom"]
	assert.True(t, result.Success)
	assert.NoError(t, result.Error)
	assert.Equal(t, "custom", result.SourceName)
	assert.Len(t, result.Detections, 1)
	assert.Equal(t, 1, result.RuleCount)
}

// ============================================================================
// Download & HTTP Tests
// ============================================================================

// TestGetHTTPClient tests HTTP client configuration
func TestGetHTTPClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "http-client")}
	rm := NewRulesetManager(iom, logger)

	t.Run("Basic client without proxy or TLS", func(t *testing.T) {
		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: "https://example.com/rules.tar.gz",
			License:    "MIT",
		}

		client, err := rm.getHTTPClient(source)
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, 5*time.Minute, client.Timeout)
	})

	t.Run("Client with proxy", func(t *testing.T) {
		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: "https://example.com/rules.tar.gz",
			License:    "MIT",
			ProxyURL:   "http://proxy.example.com:8080",
		}

		client, err := rm.getHTTPClient(source)
		assert.NoError(t, err)
		assert.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.NotNil(t, transport.Proxy)
	})

	t.Run("Client with proxy authentication", func(t *testing.T) {
		source := &RulesetSource{
			Name:          "test",
			SourceType:    "url",
			SourcePath:    "https://example.com/rules.tar.gz",
			License:       "MIT",
			ProxyURL:      "http://proxy.example.com:8080",
			ProxyUsername: "user",
			ProxyPassword: "pass",
		}

		client, err := rm.getHTTPClient(source)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Invalid proxy URL", func(t *testing.T) {
		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: "https://example.com/rules.tar.gz",
			License:    "MIT",
			ProxyURL:   "://invalid-url",
		}

		client, err := rm.getHTTPClient(source)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "invalid proxy URL")
	})

	t.Run("Client with InsecureSkipVerify", func(t *testing.T) {
		source := &RulesetSource{
			Name:               "test",
			SourceType:         "url",
			SourcePath:         "https://example.com/rules.tar.gz",
			License:            "MIT",
			InsecureSkipVerify: true,
		}

		client, err := rm.getHTTPClient(source)
		assert.NoError(t, err)
		assert.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("Invalid CA certificate", func(t *testing.T) {
		source := &RulesetSource{
			Name:        "test",
			SourceType:  "url",
			SourcePath:  "https://example.com/rules.tar.gz",
			License:     "MIT",
			ProxyCACert: "/path/to/ca.crt",
		}

		// Return invalid certificate data that can't be parsed
		iom.EXPECT().ReadFile("/path/to/ca.crt").Return([]byte("not a valid certificate"), nil)

		client, err := rm.getHTTPClient(source)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to parse CA certificate")
	})

	t.Run("CA certificate file read error", func(t *testing.T) {
		source := &RulesetSource{
			Name:        "test",
			SourceType:  "url",
			SourcePath:  "https://example.com/rules.tar.gz",
			License:     "MIT",
			ProxyCACert: "/path/to/ca.crt",
		}

		iom.EXPECT().ReadFile("/path/to/ca.crt").Return(nil, os.ErrNotExist)

		client, err := rm.getHTTPClient(source)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to read CA certificate")
	})
}

// TestDownloadURL tests HTTP download functionality
func TestDownloadURL(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Successful download", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/rules.tar.gz", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("rule content here"))
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-url")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			License:    "MIT",
		}

		content, err := rm.downloadURL(context.Background(), source, source.SourcePath, "ruleset")
		assert.NoError(t, err)
		assert.Equal(t, []byte("rule content here"), content)
	})

	t.Run("HTTP 404 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-url")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/notfound.tar.gz",
			License:    "MIT",
		}

		content, err := rm.downloadURL(context.Background(), source, source.SourcePath, "ruleset")
		assert.Error(t, err)
		assert.Nil(t, content)
		assert.Contains(t, err.Error(), "HTTP 404")
	})

	t.Run("HTTP 500 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-url")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/error",
			License:    "MIT",
		}

		content, err := rm.downloadURL(context.Background(), source, source.SourcePath, "ruleset")
		assert.Error(t, err)
		assert.Nil(t, content)
		assert.Contains(t, err.Error(), "HTTP 500")
	})

	t.Run("Context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Write([]byte("slow response"))
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-url")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/slow",
			License:    "MIT",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		content, err := rm.downloadURL(ctx, source, source.SourcePath, "ruleset")
		assert.Error(t, err)
		assert.Nil(t, content)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})

	t.Run("Invalid URL", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-url")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: "://invalid-url",
			License:    "MIT",
		}

		content, err := rm.downloadURL(context.Background(), source, source.SourcePath, "ruleset")
		assert.Error(t, err)
		assert.Nil(t, content)
	})
}

// TestDownloadHashFile tests hash file download
func TestDownloadHashFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Valid MD5 hash file", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("9473fdd0d880a43c21b7778d34872157"))
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "hash-file")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.md5",
			License:    "MIT",
		}

		hash, err := rm.downloadHashFile(context.Background(), source)
		assert.NoError(t, err)
		assert.Equal(t, "9473fdd0d880a43c21b7778d34872157", hash)
	})

	t.Run("Valid SHA256 hash file", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"))
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "hash-file")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.sha256",
			License:    "MIT",
		}

		hash, err := rm.downloadHashFile(context.Background(), source)
		assert.NoError(t, err)
		assert.Equal(t, "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72", hash)
	})

	t.Run("Empty hash file", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("   \n  ")) // Whitespace only
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "hash-file")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/empty.md5",
			License:    "MIT",
		}

		hash, err := rm.downloadHashFile(context.Background(), source)
		assert.Error(t, err)
		assert.Empty(t, hash)
		assert.Contains(t, err.Error(), "hash file is empty")
	})

	t.Run("Invalid hex in hash file", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not-a-valid-hex-string"))
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "hash-file")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/invalid.md5",
			License:    "MIT",
		}

		hash, err := rm.downloadHashFile(context.Background(), source)
		assert.Error(t, err)
		assert.Empty(t, hash)
		assert.Contains(t, err.Error(), "invalid hash format")
	})

	t.Run("No hash URL specified", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "hash-file")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: "https://example.com/rules.tar.gz",
			URLHash:    "",
			License:    "MIT",
		}

		hash, err := rm.downloadHashFile(context.Background(), source)
		assert.NoError(t, err)
		assert.Empty(t, hash)
	})
}

// TestDownloadRuleset tests complete ruleset download with hash verification
func TestDownloadRuleset(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ruleContent := []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)")

	t.Run("Download without hash verification", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(ruleContent)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-ruleset")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			License:    "MIT",
		}

		content, err := rm.downloadRuleset(context.Background(), source)
		assert.NoError(t, err)
		assert.Equal(t, ruleContent, content)
	})

	t.Run("Download with MD5 verification (success)", func(t *testing.T) {
		// Calculate MD5 of rule content
		md5Sum := md5.Sum(ruleContent)
		expectedHash := hex.EncodeToString(md5Sum[:])

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/rules.tar.gz" {
				w.Write(ruleContent)
			} else if r.URL.Path == "/rules.tar.gz.md5" {
				w.Write([]byte(expectedHash))
			}
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-ruleset")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.md5",
			License:    "MIT",
		}

		content, err := rm.downloadRuleset(context.Background(), source)
		assert.NoError(t, err)
		assert.Equal(t, ruleContent, content)
	})

	t.Run("Download with SHA256 verification (success)", func(t *testing.T) {
		// Calculate SHA256 of rule content
		sha256Sum := sha256.Sum256(ruleContent)
		expectedHash := hex.EncodeToString(sha256Sum[:])

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/rules.tar.gz" {
				w.Write(ruleContent)
			} else if r.URL.Path == "/rules.tar.gz.sha256" {
				w.Write([]byte(expectedHash))
			}
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-ruleset")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.sha256",
			License:    "MIT",
		}

		content, err := rm.downloadRuleset(context.Background(), source)
		assert.NoError(t, err)
		assert.Equal(t, ruleContent, content)
	})

	t.Run("Download with hash mismatch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/rules.tar.gz" {
				w.Write(ruleContent)
			} else if r.URL.Path == "/rules.tar.gz.md5" {
				w.Write([]byte("00000000000000000000000000000000"))
			}
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "download-ruleset")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.md5",
			License:    "MIT",
		}

		content, err := rm.downloadRuleset(context.Background(), source)
		assert.Error(t, err)
		assert.Nil(t, content)
		assert.Contains(t, err.Error(), "hash verification failed")
	})
}

// ============================================================================
// Archive Extraction Tests
// ============================================================================

// Helper function to create a test tar.gz archive
func createTestTarGz(files map[string]string) []byte {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			panic(err)
		}
		if _, err := tarWriter.Write([]byte(content)); err != nil {
			panic(err)
		}
	}

	tarWriter.Close()
	gzWriter.Close()
	return buf.Bytes()
}

// Helper function to create a test gzip file
func createTestGzip(content string) []byte {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	gzWriter.Write([]byte(content))
	gzWriter.Close()
	return buf.Bytes()
}

// TestExtractTarGzFiles tests tar.gz extraction
func TestExtractTarGzFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "extract-tgz")}
	rm := NewRulesetManager(iom, logger)

	t.Run("Extract single .rules file", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"emerging-attack.rules": "alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n",
		})

		files, err := rm.extractTarGzFiles(tarGz)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "emerging-attack.rules")
		assert.Equal(t, "alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n", string(files["emerging-attack.rules"]))
	})

	t.Run("Extract multiple .rules files", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"emerging-attack.rules":  "alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n",
			"emerging-malware.rules": "alert tcp any any -> any any (msg:\"malware\"; sid:2;)\n",
			"emerging-scan.rules":    "alert tcp any any -> any any (msg:\"scan\"; sid:3;)\n",
		})

		files, err := rm.extractTarGzFiles(tarGz)
		assert.NoError(t, err)
		assert.Len(t, files, 3)
		assert.Contains(t, files, "emerging-attack.rules")
		assert.Contains(t, files, "emerging-malware.rules")
		assert.Contains(t, files, "emerging-scan.rules")
	})

	t.Run("Skip non-.rules files", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"emerging-attack.rules": "alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n",
			"README.md":             "This is a readme",
			"LICENSE.txt":           "License text",
			"doc/usage.txt":         "Usage docs",
		})

		files, err := rm.extractTarGzFiles(tarGz)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "emerging-attack.rules")
		assert.NotContains(t, files, "README.md")
		assert.NotContains(t, files, "LICENSE.txt")
	})

	t.Run("Handle nested directories", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"rules/emerging-attack.rules":  "alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n",
			"rules/malware/botnet.rules":   "alert tcp any any -> any any (msg:\"botnet\"; sid:2;)\n",
			"rules/policy/social.rules":    "alert tcp any any -> any any (msg:\"social\"; sid:3;)\n",
		})

		files, err := rm.extractTarGzFiles(tarGz)
		assert.NoError(t, err)
		assert.Len(t, files, 3)
		assert.Contains(t, files, "rules/emerging-attack.rules")
		assert.Contains(t, files, "rules/malware/botnet.rules")
		assert.Contains(t, files, "rules/policy/social.rules")
	})

	t.Run("Invalid gzip data", func(t *testing.T) {
		invalidData := []byte("not a gzip file")

		files, err := rm.extractTarGzFiles(invalidData)
		assert.Error(t, err)
		assert.Nil(t, files)
	})

	t.Run("Empty tar.gz", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{})

		files, err := rm.extractTarGzFiles(tarGz)
		assert.NoError(t, err)
		assert.Empty(t, files)
	})
}

// TestExtractGzipFiles tests gzip extraction
func TestExtractGzipFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "extract-gz")}
	rm := NewRulesetManager(iom, logger)

	t.Run("Extract .rules.gz file", func(t *testing.T) {
		content := "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"
		gzData := createTestGzip(content)

		files, err := rm.extractGzipFiles(gzData, "https://example.com/emerging.rules.gz")
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "emerging.rules")
		assert.Equal(t, content, string(files["emerging.rules"]))
	})

	t.Run("Extract .gz file without .rules extension", func(t *testing.T) {
		content := "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"
		gzData := createTestGzip(content)

		files, err := rm.extractGzipFiles(gzData, "https://example.com/suricata.gz")
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "suricata.rules") // Should add .rules extension
	})

	t.Run("Invalid gzip data", func(t *testing.T) {
		invalidData := []byte("not gzip compressed")

		files, err := rm.extractGzipFiles(invalidData, "https://example.com/rules.gz")
		assert.Error(t, err)
		assert.Nil(t, files)
	})
}

// TestExtractArchive tests archive format auto-detection
func TestExtractArchive(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "extract-archive")}
	rm := NewRulesetManager(iom, logger)

	t.Run("Detect and extract .tar.gz", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"test.rules": "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n",
		})

		files, err := rm.extractArchive("https://example.com/rules.tar.gz", tarGz)
		assert.NoError(t, err)
		assert.Contains(t, files, "test.rules")
		assert.Contains(t, string(files["test.rules"]), "alert tcp")
	})

	t.Run("Detect and extract .tgz", func(t *testing.T) {
		tgz := createTestTarGz(map[string]string{
			"test.rules": "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n",
		})

		files, err := rm.extractArchive("https://example.com/rules.tgz", tgz)
		assert.NoError(t, err)
		assert.Contains(t, files, "test.rules")
		assert.Contains(t, string(files["test.rules"]), "alert tcp")
	})

	t.Run("Detect and extract .gz", func(t *testing.T) {
		gz := createTestGzip("alert tcp any any -> any any (msg:\"test\"; sid:1;)")

		files, err := rm.extractArchive("https://example.com/rules.gz", gz)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		// Should have a .rules file
		for _, content := range files {
			assert.Contains(t, string(content), "alert tcp")
		}
	})

	t.Run("Plain text (no extraction)", func(t *testing.T) {
		plainText := []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n")

		files, err := rm.extractArchive("https://example.com/rules.txt", plainText)
		assert.NoError(t, err)
		assert.Contains(t, files, "rules.rules")
		assert.Equal(t, plainText, files["rules.rules"])
	})

	t.Run("Single .rules file", func(t *testing.T) {
		content := []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n")

		files, err := rm.extractArchive("https://example.com/emerging.rules", content)
		assert.NoError(t, err)
		assert.Contains(t, files, "emerging.rules")
		assert.Equal(t, content, files["emerging.rules"])
	})
}

// TestConcatenateRulesFiles tests file filtering and concatenation
func TestConcatenateRulesFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "concatenate-files")}
	rm := NewRulesetManager(iom, logger)

	t.Run("Process single .rules file", func(t *testing.T) {
		files := map[string][]byte{
			"test.rules": []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"),
		}

		source := &RulesetSource{
			Name:    "test",
			License: "MIT",
		}

		rules := rm.concatenateRulesFiles(files, source)
		assert.Contains(t, rules, "alert tcp")
	})

	t.Run("Process multiple .rules files", func(t *testing.T) {
		files := map[string][]byte{
			"attack.rules":  []byte("alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n"),
			"malware.rules": []byte("alert tcp any any -> any any (msg:\"malware\"; sid:2;)\n"),
		}

		source := &RulesetSource{
			Name:    "test",
			License: "MIT",
		}

		rules := rm.concatenateRulesFiles(files, source)
		assert.Contains(t, rules, "attack")
		assert.Contains(t, rules, "malware")
	})

	t.Run("Skip non-.rules files", func(t *testing.T) {
		files := map[string][]byte{
			"test.rules":  []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"),
			"README.md":   []byte("Documentation"),
			"LICENSE.txt": []byte("License"),
		}

		source := &RulesetSource{
			Name:    "test",
			License: "MIT",
		}

		rules := rm.concatenateRulesFiles(files, source)
		assert.Contains(t, rules, "alert tcp")
		assert.NotContains(t, rules, "Documentation")
		assert.NotContains(t, rules, "License")
	})

	t.Run("Apply exclusion patterns", func(t *testing.T) {
		files := map[string][]byte{
			"emerging-attack.rules":  []byte("alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n"),
			"emerging-botcc.rules":   []byte("alert tcp any any -> any any (msg:\"botcc\"; sid:2;)\n"),
			"emerging-deleted.rules": []byte("alert tcp any any -> any any (msg:\"deleted\"; sid:3;)\n"),
		}

		source := &RulesetSource{
			Name:         "test",
			License:      "MIT",
			ExcludeFiles: []string{"*botcc*", "*deleted*"},
		}

		rules := rm.concatenateRulesFiles(files, source)
		assert.Contains(t, rules, "attack")
		assert.NotContains(t, rules, "botcc")
		assert.NotContains(t, rules, "deleted")
	})

	t.Run("Empty files map", func(t *testing.T) {
		files := map[string][]byte{}

		source := &RulesetSource{
			Name:    "test",
			License: "MIT",
		}

		rules := rm.concatenateRulesFiles(files, source)
		assert.Empty(t, rules)
	})

	t.Run("Consistent trailing newline trimming", func(t *testing.T) {
		// Content without trailing newline - we add one, then trim it
		files := map[string][]byte{
			"test.rules": []byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)"),
		}

		source := &RulesetSource{
			Name:    "test",
			License: "MIT",
		}

		rules := rm.concatenateRulesFiles(files, source)
		// The trailing newline we add should be trimmed
		assert.False(t, len(rules) > 0 && rules[len(rules)-1] == '\n', "should trim trailing newline we added")
	})
}

// ============================================================================
// Directory Reading Tests
// ============================================================================

// mockDirEntry is a helper for creating mock fs.DirEntry
type mockDirEntry struct {
	name  string
	isDir bool
}

func (m *mockDirEntry) Name() string               { return m.name }
func (m *mockDirEntry) IsDir() bool                { return m.isDir }
func (m *mockDirEntry) Type() fs.FileMode          { return 0 }
func (m *mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// mockFileInfo is a helper for creating mock os.FileInfo
type mockFileInfo struct {
	name  string
	isDir bool
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() interface{}   { return nil }

// TestReadDirectoryRulesFiles tests reading rules from filesystem directories
func TestReadDirectoryRulesFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Read directory with single .rules file", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				fn("/rules/test.rules", &mockDirEntry{"test.rules", false}, nil)
				return nil
			})
		iom.EXPECT().ReadFile("/rules/test.rules").Return([]byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"), nil)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.NoError(t, err)
		assert.Contains(t, files, "test.rules")
		assert.Contains(t, string(files["test.rules"]), "alert tcp")
	})

	t.Run("Read directory with multiple .rules files", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				fn("/rules/attack.rules", &mockDirEntry{"attack.rules", false}, nil)
				fn("/rules/malware.rules", &mockDirEntry{"malware.rules", false}, nil)
				return nil
			})
		iom.EXPECT().ReadFile("/rules/attack.rules").Return([]byte("alert tcp any any -> any any (msg:\"attack\"; sid:1;)\n"), nil)
		iom.EXPECT().ReadFile("/rules/malware.rules").Return([]byte("alert tcp any any -> any any (msg:\"malware\"; sid:2;)\n"), nil)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.NoError(t, err)
		assert.Contains(t, files, "attack.rules")
		assert.Contains(t, files, "malware.rules")
	})

	t.Run("Skip non-.rules files in directory", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				fn("/rules/test.rules", &mockDirEntry{"test.rules", false}, nil)
				fn("/rules/README.md", &mockDirEntry{"README.md", false}, nil)
				fn("/rules/subdir", &mockDirEntry{"subdir", true}, nil)
				return nil
			})
		iom.EXPECT().ReadFile("/rules/test.rules").Return([]byte("alert tcp any any -> any any (msg:\"test\"; sid:1;)\n"), nil)
		// README.md and subdir should NOT be read

		files, err := rm.readDirectoryRulesFiles(source)
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "test.rules")
	})

	t.Run("Read single .rules file directly", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules/custom.rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules/custom.rules").Return(&mockFileInfo{"custom.rules", false}, nil)
		iom.EXPECT().ReadFile("/rules/custom.rules").Return([]byte("alert tcp any any -> any any (msg:\"custom\"; sid:1;)\n"), nil)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.NoError(t, err)
		assert.Contains(t, files, "custom.rules")
	})

	t.Run("Read single .tar.gz file directly", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules/emerging.tar.gz",
			License:    "MIT",
		}

		tarGz := createTestTarGz(map[string]string{
			"emerging.rules": "alert tcp any any -> any any (msg:\"emerging\"; sid:1;)\n",
		})

		iom.EXPECT().Stat("/rules/emerging.tar.gz").Return(&mockFileInfo{"emerging.tar.gz", false}, nil)
		iom.EXPECT().ReadFile("/rules/emerging.tar.gz").Return(tarGz, nil)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.NoError(t, err)
		assert.Contains(t, files, "emerging.rules")
	})

	t.Run("Handle read error", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				return fn("/rules/test.rules", &mockDirEntry{"test.rules", false}, nil)
			})
		iom.EXPECT().ReadFile("/rules/test.rules").Return(nil, os.ErrPermission)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.Error(t, err)
		assert.Nil(t, files)
	})

	t.Run("Handle Stat error", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(nil, os.ErrNotExist)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.Error(t, err)
		assert.Nil(t, files)
	})

	t.Run("Handle WalkDir error", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "read-dir")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).Return(os.ErrNotExist)

		files, err := rm.readDirectoryRulesFiles(source)
		assert.Error(t, err)
		assert.Nil(t, files)
	})
}

// ============================================================================
// FetchRulesFiles Tests
// ============================================================================

// TestFetchRulesFiles tests the fetchRulesFiles dispatcher
func TestFetchRulesFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("URL source downloads and extracts", func(t *testing.T) {
		tarGz := createTestTarGz(map[string]string{
			"emerging.rules": "alert tcp any any -> any any (msg:\"test\"; sid:1;)\n",
		})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(tarGz)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "fetch-rules")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			License:    "MIT",
		}

		files, err := rm.fetchRulesFiles(context.Background(), source)
		assert.NoError(t, err)
		assert.Contains(t, files, "emerging.rules")
		assert.Contains(t, string(files["emerging.rules"]), "alert tcp")
	})

	t.Run("Directory source reads files", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "fetch-rules")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourceType: "directory",
			SourcePath: "/rules",
			License:    "MIT",
		}

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				fn("/rules/local.rules", &mockDirEntry{"local.rules", false}, nil)
				return nil
			})
		iom.EXPECT().ReadFile("/rules/local.rules").Return([]byte("alert tcp any any -> any any (msg:\"local\"; sid:100;)\n"), nil)

		files, err := rm.fetchRulesFiles(context.Background(), source)
		assert.NoError(t, err)
		assert.Contains(t, files, "local.rules")
		assert.Contains(t, string(files["local.rules"]), "alert tcp")
	})

	t.Run("Unsupported source type returns error", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "fetch-rules")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "invalid",
			SourceType: "elasticsearch", // Not supported by fetchRulesFiles
			SourcePath: "query",
			License:    "MIT",
		}

		files, err := rm.fetchRulesFiles(context.Background(), source)
		assert.Error(t, err)
		assert.Nil(t, files)
		assert.Contains(t, err.Error(), "unsupported source type")
	})

	t.Run("URL download failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "fetch-rules")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			License:    "MIT",
		}

		files, err := rm.fetchRulesFiles(context.Background(), source)
		assert.Error(t, err)
		assert.Nil(t, files)
	})
}

// ============================================================================
// SyncSource Tests
// ============================================================================

// TestSyncSource tests the syncSource orchestration function
func TestSyncSource(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("URL source full path - download, parse, apply metadata", func(t *testing.T) {
		ruleContent := "alert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)\n"
		tarGz := createTestTarGz(map[string]string{
			"test.rules": ruleContent,
		})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(tarGz)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "ETOPEN",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			ReadOnly:   true,
			License:    "MIT",
			Enabled:    util.Ptr(true),
		}

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.NoError(t, err)
		assert.Len(t, detections, 1)

		// Verify metadata was applied
		det := detections[0]
		assert.True(t, det.IsCommunity, "ReadOnly source should set IsCommunity=true")
		assert.Equal(t, "MIT", det.License)
		assert.Equal(t, "ETOPEN", det.Ruleset)
		assert.Contains(t, det.Content, "Test Rule")
	})

	t.Run("URL source with hash verification", func(t *testing.T) {
		ruleContent := "alert tcp any any -> any any (msg:\"Hash Verified Rule\"; sid:2000001; rev:1;)\n"
		tarGz := createTestTarGz(map[string]string{
			"verified.rules": ruleContent,
		})

		// Calculate MD5 hash of the tarGz content
		md5Hash := md5.Sum(tarGz)
		expectedHash := hex.EncodeToString(md5Hash[:])

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/rules.tar.gz" {
				w.Write(tarGz)
			} else if r.URL.Path == "/rules.tar.gz.md5" {
				w.Write([]byte(expectedHash))
			}
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source-hash")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "ETOPEN",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.md5",
			ReadOnly:   true,
			License:    "MIT",
			Enabled:    util.Ptr(true),
		}

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.NoError(t, err)
		assert.Len(t, detections, 1)
		assert.Contains(t, detections[0].Content, "Hash Verified Rule")
	})

	t.Run("URL source with hash verification failure", func(t *testing.T) {
		ruleContent := "alert tcp any any -> any any (msg:\"Bad Hash Rule\"; sid:3000001; rev:1;)\n"
		tarGz := createTestTarGz(map[string]string{
			"bad.rules": ruleContent,
		})

		// Return a wrong hash
		wrongHash := "00000000000000000000000000000000"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.URL.Path == "/rules.tar.gz" {
				w.Write(tarGz)
			} else if r.URL.Path == "/rules.tar.gz.md5" {
				w.Write([]byte(wrongHash))
			}
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source-hash-fail")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "ETOPEN",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			URLHash:    server.URL + "/rules.tar.gz.md5",
			ReadOnly:   true,
			License:    "MIT",
			Enabled:    util.Ptr(true),
		}

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.Error(t, err)
		assert.Nil(t, detections)
		assert.Contains(t, err.Error(), "hash verification failed")
	})

	t.Run("Directory source full path", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "local",
			SourceType: "directory",
			SourcePath: "/rules",
			ReadOnly:   false,
			License:    "Custom",
			Enabled:    util.Ptr(true),
		}

		ruleContent := "alert tcp any any -> any any (msg:\"Local Rule\"; sid:9000001; rev:1;)\n"

		iom.EXPECT().Stat("/rules").Return(&mockFileInfo{"rules", true}, nil)
		iom.EXPECT().WalkDir("/rules", gomock.Any()).DoAndReturn(
			func(root string, fn fs.WalkDirFunc) error {
				fn("/rules/local.rules", &mockDirEntry{"local.rules", false}, nil)
				return nil
			})
		iom.EXPECT().ReadFile("/rules/local.rules").Return([]byte(ruleContent), nil)

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.NoError(t, err)
		assert.Len(t, detections, 1)

		// Verify metadata was applied
		det := detections[0]
		assert.False(t, det.IsCommunity, "Non-ReadOnly source should set IsCommunity=false")
		assert.Equal(t, "Custom", det.License)
		assert.Equal(t, "local", det.Ruleset)
	})

	t.Run("Elasticsearch source routes to queryElasticsearch", func(t *testing.T) {
		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "custom",
			SourceType: "elasticsearch",
			SourcePath: "so_detection.ruleset:__custom__",
			License:    "Unknown",
			Enabled:    util.Ptr(true),
		}

		// Mock ES response
		detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
			"5001": {
				PublicID:  "5001",
				Content:   "alert tcp any any -> any any (msg:\"ES Rule\"; sid:5001;)",
				IsEnabled: true,
				Ruleset:   "__custom__",
				Engine:    model.EngineNameSuricata,
			},
		}, nil)

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.NoError(t, err)
		assert.Len(t, detections, 1)
		assert.Equal(t, "5001", detections[0].PublicID)
	})

	t.Run("Fetch failure returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/notfound.tar.gz",
			License:    "MIT",
			Enabled:    util.Ptr(true),
		}

		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.Error(t, err)
		assert.Nil(t, detections)
		assert.Contains(t, err.Error(), "failed to fetch ruleset")
	})

	t.Run("Parse failure returns error", func(t *testing.T) {
		// Create tar.gz with invalid rule content
		tarGz := createTestTarGz(map[string]string{
			"bad.rules": "this is not a valid suricata rule",
		})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(tarGz)
		}))
		defer server.Close()

		iom := mock.NewMockIOManager(ctrl)
		detStore := servermock.NewMockDetectionstore(ctrl)
		logger := &nidsLogger{log.WithField("test", "sync-source")}
		rm := NewRulesetManager(iom, logger)

		source := &RulesetSource{
			Name:       "test",
			SourceType: "url",
			SourcePath: server.URL + "/rules.tar.gz",
			License:    "MIT",
			Enabled:    util.Ptr(true),
		}

		// ParseSuricataRules returns an error for invalid rules
		detections, err := rm.syncSource(context.Background(), detStore, source)
		assert.Error(t, err)
		assert.Nil(t, detections)
		assert.Contains(t, err.Error(), "failed to parse rules")
	})
}

// ============================================================================
// Additional QueryElasticsearch Tests
// ============================================================================

// TestQueryElasticsearchFiltersPendingDelete tests that PendingDelete rules are filtered out
func TestQueryElasticsearchFiltersPendingDelete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	iom := mock.NewMockIOManager(ctrl)
	detStore := servermock.NewMockDetectionstore(ctrl)
	logger := &nidsLogger{log.WithField("test", "es-pending-delete")}
	rm := NewRulesetManager(iom, logger)

	source := &RulesetSource{
		Name:       "custom",
		SourceType: "elasticsearch",
		SourcePath: "so_detection.ruleset:__custom__",
		License:    "Unknown",
		Enabled:    util.Ptr(true),
	}

	// Mock ES response with mix of normal and pending delete rules
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": {
			PublicID:      "1001",
			Content:       "alert tcp any any -> any any (msg:\"Active Rule\"; sid:1001;)",
			IsEnabled:     true,
			Ruleset:       "__custom__",
			Engine:        model.EngineNameSuricata,
			PendingDelete: false,
		},
		"1002": {
			PublicID:      "1002",
			Content:       "alert tcp any any -> any any (msg:\"Deleted Rule\"; sid:1002;)",
			IsEnabled:     true,
			Ruleset:       "__custom__",
			Engine:        model.EngineNameSuricata,
			PendingDelete: true, // Should be filtered out
		},
		"1003": {
			PublicID:      "1003",
			Content:       "alert tcp any any -> any any (msg:\"Other Ruleset\"; sid:1003;)",
			IsEnabled:     true,
			Ruleset:       "other", // Not __custom__, should be filtered out
			Engine:        model.EngineNameSuricata,
			PendingDelete: false,
		},
	}, nil)

	detections, err := rm.queryElasticsearch(ctx, detStore, source)

	assert.NoError(t, err)
	assert.Len(t, detections, 1, "Should only return active __custom__ rules")
	assert.Equal(t, "1001", detections[0].PublicID)
}

// TestQueryElasticsearchNilDetStore tests error when detection store is nil
func TestQueryElasticsearchNilDetStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "es-nil-store")}
	rm := NewRulesetManager(iom, logger)

	source := &RulesetSource{
		Name:       "custom",
		SourceType: "elasticsearch",
		SourcePath: "so_detection.ruleset:__custom__",
		License:    "Unknown",
		Enabled:    util.Ptr(true),
	}

	detections, err := rm.queryElasticsearch(ctx, nil, source)

	assert.Error(t, err)
	assert.Nil(t, detections)
	assert.Contains(t, err.Error(), "detection store not available")
}

// ============================================================================
// Additional ShouldExcludeFile Tests
// ============================================================================

// TestShouldExcludeFileInvalidPattern tests handling of invalid glob patterns
func TestShouldExcludeFileInvalidPattern(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	logger := &nidsLogger{log.WithField("test", "exclude-invalid")}
	rm := NewRulesetManager(iom, logger)

	// Invalid pattern with unclosed bracket
	result := rm.shouldExcludeFile("test.rules", []string{"[invalid"})

	// Should not crash, should return false (file not excluded due to invalid pattern)
	assert.False(t, result)
}
