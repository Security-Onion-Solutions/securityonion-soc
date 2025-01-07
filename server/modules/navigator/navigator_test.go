// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package navigator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNavigatorInit(t *testing.T) {
	tests := []struct {
		name          string
		config        module.ModuleConfig
		expectedPath  string
		expectedDays  int
		expectedError bool
	}{
		{
			name: "valid config",
			config: module.ModuleConfig{
				"outputPath":   "/tmp/navigator",
				"lookbackDays": float64(7),
			},
			expectedPath: "/tmp/navigator",
			expectedDays: 7,
		},
		{
			name: "missing output path",
			config: module.ModuleConfig{
				"lookbackDays": float64(7),
			},
			expectedError: true,
		},
		{
			name:          "empty config",
			config:        module.ModuleConfig{},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			srv := &server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
				Detectionstore:   mockDetectionstore,
			}

			nav := NewNavigator(srv)
			err := nav.Init(tt.config)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPath, nav.outputPath)
				assert.Equal(t, tt.expectedDays, nav.lookbackDays)
			}
		})
	}
}

func TestExtractSuricataTechniques(t *testing.T) {
	// Test cases for extracting techniques from Suricata rules
	// 1. Test rule with base technique (T1071)
	// 2. Test rule with sub-technique (T5678.001) - should extract base technique (T5678)
	// 3. Test rule without technique
	logger := log.WithField("test", "TestExtractSuricataTechniques")
	rules := map[string]*model.Detection{
		"rule1": {
			Title:   "Test Rule 1",
			Content: `alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Malicious SSL certificate detected (Ursnif Injects)"; flow:established,to_client; tls.cert_subject; content:"CN=dolbyfck.com"; classtype:domain-c2; sid:2022613; rev:4; metadata:attack_target Client_and_Server, created_at 2016_03_12, deployment Perimeter, performance_impact Low, confidence High, signature_severity Major, tag SSL_Malicious_Cert, updated_at 2024_04_22, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol;)`,
		},
		"rule2": {
			// Testing sub-technique extraction - should only keep base technique T5678
			Title:   "Test Rule 2",
			Content: `alert tcp any any -> any any (msg:"Test Rule"; metadata:mitre_technique_id T5678.001;)`,
		},
		"rule3": {
			Title:   "Test Rule 3 - No Technique",
			Content: `alert tcp any any -> any any (msg:"Test Rule"; sid:3;)`,
		},
	}

	techniques := extractSuricataTechniques(rules, logger)
	// Verify base technique without sub-technique (T1071)
	assert.Contains(t, techniques, "T1071")
	// Verify base technique is extracted from sub-technique (T5678.001 -> T5678)
	assert.Contains(t, techniques, "T5678")
	assert.Len(t, techniques, 2)
}

func TestExtractSigmaTechniques(t *testing.T) {
	logger := log.WithField("test", "TestExtractSigmaTechniques")
	rules := map[string]*model.Detection{
		"rule1": {
			Title: "Test Rule 1",
			Content: `title: Griffon Malware Attack Pattern
status: experimental
description: Detects process execution patterns
author: Test Author
date: 2023/03/09
tags:
  - attack.t1234
  - attack.t5678.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: test
  condition: selection
falsepositives:
  - Unlikely
level: critical`,
		},
		"rule2": {
			Title: "Test Rule 2",
			Content: `title: Test Rule
status: experimental
tags:
  - attack.execution
detection:
  selection:
    field: value
  condition: selection`,
		},
	}

	techniques := extractSigmaTechniques(rules, logger)
	assert.Contains(t, techniques, "T1234")
	assert.Contains(t, techniques, "T5678") // Base technique ID
	assert.Len(t, techniques, 2)
}

func TestMergeTechniques(t *testing.T) {
	// Test cases:
	// 1. Merging maps with overlapping techniques (T1234 appears in both map1 and map2)
	// 2. Merging maps with unique techniques (T5678, T9012, T3456)
	// 3. Merging more than two maps at once
	// 4. Empty map handling (map4 is empty and should be handled gracefully)

	map1 := techniqueMap{"T1234": struct{}{}, "T5678": struct{}{}}
	map2 := techniqueMap{"T1234": struct{}{}, "T9012": struct{}{}}
	map3 := techniqueMap{"T3456": struct{}{}}
	map4 := techniqueMap{}

	merged := mergeTechniques(map1, map2, map3, map4)

	// Verify all unique techniques are present
	assert.Len(t, merged, 4)
	assert.Contains(t, merged, "T1234")
	assert.Contains(t, merged, "T5678")
	assert.Contains(t, merged, "T9012")
	assert.Contains(t, merged, "T3456")
}

func TestCreateLayer(t *testing.T) {
	techniques := techniqueMap{
		"T1234":     struct{}{},
		"T5678.001": struct{}{},
	}

	layer, err := createLayer("test", techniques)
	assert.NoError(t, err)
	assert.Equal(t, "test", layer["name"])

	techniques_, ok := layer["techniques"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, techniques_, 2)

	techniqueIDs := make(map[string]bool)
	for _, t := range techniques_ {
		techniqueIDs[t["techniqueID"].(string)] = true
	}
	assert.True(t, techniqueIDs["T1234"])
	assert.True(t, techniqueIDs["T5678.001"])
}

func TestWriteLayer(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "navigator-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "test-layer.json")
	logger := log.WithField("test", "TestWriteLayer")

	nav := &Navigator{}
	layer := map[string]interface{}{
		"name": "test",
		"techniques": []interface{}{
			map[string]interface{}{
				"techniqueID": "T1234",
			},
		},
	}

	err = nav.writeLayer(layer, filePath, logger)
	assert.NoError(t, err)

	// Read and verify the written file
	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)

	var writtenLayer map[string]interface{}
	err = json.Unmarshal(data, &writtenLayer)
	assert.NoError(t, err)

	assert.Equal(t, layer, writtenLayer)
}

func TestStartStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	fakeEventstore := server.NewFakeEventstore()

	srv := &server.Server{
		Context:          context.Background(),
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
		Detectionstore:   mockDetectionstore,
		Eventstore:       fakeEventstore,
	}

	nav := NewNavigator(srv)
	nav.Init(module.ModuleConfig{
		"outputPath": "/tmp",
		"interval":   "1", // Set interval to 1 minute for testing
	})

	// Set up expectations for GetAllDetections
	mockDetectionstore.EXPECT().
		GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(map[string]*model.Detection{}, nil).
		AnyTimes()

	// Start the navigator
	err := nav.Start()
	assert.NoError(t, err)

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	// Stop the navigator
	err = nav.Stop()
	assert.NoError(t, err)
}

func TestExtractAlertTechniques(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	fakeEventstore := server.NewFakeEventstore()

	srv := &server.Server{
		Context:          context.Background(),
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
		Detectionstore:   mockDetectionstore,
		Eventstore:       fakeEventstore,
	}

	nav := NewNavigator(srv)
	nav.Init(module.ModuleConfig{
		"outputPath": "/tmp",
	})

	logger := log.WithField("test", "TestExtractAlertTechniques")

	// Test cases for extracting techniques from alerts
	tests := []struct {
		name      string
		metrics   map[string][]*model.EventMetric
		expected  techniqueMap
		expectErr bool
	}{
		{
			name: "Extract techniques from alerts",
			metrics: map[string][]*model.EventMetric{
				"rule.metadata.mitre_technique_id": {
					{
						Keys: []interface{}{"T1234"},
					},
					{
						Keys: []interface{}{"T5678.001"},
					},
				},
			},
			expected: techniqueMap{
				"T1234": struct{}{},
				"T5678": struct{}{},
			},
			expectErr: false,
		},
		{
			name:      "Empty alerts",
			metrics:   map[string][]*model.EventMetric{},
			expected:  techniqueMap{},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up expectations for GetAllDetections
			mockDetectionstore.EXPECT().
				GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(map[string]*model.Detection{}, nil).
				AnyTimes()

			// Set up expectations for Query
			mockDetectionstore.EXPECT().
				Query(gomock.Any(), gomock.Any(), gomock.Any()).
				Return([]interface{}{}, nil).
				AnyTimes()

			// Set up expectations for Eventstore.Search
			fakeEventstore.SearchResults = []*model.EventSearchResults{
				{
					Metrics: tt.metrics,
					Events:  []*model.EventRecord{},
				},
			}

			techniques, err := nav.extractAlertTechniques(context.Background(), logger)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, techniques)
			}
		})
	}
}

func TestGenerateNavigatorLayer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	fakeEventstore := server.NewFakeEventstore()

	srv := &server.Server{
		Context:          context.Background(),
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
		Detectionstore:   mockDetectionstore,
		Eventstore:       fakeEventstore,
	}

	nav := NewNavigator(srv)
	nav.Init(module.ModuleConfig{
		"outputPath": "/tmp",
	})

	logger := log.WithField("test", "TestGenerateNavigatorLayer")

	tests := []struct {
		name      string
		expected  techniqueMap
		expectErr bool
	}{
		{
			name: "Generate layer with techniques",
			expected: techniqueMap{
				"T1234": struct{}{},
				"T5678": struct{}{},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up expectations for GetAllDetections with any arguments
			mockDetectionstore.EXPECT().
				GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(map[string]*model.Detection{}, nil).
				AnyTimes()

			// Set up expectations for Query
			mockDetectionstore.EXPECT().
				Query(gomock.Any(), gomock.Any(), gomock.Any()).
				Return([]interface{}{}, nil).
				AnyTimes()

			err := nav.generateNavigatorLayer(context.Background(), logger)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	fakeEventstore := server.NewFakeEventstore()

	srv := &server.Server{
		Context:          context.Background(),
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
		Detectionstore:   mockDetectionstore,
		Eventstore:       fakeEventstore,
	}

	nav := NewNavigator(srv)
	nav.Init(module.ModuleConfig{
		"outputPath": "/tmp",
	})

	logger := log.WithField("test", "TestErrorCases")

	tests := []struct {
		name      string
		expectErr bool
	}{
		{
			name:      "Query error",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up expectations for GetAllDetections with any arguments
			mockDetectionstore.EXPECT().
				GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, errors.New("detection error")).
				AnyTimes()

			// Set up expectations for Query to return an error
			mockDetectionstore.EXPECT().
				Query(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, errors.New("query error")).
				AnyTimes()

			err := nav.generateNavigatorLayer(context.Background(), logger)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
