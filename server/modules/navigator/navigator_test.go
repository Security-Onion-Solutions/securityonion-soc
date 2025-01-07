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

// Test setup structure for common test components
type testSetup struct {
	ctrl               *gomock.Controller
	mockDetectionstore *mock.MockDetectionstore
	fakeEventstore     *server.FakeEventstore
	navigator          *Navigator
	logger             *log.Entry
}

// Common test data
var (
	testTechniques = techniqueMap{
		"T1234": struct{}{},
		"T5678": struct{}{},
	}
	testSuricataRules = map[string]*model.Detection{
		"rule1": {
			Content: `alert tcp any any -> any any (msg:"Test Rule"; metadata:mitre_technique_id T1234;)`,
		},
		"rule2": {
			Content: `alert tcp any any -> any any (msg:"Test Rule 2"; metadata:mitre_technique_id T5678.001;)`,
		},
	}
	testSigmaRules = map[string]*model.Detection{
		"rule1": {
			Content: "title: Test\ntags:\n  - attack.t1234",
		},
	}
	testAlertMetrics = map[string][]*model.EventMetric{
		"rule.metadata.mitre_technique_id": {
			{Keys: []interface{}{"T1234"}},
			{Keys: []interface{}{"T5678.001"}},
		},
	}
)

// Setup helper for tests
func setupTest(t *testing.T) *testSetup {
	ctrl := gomock.NewController(t)
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

	return &testSetup{
		ctrl:               ctrl,
		mockDetectionstore: mockDetectionstore,
		fakeEventstore:     fakeEventstore,
		navigator:          nav,
		logger:             log.WithField("test", t.Name()),
	}
}

// Helper for setting up GetAllDetections expectations
func (ts *testSetup) expectGetAllDetections(returns map[string]*model.Detection, err error) {
	ts.mockDetectionstore.EXPECT().
		GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(returns, err).
		AnyTimes()
}

// Helper for setting up Query expectations
func (ts *testSetup) expectQuery(returns []interface{}, err error) {
	ts.mockDetectionstore.EXPECT().
		Query(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(returns, err).
		AnyTimes()
}

// Helper for setting up alert metrics
func (ts *testSetup) setupAlertMetrics(metrics map[string][]*model.EventMetric) {
	ts.fakeEventstore.SearchResults = []*model.EventSearchResults{
		{
			Metrics: metrics,
			Events:  []*model.EventRecord{},
		},
	}
}

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
			ts := setupTest(t)
			defer ts.ctrl.Finish()

			err := ts.navigator.Init(tt.config)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPath, ts.navigator.outputPath)
				assert.Equal(t, tt.expectedDays, ts.navigator.lookbackDays)
			}
		})
	}
}

func TestExtractSuricataTechniques(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	techniques := extractSuricataTechniques(testSuricataRules, ts.logger)

	expected := techniqueMap{
		"T1234": struct{}{},
		"T5678": struct{}{}, // Note: sub-technique .001 is stripped
	}

	assert.Equal(t, expected, techniques)
}

func TestExtractSigmaTechniques(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	techniques := extractSigmaTechniques(testSigmaRules, ts.logger)

	expected := techniqueMap{
		"T1234": struct{}{},
	}

	assert.Equal(t, expected, techniques)
}

func TestMergeTechniques(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	map1 := techniqueMap{
		"T1234": struct{}{},
	}
	map2 := techniqueMap{
		"T5678": struct{}{},
	}

	merged := mergeTechniques(map1, map2)

	expected := techniqueMap{
		"T1234": struct{}{},
		"T5678": struct{}{},
	}

	assert.Equal(t, expected, merged)
}

func TestCreateLayer(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	layer, err := createLayer("test layer", testTechniques)
	assert.NoError(t, err)

	// Verify layer structure
	assert.Equal(t, "test layer", layer["name"])
	versions := layer["versions"].(map[string]interface{})
	assert.Equal(t, "4.5", versions["layer"])
	assert.Equal(t, "5.1.0", versions["navigator"])

	// Verify techniques
	techniques := layer["techniques"].([]map[string]interface{})
	assert.Len(t, techniques, len(testTechniques))

	// Verify each technique is present
	techniqueIDs := make(map[string]bool)
	for _, tech := range techniques {
		techniqueIDs[tech["techniqueID"].(string)] = true
	}
	for id := range testTechniques {
		assert.True(t, techniqueIDs[id], "Technique %s should be present", id)
	}
}

func TestWriteLayer(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	// Create temporary directory for test
	tmpDir, err := os.MkdirTemp("", "navigator-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test layer
	layer, err := createLayer("test layer", testTechniques)
	assert.NoError(t, err)

	// Write layer to file
	filePath := filepath.Join(tmpDir, "test-layer.json")
	err = ts.navigator.writeLayer(layer, filePath, ts.logger)
	assert.NoError(t, err)

	// Verify file exists and contains valid JSON
	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)

	var readLayer map[string]interface{}
	err = json.Unmarshal(data, &readLayer)
	assert.NoError(t, err)

	// Compare only the relevant fields since JSON unmarshaling might change number types
	assert.Equal(t, layer["name"], readLayer["name"])
	assert.Equal(t, layer["versions"], readLayer["versions"])

	// Compare techniques separately, accounting for number type differences
	expectedTechs := layer["techniques"].([]map[string]interface{})
	actualTechs := readLayer["techniques"].([]interface{})
	assert.Equal(t, len(expectedTechs), len(actualTechs))

	// Create maps of technique IDs to verify all are present
	expectedTechMap := make(map[string]bool)
	actualTechMap := make(map[string]bool)

	for _, tech := range expectedTechs {
		expectedTechMap[tech["techniqueID"].(string)] = true
	}

	for _, tech := range actualTechs {
		techMap := tech.(map[string]interface{})
		actualTechMap[techMap["techniqueID"].(string)] = true
		assert.True(t, techMap["enabled"].(bool))
		assert.Equal(t, float64(100), techMap["score"].(float64))
	}

	assert.Equal(t, expectedTechMap, actualTechMap)
}

func TestStartStop(t *testing.T) {
	ts := setupTest(t)
	defer ts.ctrl.Finish()

	// Set up expectations
	ts.expectGetAllDetections(testSuricataRules, nil)
	ts.setupAlertMetrics(testAlertMetrics)

	// Start navigator
	err := ts.navigator.Start()
	assert.NoError(t, err)
	assert.True(t, ts.navigator.IsRunning())

	// Wait briefly to allow first run to complete
	time.Sleep(100 * time.Millisecond)

	// Stop navigator
	err = ts.navigator.Stop()
	assert.NoError(t, err)
	assert.False(t, ts.navigator.IsRunning())
}

func TestExtractAlertTechniques(t *testing.T) {
	tests := []struct {
		name          string
		alertMetrics  map[string][]*model.EventMetric
		expectedTechs techniqueMap
		expectEmpty   bool
	}{
		{
			name:         "Extract techniques from alerts",
			alertMetrics: testAlertMetrics,
			expectedTechs: techniqueMap{
				"T1234": struct{}{},
				"T5678": struct{}{},
			},
		},
		{
			name:         "Empty alerts",
			alertMetrics: map[string][]*model.EventMetric{},
			expectEmpty:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			defer ts.ctrl.Finish()

			ts.setupAlertMetrics(tt.alertMetrics)

			techniques, err := ts.navigator.extractAlertTechniques(context.Background(), ts.logger)
			assert.NoError(t, err)

			if tt.expectEmpty {
				assert.Empty(t, techniques)
			} else {
				assert.Equal(t, tt.expectedTechs, techniques)
			}
		})
	}
}

func TestGenerateNavigatorLayer(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(*testSetup)
		expectError bool
	}{
		{
			name: "Generate layer with techniques",
			setupMocks: func(ts *testSetup) {
				ts.expectGetAllDetections(testSuricataRules, nil)
				ts.setupAlertMetrics(testAlertMetrics)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			defer ts.ctrl.Finish()

			if tt.setupMocks != nil {
				tt.setupMocks(ts)
			}

			err := ts.navigator.generateNavigatorLayer(context.Background(), ts.logger)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*testSetup)
	}{
		{
			name: "Query error",
			setupMocks: func(ts *testSetup) {
				ts.expectGetAllDetections(nil, errors.New("detection error"))
				ts.expectQuery(nil, errors.New("query error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			defer ts.ctrl.Finish()

			if tt.setupMocks != nil {
				tt.setupMocks(ts)
			}

			err := ts.navigator.generateNavigatorLayer(context.Background(), ts.logger)
			assert.Error(t, err)
		})
	}
}
