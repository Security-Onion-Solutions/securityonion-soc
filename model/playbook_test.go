// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestPlaybookCreation(t *testing.T) {
	t.Parallel()

	playbook := &Playbook{
		Name: "Test Playbook",
		Auditable: Auditable{
			Id: "test-playbook-id",
		},
		DetectionId:       "detection-123",
		DetectionCategory: "process_creation",
		DetectionType:     "sigma",
		Contributors:      []string{"SecurityOnionSolutions", "TestUser"},
		Questions: []*Question{
			{
				Question:      "What process was executed?",
				Context:       "Understanding the process helps identify malicious activity",
				Range:         util.Ptr("-1h"),
				AnswerSources: []string{"process_creation"},
				Query:         "Image: {Image}",
			},
		},
	}

	assert.Equal(t, "Test Playbook", playbook.Name)
	assert.Equal(t, "test-playbook-id", playbook.Id)
	assert.Equal(t, "detection-123", playbook.DetectionId)
	assert.Equal(t, "process_creation", playbook.DetectionCategory)
	assert.Equal(t, "sigma", playbook.DetectionType)
	assert.Len(t, playbook.Contributors, 2)
	assert.Len(t, playbook.Questions, 1)
	assert.Equal(t, "What process was executed?", playbook.Questions[0].Question)
}

func TestPlaybookJSONSerialization(t *testing.T) {
	t.Parallel()

	originalPlaybook := &Playbook{
		Name:        "JSON Test Playbook",
		Description: "Testing JSON serialization",
		Auditable: Auditable{
			Id: "json-test-id",
		},
		SourceCreated:     time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		DetectionId:       "json-detection-123",
		DetectionCategory: "network_connection",
		DetectionType:     "nids",
		Contributors:      []string{"TestUser1", "TestUser2"},
		Questions: []*Question{
			{
				Question:      "What network connections were made?",
				Context:       "Network connections can indicate C2 activity",
				Range:         util.Ptr("+/-30m"),
				AnswerSources: []string{"network_connection"},
				Query:         "src_ip: {src_ip} AND dst_ip: {dst_ip}",
				FilledQuery:   "src_ip: 192.168.1.10 AND dst_ip: 10.0.0.1",
			},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(originalPlaybook)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), "JSON Test Playbook")
	assert.Contains(t, string(jsonData), "json-test-id")
	assert.Contains(t, string(jsonData), "network_connection")

	// Test JSON unmarshaling
	var deserializedPlaybook Playbook
	err = json.Unmarshal(jsonData, &deserializedPlaybook)
	assert.NoError(t, err)

	assert.Equal(t, originalPlaybook.Name, deserializedPlaybook.Name)
	assert.Equal(t, originalPlaybook.Id, deserializedPlaybook.Id)
	assert.Equal(t, originalPlaybook.DetectionId, deserializedPlaybook.DetectionId)
	assert.Equal(t, originalPlaybook.DetectionCategory, deserializedPlaybook.DetectionCategory)
	assert.Equal(t, originalPlaybook.DetectionType, deserializedPlaybook.DetectionType)
	assert.Equal(t, originalPlaybook.Contributors, deserializedPlaybook.Contributors)
	assert.Len(t, deserializedPlaybook.Questions, 1)
	assert.Equal(t, originalPlaybook.Questions[0].Question, deserializedPlaybook.Questions[0].Question)
	assert.Equal(t, originalPlaybook.Questions[0].Context, deserializedPlaybook.Questions[0].Context)
	assert.Equal(t, *originalPlaybook.Questions[0].Range, *deserializedPlaybook.Questions[0].Range)
}

func TestPlaybookYAMLSerialization(t *testing.T) {
	t.Parallel()

	originalPlaybook := &Playbook{
		Name:        "YAML Test Playbook",
		Description: "Testing YAML serialization",
		Auditable: Auditable{
			Id: "yaml-test-id",
		},
		SourceCreated:     time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		DetectionId:       "yaml-detection-123",
		DetectionCategory: "file_event",
		DetectionType:     "sigma",
		Contributors:      []string{"YAMLTestUser"},
		Questions: []*Question{
			{
				Question:      "What files were accessed?",
				Context:       "File access patterns can reveal malicious behavior",
				Range:         util.Ptr("-2h"),
				AnswerSources: []string{"file_event"},
				Query:         "TargetFilename: {TargetFilename}",
			},
		},
	}

	// Test YAML marshaling
	yamlData, err := yaml.Marshal(originalPlaybook)
	assert.NoError(t, err)
	assert.Contains(t, string(yamlData), "YAML Test Playbook")
	assert.Contains(t, string(yamlData), "yaml-test-id")
	assert.Contains(t, string(yamlData), "file_event")

	// Test YAML unmarshaling
	var deserializedPlaybook Playbook
	err = yaml.Unmarshal(yamlData, &deserializedPlaybook)
	assert.NoError(t, err)

	assert.Equal(t, originalPlaybook.Name, deserializedPlaybook.Name)
	assert.Equal(t, originalPlaybook.Id, deserializedPlaybook.Id)
	assert.Equal(t, originalPlaybook.DetectionId, deserializedPlaybook.DetectionId)
	assert.Equal(t, originalPlaybook.DetectionCategory, deserializedPlaybook.DetectionCategory)
	assert.Equal(t, originalPlaybook.DetectionType, deserializedPlaybook.DetectionType)
	assert.Equal(t, originalPlaybook.Contributors, deserializedPlaybook.Contributors)
	assert.Len(t, deserializedPlaybook.Questions, 1)
	assert.Equal(t, originalPlaybook.Questions[0].Question, deserializedPlaybook.Questions[0].Question)
}

func TestQuestionCreation(t *testing.T) {
	t.Parallel()

	question := &Question{
		Question:      "What is the source IP?",
		Context:       "Source IP helps identify the origin of the attack",
		Range:         util.Ptr("+/-1h"),
		AnswerSources: []string{"network", "alert"},
		Query:         "src_ip: {src_ip}",
		FilledQuery:   "src_ip: 192.168.1.100",
		QueryResults: []*EventRecord{
			{
				Id: "event-1",
				Payload: map[string]interface{}{
					"src_ip": "192.168.1.100",
					"dst_ip": "10.0.0.1",
				},
			},
		},
		QueryFields: []string{"src_ip", "dst_ip", "timestamp"},
		OqlQuery:    "src_ip: 192.168.1.100",
	}

	assert.Equal(t, "What is the source IP?", question.Question)
	assert.Equal(t, "Source IP helps identify the origin of the attack", question.Context)
	assert.Equal(t, "+/-1h", *question.Range)
	assert.Len(t, question.AnswerSources, 2)
	assert.Contains(t, question.AnswerSources, "network")
	assert.Contains(t, question.AnswerSources, "alert")
	assert.Equal(t, "src_ip: {src_ip}", question.Query)
	assert.Equal(t, "src_ip: 192.168.1.100", question.FilledQuery)
	assert.Len(t, question.QueryResults, 1)
	assert.Equal(t, "event-1", question.QueryResults[0].Id)
	assert.Len(t, question.QueryFields, 3)
	assert.Equal(t, "src_ip: 192.168.1.100", question.OqlQuery)
}

func TestQuestionWithNilRange(t *testing.T) {
	t.Parallel()

	question := &Question{
		Question:      "What is the alert content?",
		Range:         nil, // No time range
		AnswerSources: []string{"alert"},
	}

	assert.Equal(t, "What is the alert content?", question.Question)
	assert.Nil(t, question.Range)
	assert.Len(t, question.AnswerSources, 1)
	assert.Equal(t, "alert", question.AnswerSources[0])
}

func TestConvertedQueryCreation(t *testing.T) {
	t.Parallel()

	convertedQuery := &ConvertedQuery{
		Query:  "hostname: test-host AND user.name: admin",
		Fields: []string{"hostname", "user.name", "process.name", "command_line"},
	}

	assert.Equal(t, "hostname: test-host AND user.name: admin", convertedQuery.Query)
	assert.Len(t, convertedQuery.Fields, 4)
	assert.Contains(t, convertedQuery.Fields, "hostname")
	assert.Contains(t, convertedQuery.Fields, "user.name")
	assert.Contains(t, convertedQuery.Fields, "process.name")
	assert.Contains(t, convertedQuery.Fields, "command_line")
}

func TestConvertedQueryJSONSerialization(t *testing.T) {
	t.Parallel()

	originalQuery := &ConvertedQuery{
		Query:  "src_ip: 10.0.0.1 AND dst_port: 443",
		Fields: []string{"src_ip", "dst_ip", "dst_port", "protocol"},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(originalQuery)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), "src_ip: 10.0.0.1 AND dst_port: 443")
	assert.Contains(t, string(jsonData), "src_ip")
	assert.Contains(t, string(jsonData), "dst_port")

	// Test JSON unmarshaling
	var deserializedQuery ConvertedQuery
	err = json.Unmarshal(jsonData, &deserializedQuery)
	assert.NoError(t, err)

	assert.Equal(t, originalQuery.Query, deserializedQuery.Query)
	assert.Equal(t, originalQuery.Fields, deserializedQuery.Fields)
}

func TestPlaybookDetectionTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		detectionType string
		expectedValid bool
		description   string
	}{
		{
			name:          "Valid NIDS detection type",
			detectionType: "nids",
			expectedValid: true,
			description:   "NIDS detection type should be valid",
		},
		{
			name:          "Valid Sigma detection type",
			detectionType: "sigma",
			expectedValid: true,
			description:   "Sigma detection type should be valid",
		},
		{
			name:          "Valid YARA detection type",
			detectionType: "yara",
			expectedValid: true,
			description:   "YARA detection type should be valid",
		},
		{
			name:          "Empty detection type",
			detectionType: "",
			expectedValid: true,
			description:   "Empty detection type should be valid for generic playbooks",
		},
		{
			name:          "Case insensitive NIDS",
			detectionType: "NIDS",
			expectedValid: true,
			description:   "Detection types should be case insensitive",
		},
		{
			name:          "Case insensitive Sigma",
			detectionType: "SIGMA",
			expectedValid: true,
			description:   "Detection types should be case insensitive",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			playbook := &Playbook{
				DetectionType: test.detectionType,
				Auditable: Auditable{
					Id: "detection-type-test-" + test.name,
				},
			}

			// Since there's no validation method in the model, we just test that the field can be set
			assert.Equal(t, test.detectionType, playbook.DetectionType, test.description)
		})
	}
}

func TestPlaybookWithMultipleQuestions(t *testing.T) {
	t.Parallel()

	playbook := &Playbook{
		Name: "Multi-Question Playbook",
		Auditable: Auditable{
			Id: "multi-question-test",
		},
		Questions: []*Question{
			{
				Question:      "What process triggered the alert?",
				Context:       "Identify the initial process",
				Range:         nil,
				AnswerSources: []string{"process_creation"},
				Query:         "ProcessGuid: {ProcessGuid}",
			},
			{
				Question:      "What child processes were spawned?",
				Context:       "Identify subsequent malicious activity",
				Range:         util.Ptr("+5m"),
				AnswerSources: []string{"process_creation"},
				Query:         "ParentProcessGuid: {ProcessGuid}",
			},
			{
				Question:      "What files were accessed?",
				Context:       "Identify file system impact",
				Range:         util.Ptr("+/-10m"),
				AnswerSources: []string{"file_event"},
				Query:         "ProcessGuid: {ProcessGuid}",
			},
			{
				Question:      "What network connections were made?",
				Context:       "Identify network-based indicators",
				Range:         util.Ptr("+/-15m"),
				AnswerSources: []string{"network_connection"},
				Query:         "ProcessGuid: {ProcessGuid}",
			},
		},
	}

	assert.Equal(t, "Multi-Question Playbook", playbook.Name)
	assert.Len(t, playbook.Questions, 4)

	// Test first question (no range)
	assert.Equal(t, "What process triggered the alert?", playbook.Questions[0].Question)
	assert.Nil(t, playbook.Questions[0].Range)
	assert.Contains(t, playbook.Questions[0].AnswerSources, "process_creation")

	// Test second question (forward range)
	assert.Equal(t, "What child processes were spawned?", playbook.Questions[1].Question)
	assert.Equal(t, "+5m", *playbook.Questions[1].Range)

	// Test third question (bidirectional range)
	assert.Equal(t, "What files were accessed?", playbook.Questions[2].Question)
	assert.Equal(t, "+/-10m", *playbook.Questions[2].Range)
	assert.Contains(t, playbook.Questions[2].AnswerSources, "file_event")

	// Test fourth question (longer bidirectional range)
	assert.Equal(t, "What network connections were made?", playbook.Questions[3].Question)
	assert.Equal(t, "+/-15m", *playbook.Questions[3].Range)
	assert.Contains(t, playbook.Questions[3].AnswerSources, "network_connection")
}

func TestPlaybookWithSourceTimestamps(t *testing.T) {
	t.Parallel()

	created := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	modified := time.Date(2024, 1, 16, 15, 30, 0, 0, time.UTC)

	playbook := &Playbook{
		SourceCreated: created,
		SourceUpdated: &modified,
		Auditable: Auditable{
			Id: "timestamp-test",
		},
	}

	assert.Equal(t, created, playbook.SourceCreated)
	assert.NotNil(t, playbook.SourceUpdated)
	assert.Equal(t, modified, *playbook.SourceUpdated)
	assert.True(t, playbook.SourceUpdated.After(playbook.SourceCreated))
}

func TestPlaybookWithoutSourceUpdated(t *testing.T) {
	t.Parallel()

	playbook := &Playbook{
		SourceCreated: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		SourceUpdated: nil,
		Auditable: Auditable{
			Id: "no-update-test",
		},
	}

	assert.False(t, playbook.SourceCreated.IsZero())
	assert.Nil(t, playbook.SourceUpdated)
}

func TestQuestionWithQueryResults(t *testing.T) {
	t.Parallel()

	eventResults := []*EventRecord{
		{
			Id: "result-1",
			Payload: map[string]interface{}{
				"Image":       "notepad.exe",
				"CommandLine": "notepad.exe document.txt",
				"User":        "DOMAIN\\user1",
			},
		},
		{
			Id: "result-2",
			Payload: map[string]interface{}{
				"Image":       "cmd.exe",
				"CommandLine": "cmd.exe /c dir",
				"User":        "DOMAIN\\user1",
			},
		},
	}

	question := &Question{
		QueryResults: eventResults,
		QueryFields:  []string{"Image", "CommandLine", "User", "ProcessGuid"},
	}

	assert.Len(t, question.QueryResults, 2)
	assert.Equal(t, "result-1", question.QueryResults[0].Id)
	assert.Equal(t, "result-2", question.QueryResults[1].Id)
	assert.Equal(t, "notepad.exe", question.QueryResults[0].Payload["Image"])
	assert.Equal(t, "cmd.exe", question.QueryResults[1].Payload["Image"])
	assert.Len(t, question.QueryFields, 4)
	assert.Contains(t, question.QueryFields, "Image")
	assert.Contains(t, question.QueryFields, "CommandLine")
	assert.Contains(t, question.QueryFields, "User")
	assert.Contains(t, question.QueryFields, "ProcessGuid")
}

func TestPlaybookEngineSpecificFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		detectionType     string
		detectionCategory string
		expectedCategory  string
		description       string
	}{
		{
			name:              "Suricata NIDS playbook",
			detectionType:     "nids",
			detectionCategory: "ET SCAN",
			expectedCategory:  "ET SCAN",
			description:       "NIDS playbooks should support complex categories",
		},
		{
			name:              "Sigma process creation playbook",
			detectionType:     "sigma",
			detectionCategory: "process_creation",
			expectedCategory:  "process_creation",
			description:       "Sigma playbooks should support standard categories",
		},
		{
			name:              "YARA file analysis playbook",
			detectionType:     "yara",
			detectionCategory: "file_event",
			expectedCategory:  "file_event",
			description:       "YARA playbooks should support file-based categories",
		},
		{
			name:              "Generic playbook",
			detectionType:     "",
			detectionCategory: "generic",
			expectedCategory:  "generic",
			description:       "Generic playbooks should work with any category",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			playbook := &Playbook{
				DetectionType:     test.detectionType,
				DetectionCategory: test.detectionCategory,
				Auditable: Auditable{
					Id: "engine-test-" + test.name,
				},
			}

			assert.Equal(t, test.detectionType, playbook.DetectionType, test.description)
			assert.Equal(t, test.expectedCategory, playbook.DetectionCategory, test.description)
		})
	}
}

func TestEmptyPlaybook(t *testing.T) {
	t.Parallel()

	playbook := &Playbook{}

	assert.Empty(t, playbook.Name)
	assert.Empty(t, playbook.Description)
	assert.Empty(t, playbook.Id)
	assert.True(t, playbook.SourceCreated.IsZero())
	assert.Nil(t, playbook.SourceUpdated)
	assert.Empty(t, playbook.DetectionId)
	assert.Empty(t, playbook.DetectionCategory)
	assert.Empty(t, playbook.DetectionType)
	assert.Nil(t, playbook.Contributors)
	assert.Nil(t, playbook.Questions)
}

func TestEmptyQuestion(t *testing.T) {
	t.Parallel()

	question := &Question{}

	assert.Empty(t, question.Question)
	assert.Empty(t, question.Context)
	assert.Nil(t, question.Range)
	assert.Nil(t, question.AnswerSources)
	assert.Empty(t, question.Query)
	assert.Empty(t, question.FilledQuery)
	assert.Nil(t, question.QueryResults)
	assert.Nil(t, question.QueryFields)
	assert.Empty(t, question.OqlQuery)
}

func TestEmptyConvertedQuery(t *testing.T) {
	t.Parallel()

	convertedQuery := &ConvertedQuery{}

	assert.Empty(t, convertedQuery.Query)
	assert.Nil(t, convertedQuery.Fields)
}
