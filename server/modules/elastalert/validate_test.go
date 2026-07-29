// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSigmaDetectionOrdering(t *testing.T) {
	detection := SigmaDetection{
		Rest: map[string]interface{}{
			"selection": map[string]interface{}{
				"TargetObject|startswith": "HKCR\\ms-msdt\\",
			},
		},
		Condition: OneOrMore[string]{Value: "selection"},
	}

	yamlContent, err := yaml.Marshal(detection)
	assert.NoError(t, err)

	expectedYAML := `selection:
    TargetObject|startswith: HKCR\ms-msdt\
condition: selection
`
	assert.Equal(t, expectedYAML, string(yamlContent))
}

func TestParseRule(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name          string
		Input         string
		ExpectedError *string
	}{
		{
			Name:          "Empty Rule",
			Input:         `{}`,
			ExpectedError: util.Ptr("missing required fields: id, title, logsource, detection.condition"),
		},
		{
			Name:          "Detection but No Condition",
			Input:         `{ id: "x", title: "title", logsource: { category: "test" }, detection: {}}`,
			ExpectedError: util.Ptr("missing required fields: detection.condition"),
		},
		{
			Name:  "Minimal Rule With Single Detection Condition",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "condition" }}`,
		},
		{
			Name:  "Minimal Rule With Multiple Detection Condition",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: [ "conditionOne", "conditionTwo" ] }}`,
		},
		{
			Name:  "Rule With Correlation",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}`,
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Rules",
			Input:         `{ id: "x", title: "title", correlation: { type: event_count, group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}`,
			ExpectedError: util.Ptr("missing required fields: correlation.rules"),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Timespan",
			Input:         `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], condition: { gte: 2 } }}`,
			ExpectedError: util.Ptr("missing required fields: correlation.timespan"),
		},
		{
			Name:  "Rule With Incomplete Correlation - Missing Condition",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s" }}`,
		},
		{
			Name:  "Rule With Incomplete Correlation - Missing GroupBy",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], timespan: "30s", condition: { gte: 2 } }}`,
		},
		{
			Name:          "Rule With Correlation but No LogSource or Detection",
			Input:         `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}`,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseElastAlertRule([]byte(test.Input))
			if test.ExpectedError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, *test.ExpectedError, err.Error())
			}
		})
	}
}

func TestDuplicateDetection(t *testing.T) {
	det := &model.Detection{
		Engine:   model.EngineNameElastAlert,
		Language: model.SigLangSigma,
		Content: `title: Potential LSASS Process Dump Via Procdump
id: 5afee48e-67dd-4e03-a783-f74259dcf998
status: stable
description: |
    Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process.
    This way we are also able to catch cases in which the attacker has renamed the procdump executable.
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth (Nextron Systems)
date: 2018/10/30
modified: 2024/03/13
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003.001
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|windash: ' -ma '
    selection_process:
        CommandLine|contains: ' ls' # Short for lsass
    condition: all of selection*
falsepositives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses command line flags similar to ProcDump
level: high`,
		IsCommunity: true,
		Ruleset:     "somewhere",
		Author:      "Alec Hardison",
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	ctrl := gomock.NewController(t)
	mUser := mock.NewMockUserstore(ctrl)
	mUser.EXPECT().GetUserById(ctx, "myRequestorId").Return(&model.User{
		FirstName: "Alec",
		LastName:  "Hardison",
	}, nil)

	mDetect := mock.NewMockDetectionstore(ctrl)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(&model.Detection{}, nil)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(nil, nil)

	eng := ElastAlertEngine{
		srv: &server.Server{
			Userstore:      mUser,
			Detectionstore: mDetect,
		},
		isRunning: true,
	}

	_ = eng.ExtractDetails(det)

	dupe, err := eng.DuplicateDetection(ctx, det)

	assert.NoError(t, err)
	assert.NotNil(t, dupe)

	// expected differences
	assert.NotEqual(t, det.Title, dupe.Title)
	assert.Equal(t, det.Title, dupe.Title[:len(dupe.Title)-len(" (copy)")])
	assert.NotEqual(t, det.PublicID, dupe.PublicID)
	assert.NotEmpty(t, dupe.PublicID)
	assert.NotEqual(t, det.IsCommunity, dupe.IsCommunity)
	assert.NotEqual(t, det.Ruleset, dupe.Ruleset)

	// expected similarities
	assert.Equal(t, det.Severity, dupe.Severity)
	assert.Equal(t, "Florian Roth (Nextron Systems), Alec Hardison", dupe.Author)
	assert.Equal(t, det.Category, dupe.Category)
	assert.Equal(t, det.Description, dupe.Description)
	assert.Equal(t, det.Engine, dupe.Engine)
	assert.Equal(t, det.Language, dupe.Language)

	// always empty after duplication
	assert.False(t, det.IsEnabled)
	assert.False(t, det.IsReporting)
	assert.Equal(t, det.License, dupe.License)
	assert.Empty(t, dupe.Overrides)
	assert.Empty(t, dupe.Tags)
}

func TestGenerateUnusedPublicId(t *testing.T) {
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	mDetect := mock.NewMockDetectionstore(ctrl)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(&model.Detection{}, nil).Times(10)

	eng := ElastAlertEngine{
		srv: &server.Server{
			Detectionstore: mDetect,
		},
		isRunning: true,
	}

	id, err := eng.GenerateUnusedPublicId(ctx)

	assert.Empty(t, id)
	assert.Error(t, err)
	assert.Equal(t, "unable to generate a unique publicId", err.Error())
}

func TestToDetection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		rule      *SigmaRule
		ruleset   string
		license   string
		community bool
		expected  *model.Detection
	}{
		{
			name: "nil fields",
			rule: &SigmaRule{
				Title:     "Test Rule",      // Title is non-pointer string, can't be nil
				LogSource: LogSource{},      // LogSource is non-pointer struct
				Detection: SigmaDetection{}, // Detection is non-pointer struct
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: false,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "Test Rule", // defaults to Title when ID is nil
				Author:      "unknown",   // default when Author is nil
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityUnknown, // default when Level is nil
				IsCommunity: false,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
		{
			name: "empty strings",
			rule: &SigmaRule{
				Title:       "Test Rule",
				ID:          util.Ptr(""),
				Author:      util.Ptr(""),
				Level:       util.Ptr(SigmaLevelUnknown),
				Description: util.Ptr(""),
				LogSource: LogSource{
					Category: util.Ptr(""),
					Product:  util.Ptr(""),
					Service:  util.Ptr(""),
				},
				Detection: SigmaDetection{},
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: true,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "", // empty string ID is preserved
				Author:      "", // empty string Author is preserved
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityUnknown,
				Description: "", // empty string Description is preserved
				IsCommunity: true,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
		{
			name: "all fields populated",
			rule: &SigmaRule{
				Title:       "Test Rule",
				ID:          util.Ptr("custom-id"),
				Author:      util.Ptr("test author"),
				Level:       util.Ptr(SigmaLevelHigh),
				Description: util.Ptr("test description"),
				LogSource: LogSource{
					Category: util.Ptr("test-category"),
					Product:  util.Ptr("test-product"),
					Service:  util.Ptr("test-service"),
				},
				Detection: SigmaDetection{},
				Date:      util.Ptr("2023-10-01"),
				Modified:  util.Ptr("2023-10-02"),
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: true,
			expected: &model.Detection{
				Title:         "Test Rule",
				PublicID:      "custom-id",
				Author:        "test author",
				Engine:        model.EngineNameElastAlert,
				Severity:      model.SeverityHigh,
				Description:   "test description",
				Category:      "test-category",
				Product:       "test-product",
				Service:       "test-service",
				IsCommunity:   true,
				Language:      model.SigLangSigma,
				Ruleset:       "test-ruleset",
				License:       "test-license",
				SourceCreated: util.Ptr(time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)),
				SourceUpdated: util.Ptr(time.Date(2023, 10, 2, 0, 0, 0, 0, time.UTC)),
			},
		},
		{
			name: "severity levels",
			rule: &SigmaRule{
				Title:     "Test Rule",
				Level:     util.Ptr(SigmaLevelInformational),
				LogSource: LogSource{},
				Detection: SigmaDetection{},
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: false,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "Test Rule",
				Author:      "unknown",
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityInformational,
				IsCommunity: false,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
		{
			name: "severity medium",
			rule: &SigmaRule{
				Title:     "Test Rule",
				Level:     util.Ptr(SigmaLevelMedium),
				LogSource: LogSource{},
				Detection: SigmaDetection{},
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: false,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "Test Rule",
				Author:      "unknown",
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityMedium,
				IsCommunity: false,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
		{
			name: "severity critical",
			rule: &SigmaRule{
				Title:     "Test Rule",
				Level:     util.Ptr(SigmaLevelCritical),
				LogSource: LogSource{},
				Detection: SigmaDetection{},
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: false,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "Test Rule",
				Author:      "unknown",
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityCritical,
				IsCommunity: false,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
		{
			name: "severity low",
			rule: &SigmaRule{
				Title:     "Test Rule",
				Level:     util.Ptr(SigmaLevelLow),
				LogSource: LogSource{},
				Detection: SigmaDetection{},
			},
			ruleset:   "test-ruleset",
			license:   "test-license",
			community: false,
			expected: &model.Detection{
				Title:       "Test Rule",
				PublicID:    "Test Rule",
				Author:      "unknown",
				Engine:      model.EngineNameElastAlert,
				Severity:    model.SeverityLow,
				IsCommunity: false,
				Language:    model.SigLangSigma,
				Ruleset:     "test-ruleset",
				License:     "test-license",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := tc.rule.ToDetection(tc.ruleset, tc.license, tc.community)

			// First verify the content field separately since it's a YAML marshaled string
			expectedContent, err := yaml.Marshal(tc.rule)
			assert.NoError(t, err)
			assert.Equal(t, string(expectedContent), result.Content, "Content field mismatch")

			// Now clear the content field for the full struct comparison
			result.Content = ""
			tc.expected.Content = ""

			assert.Equal(t, tc.expected, result, "Detection struct mismatch")
		})
	}
}
