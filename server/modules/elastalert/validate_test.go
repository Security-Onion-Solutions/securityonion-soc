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
			Input: `{ id: "x", title: "title", type: "correlation", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}`,
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Rules",
			Input:         `{ id: "x", title: "title", type: "correlation", correlation: { type: event_count, group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}`,
			ExpectedError: util.Ptr("missing required fields: correlation.rules"),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Timespan",
			Input:         `{ id: "x", title: "title", type: "correlation", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], condition: { gte: 2 } }}`,
			ExpectedError: util.Ptr("missing required fields: correlation.timespan"),
		},
		{
			Name:  "Rule With Incomplete Correlation - Missing Condition",
			Input: `{ id: "x", title: "title", type: "correlation", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s" }}`,
		},
		{
			Name:  "Rule With Incomplete Correlation - Missing GroupBy",
			Input: `{ id: "x", title: "title", type: "correlation", correlation: { type: event_count, rules: ["rule1"], timespan: "30s", condition: { gte: 2 } }}`,
		},
		{
			Name: "Correlation Rule event_count single rule",
			Input: `{ id: "x", title: "Brute Force", type: "correlation", correlation: { type: "event_count", rules: "failed_login", group-by: ["source.ip"], timespan: "10m", condition: { gte: 5 } } }`,
		},
		{
			Name: "Correlation Rule value_count",
			Input: `{ id: "x", title: "Credential Stuffing", type: "correlation", correlation: { type: "value_count", rules: "failed_login", group-by: ["source.ip"], timespan: "5m", condition: { gte: 3 }, field: "user.name" } }`,
		},
		{
			Name:  "Correlation Rule temporal (parses but not convertible)",
			Input: `{ id: "x", title: "Temporal", type: "correlation", correlation: { type: "temporal", rules: "base", timespan: "5m", condition: { gte: 1 } } }`,
		},
		{
			Name:  "Correlation Rule temporal_ordered",
			Input: `{ id: "x", title: "Temporal Ordered", type: "correlation", correlation: { type: "temporal_ordered", rules: ["rule_a", "rule_b"], timespan: "5m", condition: { gte: 1 } } }`,
		},
		{
			Name:          "Correlation Rule unknown type",
			Input:         `{ id: "x", title: "Bad", type: "correlation", correlation: { type: "bogus", rules: "base", timespan: "5m", condition: { gte: 1 } } }`,
			ExpectedError: util.Ptr(`unsupported correlation type: "bogus"`),
		},
		{
			Name:          "value_count Missing Field",
			Input:         `{ id: "x", title: "Bad", type: "correlation", correlation: { type: "value_count", rules: "base", timespan: "5m", condition: { gte: 3 } } }`,
			ExpectedError: util.Ptr("value_count correlation must specify a 'field'"),
		},
		{
			Name:          "Correlation Rule Invalid Timespan",
			Input:         `{ id: "x", title: "Bad", type: "correlation", correlation: { type: "event_count", rules: "base", timespan: "abc", condition: { gte: 5 } } }`,
			ExpectedError: util.Ptr(`invalid correlation timespan "abc": invalid number in timespan: strconv.Atoi: parsing "ab": invalid syntax`),
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

func TestParseTimespan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		wantErr  bool
		checkFn  func(*testing.T, *TimeFrame)
	}{
		{"5m", false, func(t *testing.T, tf *TimeFrame) { assert.Equal(t, 5, *tf.Minutes) }},
		{"10s", false, func(t *testing.T, tf *TimeFrame) { assert.Equal(t, 10, *tf.Seconds) }},
		{"2h", false, func(t *testing.T, tf *TimeFrame) { assert.Equal(t, 2, *tf.Hours) }},
		{"1d", false, func(t *testing.T, tf *TimeFrame) { assert.Equal(t, 1, *tf.Days) }},
		{"", true, nil},
		{"x", true, nil},
		{"5x", true, nil},
		{"abcm", true, nil},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			tf, err := ParseTimespan(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				tt.checkFn(t, tf)
			}
		})
	}
}

func TestIsCorrelationRule(t *testing.T) {
	t.Parallel()

	t.Run("standard rule", func(t *testing.T) {
		rule := &SigmaRule{RuleType: "", Correlation: nil}
		assert.False(t, rule.IsCorrelationRule())
	})

	t.Run("correlation rule", func(t *testing.T) {
		rule := &SigmaRule{
			RuleType: "correlation",
			Correlation: &SigmaCorrelation{
				Type:      SigmaCorrelationEventCount,
				Rules:     OneOrMore[string]{Value: "base_rule"},
				Timespan:  util.Ptr("5m"),
				Condition: map[string]int{"gte": 5},
			},
		}
		assert.True(t, rule.IsCorrelationRule())
	})

	t.Run("type set but no correlation block", func(t *testing.T) {
		rule := &SigmaRule{RuleType: "correlation", Correlation: nil}
		assert.False(t, rule.IsCorrelationRule())
	})
}

func TestApplyCorrelationEventCount(t *testing.T) {
	w := &CustomWrapper{Type: "any"}
	c := &SigmaCorrelation{
		Type:      SigmaCorrelationEventCount,
		Rules:     OneOrMore[string]{Value: "failed_login"},
		GroupBy:   []string{"source.ip"},
		Timespan:  util.Ptr("10m"),
		Condition: map[string]int{"gte": 5},
	}

	applyCorrelation(w, c)

	assert.Equal(t, "frequency", w.Type)
	assert.Equal(t, 5, *w.NumEvents)
	assert.Equal(t, 10, *w.Timeframe.Minutes)
	assert.Equal(t, []string{"source.ip"}, w.QueryKey)
	assert.Nil(t, w.CardinalityField)
}

func TestApplyCorrelationValueCount(t *testing.T) {
	w := &CustomWrapper{Type: "any"}
	c := &SigmaCorrelation{
		Type:      SigmaCorrelationValueCount,
		Rules:     OneOrMore[string]{Value: "failed_login"},
		GroupBy:   []string{"source.ip"},
		Timespan:  util.Ptr("5m"),
		Condition: map[string]int{"gte": 3},
		Field:     util.Ptr("user.name"),
	}

	applyCorrelation(w, c)

	assert.Equal(t, "cardinality", w.Type)
	assert.Equal(t, "user.name", *w.CardinalityField)
	assert.Equal(t, 3, *w.MaxCardinality)
	assert.Equal(t, 5, *w.Timeframe.Minutes)
	assert.Equal(t, []string{"source.ip"}, w.QueryKey)
	assert.Nil(t, w.NumEvents)
}

func TestApplyCorrelationGtCondition(t *testing.T) {
	w := &CustomWrapper{Type: "any"}
	c := &SigmaCorrelation{
		Type:      SigmaCorrelationEventCount,
		Rules:     OneOrMore[string]{Value: "base"},
		Timespan:  util.Ptr("5m"),
		Condition: map[string]int{"gt": 4},
	}

	applyCorrelation(w, c)

	assert.Equal(t, "frequency", w.Type)
	assert.Equal(t, 5, *w.NumEvents)
}

func TestCorrelationMultiRuleParsing(t *testing.T) {
	t.Parallel()

	input := `{ id: "x", title: "Multi Rule", type: "correlation", correlation: { type: "event_count", rules: ["rule_a", "rule_b", "rule_c"], group-by: ["source.ip"], timespan: "10m", condition: { gte: 5 } } }`
	rule, err := ParseElastAlertRule([]byte(input))
	assert.NoError(t, err)
	assert.True(t, rule.IsCorrelationRule())
	assert.Equal(t, 3, len(rule.Correlation.Rules.Values))
	assert.Equal(t, "rule_a", rule.Correlation.Rules.Values[0])
	assert.Equal(t, "rule_b", rule.Correlation.Rules.Values[1])
	assert.Equal(t, "rule_c", rule.Correlation.Rules.Values[2])
}

func TestApplyCorrelationTemporalSkipped(t *testing.T) {
	w := &CustomWrapper{Type: "any"}
	c := &SigmaCorrelation{
		Type:      SigmaCorrelationTemporal,
		Rules:     OneOrMore[string]{Values: []string{"a", "b"}},
		Timespan:  util.Ptr("5m"),
		Condition: map[string]int{"gte": 1},
	}

	applyCorrelation(w, c)

	assert.Equal(t, "any", w.Type)
	assert.Nil(t, w.NumEvents)
	assert.Nil(t, w.CardinalityField)
}
