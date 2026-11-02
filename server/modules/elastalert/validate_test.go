// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		ExpectedCode  error
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
			Input: correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 }`),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Rules",
			Input:         correlationRule(`type: event_count, group-by: ["field1"], timespan: "30s", condition: { gte: 2 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.rules"),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Timespan",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], condition: { gte: 2 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.timespan"),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing Condition",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s"`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.condition (a count comparison such as gte)"),
		},
		{
			Name:          "Rule With Incomplete Correlation - Missing GroupBy",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], timespan: "30s", condition: { gte: 2 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.group-by"),
		},
		{
			Name:  "Value Count Correlation Carries A Field In Its Condition",
			Input: correlationRule(`type: value_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "field2", gte: 2 }`),
		},
		{
			Name:          "Value Count Correlation Without A Condition Field",
			Input:         correlationRule(`type: value_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.condition.field"),
		},
		{
			Name:          "Correlation Without A Type",
			Input:         correlationRule(`rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.type"),
		},
		{
			Name:  "Metric Correlation With A Fractional Threshold",
			Input: correlationRule(`type: value_avg, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", gt: 0.5 }`),
		},
		{
			Name:          "Metric Correlation Without A Comparison Or Field",
			Input:         correlationRule(`type: value_sum, rules: ["rule1"], group-by: ["field1"], timespan: "30s"`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.condition (a comparison such as gt), correlation.condition.field"),
		},
		{
			Name:          "Percentile Correlation Without A Percentile",
			Input:         correlationRule(`type: value_percentile, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", gt: 5 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: missing required fields: correlation.condition.percentile"),
		},
		{
			Name:          "Correlation With A Range Condition",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2, lte: 5 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation.condition must have exactly one comparison (gt, gte, lt, lte, eq or neq), found 2; ranges are not supported"),
			ExpectedCode:  errRuleInvalidCorrelation,
		},
		{
			Name:          "Correlation With Unknown Condition Keys",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2, within: 5, above: 1 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: unsupported correlation.condition keys: above, within; use field, percentile and one of gt, gte, lt, lte, eq or neq"),
		},
		{
			Name:          "Percentile Correlation With A Percentile Above 100",
			Input:         correlationRule(`type: value_percentile, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", percentile: 150, gt: 5 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation.condition.percentile must be between 0 and 100, found 150"),
		},
		{
			Name:          "Percentile Correlation With A Negative Percentile",
			Input:         correlationRule(`type: value_percentile, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", percentile: -1, gt: 5 }`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation.condition.percentile must be between 0 and 100, found -1"),
		},
		{
			Name:  "Percentile Correlation At 0",
			Input: correlationRule(`type: value_percentile, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", percentile: 0, gt: 5 }`),
		},
		{
			Name:  "Percentile Correlation At 100",
			Input: correlationRule(`type: value_percentile, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { field: "bytes", percentile: 100, gt: 5 }`),
		},
		{
			Name:  "Temporal Correlation Requiring Some Of Its Rules",
			Input: correlationRule(`type: temporal, rules: ["rule1", "rule2", "rule3"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 }`, "rule1", "rule2", "rule3"),
		},
		{
			Name:          "Temporal Correlation Condition Naming A Field",
			Input:         correlationRule(`type: temporal, rules: ["rule1", "rule2"], group-by: ["field1"], timespan: "30s", condition: { field: "user.name", gte: 2 }`, "rule1", "rule2"),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: a temporal correlation counts matching rules, so its condition cannot name a field"),
		},
		{
			Name:  "Temporal Correlation Needs No Condition",
			Input: correlationRule(`type: temporal, rules: ["rule1", "rule2"], group-by: ["field1"], timespan: "30s"`, "rule1", "rule2"),
		},
		{
			Name:          "Temporal Correlation With Only One Rule",
			Input:         correlationRule(`type: temporal, rules: ["rule1"], group-by: ["field1"], timespan: "30s"`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: a temporal correlation must reference at least 2 rules, found 1"),
		},
		{
			Name:          "Correlation Type Unsupported By The ESQL Backend",
			Input:         correlationRule(`type: temporal_ordered, rules: ["rule1"], group-by: ["field1"], timespan: "30s"`),
			ExpectedError: util.Ptr(`ERROR_RULE_INVALID__CORRELATION: unsupported correlation type "temporal_ordered"; supported types are: event_count, value_count, temporal, value_sum, value_avg, value_percentile, value_median`),
			ExpectedCode:  errRuleInvalidCorrelation,
		},
		{
			Name:          "Correlation With An Unparseable Timespan",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30 minutes", condition: { gte: 2 }`),
			ExpectedError: util.Ptr(`ERROR_RULE_INVALID__CORRELATION: invalid timespan "30 minutes": expected a positive count followed by s, m, h, d or w (e.g. 15m)`),
		},
		{
			Name:          "Correlation With A Timespan Too Long For A Duration",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "99999999999w", condition: { gte: 2 }`),
			ExpectedError: util.Ptr(`ERROR_RULE_INVALID__CORRELATION: invalid timespan "99999999999w": too long`),
		},
		{
			Name: "Correlation Referencing A Rule By Its ID",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["abc-123"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}
---
{ id: "abc-123", title: "t1", logsource: { category: "test" }, detection: { condition: "sel" }}`,
		},
		{
			Name: "Correlation Chained Onto Another Correlation",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["inner"], group-by: ["field1"], timespan: "1h", condition: { gte: 2 } }}
---
{ name: "inner", title: "t1", correlation: { type: event_count, rules: ["base"], group-by: ["field1"], timespan: "10m", condition: { gte: 5 } }}
---
{ name: "base", title: "t2", logsource: { category: "test" }, detection: { condition: "sel" }}`,
			ExpectedError: util.Ptr(`ERROR_RULE_INVALID__CORRELATION: referenced rule "inner" is itself a correlation, which is not supported; refer to the rules it correlates directly`),
			ExpectedCode:  errRuleInvalidCorrelation,
		},
		{
			Name: "Correlation Referencing A Rule That Is Not Present",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["missing_rule"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}
---
{ name: "other_rule", title: "t1", logsource: { category: "test" }, detection: { condition: "sel" }}`,
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation references 1 rule(s) not defined in this detection: missing_rule; " +
				"add each referenced rule as an additional YAML document (separated by ---) with a matching id or name"),
		},
		{
			Name: "Correlation With A Document It Does Not Use",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}
---
{ name: "rule1", title: "t1", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ name: "leftover", title: "t2", logsource: { category: "test" }, detection: { condition: "sel" }}`,
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: document 3 is not used by the correlation; list its id or name in correlation.rules or remove it"),
		},
		{
			Name: "Referenced Rule Missing Its Detection",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}
---
{ name: "rule1", title: "t1", logsource: { category: "test" }}`,
			ExpectedError: util.Ptr(`ERROR_RULE_INVALID__CORRELATION: referenced rule "rule1" is invalid: missing required fields: detection.condition`),
		},
		{
			Name:          "Correlation That Also Generates Its Referenced Rules",
			Input:         correlationRule(`type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "10m", condition: { gte: 2 }, generate: true`),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation.generate is not supported; to alert on a referenced rule by itself as well, add it as its own detection"),
		},
		{
			Name:          "Correlation With Aliases",
			Input:         correlationRule(`type: temporal, rules: ["rule1", "rule2"], group-by: ["host"], timespan: "10m", aliases: { host: { rule1: source.ip, rule2: client.ip } }`, "rule1", "rule2"),
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: correlation.aliases is not supported; give the referenced rules the same field name instead"),
		},
		{
			Name: "Referenced Rule With Neither ID Nor Name",
			Input: `{ id: "x", title: "title", correlation: { type: event_count, rules: ["rule1"], group-by: ["field1"], timespan: "30s", condition: { gte: 2 } }}
---
{ name: "rule1", title: "t1", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "orphan", logsource: { category: "test" }, detection: { condition: "sel" }}`,
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__CORRELATION: document 3 is invalid: missing required fields: id or name"),
		},
		{
			Name: "Plain Rule May Not Carry Extra Documents",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ id: "y", title: "title2", logsource: { category: "test" }, detection: { condition: "sel" }}`,
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__EXTRA_DOCUMENT: document 2 is not a Sigma filter for this rule; a plain rule may only be followed by filters that name it"),
		},
		{
			Name: "Plain Rule Followed By A Filter Naming It",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "f", logsource: { category: "test" }, filter: { rules: ["x"], admin: { host: "a" }, condition: "not admin" }}`,
		},
		{
			Name: "Plain Rule Followed By A Filter For Any Rule",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "f", logsource: { category: "test" }, filter: { rules: "any", admin: { host: "a" }, condition: "not admin" }}`,
		},
		{
			Name: "Plain Rule Followed By A Filter With An Empty Rule List",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "f", logsource: { category: "test" }, filter: { rules: [], admin: { host: "a" }, condition: "not admin" }}`,
		},
		{
			Name: "Plain Rule Followed By A Filter Naming It By Name",
			Input: `{ id: "x", name: "base", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "f", logsource: { category: "test" }, filter: { rules: ["base"], admin: { host: "a" }, condition: "not admin" }}`,
		},
		{
			Name: "Plain Rule Followed By A Filter For Another Rule",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "f", logsource: { category: "test" }, filter: { rules: ["y"], admin: { host: "a" }, condition: "not admin" }}`,
			ExpectedError: util.Ptr("ERROR_RULE_INVALID__EXTRA_DOCUMENT: document 2 is not a Sigma filter for this rule; a plain rule may only be followed by filters that name it"),
			ExpectedCode:  errRuleInvalidExtraDocument,
		},
		{
			Name: "Plain Rule With Leading And Trailing Separators",
			Input: `---
{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
# only a comment
---
`,
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseElastAlertRuleCollection([]byte(test.Input))
			if test.ExpectedError == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, *test.ExpectedError)
			}

			if test.ExpectedCode != nil {
				assert.ErrorIs(t, err, test.ExpectedCode)
			}
		})
	}
}

func TestParseElastAlertRuleReadsStoredRules(t *testing.T) {
	t.Parallel()

	// accepted before stricter validation; still rejected as new content
	table := []struct {
		Name  string
		Input string
	}{
		{
			Name: "Extra Document",
			Input: `{ id: "x", title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}
---
{ title: "other", logsource: { category: "test" }, detection: { condition: "sel" }}`,
		},
		{
			Name:  "Missing Referenced Rule",
			Input: correlationRule(`type: event_count, rules: ["missing"], group-by: ["field1"], timespan: "10m", condition: { gte: 2 }`),
		},
		{
			Name:  "Unsupported Correlation Type",
			Input: correlationRule(`type: nonsense, rules: ["rule1"], group-by: ["field1"], timespan: "30s"`),
		},
	}

	for _, test := range table {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rule, err := ParseElastAlertRule([]byte(test.Input))
			require.NoError(t, err)
			assert.Equal(t, "x", *rule.ID)

			_, err = ParseElastAlertRuleCollection([]byte(test.Input))
			assert.Error(t, err)
		})
	}

	_, err := ParseElastAlertRule([]byte(`{ title: "title", logsource: { category: "test" }, detection: { condition: "sel" }}`))
	assert.EqualError(t, err, "missing required fields: id")
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
		{
			name: "correlation",
			rule: &SigmaRule{
				Title:       "Correlated",
				ID:          util.Ptr("x"),
				Correlation: &SigmaCorrelation{Type: "value_count"},
			},
			ruleset: "test-ruleset",
			license: "test-license",
			expected: &model.Detection{
				Title:    "Correlated",
				PublicID: "x",
				Author:   "unknown",
				Engine:   model.EngineNameElastAlert,
				Severity: model.SeverityUnknown,
				Language: model.SigLangSigma,
				Ruleset:  "test-ruleset",
				License:  "test-license",
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

// correlationRule wraps a correlation section with the referenced rules it names.
func correlationRule(correlation string, refs ...string) string {
	if len(refs) == 0 {
		refs = []string{"rule1"}
	}

	rule := `{ id: "x", title: "title", correlation: { ` + correlation + ` }}`
	for _, ref := range refs {
		rule += "\n---\n" + `{ name: "` + ref + `", title: "t1", logsource: { category: "test" }, detection: { condition: "sel" }}`
	}

	return rule
}

var testCustomFilters = []*model.Override{
	{
		Type:      model.OverrideTypeCustomFilter,
		IsEnabled: true,
		OverrideParameters: model.OverrideParameters{
			CustomFilter: util.Ptr("sofilter_hosts:\n  source.ip: 10.0.0.1"),
		},
	},
}

const testTwoRuleCorrelationContent = `title: Correlated
id: 11111111-1111-1111-1111-111111111111
correlation:
    type: temporal
    rules:
        - rule_a
        - rule_b
    group-by:
        - source.ip
    timespan: 10m
---
title: A
name: rule_a
logsource:
    category: network
    service: dns
detection:
    selection:
        dns.query.name|exists: true
    condition: selection
---
title: B
name: rule_b
logsource:
    category: network
    service: ssl
detection:
    selection:
        ssl.server_name|exists: true
    condition: selection
`

func TestDuplicateContentPreservesEveryDocument(t *testing.T) {
	t.Parallel()

	content := "# a leading comment\n" + testTwoRuleCorrelationContent

	duplicated, err := duplicateContent(content, "22222222-2222-2222-2222-222222222222", "Correlated (copy)")
	require.NoError(t, err)

	collection, err := ParseElastAlertRuleCollection([]byte(duplicated))
	require.NoError(t, err)
	require.Len(t, collection.Referenced, 2)

	// only the first document gets the new id and title
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", *collection.Primary.ID)
	assert.Equal(t, "Correlated (copy)", collection.Primary.Title)
	assert.NotContains(t, duplicated, "11111111-1111-1111-1111-111111111111")
	assert.Nil(t, collection.Referenced[0].ID)
	assert.Equal(t, "A", collection.Referenced[0].Title)
	assert.Equal(t, "rule_b", *collection.Referenced[1].Name)
	assert.Contains(t, duplicated, "a leading comment")
}

func TestDuplicateContent(t *testing.T) {
	t.Parallel()

	duplicated, err := duplicateContent("logsource:\n    category: test\n", "22222222-2222-2222-2222-222222222222", "Copy")
	require.NoError(t, err)
	assert.Equal(t, "logsource:\n    category: test\nid: 22222222-2222-2222-2222-222222222222\ntitle: Copy\n", duplicated)

	_, err = duplicateContent("", "id", "title")
	assert.EqualError(t, err, "no Sigma rule documents found to duplicate")

	_, err = duplicateContent("not: [valid", "id", "title")
	assert.Error(t, err)
}

func TestApplyCustomFiltersToCorrelation(t *testing.T) {
	t.Parallel()

	filtered, err := applyCustomFilters(testTwoRuleCorrelationContent, testCustomFilters)
	require.NoError(t, err)

	// The filter reaches every referenced rule, not just the first.
	assert.Equal(t, 2, strings.Count(filtered, "and not 1 of sofilter*"))
	assert.Equal(t, 2, strings.Count(filtered, "sofilter_hosts"))

	collection, err := ParseElastAlertRuleCollection([]byte(filtered))
	require.NoError(t, err)
	assert.True(t, collection.IsCorrelation())
	assert.Len(t, collection.Referenced, 2)
}

func TestApplyCustomFiltersErrors(t *testing.T) {
	t.Parallel()

	_, err := applyCustomFilters("not: [valid", testCustomFilters)
	assert.ErrorContains(t, err, "unable to unmarshal sigma rule")

	_, err = applyCustomFilters(`{ title: c, correlation: { type: event_count } }`, testCustomFilters)
	assert.EqualError(t, err, "sigma rule does not contain a detection section")
}
