// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapRuleSchedule(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{
		useEsql:                  true,
		elastAlertRunEvery:       3 * time.Minute,
		esqlQueryDelay:           30 * time.Second,
		esqlCorrelationAllowance: 10 * time.Minute,
	}

	table := []struct {
		Name        string
		Content     string
		Query       string
		Contains    []string
		NotContains []string
	}{
		{
			Name:    "Window Spans The Timespan, The Last Run And The Allowance",
			Content: testCorrelationContent,
			Query:   esqlCorrelationOutput("source.ip", "host.name"),
			Contains: []string{
				"buffer_time:\n    seconds: 1380",
				"query_key:\n    - source.ip\n    - host.name\n",
				"realert:\n    seconds: 1380",
				"timeframe:\n    seconds: 1380",
				"scan_entire_timeframe: true",
				"sigma_correlation: value_count",
			},
		},
		{
			Name: "Window Follows The Timespan",
			Content: `title: Short Burst
id: 33333333-3333-3333-3333-333333333333
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - source.ip
    timespan: 30s
    condition:
        gte: 3
---
title: Base
name: base_rule
logsource:
    category: network
    service: dns
detection:
    selection:
        dns.query.name|exists: true
    condition: selection
`,
			Query:    esqlCorrelationOutput("source.ip"),
			Contains: []string{"buffer_time:\n    seconds: 810", "realert:\n    seconds: 810"},
		},
		{
			Name: "Plain Rule Keeps The Grid Schedule",
			Content: `title: Plain
id: 22222222-2222-2222-2222-222222222222
logsource:
    category: network
    service: dns
detection:
    selection:
        dns.query.name|exists: true
    condition: selection
`,
			Query:       "<query>",
			Contains:    []string{"realert:\n    seconds: 0"},
			NotContains: []string{"buffer_time:", "query_key:", "timeframe:", "scan_entire_timeframe:", "sigma_correlation:"},
		},
	}

	for _, test := range table {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			det := &model.Detection{
				PublicID: "11111111-1111-1111-1111-111111111111",
				Title:    "Test",
				Severity: model.SeverityMedium,
				Content:  test.Content,
			}

			wrapped, err := engine.wrapRule(det, test.Query)
			require.NoError(t, err)

			for _, expected := range test.Contains {
				assert.Contains(t, wrapped, expected)
			}
			for _, unexpected := range test.NotContains {
				assert.NotContains(t, wrapped, unexpected)
			}
		})
	}
}

func TestCorrelationRequiresEsql(t *testing.T) {
	t.Parallel()

	// no expectations: neither validation nor conversion may run sigma-cli
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	engine := &ElastAlertEngine{IOManager: iom}

	_, err := engine.ValidateRule(testCorrelationContent)
	assert.ErrorIs(t, err, errCorrelationNeedsEsql)

	_, err = engine.sigmaToElastAlert(context.Background(), &model.Detection{Content: testCorrelationContent})
	assert.ErrorIs(t, err, errCorrelationNeedsEsql)

	_, err = engine.ValidateRule(SimpleRule)
	assert.NoError(t, err)

	engine.useEsql = true

	_, err = engine.ValidateRule(testCorrelationContent)
	assert.NoError(t, err)
}

func TestConvertRulePreviewsOnlyTheQuery(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name     string
		Content  string
		Output   string
		Expected string
	}{
		{
			Name:     "Correlation",
			Content:  testCorrelationContent,
			Output:   esqlCorrelationOutput("source.ip", "host.name"),
			Expected: "from .ds-logs-*\n| stats event_count=count() by w, source.ip, host.name\n| stats event_count=max(event_count) by source.ip, host.name",
		},
		{
			Name:     "Plain Rule",
			Content:  SimpleRule,
			Output:   "from .ds-logs-* | where true",
			Expected: "from .ds-logs-* | where true",
		},
	}

	for _, test := range table {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iom := mock.NewMockIOManager(ctrl)
			iom.EXPECT().ExecCommand(gomock.Any()).Return([]byte("Parsing Sigma rules\n"+test.Output), 0, time.Duration(0), nil)

			engine := &ElastAlertEngine{IOManager: iom, useEsql: true}

			query, err := engine.ConvertRule(context.Background(), &model.Detection{Content: test.Content})
			require.NoError(t, err)
			assert.Equal(t, test.Expected, query)
		})
	}
}

func TestSigmaCliError(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "bad condition", sigmaCliError([]byte("Parsing Sigma rules\nError: Error while converting: bad condition in /dev/stdin\n")))
	assert.Equal(t, "The pipeline 'x' was not found.", sigmaCliError([]byte("Usage: sigma convert\n\nError: The pipeline 'x' was not found.\nList all installed processing pipelines with: ...")))
	// a traceback ends with the exception
	assert.Equal(t, "AttributeError: 'int' object has no attribute 'replace'", sigmaCliError([]byte("Traceback (most recent call last):\n  File \"x.py\"\nAttributeError: 'int' object has no attribute 'replace'")))
	assert.Equal(t, "second", sigmaCliError([]byte("Error: first\nError: second\n")))
	assert.Equal(t, "last line", sigmaCliError([]byte("Error: \nlast line")))
	assert.Empty(t, sigmaCliError(nil))
}

func TestParseRepoRulesSkipsCorrelationsWithoutEsql(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name     string
		UseEsql  bool
		Expected int
	}{
		{Name: "Without ES|QL", UseEsql: false, Expected: 0},
		{Name: "With ES|QL", UseEsql: true, Expected: 1},
	}

	for _, test := range table {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iom := mock.NewMockIOManager(ctrl)
			iom.EXPECT().WalkDir("repo", gomock.Any()).DoAndReturn(func(path string, fn fs.WalkDirFunc) error {
				return fn("repo/correlation.yml", &handmock.MockDirEntry{Filename: "correlation.yml"}, nil)
			})
			iom.EXPECT().ReadFile("repo/correlation.yml").Return([]byte(testCorrelationContent), nil)

			engine := &ElastAlertEngine{isRunning: true, useEsql: test.UseEsql, IOManager: iom}

			dets, errMap := engine.parseRepoRules([]*detections.RepoOnDisk{{Repo: &model.Repo{}, Path: "repo"}})
			assert.Empty(t, errMap)
			assert.Len(t, dets, test.Expected)
		})
	}
}

func TestWrapRuleInvalidStoredContent(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{useEsql: true, elastAlertRunEvery: 3 * time.Minute}

	// stored before stricter validation
	det := &model.Detection{
		PublicID: "11111111-1111-1111-1111-111111111111",
		Content:  strings.Replace(testCorrelationContent, "    group-by:\n        - source.ip\n        - host.name\n", "", 1),
	}
	require.NotEqual(t, testCorrelationContent, det.Content)

	_, err := engine.wrapRule(det, esqlCorrelationOutput("source.ip", "host.name"))
	assert.EqualError(t, err, "invalid correlation: missing required fields: correlation.group-by")

	// even the lenient parse fails
	det.Content = strings.Replace(testCorrelationContent, "id: "+det.PublicID+"\n", "", 1)
	require.NotEqual(t, testCorrelationContent, det.Content)

	_, err = engine.wrapRule(det, esqlCorrelationOutput("source.ip", "host.name"))
	assert.EqualError(t, err, "unable to parse correlation rule: missing required fields: id")

	// a plain rule that fails the primary-document check still deploys, as before
	det.Content = strings.Replace(SimpleRule, "id: "+SimpleRuleSID+"\n", "", 1)
	require.NotEqual(t, SimpleRule, det.Content)

	_, err = engine.wrapRule(det, "<query>")
	assert.NoError(t, err)
}

func TestWrapRuleQueryFromPipelineOutput(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{useEsql: true, elastAlertRunEvery: 3 * time.Minute}

	// ecs_windows maps SubjectUserName to user.name and IpAddress to source.ip
	content := strings.Replace(testCorrelationContent, "        - source.ip\n        - host.name\n",
		"        - SubjectUserName\n        - IpAddress\n", 1)
	det := &model.Detection{
		PublicID: "11111111-1111-1111-1111-111111111111",
		Title:    "Many Distinct Names",
		Severity: model.SeverityMedium,
		Content:  content,
	}

	wrapped, err := engine.wrapRule(det, esqlCorrelationOutput("user.name", "source.ip"))
	require.NoError(t, err)
	assert.Contains(t, wrapped, "query_key:\n    - user.name\n    - source.ip\n")
	assert.Contains(t, wrapped, "esql: |-\n        from .ds-logs-*")
	assert.NotContains(t, wrapped, "group_by")

	// no fallback to the rule's own names, which could merge groups
	_, err = engine.wrapRule(det, "from .ds-logs-* | where true")
	assert.EqualError(t, err, "the converted correlation lacks its group-by columns; check the ES|QL sigma pipeline")
}

func TestWrapRuleSummaryTemplate(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{useEsql: true, elastAlertRunEvery: 3 * time.Minute}

	det := &model.Detection{
		PublicID: "11111111-1111-1111-1111-111111111111",
		Title:    "Many Distinct Names",
		Severity: model.SeverityMedium,
		Content:  strings.Replace(testCorrelationContent, "level: medium", "summary: '%count% names for %source.ip% in %duration%'\nlevel: medium", 1),
	}

	wrapped, err := engine.wrapRule(det, esqlCorrelationOutput("source.ip", "host.name"))
	require.NoError(t, err)
	assert.Contains(t, wrapped, "summary_template: '%count% names for %source.ip% in %duration%'")

	det.Content = `title: Plain
id: 22222222-2222-2222-2222-222222222222
summary: 'ignored without a correlation'
logsource:
    category: network
detection:
    selection:
        dns.query.name|exists: true
    condition: selection
`
	wrapped, err = engine.wrapRule(det, "<query>")
	require.NoError(t, err)
	assert.NotContains(t, wrapped, "summary_template")
}

// esqlCorrelationOutput is a converted correlation as sigma_esql_pipeline.yml emits it.
func esqlCorrelationOutput(groups ...string) string {
	by := strings.Join(groups, ", ")
	query := "from .ds-logs-*\n| stats event_count=count() by w, " + by + "\n| stats event_count=max(event_count) by " + by

	output, _ := json.Marshal(correlationOutput{Query: query, GroupBy: groups})

	return string(output)
}

const testCorrelationContent = `title: Many Distinct Names
id: 11111111-1111-1111-1111-111111111111
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - source.ip
        - host.name
    timespan: 10m
    condition:
        field: dns.query.name
        gte: 40
level: medium
---
title: Base
name: base_rule
logsource:
    category: network
    service: dns
detection:
    selection:
        dns.query.name|exists: true
    condition: selection
`
