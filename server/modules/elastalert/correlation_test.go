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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			Query:   esqlCorrelationQuery("source.ip", "host.name"),
			Contains: []string{
				"buffer_time:\n    seconds: 1380",
				"query_key:\n    - source.ip\n    - host.name\n",
				"realert:\n    seconds: 1380",
				"timestamp_field: event.ingested",
				"query_delay:\n    seconds: 30",
				"timeframe:\n    seconds: 1380",
				"scan_entire_timeframe: true",
				"sigma_correlation: value_count",
			},
		},
		{
			Name: "Timespan Shorter Than The Run Interval Deploys",
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
			Query:    esqlCorrelationQuery("source.ip"),
			Contains: []string{"buffer_time:\n    seconds: 810", "realert:\n    seconds: 810"},
		},
		{
			Name: "Hour Timespan",
			Content: `title: Sustained
id: 44444444-4444-4444-4444-444444444444
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - source.ip
    timespan: 1h
    condition:
        gte: 50
---
title: Base
name: base_rule
logsource:
    category: network
    service: ssl
detection:
    selection:
        ssl.server_name|exists: true
    condition: selection
`,
			Query: esqlCorrelationQuery("source.ip"),
			Contains: []string{
				"buffer_time:\n    seconds: 4380",
				"query_key:\n    - source.ip\n",
				"realert:\n    seconds: 4380",
				"timeframe:\n    seconds: 4380",
				"scan_entire_timeframe: true",
				"sigma_correlation: event_count",
			},
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
			Query: "<query>",
			Contains: []string{
				"realert:\n    seconds: 0",
				"timestamp_field: event.ingested",
				"query_delay:\n    seconds: 30",
			},
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

	engine := &ElastAlertEngine{}

	_, err := engine.ValidateRule(testCorrelationContent)
	assert.ErrorIs(t, err, errCorrelationNeedsEsql)

	// rejected before sigma-cli runs, so no EQL query is deployed
	_, err = engine.sigmaToElastAlert(context.Background(), &model.Detection{Content: testCorrelationContent})
	assert.ErrorIs(t, err, errCorrelationNeedsEsql)

	_, err = engine.ValidateRule(SimpleRule)
	assert.NoError(t, err)
}

func TestWrapRuleQueryKeyFromQueryColumns(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{useEsql: true, elastAlertRunEvery: 3 * time.Minute}

	// ecs_windows maps SubjectUserName to user.name and IpAddress to source.ip in the query.
	content := strings.Replace(testCorrelationContent, "        - source.ip\n        - host.name\n",
		"        - SubjectUserName\n        - IpAddress\n", 1)
	det := &model.Detection{
		PublicID: "11111111-1111-1111-1111-111111111111",
		Title:    "Many Distinct Names",
		Severity: model.SeverityMedium,
		Content:  content,
	}

	wrapped, err := engine.wrapRule(det, esqlCorrelationQuery("user.name", "source.ip"))
	require.NoError(t, err)
	assert.Contains(t, wrapped, "query_key:\n    - user.name\n    - source.ip\n")

	// the rule's own names may not be columns, so keying on them could merge groups
	_, err = engine.wrapRule(det, "from .ds-logs-* | where true")
	assert.EqualError(t, err, "unable to read the group-by columns [SubjectUserName IpAddress] from the converted query")
}

func TestEsqlGroupColumns(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"host.name", "process.entity_id"},
		esqlGroupColumns("| stats n=count() by w, host.name, process.entity_id\n| stats n=max(n) by host.name, process.entity_id\n| where @timestamp is not null"))
	assert.Equal(t, []string{"source.ip"}, esqlGroupColumns("| stats event_type_count=count_distinct(event_type) by source.ip\n"))
	assert.Equal(t, []string{"http.request.headers.x-real-ip"},
		esqlGroupColumns("| stats value_count=count_distinct(user.name) by `http.request.headers.x-real-ip`\n"))
	assert.Nil(t, esqlGroupColumns("from .ds-logs-* | where true"))
}

func TestValidateRuleShortCorrelation(t *testing.T) {
	t.Parallel()

	engine := &ElastAlertEngine{useEsql: true}

	_, err := engine.ValidateRule(strings.Replace(testCorrelationContent, "timespan: 10m", "timespan: 30s", 1))
	assert.NoError(t, err)
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

	wrapped, err := engine.wrapRule(det, esqlCorrelationQuery("source.ip", "host.name"))
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

// esqlCorrelationQuery is shaped like the backend's window correlation, grouped by the given columns.
func esqlCorrelationQuery(groups ...string) string {
	by := strings.Join(groups, ", ")

	return `from .ds-logs-* metadata _id, _index, _source | where dns.query.name is not null
| where ` + strings.Join(groups, " is not null and ") + ` is not null
| where @timestamp is not null
| eval w = mv_dedupe(mv_append(mv_append(date_trunc(10minutes, @timestamp), date_trunc(10minutes, @timestamp - 150 seconds) + 150 seconds), mv_append(date_trunc(10minutes, @timestamp - 300 seconds) + 300 seconds, date_trunc(10minutes, @timestamp - 450 seconds) + 450 seconds)))
| mv_expand w
| stats event_count=count(), window_start=min(@timestamp), @timestamp=max(@timestamp), event.ingested=max(event.ingested) by w, ` + by + `
| where event_count >= 5
| stats event_count=max(event_count), window_start=min(window_start), @timestamp=max(@timestamp), event.ingested=max(event.ingested) by ` + by + `
| where @timestamp is not null`
}
