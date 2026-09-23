// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAlertTriageUpdate() *AlertTriageUpdate {
	return &AlertTriageUpdate{
		Query:     `rule.name:"Foo"`,
		Ceiling:   time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC),
		RunId:     "run-1",
		SessionId: "session-1",
	}
}

func TestAlertTriageUnprocessedQuery(t *testing.T) {
	base := "tags:alert AND NOT event.acknowledged:true AND NOT _exists_:event.triage.session_id"
	capped := base + " AND NOT event.triage.failed_count:>=3"

	query, err := BuildAlertTriageUnprocessedQuery("", 0)
	require.NoError(t, err)
	assert.Equal(t, base, query)

	query, err = BuildAlertTriageUnprocessedQuery("   ", 3)
	require.NoError(t, err)
	assert.Equal(t, capped, query)

	query, err = BuildAlertTriageUnprocessedQuery(`message:"a|b"`, 3)
	require.NoError(t, err)
	assert.Equal(t, "("+capped+`) AND (message:"a|b")`, query)

	query, err = BuildAlertTriageUnprocessedQuery("event.module:suricata | groupby rule.name", 3)
	assert.EqualError(t, err, "alert triage query must be search-only")
	assert.Empty(t, query)

	query, err = BuildAlertTriageUnprocessedQuery(`event.module:suricata OR rule.name:"Foo"`, 3)
	require.NoError(t, err)
	assert.Equal(t, "("+capped+`) AND (event.module:suricata OR rule.name:"Foo")`, query)

	parsed := NewQuery()
	require.NoError(t, parsed.Parse(query+" | groupby rule.name"))
	search := parsed.NamedSegment(SegmentKind_Search).(*SearchSegment)
	assert.Contains(t, search.String(), "NOT event.triage.failed_count:>=3")
	assert.Len(t, search.Terms(), 3)
	assert.NotNil(t, parsed.NamedSegment(SegmentKind_GroupBy))
}

func TestAlertTriageRunQuery(t *testing.T) {
	assert.Equal(t, `event.triage.automation_run_ids:"run-1"`, BuildAlertTriageQuery("run-1"))
	assert.Equal(t, `event.triage.automation_run_ids:"x\" OR *"`, BuildAlertTriageQuery(`x" OR *`))
}

func TestAlertTriageDateRange(t *testing.T) {
	ceiling := time.Date(2026, 9, 22, 14, 3, 11, 0, time.UTC)

	assert.Equal(t, "1970-01-01T00:00:00Z - 2026-09-22T14:03:11Z", AlertTriageDateRange(time.Time{}, ceiling))

	floor := time.Date(2026, 9, 1, 8, 30, 0, 0, time.FixedZone("CST", -6*3600))
	dateRange := AlertTriageDateRange(floor, ceiling)
	assert.Equal(t, "2026-09-01T14:30:00Z - 2026-09-22T14:03:11Z", dateRange)

	begin, end, err := util.ParseDateRange(dateRange, time.RFC3339, "")
	require.NoError(t, err)
	assert.True(t, begin.Equal(floor))
	assert.True(t, end.Equal(ceiling))
}

func TestAlertTriageUpdateValidate(t *testing.T) {
	assert.NoError(t, validAlertTriageUpdate().Validate())

	failed := validAlertTriageUpdate()
	failed.Failed = true
	assert.NoError(t, failed.Validate())

	quotedPipe := validAlertTriageUpdate()
	quotedPipe.Query = `message:"a|b"`
	assert.NoError(t, quotedPipe.Validate())

	tests := []struct {
		name   string
		mutate func(update *AlertTriageUpdate)
	}{
		{"empty query", func(u *AlertTriageUpdate) { u.Query = " " }},
		{"unparseable query", func(u *AlertTriageUpdate) { u.Query = `rule.name:"Foo` }},
		{"query with groupby", func(u *AlertTriageUpdate) { u.Query = `rule.name:"Foo" | groupby rule.name` }},
		{"missing ceiling", func(u *AlertTriageUpdate) { u.Ceiling = time.Time{} }},
		{"floor after ceiling", func(u *AlertTriageUpdate) { u.Floor = u.Ceiling.Add(time.Second) }},
		{"missing run id", func(u *AlertTriageUpdate) { u.RunId = "" }},
		{"missing session id", func(u *AlertTriageUpdate) { u.SessionId = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			update := validAlertTriageUpdate()
			tt.mutate(update)
			assert.Error(t, update.Validate())
		})
	}
}
