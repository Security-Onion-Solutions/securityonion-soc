// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAlertTriageUpdate() *AlertTriageUpdate {
	return &AlertTriageUpdate{
		Query:     `rule.name:"Foo"`,
		Floor:     time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC),
		Ceiling:   time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC),
		RunId:     "run-1",
		SessionId: "session-1",
	}
}

func TestAlertTriageUnprocessedQuery(t *testing.T) {
	base := "tags:alert AND NOT event.acknowledged:true AND NOT _exists_:event.so_alerttriage.session_id"
	capped := base + " AND NOT event.so_alerttriage.failed_count:>=3"

	// A zero cap falls back to the default rather than retrying forever.
	query, err := BuildAlertTriageUnprocessedQuery("so_", "", 0)
	require.NoError(t, err)
	assert.Equal(t, base+" AND NOT event.so_alerttriage.failed_count:>="+strconv.Itoa(DefaultAlertTriageMaxFailures), query)

	query, err = BuildAlertTriageUnprocessedQuery("so_", "", -1)
	require.NoError(t, err)
	assert.Contains(t, query, "failed_count:>="+strconv.Itoa(DefaultAlertTriageMaxFailures))

	query, err = BuildAlertTriageUnprocessedQuery("so_", "", 5)
	require.NoError(t, err)
	assert.Equal(t, base+" AND NOT event.so_alerttriage.failed_count:>=5", query)

	query, err = BuildAlertTriageUnprocessedQuery("so_", "   ", 3)
	require.NoError(t, err)
	assert.Equal(t, capped, query)

	query, err = BuildAlertTriageUnprocessedQuery("so_", `message:"a|b"`, 3)
	require.NoError(t, err)
	assert.Equal(t, "("+capped+`) AND (message:"a|b")`, query)

	query, err = BuildAlertTriageUnprocessedQuery("so_", "event.module:suricata | groupby rule.name", 3)
	assert.EqualError(t, err, "alert triage query must be search-only")
	assert.Empty(t, query)

	query, err = BuildAlertTriageUnprocessedQuery("so_", `event.module:suricata OR rule.name:"Foo"`, 3)
	require.NoError(t, err)
	assert.Equal(t, "("+capped+`) AND (event.module:suricata OR rule.name:"Foo")`, query)

	parsed := NewQuery()
	require.NoError(t, parsed.Parse(query+" | groupby rule.name"))
	search := parsed.NamedSegment(SegmentKind_Search).(*SearchSegment)
	assert.Contains(t, search.String(), "NOT event.so_alerttriage.failed_count:>=3")
	assert.Len(t, search.Terms(), 3)
	assert.NotNil(t, parsed.NamedSegment(SegmentKind_GroupBy))
}

func TestAlertTriageRunQuery(t *testing.T) {
	assert.Equal(t, `event.so_alerttriage.automation_run_ids:"run-1"`, BuildAlertTriageQuery("so_", "run-1"))
	assert.Equal(t, `event.so_alerttriage.automation_run_ids:"x\" OR *"`, BuildAlertTriageQuery("so_", `x" OR *`))
	assert.Equal(t, `event.x_alerttriage.automation_run_ids:"run-1"`, BuildAlertTriageQuery("x_", "run-1"))
}

func TestAlertTriageDateRange(t *testing.T) {
	ceiling := time.Date(2026, 9, 30, 14, 3, 11, 0, time.UTC)

	assert.Equal(t, "2026-09-01T00:00:00Z - 2026-09-30T14:03:11Z", AlertTriageDateRange(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), ceiling))

	floor := time.Date(2026, 9, 25, 8, 30, 0, 0, time.FixedZone("CST", -6*3600))
	dateRange := AlertTriageDateRange(floor, ceiling)
	assert.Equal(t, "2026-09-25T14:30:00Z - 2026-09-30T14:03:11Z", dateRange)

	begin, end, err := util.ParseDateRange(dateRange, time.RFC3339, "")
	require.NoError(t, err)
	assert.True(t, begin.Equal(floor))
	assert.True(t, end.Equal(ceiling))
}

func TestAlertTriageGroupTerms(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		keys   []any
		want   string
	}{
		{"one string", []string{"rule.name"}, []any{"ET SCAN"}, `rule.name:"ET SCAN"`},
		{"string and number", []string{"rule.name", "event.severity"}, []any{"ET SCAN", float64(3)}, `rule.name:"ET SCAN" AND event.severity:3`},
		{"fraction stays plain", []string{"score"}, []any{1.5}, `score:1.5`},
		{"large number not exponent", []string{"bytes"}, []any{float64(1234567890)}, `bytes:1234567890`},
		{"quotes and backslashes escaped", []string{"message"}, []any{`say "hi" C:\tmp`}, `message:"say \"hi\" C:\\tmp"`},
		{"spaces and pipe quoted", []string{"message"}, []any{"a | b"}, `message:"a | b"`},
		{"missing bucket", []string{"rule.name", "event.module*"}, []any{"ET SCAN", "__missing__"}, `rule.name:"ET SCAN" AND NOT _exists_:"event.module"`},
		{"bool from key_as_string", []string{"event.acknowledged"}, []any{"true"}, `event.acknowledged:"true"`},
		{"native bool", []string{"flag"}, []any{true}, `flag:true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildAlertTriageGroupTerms(tt.fields, tt.keys)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.NoError(t, ValidateAlertTriageSearch(got))
		})
	}

	_, err := BuildAlertTriageGroupTerms([]string{"a", "b"}, []any{"x"})
	assert.Error(t, err)
	_, err = BuildAlertTriageGroupTerms(nil, nil)
	assert.Error(t, err)
	_, err = BuildAlertTriageGroupTerms([]string{"a"}, []any{nil})
	assert.Error(t, err)
	_, err = BuildAlertTriageGroupTerms([]string{"a"}, []any{[]any{"x"}})
	assert.Error(t, err)
}

func TestAlertTriageUpdateValidate(t *testing.T) {
	assert.NoError(t, validAlertTriageUpdate().Validate())

	failed := validAlertTriageUpdate()
	failed.Failed = true
	failed.FailedRunIds = []string{"run-0", "run-1"}
	assert.NoError(t, failed.Validate())

	// A failed attempt may not have got as far as opening a session.
	failed.SessionId = ""
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
		{"missing floor", func(u *AlertTriageUpdate) { u.Floor = time.Time{} }},
		{"missing ceiling", func(u *AlertTriageUpdate) { u.Ceiling = time.Time{} }},
		{"floor after ceiling", func(u *AlertTriageUpdate) { u.Floor = u.Ceiling.Add(time.Second) }},
		{"missing run id", func(u *AlertTriageUpdate) { u.RunId = "" }},
		{"missing session id", func(u *AlertTriageUpdate) { u.SessionId = "" }},
		{"failed without run ids", func(u *AlertTriageUpdate) { u.Failed = true }},
		{"failed with an empty run id", func(u *AlertTriageUpdate) { u.Failed = true; u.FailedRunIds = []string{"run-0", ""} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			update := validAlertTriageUpdate()
			tt.mutate(update)
			assert.Error(t, update.Validate())
		})
	}
}
