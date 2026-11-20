// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

const singleNodeHostFilter = "(tag.tags->>'node_name' = $4 OR tag.tags->>'node_host' = $4 OR tag.tags->>'host' = $4 OR tag.tags->>'es_host' = $4)"

func runTagRate(t *testing.T, table, field, seriesTag string, factor, max float64, nodeId string, rows [][]interface{}, queryErr error) (string, []any, map[string][]model.MetricSample, error) {
	var capturedSql string
	var capturedArgs []any
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			capturedSql = sql
			capturedArgs = args
			if queryErr != nil {
				return nil, queryErr
			}
			return &MockRows{rows: rows}, nil
		},
	}
	s := New(mockDb)

	hostFilter := "1=1"
	args := []interface{}{60, time.Now().Add(-time.Hour), time.Now()}
	if nodeId != "" {
		hostFilter = singleNodeHostFilter
		args = append(args, nodeId)
	}

	handler := tagRateHandler(table, field, seriesTag, factor, max)
	res, err := handler(context.Background(), s, nodeId, "ignored", hostFilter, "$2", "$3", args)
	return capturedSql, capturedArgs, res, err
}

func TestQueryTagRateMetric_Sql(t *testing.T) {
	for _, nodeId := range []string{"node1", ""} {
		for _, seriesTag := range []string{"pipeline", "device"} {
			sql, _, _, err := runTagRate(t, "logstash_events", "in", seriesTag, 8, 0, nodeId, nil, nil)
			assert.NoError(t, err)

			assert.Contains(t, sql, "FROM telegraf.logstash_events m")
			assert.Contains(t, sql, "JOIN telegraf.logstash_events_tag tag USING (tag_id)")
			assert.Contains(t, sql, "m.fields->>'in'")
			assert.Contains(t, sql, "tag.tags->>'"+seriesTag+"' AS series")
			assert.Contains(t, sql, "tag.tags->>'"+seriesTag+"' IS NOT NULL")
			assert.Contains(t, sql, "tag.tags->>'host' AS host")
			assert.Contains(t, sql, "LAG((m.fields->>'in')::double precision) OVER w")
			assert.Contains(t, sql, "LAG(m.time) OVER w")
			assert.Contains(t, sql, "WINDOW w AS (PARTITION BY tag.tags->>'host', tag.tags->>'"+seriesTag+"' ORDER BY m.time)")

			if nodeId != "" {
				assert.Contains(t, sql, singleNodeHostFilter)
			} else {
				assert.Contains(t, sql, "WHERE 1=1 AND")
			}

			seedIdx := strings.Index(sql, "m.time >= ($2 AT TIME ZONE 'UTC') - INTERVAL '2 minutes'")
			outerIdx := strings.Index(sql, ") deltas\n\t\tWHERE time >= ($2 AT TIME ZONE 'UTC')")
			assert.Greater(t, seedIdx, 0)
			assert.Greater(t, outerIdx, seedIdx)
			assert.Equal(t, 1, strings.Count(sql, "INTERVAL '2 minutes'"))
			assert.Contains(t, sql, "m.time <= ($3 AT TIME ZONE 'UTC')")

			assert.Contains(t, sql, "WHEN delta IS NULL OR seconds IS NULL OR seconds <= 0 OR delta < 0 THEN 0.0")
			assert.Contains(t, sql, "delta / seconds * 8")
			assert.Contains(t, sql, "floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1")
			assert.Contains(t, sql, "AVG(CASE")
			assert.Contains(t, sql, "GROUP BY bucket, host, series")
			assert.NotContains(t, sql, "LEAST(")
		}
	}
}

func TestQueryTagRateMetric_Max(t *testing.T) {
	sql, _, _, err := runTagRate(t, "diskio", "read_bytes", "name", 1, 1000, "node1", nil, nil)
	assert.NoError(t, err)
	assert.Contains(t, sql, "LEAST(delta / seconds * 1, 1000)")
}

func TestQueryTagRateMetric_Args(t *testing.T) {
	_, args, _, err := runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "node1", nil, nil)
	assert.NoError(t, err)
	assert.Len(t, args, 4)
	assert.Equal(t, "node1", args[3])

	_, args, _, err = runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "", nil, nil)
	assert.NoError(t, err)
	assert.Len(t, args, 3)
}

func TestQueryTagRateMetric_Keys(t *testing.T) {
	t1 := time.Now().Add(-2 * time.Minute)
	t2 := time.Now().Add(-1 * time.Minute)

	_, _, res, err := runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "node1", [][]interface{}{
		{t2, "node1", "search", 20.0},
		{t1, "node1", "manager", 5.0},
		{t1, "node1", "search", 10.0},
	}, nil)
	assert.NoError(t, err)
	assert.Len(t, res, 2)
	assert.NotContains(t, res, "logstash_eps")
	assert.Equal(t, []model.MetricSample{{Timestamp: t1, Value: 5.0}}, res["manager"])
	assert.Equal(t, []model.MetricSample{{Timestamp: t1, Value: 10.0}, {Timestamp: t2, Value: 20.0}}, res["search"])

	_, _, res, err = runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "", [][]interface{}{
		{t1, "h1", "search", 1.0},
		{t1, "h2", "search", 2.0},
	}, nil)
	assert.NoError(t, err)
	assert.Len(t, res, 2)
	assert.Equal(t, []model.MetricSample{{Timestamp: t1, Value: 1.0}}, res["h1::search"])
	assert.Equal(t, []model.MetricSample{{Timestamp: t1, Value: 2.0}}, res["h2::search"])
}

func TestQueryTagRateMetric_EmptyAndErrors(t *testing.T) {
	_, _, res, err := runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "node1", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res)

	missing := &pgconn.PgError{Code: "42P01", Message: `relation "telegraf.logstash_events" does not exist`}
	_, _, res, err = runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "", nil, missing)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res)

	_, _, res, err = runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "", nil, errors.New("connection reset"))
	assert.EqualError(t, err, "connection reset")
	assert.Nil(t, res)
}

func TestQueryTagRateMetric_ScanErrorSkipped(t *testing.T) {
	t1 := time.Now().Add(-2 * time.Minute)

	_, _, res, err := runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "node1", [][]interface{}{
		{t1, "node1", "manager"},
		{t1, "node1", "search", 10.0},
	}, nil)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, []model.MetricSample{{Timestamp: t1, Value: 10.0}}, res["search"])
}

func TestQueryTagRateMetric_AllHostsSortedByTime(t *testing.T) {
	t1 := time.Now().Add(-3 * time.Minute)
	t2 := time.Now().Add(-2 * time.Minute)
	t3 := time.Now().Add(-1 * time.Minute)

	_, _, res, err := runTagRate(t, "logstash_events", "in", "pipeline", 1, 0, "", [][]interface{}{
		{t3, "h1", "search", 30.0},
		{t1, "h1", "search", 10.0},
		{t2, "h1", "search", 20.0},
	}, nil)
	assert.NoError(t, err)
	assert.Equal(t, []model.MetricSample{
		{Timestamp: t1, Value: 10.0},
		{Timestamp: t2, Value: 20.0},
		{Timestamp: t3, Value: 30.0},
	}, res["h1::search"])
}

func TestQueryTagRateMetric_FractionalFactorAndMax(t *testing.T) {
	sql, _, _, err := runTagRate(t, "logstash_events", "in", "pipeline", 0.125, 12.5, "node1", nil, nil)
	assert.NoError(t, err)
	assert.Contains(t, sql, "delta / seconds * 0.125")
	assert.Contains(t, sql, "LEAST(delta / seconds * 0.125, 12.5)")
	assert.NotContains(t, sql, "0.125000")
	assert.NotContains(t, sql, "12.500000")
}

func TestTagRateHandler_IgnoresContainer(t *testing.T) {
	ts := time.Now()
	run := func(container string) (string, map[string][]model.MetricSample) {
		var capturedSql string
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				capturedSql = sql
				return &MockRows{rows: [][]interface{}{{ts, "node1", "search", 3.0}}}, nil
			},
		}
		s := New(mockDb)
		res, err := tagRateHandler("logstash_events", "in", "pipeline", 1, 0)(context.Background(), s, "node1", container, singleNodeHostFilter, "$2", "$3",
			[]interface{}{60, time.Now().Add(-time.Hour), time.Now(), "node1"})
		assert.NoError(t, err)
		return capturedSql, res
	}

	sqlA, resA := run("")
	sqlB, resB := run("so-logstash")
	assert.Equal(t, sqlA, sqlB)
	assert.NotContains(t, sqlB, "so-logstash")
	assert.Equal(t, resA, resB)
	assert.Equal(t, []model.MetricSample{{Timestamp: ts, Value: 3.0}}, resB["search"])
}

func TestTagRateHandler_ValidatesNames(t *testing.T) {
	assert.Panics(t, func() { tagRateHandler("logstash_events'", "in", "pipeline", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("logstash_events", "in out", "pipeline", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("logstash_events", "in", "pipe'line", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("", "in", "pipeline", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("logstash_events", "", "pipeline", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("logstash_events", "in", "", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("Logstash_Events", "in", "pipeline", 1, 0) })
	assert.Panics(t, func() { tagRateHandler("logstash_events", "1n", "pipeline", 1, 0) })
	assert.NotPanics(t, func() { tagRateHandler("diskio", "read_bytes", "name", 1, 0) })
}
