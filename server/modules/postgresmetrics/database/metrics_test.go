// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestMetricConfigs_LogstashEps(t *testing.T) {
	config, ok := MetricConfigs["logstash_eps"]
	assert.True(t, ok, "logstash_eps metric config should exist")
	assert.Equal(t, "metricsLogstashEps", config.TitleKey)
	assert.Equal(t, []string{"metricsEventsReceived"}, config.LabelKeys)
	assert.Equal(t, []string{"logstash_eps"}, config.Keys)
	assert.Empty(t, config.Tables)
	assert.Empty(t, config.Fields)
	assert.Zero(t, config.Factor)
	assert.Empty(t, config.Aggregate)
	assert.NotNil(t, config.CustomHandler)

	var capturedSql string
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			capturedSql = sql
			return &MockRows{}, nil
		},
	}
	_, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", "logstash_eps", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Contains(t, capturedSql, "telegraf.logstash_events")
	assert.Contains(t, capturedSql, "m.fields->>'in'")
	assert.Contains(t, capturedSql, "tag.tags->>'pipeline'")
	assert.NotContains(t, capturedSql, "LEAST")
}

func TestMetricConfigs_Eps(t *testing.T) {
	assert.Equal(t, "AVG", MetricConfigs["eps"].Aggregate)
}

func TestMetricConfigs_LossFactors(t *testing.T) {
	assert.Equal(t, 100.0, MetricConfigs["loss"].Factor)
	assert.Equal(t, 1.0, MetricConfigs["capture_loss"].Factor)
}

func TestMetricConfigs_ElasticsearchDocs(t *testing.T) {
	config, ok := MetricConfigs["elasticsearch_docs"]
	assert.True(t, ok, "elasticsearch_docs metric config should exist")
	assert.Equal(t, "metricsElasticsearchDocs", config.TitleKey)
	assert.Equal(t, []string{"metricsDocsCount"}, config.LabelKeys)
	assert.Equal(t, "AVG", config.Aggregate)
}

func TestMetricConfigs_ElasticsearchSize(t *testing.T) {
	config, ok := MetricConfigs["elasticsearch_size"]
	assert.True(t, ok, "elasticsearch_size metric config should exist")
	assert.Equal(t, "metricsElasticsearchSize", config.TitleKey)
	assert.Equal(t, []string{"metricsStorageSize"}, config.LabelKeys)
	assert.Equal(t, "AVG", config.Aggregate)
}

func TestMetricConfigs_TagRateHandlerNamesAreValid(t *testing.T) {
	found := 0
	for metric, config := range MetricConfigs {
		if config.CustomHandler == nil {
			continue
		}
		fnName := runtime.FuncForPC(reflect.ValueOf(config.CustomHandler).Pointer()).Name()
		if !strings.Contains(fnName, ".tagRateHandler.") {
			continue
		}
		found++

		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return &MockRows{}, nil
			},
		}
		_, err := config.CustomHandler(context.Background(), New(mockDb), "node1", "", singleNodeHostFilter, "$2", "$3",
			[]interface{}{60, time.Now().Add(-time.Hour), time.Now(), "node1"})
		assert.NoError(t, err, "metric %s has an invalid identifier", metric)
	}
	assert.Positive(t, found, "expected at least one tagRateHandler metric config")
}
