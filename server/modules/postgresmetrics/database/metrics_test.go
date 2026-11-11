// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
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

func TestMetricConfigs_EpsAverages(t *testing.T) {
	config, ok := MetricConfigs["eps"]
	assert.True(t, ok, "eps metric config should exist")
	assert.Equal(t, "AVG", config.Aggregate)
}

func TestMetricConfigs_LossScalesFractionToPercent(t *testing.T) {
	config, ok := MetricConfigs["loss"]
	assert.True(t, ok, "loss metric config should exist")
	assert.Equal(t, 100.0, config.Factor)
	assert.Equal(t, "percent", config.Units)
	assert.Equal(t, 1.0, MetricConfigs["capture_loss"].Factor)

	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			return &MockRows{
				rows: [][]interface{}{
					{time.Now(), 0.025},
				},
			}, nil
		},
	}
	s := New(mockDb)
	res, err := s.GetTimeSeriesMetrics(context.Background(), "node1", "", "loss", time.Now().Add(-1*time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Len(t, res["suricata_loss"], 1)
	assert.InDelta(t, 0.025*100.0, res["suricata_loss"][0].Value, 0.000001)
	assert.InDelta(t, 0.025*100.0, res["zeek_loss"][0].Value, 0.000001)
}
