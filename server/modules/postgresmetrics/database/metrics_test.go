// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"testing"

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
