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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
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

func TestMetricConfigs_AllHaveKeys(t *testing.T) {
	for metric, config := range MetricConfigs {
		assert.NotEmpty(t, config.Keys, "metric %s must have keys", metric)
	}
}

func TestMetricConfigs_TagRateMetrics(t *testing.T) {
	tests := []struct {
		metric    string
		titleKey  string
		units     string
		table     string
		field     string
		seriesTag string
		rate      string
		capped    bool
	}{
		{"disk_read", "metricsDiskRead", "bytes_per_second", "diskio", "read_bytes", "name", "delta / seconds * 1", false},
		{"disk_write", "metricsDiskWrite", "bytes_per_second", "diskio", "write_bytes", "name", "delta / seconds * 1", false},
		{"disk_busy", "metricsDiskBusy", "percent", "diskio", "io_time", "name", "LEAST(delta / seconds * 0.1, 100)", true},
		{"logstash_out", "metricsLogstashSent", "", "logstash_events", "out", "pipeline", "delta / seconds * 1", false},
	}

	for _, tt := range tests {
		t.Run(tt.metric, func(t *testing.T) {
			config, ok := MetricConfigs[tt.metric]
			assert.True(t, ok)
			assert.Equal(t, tt.titleKey, config.TitleKey)
			assert.Equal(t, []string{tt.metric}, config.Keys)
			assert.Equal(t, []string{tt.titleKey}, config.LabelKeys)
			assert.Equal(t, tt.units, config.Units)
			assert.Empty(t, config.Tables)
			assert.Empty(t, config.Fields)
			assert.NotNil(t, config.CustomHandler)

			var capturedSql string
			mockDb := &MockDB{
				QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
					capturedSql = sql
					return &MockRows{}, nil
				},
			}
			_, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", tt.metric, time.Now().Add(-time.Hour), time.Now())
			assert.NoError(t, err)
			assert.Contains(t, capturedSql, "telegraf."+tt.table+" m")
			assert.Contains(t, capturedSql, "telegraf."+tt.table+"_tag")
			assert.Contains(t, capturedSql, "m.fields->>'"+tt.field+"'")
			assert.Contains(t, capturedSql, "tag.tags->>'"+tt.seriesTag+"'")
			assert.Contains(t, capturedSql, tt.rate)
			if tt.capped {
				assert.Contains(t, capturedSql, "LEAST")
			} else {
				assert.NotContains(t, capturedSql, "LEAST")
			}
		})
	}
}

func TestMetricConfigs_Processes(t *testing.T) {
	config, ok := MetricConfigs["processes"]
	assert.True(t, ok)
	assert.Equal(t, "metricsProcesses", config.TitleKey)
	assert.Equal(t, []string{"processes"}, config.Tables)
	assert.Equal(t, []string{"running", "blocked", "zombies"}, config.Fields)
	assert.Equal(t, []string{"running", "blocked", "zombies"}, config.Keys)
	assert.Equal(t, []string{"stateRunning", "metricsProcBlocked", "metricsProcZombies"}, config.LabelKeys)
	assert.Equal(t, "AVG", config.Aggregate)
	assert.Equal(t, 1.0, config.Factor)
	assert.Empty(t, config.Units)
	assert.Nil(t, config.CustomHandler)
}

func TestMetricConfigs_ProcessesTotal(t *testing.T) {
	config, ok := MetricConfigs["processes_total"]
	assert.True(t, ok)
	assert.Equal(t, "metricsProcessesTotal", config.TitleKey)
	assert.Equal(t, []string{"processes"}, config.Tables)
	assert.Equal(t, []string{"total", "sleeping"}, config.Fields)
	assert.Equal(t, []string{"total", "sleeping"}, config.Keys)
	assert.Equal(t, []string{"metricsProcTotal", "metricsProcSleeping"}, config.LabelKeys)
	assert.Equal(t, "AVG", config.Aggregate)
	assert.Equal(t, 1.0, config.Factor)
	assert.Empty(t, config.Units)
	assert.Nil(t, config.CustomHandler)
}

func TestMetricConfigs_ProcessesQueriesEachField(t *testing.T) {
	var capturedSql []string
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			capturedSql = append(capturedSql, sql)
			return &MockRows{}, nil
		},
	}
	res, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", "processes", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Len(t, capturedSql, 3)
	for i, field := range []string{"running", "blocked", "zombies"} {
		assert.Contains(t, capturedSql[i], "telegraf.processes")
		assert.Contains(t, capturedSql[i], "'"+field+"'")
		assert.Contains(t, capturedSql[i], "AVG")
		assert.Contains(t, res, field)
	}
}

func TestDashboardMetricOrder_NewMetrics(t *testing.T) {
	assert.Len(t, DashboardMetricOrder, 32)

	indexOf := func(id string) int {
		idx := -1
		count := 0
		for i, m := range DashboardMetricOrder {
			if m == id {
				idx = i
				count++
			}
		}
		assert.Equal(t, 1, count, "metric %s should appear exactly once", id)
		return idx
	}

	assert.Equal(t, indexOf("load")+1, indexOf("processes"))
	assert.Equal(t, indexOf("processes")+1, indexOf("processes_total"))
	assert.Equal(t, indexOf("disk")+1, indexOf("disk_read"))
	assert.Equal(t, indexOf("disk_read")+1, indexOf("disk_write"))
	assert.Equal(t, indexOf("disk_write")+1, indexOf("disk_busy"))
	assert.Equal(t, indexOf("logstash_eps")+1, indexOf("logstash_out"))

	for _, id := range DashboardMetricOrder {
		_, ok := MetricConfigs[id]
		assert.True(t, ok, "metric %s in order has no config", id)
	}
}

func TestGetTimeSeriesMetrics_ProcessesAllHostsKeys(t *testing.T) {
	bucket := time.Now().Add(-time.Minute)
	var capturedSql []string
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			capturedSql = append(capturedSql, sql)
			return &MockRows{rows: [][]interface{}{
				{bucket, "sens1", 2.0},
			}}, nil
		},
	}
	res, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "", "", "processes", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Len(t, capturedSql, 3)
	assert.Len(t, res, 3)
	for _, field := range []string{"running", "blocked", "zombies"} {
		assert.Equal(t, []model.MetricSample{{Timestamp: bucket, Value: 2.0}}, res["sens1::"+field],
			"All Hosts processes should key %s as host::field", field)
	}
}

func TestGetTimeSeriesMetrics_ProcessesTotalSingleHostKeys(t *testing.T) {
	bucket := time.Now().Add(-time.Minute)
	var capturedSql []string
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			capturedSql = append(capturedSql, sql)
			return &MockRows{rows: [][]interface{}{
				{bucket, 200.0},
			}}, nil
		},
	}
	res, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", "processes_total", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Len(t, capturedSql, 2)
	assert.Len(t, res, 2)
	for _, field := range []string{"total", "sleeping"} {
		assert.Equal(t, []model.MetricSample{{Timestamp: bucket, Value: 200.0}}, res[field])
	}
}

func TestGetTimeSeriesMetrics_NewMetricsMissingTable(t *testing.T) {
	missing := &pgconn.PgError{Code: "42P01", Message: `relation "telegraf.processes" does not exist`}
	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			return nil, missing
		},
	}

	// Gauge metric: pre-populated keys stay present but empty, no error.
	res, err := New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", "processes", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	for _, field := range []string{"running", "blocked", "zombies"} {
		assert.Contains(t, res, field)
		assert.Empty(t, res[field])
	}

	// Rate metric: empty result, no error.
	res, err = New(mockDb).GetTimeSeriesMetrics(context.Background(), "node1", "", "disk_read", time.Now().Add(-time.Hour), time.Now())
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestGenerateDefaultMetricsDashboard_NewPanels(t *testing.T) {
	dash, err := GenerateDefaultMetricsDashboard()
	assert.NoError(t, err)

	ids := make([]string, 0, len(dash.Panels))
	for _, panel := range dash.Panels {
		ids = append(ids, panel.ID)
	}
	assert.Equal(t, DashboardMetricOrder, ids, "panels should follow DashboardMetricOrder")

	tests := []struct {
		id        string
		titleKey  string
		labelKeys []string
		keys      []string
		units     string
	}{
		{"disk_read", "metricsDiskRead", []string{"metricsDiskRead"}, []string{"disk_read"}, "bytes_per_second"},
		{"disk_write", "metricsDiskWrite", []string{"metricsDiskWrite"}, []string{"disk_write"}, "bytes_per_second"},
		{"disk_busy", "metricsDiskBusy", []string{"metricsDiskBusy"}, []string{"disk_busy"}, "percent"},
		{"logstash_out", "metricsLogstashSent", []string{"metricsLogstashSent"}, []string{"logstash_out"}, ""},
		{"processes", "metricsProcesses", []string{"stateRunning", "metricsProcBlocked", "metricsProcZombies"}, []string{"running", "blocked", "zombies"}, ""},
		{"processes_total", "metricsProcessesTotal", []string{"metricsProcTotal", "metricsProcSleeping"}, []string{"total", "sleeping"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			var panel *model.MetricPanel
			for i := range dash.Panels {
				if dash.Panels[i].ID == tt.id {
					panel = &dash.Panels[i]
				}
			}
			if !assert.NotNil(t, panel, "dashboard should include a %s panel", tt.id) {
				return
			}
			assert.Equal(t, tt.id, panel.Metric)
			assert.Equal(t, "line_chart", panel.Type)
			assert.Equal(t, tt.titleKey, panel.TitleKey)
			assert.Equal(t, tt.keys, panel.Keys)
			assert.Equal(t, tt.labelKeys, panel.LabelKeys)
			assert.Equal(t, tt.units, panel.Units)
			assert.Empty(t, panel.Labels)
			assert.NotEmpty(t, panel.Colors)
		})
	}
}
