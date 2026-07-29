// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"embed"
	"errors"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

type MockRow struct {
	values []interface{}
	err    error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	if m.err != nil {
		return m.err
	}
	if len(dest) != len(m.values) {
		return errors.New("mismatch scan count")
	}
	for i, val := range m.values {
		switch d := dest[i].(type) {
		case *string:
			*d = val.(string)
		case *int:
			*d = val.(int)
		case *float64:
			*d = val.(float64)
		case *time.Time:
			*d = val.(time.Time)
		default:
			return errors.New("unsupported scan destination type")
		}
	}
	return nil
}

type MockRows struct {
	rows  [][]interface{}
	index int
	err   error
}

func (m *MockRows) Close() {}
func (m *MockRows) Err() error { return m.err }
func (m *MockRows) Next() bool {
	m.index++
	return m.index <= len(m.rows)
}
func (m *MockRows) Scan(dest ...interface{}) error {
	row := m.rows[m.index-1]
	if len(dest) != len(row) {
		return errors.New("mismatch scan count")
	}
	for i, val := range row {
		switch d := dest[i].(type) {
		case *string:
			*d = val.(string)
		case *int:
			*d = val.(int)
		case *float64:
			*d = val.(float64)
		case *time.Time:
			*d = val.(time.Time)
		default:
			return errors.New("unsupported scan destination type")
		}
	}
	return nil
}

type MockDB struct {
	QueryFunc func(sql string, args ...interface{}) (db.Rows, error)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...any) error { return nil }
func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...any) db.Row { return nil }
func (m *MockDB) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(sql, args...)
	}
	return &MockRows{}, nil
}
func (m *MockDB) Begin(ctx context.Context) (db.Tx, error) { return nil, nil }
func (m *MockDB) Migrate(ctx context.Context, fs embed.FS, module string) error { return nil }
func (m *MockDB) Close() {}

func TestPostgresMetrics_Init(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(make(map[string][]string))
	pm := NewPostgresMetrics(srv)
	pm.Init(10000, 600)
	assert.Equal(t, 10000, pm.cacheExpirationMs)
	assert.Equal(t, 600, pm.maxMetricAgeSeconds)
}

func TestPostgresMetrics_GetTimeSeriesMetrics(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(make(map[string][]string))
	mockDb := &MockDB{
		QueryFunc: func(sql string, args ...interface{}) (db.Rows, error) {
			now := time.Now()
			return &MockRows{
				rows: [][]interface{}{
					{now, 25.5},
				},
			}, nil
		},
	}
	srv.DB = mockDb
	pm := NewPostgresMetrics(srv)
	pm.Init(10000, 600)

	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	res, err := pm.GetTimeSeriesMetrics(ctx, "host1", "", "cpu", startTime, endTime)
	assert.NoError(t, err)
	assert.Contains(t, res, "cpu_used")
	assert.Len(t, res["cpu_used"], 1)
	assert.Equal(t, 25.5, res["cpu_used"][0].Value)

	res, err = pm.GetTimeSeriesMetrics(ctx, "host1", "", "memory", startTime, endTime)
	assert.NoError(t, err)
	assert.Contains(t, res, "memory_used")

	res, err = pm.GetTimeSeriesMetrics(ctx, "host1", "", "load", startTime, endTime)
	assert.NoError(t, err)
	assert.Contains(t, res, "load1")

	res, err = pm.GetTimeSeriesMetrics(ctx, "host1", "", "disk", startTime, endTime)
	assert.NoError(t, err)
	assert.Contains(t, res, "disk_used_root")
}

func TestPostgresMetricsModule_PrerequisiteModules(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(make(map[string][]string))
	mod := NewPostgresMetricsModule(srv)
	assert.Equal(t, []string{"postgres"}, mod.PrerequisiteModules())
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestPostgresMetrics_UpdateNodeMetrics_And_GetGridEps(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(make(map[string][]string))

	// Set up our mock DB with query dispatching
	mockDb := &MockDB{
		QueryFunc: func(sql string, args ...interface{}) (db.Rows, error) {
			if contains(sql, "telegraf.cpu") {
				return &MockRows{rows: [][]interface{}{{"host1", 95.0}}}, nil
			}
			if contains(sql, "telegraf.mem") {
				if contains(sql, "total") {
					return &MockRows{rows: [][]interface{}{{"host1", 16000000000.0}}}, nil // 16GB total in bytes
				}
				return &MockRows{rows: [][]interface{}{{"host1", 50.0}}}, nil // 50% used
			}
			if contains(sql, "telegraf.swap") {
				if contains(sql, "total") {
					return &MockRows{rows: [][]interface{}{{"host1", 4000000000.0}}}, nil // 4GB in bytes
				}
				return &MockRows{rows: [][]interface{}{{"host1", 10.0}}}, nil // 10% used
			}
			if contains(sql, "telegraf.system") {
				if contains(sql, "load1") || contains(sql, "load5") || contains(sql, "load15") {
					return &MockRows{rows: [][]interface{}{{"host1", 1.0}}}, nil
				}
				if contains(sql, "uptime") {
					return &MockRows{rows: [][]interface{}{{"host1", 3600}}}, nil
				}
			}
			if contains(sql, "telegraf.disk") {
				if contains(sql, "total") {
					return &MockRows{rows: [][]interface{}{{"host1", 100000000000.0}}}, nil // 100GB in bytes
				}
				return &MockRows{rows: [][]interface{}{{"host1", 45.0}}}, nil // 45% used
			}
			if contains(sql, "telegraf.raid") {
				return &MockRows{rows: [][]interface{}{{"host1", 0}}}, nil
			}
			if contains(sql, "telegraf.sostatus") {
				if contains(sql, "fields->>'status'") {
					return &MockRows{rows: [][]interface{}{{"host1", 0}}}, nil
				}
				return &MockRows{rows: [][]interface{}{{"host1", `{"foo":"bar"}`}}}, nil
			}
			if contains(sql, "telegraf.consumptioneps") {
				return &MockRows{rows: [][]interface{}{{"host1", 150}}}, nil
			}
			if contains(sql, "telegraf.fbstats") {
				return &MockRows{rows: [][]interface{}{{"host1", 120}}}, nil
			}
			if contains(sql, "telegraf.elasticsearch_cluster_health") {
				return &MockRows{rows: [][]interface{}{{"host1", "green"}}}, nil
			}
			if contains(sql, "telegraf.node_config") {
				return &MockRows{rows: [][]interface{}{{"host1", "eth0", "eth1"}}}, nil
			}
			if contains(sql, "telegraf.net") {
				return &MockRows{rows: [][]interface{}{
					{"host1", "eth0", 1000000.0, 500000.0, 0.0},
					{"host1", "eth1", 2000000.0, 0.0, 5.0},
				}}, nil
			}
			if contains(sql, "telegraf.pcapage") || contains(sql, "telegraf.suridrop") || contains(sql, "telegraf.zeekdrop") || contains(sql, "telegraf.zeekcaptureloss") || contains(sql, "telegraf.elasticsearch_indices") || contains(sql, "telegraf.influxsize") {
				return &MockRows{rows: [][]interface{}{{"host1", 1.0}}}, nil
			}
			if contains(sql, "telegraf.surirules") {
				if contains(sql, "loaded") || contains(sql, "failed") {
					return &MockRows{rows: [][]interface{}{{"host1", 0}}}, nil
				}
				return &MockRows{rows: [][]interface{}{{"host1", "loaded"}}}, nil
			}
			if contains(sql, "telegraf.redisqueue") || contains(sql, "telegraf.salt") || contains(sql, "telegraf.os") || contains(sql, "telegraf.features") {
				return &MockRows{rows: [][]interface{}{{"host1", 1}}}, nil
			}
			if contains(sql, "::bigint") || contains(sql, "::int") {
				return &MockRows{rows: [][]interface{}{{"host1", 0}}}, nil
			}
			return &MockRows{rows: [][]interface{}{{"host1", 0.0}}}, nil
		},
	}
	srv.DB = mockDb

	pm := NewPostgresMetrics(srv)
	pm.Init(10000, 600)

	ctx := context.Background()

	// Test GetGridEps
	eps := pm.GetGridEps(ctx)
	assert.Equal(t, 150, eps)

	// Test UpdateNodeMetrics
	node := &model.Node{
		Id:               "host1",
		ConnectionStatus: model.NodeStatusOk,
	}
	status := pm.UpdateNodeMetrics(ctx, node)
	assert.True(t, status) // Node status should change to OK/true

	// Verify the updated node attributes
	assert.Equal(t, 5.0, node.CpuUsedPct) // 100 - 95.0
	assert.Equal(t, 50.0, node.MemoryUsedPct)
	assert.Equal(t, 16.0, node.MemoryTotalGB)
	assert.Equal(t, 1.0, node.Load1m)
	assert.Equal(t, 1.0, node.Load5m)
	assert.Equal(t, 1.0, node.Load15m)
	assert.Equal(t, 100.0, node.DiskTotalRootGB)
	assert.Equal(t, 45.0, node.DiskUsedRootPct)
	assert.Equal(t, 3600, node.OsUptimeSeconds)
	assert.Equal(t, model.NodeStatusOk, node.RaidStatus)
	assert.Equal(t, model.NodeStatusOk, node.ProcessStatus)
	assert.Equal(t, `{"foo":"bar"}`, node.ProcessJson)
	assert.Equal(t, model.NodeStatusOk, node.EventstoreStatus)
}

func TestGenerateDefaultMetricsDashboard(t *testing.T) {
	dash, err := database.GenerateDefaultMetricsDashboard()
	assert.NoError(t, err)
	assert.NotNil(t, dash)
	assert.Len(t, dash.Panels, 26)
	assert.Equal(t, "cpu", dash.Panels[0].ID)
	assert.Equal(t, "metricsCpuUsage", dash.Panels[0].TitleKey)
	assert.Equal(t, "percent", dash.Panels[0].Units)

	var foundSize, foundNet bool
	for _, p := range dash.Panels {
		if p.ID == "elasticsearch_size" {
			assert.Equal(t, "byte", p.Units)
			foundSize = true
		}
		if p.ID == "net" {
			assert.Equal(t, "bits", p.Units)
			foundNet = true
		}
	}
	assert.True(t, foundSize)
	assert.True(t, foundNet)
}

func TestPostgresMetricsModule_Init_DefaultDashboard(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(make(map[string][]string))
	mod := NewPostgresMetricsModule(srv)

	cfg := make(map[string]interface{})
	err := mod.Init(cfg)
	assert.NoError(t, err)

	// Since MetricsDashboard was empty, Init should have populated it with default dashboard
	dash := srv.Config.ClientParams.GridParams.MetricsDashboard
	assert.NotNil(t, dash)
	assert.Len(t, dash.Panels, 26)
}

