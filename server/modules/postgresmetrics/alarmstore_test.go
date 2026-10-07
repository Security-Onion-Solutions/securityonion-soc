// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics"
	"github.com/stretchr/testify/assert"
)

func TestAlarmstore_GetAlarms(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			DurationSeconds: 120,
			Severity:        "high",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()
	alarms, err := alarmStore.GetAlarms(ctx)
	assert.NoError(t, err)
	assert.Len(t, alarms, 1)
	assert.Equal(t, "alarm-1", alarms[0].ID)
}

type fakeTargetAuthorizer struct {
	allowedTarget string
}

func (f *fakeTargetAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
	if target == f.allowedTarget {
		return nil
	}
	return model.NewUnauthorized("fake-subject", operation, target)
}

func (f *fakeTargetAuthorizer) CheckUserOperationAuthorized(userId string, operation string, target string) error {
	if target == f.allowedTarget {
		return nil
	}
	return model.NewUnauthorized("fake-subject", operation, target)
}

func TestAlarmstore_GetAlarms_GridReadAuth(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:       "alarm-1",
			Name:     "High CPU",
			Enabled:  true,
			Metric:   "cpu",
			Operator: "gt",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})

	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &fakeTargetAuthorizer{allowedTarget: "grid"},
		Context:     context.Background(),
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	alarms, err := alarmStore.GetAlarms(context.Background())
	assert.NoError(t, err)
	assert.Len(t, alarms, 1)
	assert.Equal(t, "alarm-1", alarms[0].ID)
}

func TestAlarmstore_GetAlarm(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			Severity:        "high",
			DurationSeconds: 60,
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	// Invalid ID
	_, err := alarmStore.GetAlarm(ctx, "invalid id!")
	assert.ErrorIs(t, err, postgresmetrics.ErrInvalidAlarmID)

	// Not Found
	_, err = alarmStore.GetAlarm(ctx, "alarm-nonexistent")
	assert.ErrorIs(t, err, postgresmetrics.ErrAlarmNotFound)

	// Success
	a, err := alarmStore.GetAlarm(ctx, "alarm-1")
	assert.NoError(t, err)
	assert.Equal(t, "alarm-1", a.ID)
	assert.Equal(t, "High CPU", a.Name)
}

func TestAlarmstore_CreateAlarm(t *testing.T) {
	cfgStore := server.NewMemConfigStore([]*model.Setting{})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	// Nil alarm
	_, err := alarmStore.CreateAlarm(ctx, nil)
	assert.Error(t, err)

	// Valid alarm creation
	newAlarm := &model.Alarm{
		Name:            "Memory Warning",
		Enabled:         true,
		Metric:          "memory",
		Operator:        ">=",
		Threshold:       "85",
		DurationSeconds: 300,
		Severity:        "medium",
		ClearedSeverity: "info",
		Note:            "Memory is running high",
	}

	created, err := alarmStore.CreateAlarm(ctx, newAlarm)
	assert.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "Memory Warning", created.Name)
	assert.Equal(t, "gte", created.Operator)

	// Duplicate ID
	duplicate := &model.Alarm{
		ID:        created.ID,
		Name:      "Duplicate",
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "80",
		Severity:  "low",
	}
	_, err = alarmStore.CreateAlarm(ctx, duplicate)
	assert.ErrorIs(t, err, postgresmetrics.ErrDuplicateAlarmID)
}

func TestAlarmstore_UpdateAlarm(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			Severity:        "high",
			DurationSeconds: 120,
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	// Update existing
	updated := &model.Alarm{
		Name:            "High CPU Updated",
		Enabled:         false,
		Metric:          "cpu",
		Operator:        "gt",
		Threshold:       "90",
		Severity:        "critical",
		DurationSeconds: 60,
	}

	res, err := alarmStore.UpdateAlarm(ctx, "alarm-1", updated)
	assert.NoError(t, err)
	assert.Equal(t, "alarm-1", res.ID)
	assert.Equal(t, "High CPU Updated", res.Name)
	assert.False(t, res.Enabled)

	// Update non-existent
	_, err = alarmStore.UpdateAlarm(ctx, "alarm-nonexistent", updated)
	assert.ErrorIs(t, err, postgresmetrics.ErrAlarmNotFound)
}

func TestAlarmstore_DeleteAlarm(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			Severity:        "high",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	// Delete non-existent
	err := alarmStore.DeleteAlarm(ctx, "alarm-nonexistent")
	assert.ErrorIs(t, err, postgresmetrics.ErrAlarmNotFound)

	// Delete existing
	err = alarmStore.DeleteAlarm(ctx, "alarm-1")
	assert.NoError(t, err)

	alarms, err := alarmStore.GetAlarms(ctx)
	assert.NoError(t, err)
	assert.Empty(t, alarms)
}

func TestAlarmstore_GetAlarmMetrics(t *testing.T) {
	srv := &server.Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	metrics, err := alarmStore.GetAlarmMetrics(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, metrics)

	foundCPU := false
	for _, m := range metrics {
		if m.Metric == "cpu" {
			foundCPU = true
			assert.Equal(t, "metricsCpuUsage", m.TitleKey)
			assert.Equal(t, "numeric", m.Type)
			assert.Equal(t, "percent", m.Units)
		}
	}
	assert.True(t, foundCPU)
}

func TestAlarmstore_EvaluateAlarms_Breach(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			DurationSeconds: 0,
			Severity:        "high",
			ClearedSeverity: "info",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})

	fakeNotifier := &server.FakeNotifier{}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Notifier:    fakeNotifier,
		Datastore:   &fakeDatastore{nodes: []*model.Node{{Id: "node-1", CpuUsedPct: 85.0}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	err := alarmStore.EvaluateAlarms(ctx)
	assert.NoError(t, err)

	assert.Len(t, fakeNotifier.InputPayloads, 1)
	assert.Contains(t, fakeNotifier.InputPayloads[0].Title, "High CPU")
	assert.Equal(t, "high", fakeNotifier.InputPayloads[0].Severity)
	assert.Equal(t, "true", fakeNotifier.InputPayloads[0].Fields["Triggered"])
	assert.NotContains(t, fakeNotifier.InputPayloads[0].Fields, "Status")
}

func TestAlarmstore_EvaluateAlarms_Breach_Unlicensed(t *testing.T) {
	licensing.Shutdown()

	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			DurationSeconds: 0,
			Severity:        "high",
			ClearedSeverity: "info",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})

	fakeNotifier := &server.FakeNotifier{}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Notifier:    fakeNotifier,
		Datastore:   &fakeDatastore{nodes: []*model.Node{{Id: "node-1", CpuUsedPct: 85.0}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	err := alarmStore.EvaluateAlarms(ctx)
	assert.NoError(t, err)

	// No notification should be dispatched when unlicensed for FEAT_NTF
	assert.Empty(t, fakeNotifier.InputPayloads)
}

func TestAlarmstore_EvaluateAlarms_ContainerBreach(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	initialAlarms := []model.Alarm{
		{
			ID:              "alarm-container-1",
			Name:            "High Container CPU",
			Enabled:         true,
			Metric:          "container_cpu",
			Operator:        "gt",
			Threshold:       "80",
			DurationSeconds: 0,
			Severity:        "high",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})

	fakeNotifier := &server.FakeNotifier{}
	now := time.Now()
	fakeMetricsProvider := &fakeMetrics{
		samples: map[string][]model.MetricSample{
			"so-elasticsearch": {
				{Timestamp: now, Value: 45.0},
			},
			"so-suricata": {
				{Timestamp: now, Value: 92.5},
			},
		},
	}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Notifier:    fakeNotifier,
		Metrics:     fakeMetricsProvider,
		Datastore:   &fakeDatastore{nodes: []*model.Node{{Id: "node-1"}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	err := alarmStore.EvaluateAlarms(ctx)
	assert.NoError(t, err)

	assert.Len(t, fakeNotifier.InputPayloads, 1)
	assert.Contains(t, fakeNotifier.InputPayloads[0].Title, "High Container CPU")
	assert.Equal(t, "high", fakeNotifier.InputPayloads[0].Severity)
}

func TestAlarmstore_GetContainerLookbackDuration(t *testing.T) {
	// When pm is nil -> default 1200s > 300s -> 5m
	alarmStore := postgresmetrics.NewAlarmstore(nil, nil)
	assert.Equal(t, 5*time.Minute, alarmStore.GetContainerLookbackDuration())

	// When pm maxMetricAgeSeconds > 300 -> 5m
	pm := postgresmetrics.NewPostgresMetrics(nil)
	pm.Init(30000, 600)
	srv := &server.Server{Metrics: pm}
	alarmStore = postgresmetrics.NewAlarmstore(srv, nil)
	assert.Equal(t, 5*time.Minute, alarmStore.GetContainerLookbackDuration())

	// When pm maxMetricAgeSeconds <= 300 -> maxMetricAgeSeconds - 1
	pm.Init(30000, 180)
	assert.Equal(t, 179*time.Second, alarmStore.GetContainerLookbackDuration())

	pm.Init(30000, 300)
	assert.Equal(t, 299*time.Second, alarmStore.GetContainerLookbackDuration())

	pm.Init(30000, 60)
	assert.Equal(t, 59*time.Second, alarmStore.GetContainerLookbackDuration())
}

type fakeMetrics struct {
	server.Metrics
	samples map[string][]model.MetricSample
}

func (f *fakeMetrics) GetTimeSeriesMetrics(ctx context.Context, nodeId, container string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
	return f.samples, nil
}

type fakeDatastore struct {
	server.Datastore
	nodes []*model.Node
}

func (f *fakeDatastore) GetNodes(ctx context.Context) []*model.Node {
	return f.nodes
}

