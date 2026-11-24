// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

	restart := &model.Alarm{
		Name:      "Restart Needed",
		Metric:    "os_needs_restart",
		Operator:  "eq",
		Threshold: "1",
		Severity:  "low",
	}
	created, err = alarmStore.CreateAlarm(ctx, restart)
	assert.NoError(t, err)
	assert.Equal(t, "true", created.Threshold)
	stored, err := alarmStore.GetAlarm(ctx, created.ID)
	assert.NoError(t, err)
	assert.Equal(t, "true", stored.Threshold)

	badOperator := &model.Alarm{
		Name:      "Restart Greater",
		Metric:    "os_needs_restart",
		Operator:  "gt",
		Threshold: "true",
		Severity:  "low",
	}
	_, err = alarmStore.CreateAlarm(ctx, badOperator)
	assert.Error(t, err)
	alarms, err := alarmStore.GetAlarms(ctx)
	assert.NoError(t, err)
	assert.Len(t, alarms, 2)
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
		{
			ID:        "alarm-2",
			Name:      "Restart Needed",
			Enabled:   true,
			Metric:    "os_needs_restart",
			Operator:  "eq",
			Threshold: "true",
			Severity:  "low",
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

	_, err = alarmStore.UpdateAlarm(ctx, "alarm-2", &model.Alarm{
		Name:      "Restart Needed",
		Metric:    "os_needs_restart",
		Operator:  "gt",
		Threshold: "true",
		Severity:  "low",
	})
	assert.Error(t, err)
	stored, err := alarmStore.GetAlarm(ctx, "alarm-2")
	assert.NoError(t, err)
	assert.Equal(t, "eq", stored.Operator)
	assert.Equal(t, "true", stored.Threshold)

	res, err = alarmStore.UpdateAlarm(ctx, "alarm-2", &model.Alarm{
		Name:      "Restart Needed",
		Metric:    "os_needs_restart",
		Operator:  "==",
		Threshold: "0",
		Severity:  "low",
	})
	assert.NoError(t, err)
	assert.Equal(t, "eq", res.Operator)
	assert.Equal(t, "false", res.Threshold)
	stored, err = alarmStore.GetAlarm(ctx, "alarm-2")
	assert.NoError(t, err)
	assert.Equal(t, "eq", stored.Operator)
	assert.Equal(t, "false", stored.Threshold)

	res, err = alarmStore.UpdateAlarm(ctx, "alarm-1", &model.Alarm{
		Name:      "High CPU",
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "1",
		Severity:  "high",
	})
	assert.NoError(t, err)
	assert.Equal(t, "gt", res.Operator)
	assert.Equal(t, "1", res.Threshold)
}

func TestAlarmstore_DeleteAlarm(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
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

func TestAlarmstore_DeleteAlarm_Broadcast(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	host := web.NewHost("", "", 0, "", nil)
	host.Authorizer = &rbac.FakeAuthorizer{Authorized: true}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Host:        host,
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()
	err := alarmStore.DeleteAlarm(ctx, "alarm-1")
	assert.NoError(t, err)
}

func TestAlarmstore_UpdateAlarm_Disabled_Broadcast(t *testing.T) {
	initialAlarms := []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
		},
	}
	alarmsJSON, _ := json.Marshal(initialAlarms)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})
	host := web.NewHost("", "", 0, "", nil)
	host.Authorizer = &rbac.FakeAuthorizer{Authorized: true}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Host:        host,
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()
	updated := &model.Alarm{
		Name:      "High CPU Disabled",
		Enabled:   false,
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "80",
		Severity:  "high",
	}
	_, err := alarmStore.UpdateAlarm(ctx, "alarm-1", updated)
	assert.NoError(t, err)
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
		{
			ID:              "alarm-2",
			Name:            "Restart Needed",
			Enabled:         true,
			Metric:          "os_needs_restart",
			Operator:        "eq",
			Threshold:       "1",
			DurationSeconds: 0,
			Severity:        "low",
			ClearedSeverity: "info",
		},
		{
			ID:              "alarm-3",
			Name:            "GMD Enabled",
			Enabled:         true,
			Metric:          "gmd_enabled",
			Operator:        "ne",
			Threshold:       "0",
			DurationSeconds: 0,
			Severity:        "medium",
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
		Datastore:   &fakeDatastore{nodes: []*model.Node{{Id: "node-1", CpuUsedPct: 85.4351, OsNeedsRestart: 1, GmdEnabled: 1}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

	ctx := context.Background()

	err := alarmStore.EvaluateAlarms(ctx)
	assert.NoError(t, err)

	assert.Len(t, fakeNotifier.InputPayloads, 3)
	assert.Contains(t, fakeNotifier.InputPayloads[1].Title, "Restart Needed")
	assert.Equal(t, "low", fakeNotifier.InputPayloads[1].Severity)
	assert.Contains(t, fakeNotifier.InputPayloads[0].Title, "High CPU")
	assert.Equal(t, "high", fakeNotifier.InputPayloads[0].Severity)
	assert.Equal(t, "85.44", fakeNotifier.InputPayloads[0].Fields["Value"])
	assert.Equal(t, "true", fakeNotifier.InputPayloads[0].Fields["Triggered"])
	assert.NotContains(t, fakeNotifier.InputPayloads[0].Fields, "Status")
	assert.Contains(t, fakeNotifier.InputPayloads[2].Title, "GMD Enabled")
	assert.Equal(t, "medium", fakeNotifier.InputPayloads[2].Severity)
	assert.Equal(t, "true", fakeNotifier.InputPayloads[2].Fields["Value"])
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
				{Timestamp: now, Value: 92.5049},
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
	assert.Equal(t, "so-suricata: 92.5", fakeNotifier.InputPayloads[0].Fields["Value"])
}

func TestAlarmstore_EvaluateAlarms_ContainerCleared(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	alarmsJSON, _ := json.Marshal([]model.Alarm{
		{
			ID:              "alarm-container-1",
			Name:            "High Container CPU",
			Enabled:         true,
			Metric:          "container_cpu",
			Operator:        "gt",
			Threshold:       "80",
			Severity:        "high",
			ClearedSeverity: "info",
		},
	})
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: string(alarmsJSON),
		},
	})

	// Previously active state, so the non-breach evaluation clears the alarm
	mDB := new(mockdb.MockDB)
	mockRow := new(mockdb.MockRow)
	mDB.On("QueryRow", mock.Anything, mock.Anything, "alarm-container-1", "node-1").Return(mockRow).Once()
	mockRow.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		*args.Get(0).(*string) = "alarm-container-1"
		*args.Get(1).(*string) = "node-1"
		*args.Get(2).(*string) = model.AlarmStatusActive
	}).Return(nil).Once()
	mDB.On("Exec", mock.Anything, mock.Anything,
		"alarm-container-1", "node-1", model.AlarmStatusOk, "45",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil).Once()

	now := time.Now()
	fakeNotifier := &server.FakeNotifier{}
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Notifier:    fakeNotifier,
		Metrics: &fakeMetrics{
			samples: map[string][]model.MetricSample{
				"so-elasticsearch": {{Timestamp: now, Value: 45.0049}},
				"so-suricata":      {{Timestamp: now, Value: 30.5}},
			},
		},
		Datastore: &fakeDatastore{nodes: []*model.Node{{Id: "node-1"}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, database.New(mDB))

	err := alarmStore.EvaluateAlarms(context.Background())
	assert.NoError(t, err)

	assert.Len(t, fakeNotifier.InputPayloads, 1)
	assert.Contains(t, fakeNotifier.InputPayloads[0].Summary, "current value: 45)")
	mDB.AssertExpectations(t)
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

type failingLoadConfigstore struct {
	server.Configstore
}

func (f *failingLoadConfigstore) GetSetting(ctx context.Context, id string) (*model.Setting, error) {
	return nil, errors.New("config unavailable")
}

func captureAlarmLogs(t *testing.T) *memory.Handler {
	h := memory.New()
	logger := log.Log.(*log.Logger)
	originalHandler := logger.Handler
	originalLevel := logger.Level
	logger.Handler = h
	logger.Level = log.DebugLevel
	t.Cleanup(func() {
		logger.Handler = originalHandler
		logger.Level = originalLevel
	})
	return h
}

func logEntriesWithField(h *memory.Handler, level log.Level, field string) []*log.Entry {
	var res []*log.Entry
	for _, entry := range h.Entries {
		if entry.Level != level {
			continue
		}
		if _, ok := entry.Fields[field]; ok {
			res = append(res, entry)
		}
	}
	return res
}

func dropsAlarm(id, threshold string) model.Alarm {
	return model.Alarm{
		ID:              id,
		Name:            "Drops " + id,
		Enabled:         true,
		Metric:          "net_drops",
		MetricKey:       "traffic_mon_drops",
		Operator:        "gt",
		Threshold:       threshold,
		DurationSeconds: 60,
		Severity:        "high",
		ClearedSeverity: "info",
		Destinations:    []string{"soc-bell"},
		Note:            "note " + id,
	}
}

func cpuAlarm(id string) model.Alarm {
	return model.Alarm{
		ID:        id,
		Name:      "CPU " + id,
		Enabled:   true,
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "80",
		Severity:  "high",
	}
}

func newNetDropsAlarmstore(cfgStore *postgresmetrics.RecordingConfigstore, mDB *mockdb.MockDB) *postgresmetrics.AlarmstoreImpl {
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	var dbStore *database.Store
	if mDB != nil {
		dbStore = database.New(mDB)
	}
	return postgresmetrics.NewAlarmstore(srv, dbStore)
}

func isStateThresholdUpdate(sql string) bool {
	return strings.Contains(sql, "UPDATE alarm_states SET threshold")
}

func isStateDelete(sql string) bool {
	return strings.Contains(sql, "DELETE FROM alarm_states")
}

func expectStateThresholdUpdate(mDB *mockdb.MockDB, alarmId, threshold string, err error) {
	mDB.On("Exec", mock.Anything, mock.MatchedBy(isStateThresholdUpdate), threshold, alarmId).Return(err)
}

func stateThresholdUpdates(mDB *mockdb.MockDB) [][]any {
	var res [][]any
	for _, call := range mDB.Calls {
		if call.Method == "Exec" && isStateThresholdUpdate(call.Arguments.String(1)) {
			res = append(res, []any{call.Arguments.Get(2), call.Arguments.Get(3)})
		}
	}
	return res
}

func countSaves(cfgStore *postgresmetrics.RecordingConfigstore) int {
	return len(cfgStore.Saved())
}

func TestAlarmstore_LoadConvertsNetDropsThresholds(t *testing.T) {
	cases := map[string]string{
		"0.5":               "62500",
		".01":               "1250",
		"1e-5":              "1.25",
		"+0.5":              "62500",
		"1":                 "125000",
		" 0.5 ":             "62500",
		"-0.5":              "-62500",
		"10":                "1250000",
		"100":               "12500000",
		"0.123456789012345": "15432.0986265",
		"1e-200":            "1.25e-195",
		"1e120":             "1.25e+125",
	}

	var alarms []model.Alarm
	expected := map[string]string{}
	idx := 0
	for input, output := range cases {
		id := "drops-" + string(rune('a'+idx))
		idx++
		alarms = append(alarms, dropsAlarm(id, input))
		expected[id] = output
	}
	stamped := dropsAlarm("drops-stamped", "1000")
	stamped.ThresholdUnits = "pps"
	alarms = append(alarms, cpuAlarm("cpu-1"), stamped)

	cfgStore := postgresmetrics.NewRecordingConfigstore(alarms)
	alarmStore := newNetDropsAlarmstore(cfgStore, nil)

	loaded, err := alarmStore.GetAlarms(context.Background())
	require.NoError(t, err)
	require.Len(t, loaded, len(alarms))

	for i, alarm := range loaded {
		original := alarms[i]
		switch alarm.ID {
		case "cpu-1":
			assert.Equal(t, original, alarm)
		case "drops-stamped":
			assert.Equal(t, original, alarm)
		default:
			assert.Equal(t, expected[alarm.ID], alarm.Threshold, original.Threshold)
			assert.Equal(t, "pps", alarm.ThresholdUnits)
			assert.LessOrEqual(t, len(alarm.Threshold), model.MAX_ALARM_THRESHOLD_LEN)
			original.Threshold = alarm.Threshold
			original.ThresholdUnits = alarm.ThresholdUnits
			assert.Equal(t, original, alarm)
		}
	}
	assert.Equal(t, 0, countSaves(cfgStore))
}

func TestAlarmstore_ConvertedExtremeThresholdPassesUpdateValidation(t *testing.T) {
	cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("tiny", "1e-200"), dropsAlarm("huge", "1e120")})
	alarmStore := newNetDropsAlarmstore(cfgStore, nil)
	ctx := context.Background()

	for _, id := range []string{"tiny", "huge"} {
		alarm, err := alarmStore.GetAlarm(ctx, id)
		require.NoError(t, err)
		_, err = alarmStore.UpdateAlarm(ctx, id, alarm)
		assert.NoError(t, err)
	}
}

func TestAlarmstore_UnparsableNetDropsThresholds(t *testing.T) {
	h := captureAlarmLogs(t)
	inputs := []string{"", "abc", "NaN", "Inf", "1e305"}
	var alarms []model.Alarm
	for i, input := range inputs {
		alarms = append(alarms, dropsAlarm("bad-"+string(rune('a'+i)), input))
	}
	cfgStore := postgresmetrics.NewRecordingConfigstore(alarms)
	mDB := new(mockdb.MockDB)
	alarmStore := newNetDropsAlarmstore(cfgStore, mDB)
	ctx := context.Background()

	loaded, err := alarmStore.GetAlarms(ctx)
	require.NoError(t, err)
	for i, alarm := range loaded {
		assert.Equal(t, inputs[i], alarm.Threshold)
		assert.Equal(t, "pps", alarm.ThresholdUnits)
	}

	require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
	assert.Equal(t, 1, countSaves(cfgStore))
	warns := logEntriesWithField(h, log.WarnLevel, "netDropsUnparsableAlarmIds")
	require.Len(t, warns, 1)
	assert.Equal(t, []string{"bad-a", "bad-b", "bad-c", "bad-d", "bad-e"}, warns[0].Fields["netDropsUnparsableAlarmIds"])
	assert.Empty(t, stateThresholdUpdates(mDB))

	require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
	assert.Equal(t, 1, countSaves(cfgStore))
	assert.Len(t, logEntriesWithField(h, log.WarnLevel, "netDropsUnparsableAlarmIds"), 1)
}

func TestAlarmstore_EvaluateAlarms_UsesConvertedNetDropsThreshold(t *testing.T) {
	cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})

	mDB := new(mockdb.MockDB)
	mockRow := new(mockdb.MockRow)
	mDB.On("QueryRow", mock.Anything, mock.Anything, "drops-1", "node-1").Return(mockRow).Once()
	mockRow.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(errors.New("no rows in result set")).Once()

	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Datastore:   &fakeDatastore{nodes: []*model.Node{{Id: "node-1", TrafficMonInDropsPps: 10}}},
	}
	alarmStore := postgresmetrics.NewAlarmstore(srv, database.New(mDB))

	require.NoError(t, alarmStore.EvaluateAlarms(context.Background()))
	mDB.AssertExpectations(t)
	mDB.AssertNotCalled(t, "Exec")
	assert.Equal(t, 0, countSaves(cfgStore))
}

func TestAlarmstore_SaveConvertedThresholds(t *testing.T) {
	ctx := context.Background()

	t.Run("saves once and updates the state threshold", func(t *testing.T) {
		h := captureAlarmLogs(t)
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), cpuAlarm("cpu-1")})
		mDB := new(mockdb.MockDB)
		expectStateThresholdUpdate(mDB, "drops-1", "62500", nil)
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, 1, countSaves(cfgStore))
		infos := logEntriesWithField(h, log.InfoLevel, "netDropsConvertedAlarmIds")
		require.Len(t, infos, 1)
		assert.Equal(t, []string{"drops-1"}, infos[0].Fields["netDropsConvertedAlarmIds"])
		assert.Equal(t, [][]any{{"62500", "drops-1"}}, stateThresholdUpdates(mDB))

		stored := cfgStore.StoredAlarms()
		assert.Equal(t, "62500", stored[0].Threshold)
		assert.Equal(t, "pps", stored[0].ThresholdUnits)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, 1, countSaves(cfgStore))
		assert.Len(t, stateThresholdUpdates(mDB), 1)
	})

	t.Run("failed save is logged and retried", func(t *testing.T) {
		h := captureAlarmLogs(t)
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})
		cfgStore.FailSaves = 1
		alarmStore := newNetDropsAlarmstore(cfgStore, nil)

		assert.Error(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Len(t, logEntriesWithField(h, log.ErrorLevel, "netDropsConvertedAlarmIds"), 1)
		assert.Equal(t, 0, countSaves(cfgStore))

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, 1, countSaves(cfgStore))
		assert.Equal(t, "62500", cfgStore.StoredAlarms()[0].Threshold)
	})

	t.Run("state threshold failure is logged and ignored", func(t *testing.T) {
		h := captureAlarmLogs(t)
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})
		mDB := new(mockdb.MockDB)
		expectStateThresholdUpdate(mDB, "drops-1", "62500", errors.New("db error"))
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, 1, countSaves(cfgStore))
		errs := logEntriesWithField(h, log.ErrorLevel, "alarmId")
		require.Len(t, errs, 1)
		assert.Equal(t, "drops-1", errs[0].Fields["alarmId"])
	})

	t.Run("converted and unparsable alarms in one list", func(t *testing.T) {
		h := captureAlarmLogs(t)
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), dropsAlarm("drops-bad", "abc")})
		mDB := new(mockdb.MockDB)
		expectStateThresholdUpdate(mDB, "drops-1", "62500", nil)
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, 1, countSaves(cfgStore))

		infos := logEntriesWithField(h, log.InfoLevel, "netDropsConvertedAlarmIds")
		require.Len(t, infos, 1)
		assert.Equal(t, []string{"drops-1"}, infos[0].Fields["netDropsConvertedAlarmIds"])
		warns := logEntriesWithField(h, log.WarnLevel, "netDropsUnparsableAlarmIds")
		require.Len(t, warns, 1)
		assert.Equal(t, []string{"drops-bad"}, warns[0].Fields["netDropsUnparsableAlarmIds"])

		assert.Equal(t, [][]any{{"62500", "drops-1"}}, stateThresholdUpdates(mDB))
		stored := cfgStore.StoredAlarms()
		assert.Equal(t, "62500", stored[0].Threshold)
		assert.Equal(t, "abc", stored[1].Threshold)
	})

	t.Run("load failure returns the error and saves nothing", func(t *testing.T) {
		srv := &server.Server{
			Configstore: &failingLoadConfigstore{},
			Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		}
		alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

		assert.Error(t, alarmStore.SaveConvertedThresholds(ctx))
	})

	t.Run("nil configstore saves nothing", func(t *testing.T) {
		srv := &server.Server{
			Authorizer: &rbac.FakeAuthorizer{Authorized: true},
		}
		alarmStore := postgresmetrics.NewAlarmstore(srv, nil)

		assert.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
	})

	t.Run("reverted thresholds are converted again", func(t *testing.T) {
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})
		alarmStore := newNetDropsAlarmstore(cfgStore, nil)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		require.NoError(t, cfgStore.UpdateSetting(ctx, &model.Setting{
			Id:    postgresmetrics.ConfigSettingPostgresMetricsAlarms,
			Value: `[{"id":"drops-1","name":"Drops","enabled":true,"metric":"net_drops","operator":"gt","threshold":"0.5","severity":"high"}]`,
		}, false))
		saves := countSaves(cfgStore)

		require.NoError(t, alarmStore.SaveConvertedThresholds(ctx))
		assert.Equal(t, saves+1, countSaves(cfgStore))
		stored := cfgStore.StoredAlarms()
		assert.Equal(t, "62500", stored[0].Threshold)
		assert.Equal(t, "pps", stored[0].ThresholdUnits)
	})
}

func TestAlarmstore_SaveConvertedThresholds_ConcurrentCreate(t *testing.T) {
	ctx := context.Background()
	cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})
	alarmStore := newNetDropsAlarmstore(cfgStore, nil)

	newAlarm := cpuAlarm("cpu-new")
	var wg sync.WaitGroup
	var saveErr, createErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		saveErr = alarmStore.SaveConvertedThresholds(ctx)
	}()
	go func() {
		defer wg.Done()
		_, createErr = alarmStore.CreateAlarm(ctx, &newAlarm)
	}()
	wg.Wait()
	require.NoError(t, saveErr)
	require.NoError(t, createErr)

	stored := cfgStore.StoredAlarms()
	require.Len(t, stored, 2)
	assert.Equal(t, "62500", stored[0].Threshold)
	assert.Equal(t, "pps", stored[0].ThresholdUnits)
	assert.Equal(t, "cpu-new", stored[1].ID)
}

func TestAlarmstore_GetAlarms_DoesNotSaveConversion(t *testing.T) {
	cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5")})
	alarmStore := newNetDropsAlarmstore(cfgStore, nil)

	alarms, err := alarmStore.GetAlarms(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "62500", alarms[0].Threshold)
	assert.Equal(t, 0, countSaves(cfgStore))
	assert.Equal(t, "0.5", cfgStore.StoredAlarms()[0].Threshold)
}

func TestAlarmstore_CreateUpdate_StampThresholdUnits(t *testing.T) {
	ctx := context.Background()
	cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{})
	alarmStore := newNetDropsAlarmstore(cfgStore, nil)

	drops := dropsAlarm("drops-1", "62500")
	drops.ThresholdUnits = "mbs"
	created, err := alarmStore.CreateAlarm(ctx, &drops)
	require.NoError(t, err)
	assert.Equal(t, "pps", created.ThresholdUnits)

	cpu := cpuAlarm("cpu-1")
	cpu.ThresholdUnits = "pps"
	created, err = alarmStore.CreateAlarm(ctx, &cpu)
	require.NoError(t, err)
	assert.Equal(t, "percent", created.ThresholdUnits)

	load := model.Alarm{Name: "Load", Enabled: true, Metric: "load", MetricKey: "load1", Operator: "gt", Threshold: "4", Severity: "low", ThresholdUnits: "pps"}
	created, err = alarmStore.CreateAlarm(ctx, &load)
	require.NoError(t, err)
	assert.Equal(t, "", created.ThresholdUnits)

	update := dropsAlarm("drops-1", "1000")
	update.ThresholdUnits = ""
	updated, err := alarmStore.UpdateAlarm(ctx, "drops-1", &update)
	require.NoError(t, err)
	assert.Equal(t, "pps", updated.ThresholdUnits)

	stored := cfgStore.StoredAlarms()
	assert.Equal(t, "pps", stored[0].ThresholdUnits)
	assert.Equal(t, "1000", stored[0].Threshold)
	assert.Equal(t, "percent", stored[1].ThresholdUnits)
}

func TestAlarmstore_UserEdits_PersistConversion(t *testing.T) {
	ctx := context.Background()

	operations := map[string]func(*postgresmetrics.AlarmstoreImpl) error{
		"create": func(s *postgresmetrics.AlarmstoreImpl) error {
			alarm := cpuAlarm("cpu-new")
			_, err := s.CreateAlarm(ctx, &alarm)
			return err
		},
		"update": func(s *postgresmetrics.AlarmstoreImpl) error {
			alarm := cpuAlarm("cpu-1")
			alarm.Threshold = "90"
			_, err := s.UpdateAlarm(ctx, "cpu-1", &alarm)
			return err
		},
		"delete": func(s *postgresmetrics.AlarmstoreImpl) error {
			return s.DeleteAlarm(ctx, "cpu-1")
		},
	}

	for name, operation := range operations {
		t.Run(name+" of another alarm", func(t *testing.T) {
			cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), cpuAlarm("cpu-1")})
			mDB := new(mockdb.MockDB)
			mDB.On("Exec", mock.Anything, mock.MatchedBy(isStateDelete), mock.Anything).Return(nil)
			expectStateThresholdUpdate(mDB, "drops-1", "62500", nil)
			alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

			require.NoError(t, operation(alarmStore))
			assert.Equal(t, 1, countSaves(cfgStore))
			stored := cfgStore.StoredAlarms()
			assert.Equal(t, "62500", stored[0].Threshold)
			assert.Equal(t, "pps", stored[0].ThresholdUnits)
			assert.Equal(t, [][]any{{"62500", "drops-1"}}, stateThresholdUpdates(mDB))
		})

		t.Run(name+" succeeds when the state threshold update fails", func(t *testing.T) {
			h := captureAlarmLogs(t)
			cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), cpuAlarm("cpu-1")})
			mDB := new(mockdb.MockDB)
			mDB.On("Exec", mock.Anything, mock.MatchedBy(isStateDelete), mock.Anything).Return(nil)
			expectStateThresholdUpdate(mDB, "drops-1", "62500", errors.New("db error"))
			alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

			require.NoError(t, operation(alarmStore))
			assert.Equal(t, 1, countSaves(cfgStore))
			assert.Len(t, logEntriesWithField(h, log.ErrorLevel, "alarmId"), 1)
		})
	}

	t.Run("update of the unstamped alarm itself", func(t *testing.T) {
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), dropsAlarm("drops-2", "1")})
		mDB := new(mockdb.MockDB)
		expectStateThresholdUpdate(mDB, "drops-2", "125000", nil)
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		alarm := dropsAlarm("drops-1", "70000")
		_, err := alarmStore.UpdateAlarm(ctx, "drops-1", &alarm)
		require.NoError(t, err)
		assert.Equal(t, 1, countSaves(cfgStore))
		assert.Equal(t, [][]any{{"125000", "drops-2"}}, stateThresholdUpdates(mDB))
		assert.Equal(t, "70000", cfgStore.StoredAlarms()[0].Threshold)
	})

	t.Run("delete of the only converted alarm skips the state update", func(t *testing.T) {
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), cpuAlarm("cpu-1")})
		mDB := new(mockdb.MockDB)
		mDB.On("Exec", mock.Anything, mock.MatchedBy(isStateDelete), "drops-1").Return(nil)
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		require.NoError(t, alarmStore.DeleteAlarm(ctx, "drops-1"))
		assert.Equal(t, 1, countSaves(cfgStore))
		assert.Empty(t, stateThresholdUpdates(mDB))
		stored := cfgStore.StoredAlarms()
		require.Len(t, stored, 1)
		assert.Equal(t, "cpu-1", stored[0].ID)
	})

	t.Run("delete of the unstamped alarm itself", func(t *testing.T) {
		cfgStore := postgresmetrics.NewRecordingConfigstore([]model.Alarm{dropsAlarm("drops-1", "0.5"), dropsAlarm("drops-2", "1")})
		mDB := new(mockdb.MockDB)
		mDB.On("Exec", mock.Anything, mock.MatchedBy(isStateDelete), "drops-1").Return(nil)
		expectStateThresholdUpdate(mDB, "drops-2", "125000", nil)
		alarmStore := newNetDropsAlarmstore(cfgStore, mDB)

		require.NoError(t, alarmStore.DeleteAlarm(ctx, "drops-1"))
		assert.Equal(t, 1, countSaves(cfgStore))
		assert.Equal(t, [][]any{{"125000", "drops-2"}}, stateThresholdUpdates(mDB))
	})
}
