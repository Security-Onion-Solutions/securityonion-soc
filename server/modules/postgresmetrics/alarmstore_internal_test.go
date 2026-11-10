// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlarmstore_TriggerNotificationFields(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	fakeNotifier := &server.FakeNotifier{}
	srv := &server.Server{
		Notifier: fakeNotifier,
	}
	store := NewAlarmstore(srv, nil)

	alarm := &model.Alarm{
		ID:              "alarm-triggered-test",
		Name:            "CPU High",
		Metric:          "cpu",
		Operator:        "gt",
		Threshold:       "80",
		Severity:        "high",
		ClearedSeverity: "info",
	}

	ctx := context.Background()

	// 1. Trigger alarm notification -> Triggered must be "true"
	store.triggerAlarmNotification(ctx, alarm, "node-1", "95", 120)
	require.Len(t, fakeNotifier.InputPayloads, 1)
	assert.Equal(t, "true", fakeNotifier.InputPayloads[0].Fields["Triggered"])
	assert.NotContains(t, fakeNotifier.InputPayloads[0].Fields, "Status")

	// 2. Trigger cleared notification -> Triggered must be "false"
	store.triggerClearedNotification(ctx, alarm, "node-1", "45", 300)
	require.Len(t, fakeNotifier.InputPayloads, 2)
	assert.Equal(t, "false", fakeNotifier.InputPayloads[1].Fields["Triggered"])
	assert.NotContains(t, fakeNotifier.InputPayloads[1].Fields, "Status")
}

type unsupportedMetricDatastore struct {
	server.Datastore
	nodes []*model.Node
}

func (f *unsupportedMetricDatastore) GetNodes(ctx context.Context) []*model.Node {
	return f.nodes
}

func TestAlarmstore_EvaluateAlarms_UnsupportedMetricWarnsOnce(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	alarmsJSON, _ := json.Marshal([]model.Alarm{{
		ID:        "alarm-failed-events",
		Name:      "Failed Events",
		Enabled:   true,
		Metric:    "failed_events",
		Operator:  "gt",
		Threshold: "0",
		Severity:  "high",
	}})
	fakeNotifier := &server.FakeNotifier{}
	srv := &server.Server{
		Configstore: server.NewMemConfigStore([]*model.Setting{{Id: ConfigSettingPostgresMetricsAlarms, Value: string(alarmsJSON)}}),
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Notifier:    fakeNotifier,
		Datastore:   &unsupportedMetricDatastore{nodes: []*model.Node{{Id: "node-1"}}},
	}
	store := NewAlarmstore(srv, nil)

	handler := memory.New()
	ctx := log.NewContext(context.Background(), &log.Logger{Handler: handler, Level: log.DebugLevel})

	require.NoError(t, store.EvaluateAlarms(ctx))
	require.NoError(t, store.EvaluateAlarms(ctx))

	assert.Empty(t, fakeNotifier.InputPayloads)
	assert.True(t, store.unsupportedWarned["alarm-failed-events"])

	warnings := 0
	for _, entry := range handler.Entries {
		if entry.Message == "alarm references an unsupported metric; skipping" {
			warnings++
			assert.Equal(t, log.WarnLevel, entry.Level)
			assert.Equal(t, "alarm-failed-events", entry.Fields["alarmId"])
			assert.Equal(t, "failed_events", entry.Fields["alarmMetric"])
			assert.Equal(t, "", entry.Fields["alarmMetricKey"])
		}
	}
	assert.Equal(t, 1, warnings)
}
