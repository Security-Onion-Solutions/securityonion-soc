// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
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
