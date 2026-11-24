// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

// RecordingConfigstore is exported for the external alarm store tests.
type RecordingConfigstore struct {
	server.Configstore
	mu        sync.Mutex
	calls     []string
	saved     []string
	FailSaves int
}

func NewRecordingConfigstore(alarms []model.Alarm) *RecordingConfigstore {
	raw, _ := json.Marshal(alarms)
	return &RecordingConfigstore{
		Configstore: server.NewMemConfigStore([]*model.Setting{
			{Id: ConfigSettingPostgresMetricsAlarms, Value: string(raw)},
		}),
	}
}

func (r *RecordingConfigstore) GetSetting(ctx context.Context, id string) (*model.Setting, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "load")
	setting, err := r.Configstore.GetSetting(ctx, id)
	if setting == nil || err != nil {
		return setting, err
	}
	copied := *setting
	return &copied, nil
}

func (r *RecordingConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "save")
	if r.FailSaves > 0 {
		r.FailSaves--
		return errors.New("save failed")
	}
	r.saved = append(r.saved, setting.Value)
	return r.Configstore.UpdateSetting(ctx, setting, remove)
}

func (r *RecordingConfigstore) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

func (r *RecordingConfigstore) Saved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.saved...)
}

func (r *RecordingConfigstore) StoredAlarms() []model.Alarm {
	r.mu.Lock()
	defer r.mu.Unlock()
	setting, _ := r.Configstore.GetSetting(context.Background(), ConfigSettingPostgresMetricsAlarms)
	alarms, _ := model.UnmarshalAlarms(setting.Value)
	return alarms
}

func runEvaluationLoopUntil(t *testing.T, cfgStore *RecordingConfigstore, minCalls int) []string {
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
		Context:     context.Background(),
	}
	mod := &PostgresMetricsModule{
		server:             srv,
		alarmStore:         NewAlarmstore(srv, nil),
		evaluationInterval: 5 * time.Millisecond,
		stopChan:           make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		mod.evaluationLoop()
		close(done)
	}()

	assert.Eventually(t, func() bool { return len(cfgStore.Calls()) >= minCalls }, 2*time.Second, time.Millisecond)
	close(mod.stopChan)
	<-done
	return cfgStore.Calls()
}

func unstampedNetDropsAlarm() model.Alarm {
	return model.Alarm{
		ID:        "alarm-drops",
		Name:      "Drops",
		Enabled:   true,
		Metric:    "net_drops",
		Operator:  "gt",
		Threshold: "0.5",
		Severity:  "high",
	}
}

func TestEvaluationLoop_SavesConvertedThresholdsBeforeEvaluating(t *testing.T) {
	cfgStore := NewRecordingConfigstore([]model.Alarm{unstampedNetDropsAlarm()})

	calls := runEvaluationLoopUntil(t, cfgStore, 3)
	assert.Equal(t, []string{"load", "save", "load"}, calls[:3])

	stored := cfgStore.StoredAlarms()
	assert.Equal(t, "62500", stored[0].Threshold)
	assert.Equal(t, "pps", stored[0].ThresholdUnits)
}

func TestEvaluationLoop_EvaluatesWhenSaveFails(t *testing.T) {
	cfgStore := NewRecordingConfigstore([]model.Alarm{unstampedNetDropsAlarm()})
	cfgStore.FailSaves = 1

	calls := runEvaluationLoopUntil(t, cfgStore, 5)
	assert.Equal(t, []string{"load", "save", "load", "load", "save"}, calls[:5])
	assert.Len(t, cfgStore.Saved(), 1)
}
