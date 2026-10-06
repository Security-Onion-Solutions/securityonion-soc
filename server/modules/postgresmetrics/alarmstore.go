// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
)

const (
	ConfigSettingPostgresMetricsAlarms    = "soc.config.server.modules.postgresmetrics.alarms"
	MAX_CONTAINER_METRIC_LOOKBACK_SECONDS = 300
)

var (
	ErrAlarmNotFound    = server.ErrAlarmNotFound
	ErrInvalidAlarmID   = server.ErrInvalidAlarmID
	ErrDuplicateAlarmID = server.ErrDuplicateAlarmID
)

type AlarmstoreImpl struct {
	server  *server.Server
	dbStore *database.Store
	evalMu  sync.Mutex
	mu      sync.Mutex
}

func NewAlarmstore(srv *server.Server, dbStore *database.Store) *AlarmstoreImpl {
	return &AlarmstoreImpl{
		server:  srv,
		dbStore: dbStore,
	}
}

func (s *AlarmstoreImpl) getConfigstore() server.Configstore {
	if s.server != nil {
		return s.server.Configstore
	}
	return nil
}

func (s *AlarmstoreImpl) getDBStore(ctx context.Context) *database.Store {
	if s.dbStore != nil {
		return s.dbStore
	}
	if s.server != nil && s.server.DB != nil {
		st := database.New(s.server.DB)
		readCtx := ctx
		if readCtx == nil {
			readCtx = context.Background()
		}
		if s.server.Context != nil {
			readCtx = s.server.Context
		}
		if err := st.Migrate(readCtx); err != nil {
			log.Warnf("postgresmetrics: alarm database migration warning: %v", err)
		}
		s.dbStore = st
		return s.dbStore
	}
	return nil
}

func (s *AlarmstoreImpl) checkReadAuth(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	if err := s.server.CheckAuthorized(ctx, "read", "grid"); err == nil {
		return nil
	}
	if err := s.server.CheckAuthorized(ctx, "read", "node"); err == nil {
		return nil
	}
	return s.server.CheckAuthorized(ctx, "read", "nodes")
}

func (s *AlarmstoreImpl) checkWriteAuth(ctx context.Context) error {
	if s.server != nil {
		return s.server.CheckAuthorized(ctx, "write", "config")
	}
	return nil
}

func (s *AlarmstoreImpl) loadAlarmsRaw(ctx context.Context) ([]model.Alarm, error) {
	store := s.getConfigstore()
	if store == nil {
		return []model.Alarm{}, nil
	}
	readCtx := ctx
	if s.server != nil && s.server.Context != nil {
		readCtx = s.server.Context
	}
	setting, err := store.GetSetting(readCtx, ConfigSettingPostgresMetricsAlarms)
	if err != nil {
		return nil, err
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return []model.Alarm{}, nil
	}
	return model.UnmarshalAlarms(setting.Value)
}

func (s *AlarmstoreImpl) saveAlarms(ctx context.Context, alarms []model.Alarm) error {
	store := s.getConfigstore()
	if store == nil {
		return fmt.Errorf("config store not available")
	}
	valBytes, err := json.Marshal(alarms)
	if err != nil {
		return err
	}
	setting := &model.Setting{
		Id:    ConfigSettingPostgresMetricsAlarms,
		Value: string(valBytes),
	}
	return store.UpdateSetting(ctx, setting, false)
}

func (s *AlarmstoreImpl) GetAlarms(ctx context.Context) ([]model.Alarm, error) {
	if err := s.checkReadAuth(ctx); err != nil {
		return nil, err
	}
	return s.loadAlarmsRaw(ctx)
}

func (s *AlarmstoreImpl) GetAlarm(ctx context.Context, id string) (*model.Alarm, error) {
	if !model.IsValidAlarmID(id) {
		return nil, ErrInvalidAlarmID
	}

	alarms, err := s.GetAlarms(ctx)
	if err != nil {
		return nil, err
	}

	for _, alarm := range alarms {
		if alarm.ID == id {
			return &alarm, nil
		}
	}

	return nil, ErrAlarmNotFound
}

func (s *AlarmstoreImpl) CreateAlarm(ctx context.Context, alarm *model.Alarm) (*model.Alarm, error) {
	if err := s.checkWriteAuth(ctx); err != nil {
		return nil, err
	}

	if alarm == nil {
		return nil, fmt.Errorf("alarm cannot be nil")
	}

	if alarm.ID == "" {
		alarm.ID = uuid.NewString()
	} else if !model.IsValidAlarmID(alarm.ID) {
		return nil, ErrInvalidAlarmID
	}

	alarm.Operator = model.NormalizeOperator(alarm.Operator)

	if err := model.ValidateAlarm(alarm); err != nil {
		return nil, err
	}

	if err := ValidateAlarmThreshold(alarm.Metric, alarm.Threshold); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	alarms, err := s.loadAlarmsRaw(ctx)
	if err != nil {
		return nil, err
	}

	for _, existing := range alarms {
		if existing.ID == alarm.ID {
			return nil, ErrDuplicateAlarmID
		}
	}

	alarms = append(alarms, *alarm)
	if err := s.saveAlarms(ctx, alarms); err != nil {
		return nil, err
	}

	return alarm, nil
}

func (s *AlarmstoreImpl) UpdateAlarm(ctx context.Context, id string, alarm *model.Alarm) (*model.Alarm, error) {
	if err := s.checkWriteAuth(ctx); err != nil {
		return nil, err
	}

	if !model.IsValidAlarmID(id) {
		return nil, ErrInvalidAlarmID
	}

	if alarm == nil {
		return nil, fmt.Errorf("alarm cannot be nil")
	}

	alarm.ID = id
	alarm.Operator = model.NormalizeOperator(alarm.Operator)

	if err := model.ValidateAlarm(alarm); err != nil {
		return nil, err
	}

	if err := ValidateAlarmThreshold(alarm.Metric, alarm.Threshold); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	alarms, err := s.loadAlarmsRaw(ctx)
	if err != nil {
		return nil, err
	}

	foundIdx := -1
	for idx, existing := range alarms {
		if existing.ID == id {
			foundIdx = idx
			break
		}
	}

	if foundIdx == -1 {
		return nil, ErrAlarmNotFound
	}

	alarms[foundIdx] = *alarm
	if err := s.saveAlarms(ctx, alarms); err != nil {
		return nil, err
	}

	if !alarm.Enabled {
		if dbStore := s.getDBStore(ctx); dbStore != nil {
			_ = dbStore.DeleteAlarmStatesForAlarm(ctx, id)
		}
	}

	return alarm, nil
}

func (s *AlarmstoreImpl) DeleteAlarm(ctx context.Context, id string) error {
	if err := s.checkWriteAuth(ctx); err != nil {
		return err
	}

	if !model.IsValidAlarmID(id) {
		return ErrInvalidAlarmID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	alarms, err := s.loadAlarmsRaw(ctx)
	if err != nil {
		return err
	}

	foundIdx := -1
	for idx, existing := range alarms {
		if existing.ID == id {
			foundIdx = idx
			break
		}
	}

	if foundIdx == -1 {
		return ErrAlarmNotFound
	}

	alarms = append(alarms[:foundIdx], alarms[foundIdx+1:]...)
	if err := s.saveAlarms(ctx, alarms); err != nil {
		return err
	}

	if dbStore := s.getDBStore(ctx); dbStore != nil {
		_ = dbStore.DeleteAlarmStatesForAlarm(ctx, id)
	}

	return nil
}

func (s *AlarmstoreImpl) GetAlarmStates(ctx context.Context) ([]model.AlarmState, error) {
	if err := s.checkReadAuth(ctx); err != nil {
		return nil, err
	}
	dbStore := s.getDBStore(ctx)
	if dbStore == nil {
		return []model.AlarmState{}, nil
	}
	return dbStore.GetAlarmStates(ctx)
}

func (s *AlarmstoreImpl) GetAlarmMetrics(ctx context.Context) ([]model.AlarmMetricInfo, error) {
	if err := s.checkReadAuth(ctx); err != nil {
		return nil, err
	}
	return DefaultAlarmMetrics(), nil
}

func (s *AlarmstoreImpl) GetContainerLookbackDuration() time.Duration {
	maxAge := DEFAULT_MAX_METRIC_AGE_SECONDS
	if s.server != nil && s.server.Metrics != nil {
		if pm, ok := s.server.Metrics.(*PostgresMetrics); ok && pm.GetMaxMetricAgeSeconds() > 0 {
			maxAge = pm.GetMaxMetricAgeSeconds()
		}
	}

	if maxAge > MAX_CONTAINER_METRIC_LOOKBACK_SECONDS {
		return time.Duration(MAX_CONTAINER_METRIC_LOOKBACK_SECONDS) * time.Second
	}
	if maxAge > 1 {
		return time.Duration(maxAge-1) * time.Second
	}
	return time.Duration(maxAge) * time.Second
}

func (s *AlarmstoreImpl) EvaluateAlarms(ctx context.Context) error {
	s.evalMu.Lock()
	defer s.evalMu.Unlock()

	alarms, err := s.loadAlarmsRaw(ctx)
	if err != nil {
		return err
	}

	if len(alarms) == 0 {
		return nil
	}

	dbStore := s.getDBStore(ctx)

	var nodes []*model.Node
	if s.server != nil && s.server.Datastore != nil {
		nodes = s.server.Datastore.GetNodes(ctx)
	}

	now := time.Now().UTC()

	for _, alarm := range alarms {
		if !alarm.Enabled {
			if dbStore != nil {
				_ = dbStore.DeleteAlarmStatesForAlarm(ctx, alarm.ID)
			}
			continue
		}

		targetNodes := nodes
		if alarm.NodeID != "" && alarm.NodeID != "all" {
			targetNodes = nil
			for _, n := range nodes {
				if n.Id == alarm.NodeID {
					targetNodes = append(targetNodes, n)
					break
				}
			}
		}

		for _, node := range targetNodes {
			var val any
			var valStr string
			var breached bool

			if IsContainerMetric(alarm.Metric) {
				if s.server == nil || s.server.Metrics == nil {
					continue
				}
				lookback := s.GetContainerLookbackDuration()
				samples, err := s.server.Metrics.GetTimeSeriesMetrics(ctx, node.Id, "", alarm.Metric, now.Add(-lookback), now)
				if err != nil || len(samples) == 0 {
					continue
				}

				var foundContainer bool
				var containerBreached bool
				var maxVal float64
				var breachVal float64
				var breachContainer string

				for containerName, metricList := range samples {
					if len(metricList) == 0 {
						continue
					}
					latestSample := metricList[len(metricList)-1]
					sampleVal := latestSample.Value
					if !foundContainer || sampleVal > maxVal {
						maxVal = sampleVal
					}
					foundContainer = true

					if EvaluateCondition(alarm.Operator, alarm.Threshold, sampleVal) {
						containerBreached = true
						breachVal = sampleVal
						breachContainer = containerName
						break
					}
				}

				if !foundContainer {
					continue
				}

				breached = containerBreached
				if breached {
					val = breachVal
					valStr = fmt.Sprintf("%s: %v", breachContainer, breachVal)
				} else {
					val = maxVal
					valStr = fmt.Sprintf("%v", maxVal)
				}
			} else {
				nodeVal, found := ExtractMetricValue(node, alarm.Metric, alarm.MetricKey)
				if !found {
					continue
				}
				val = nodeVal
				valStr = fmt.Sprintf("%v", val)
				breached = EvaluateCondition(alarm.Operator, alarm.Threshold, val)
			}

			var state *model.AlarmState
			if dbStore != nil {
				var err error
				state, err = dbStore.GetAlarmState(ctx, alarm.ID, node.Id)
				if err != nil {
					log.FromContext(ctx).WithError(err).WithField("alarmId", alarm.ID).WithField("nodeId", node.Id).Warn("failed to get alarm state from database; skipping evaluation cycle for node")
					continue
				}
			}

			if breached {
				if state == nil {
					state = &model.AlarmState{
						AlarmID:         alarm.ID,
						NodeID:          node.Id,
						Status:          model.AlarmStatusOk,
						FirstBreachedAt: &now,
						Metric:          alarm.Metric,
						MetricKey:       alarm.MetricKey,
						Operator:        alarm.Operator,
						Threshold:       alarm.Threshold,
						CurrentValue:    valStr,
						LastEvaluated:   now,
					}
				} else if state.FirstBreachedAt == nil {
					state.FirstBreachedAt = &now
				}

				breachDuration := now.Sub(*state.FirstBreachedAt)
				requiredDuration := time.Duration(alarm.DurationSeconds) * time.Second

				if breachDuration >= requiredDuration {
					if state.Status != model.AlarmStatusActive {
						state.Status = model.AlarmStatusActive
						state.TriggeredAt = &now
						state.ClearedAt = nil
						s.triggerAlarmNotification(ctx, &alarm, node.Id, valStr, int(breachDuration.Seconds()))
					}
					if state.TriggeredAt != nil {
						state.DurationActiveSeconds = int(now.Sub(*state.TriggeredAt).Seconds())
					}
				}

				state.CurrentValue = valStr
				state.LastEvaluated = now
				if dbStore != nil {
					_ = dbStore.UpsertAlarmState(ctx, state)
				}
				s.broadcastAlarmState(state)
			} else {
				if state != nil && state.Status == model.AlarmStatusActive {
					state.Status = model.AlarmStatusOk
					state.ClearedAt = &now
					state.FirstBreachedAt = nil
					s.triggerClearedNotification(ctx, &alarm, node.Id, valStr, state.DurationActiveSeconds)
					state.CurrentValue = valStr
					state.LastEvaluated = now
					if dbStore != nil {
						_ = dbStore.UpsertAlarmState(ctx, state)
					}
					s.broadcastAlarmState(state)
				} else if state != nil && state.FirstBreachedAt != nil {
					state.FirstBreachedAt = nil
					state.CurrentValue = valStr
					state.LastEvaluated = now
					if dbStore != nil {
						_ = dbStore.UpsertAlarmState(ctx, state)
					}
					s.broadcastAlarmState(state)
				}
			}
		}
	}

	return nil
}

func (s *AlarmstoreImpl) triggerAlarmNotification(ctx context.Context, alarm *model.Alarm, nodeID string, currentValue string, durationSeconds int) {
	if s.server == nil || s.server.Notifier == nil {
		return
	}

	summary := alarm.Note
	if strings.TrimSpace(summary) == "" {
		summary = fmt.Sprintf("Alarm %s condition detected on node %s: %s %s %s", alarm.Name, nodeID, alarm.Metric, alarm.Operator, alarm.Threshold)
	}

	durStr := fmt.Sprintf("%ds", durationSeconds)

	payload := &model.NotificationPayload{
		ID:        uuid.NewString(),
		Source:    model.SourceMetric,
		Title:     "🔴 " + alarm.Name,
		Summary:   summary,
		Severity:  alarm.Severity,
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"Node":      nodeID,
			"Metric":    alarm.Metric,
			"Operator":  alarm.Operator,
			"Threshold": alarm.Threshold,
			"Value":     currentValue,
			"Duration":  durStr,
			"Status":    "true",
		},
		Links: map[string]string{
			"SOC": fmt.Sprintf("/#/grid?tab=metrics&nodeId=%s", url.QueryEscape(nodeID)),
		},
		Recipients: alarm.Recipients,
		SilenceKey: fmt.Sprintf("alarm:%s:%s", alarm.ID, nodeID),
	}

	_, _ = s.server.Notifier.Send(ctx, payload, alarm.Destinations...)
}

func (s *AlarmstoreImpl) triggerClearedNotification(ctx context.Context, alarm *model.Alarm, nodeID string, currentValue string, durationActiveSeconds int) {
	if s.server == nil || s.server.Notifier == nil {
		return
	}

	clearedSev := strings.ToLower(strings.TrimSpace(alarm.ClearedSeverity))
	if clearedSev == "" || clearedSev == "none" {
		return
	}

	summary := alarm.Note
	if strings.TrimSpace(summary) == "" {
		summary = fmt.Sprintf("Alarm %s condition has cleared on node %s (current value: %s)", alarm.Name, nodeID, currentValue)
	}

	durStr := fmt.Sprintf("%ds", durationActiveSeconds)

	payload := &model.NotificationPayload{
		ID:        uuid.NewString(),
		Source:    model.SourceMetric,
		Title:     "🟢 " + alarm.Name,
		Summary:   summary,
		Severity:  clearedSev,
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"Node":      nodeID,
			"Metric":    alarm.Metric,
			"Operator":  alarm.Operator,
			"Threshold": alarm.Threshold,
			"Value":     currentValue,
			"Duration":  durStr,
			"Status":    "false",
		},
		Links: map[string]string{
			"SOC": fmt.Sprintf("/#/grid?tab=metrics&nodeId=%s", url.QueryEscape(nodeID)),
		},
		Recipients: alarm.Recipients,
		SilenceKey: fmt.Sprintf("alarm:%s:%s:cleared", alarm.ID, nodeID),
	}

	_, _ = s.server.Notifier.Send(ctx, payload, alarm.Destinations...)
}

func (s *AlarmstoreImpl) broadcastAlarmState(state *model.AlarmState) {
	if state == nil || s.server == nil || s.server.Host == nil {
		return
	}
	s.server.Host.Broadcast("alarm:state", "nodes", state)
}
