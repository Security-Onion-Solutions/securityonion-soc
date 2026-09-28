// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

var (
	ErrAlarmNotFound    = errors.New("alarm not found")
	ErrInvalidAlarmID   = errors.New("invalid alarm ID")
	ErrDuplicateAlarmID = errors.New("alarm with this ID already exists")
)

type Alarmstore interface {
	GetAlarms(ctx context.Context) ([]model.Alarm, error)
	GetAlarm(ctx context.Context, id string) (*model.Alarm, error)
	CreateAlarm(ctx context.Context, alarm *model.Alarm) (*model.Alarm, error)
	UpdateAlarm(ctx context.Context, id string, alarm *model.Alarm) (*model.Alarm, error)
	DeleteAlarm(ctx context.Context, id string) error
	GetAlarmStates(ctx context.Context) ([]model.AlarmState, error)
	GetAlarmMetrics(ctx context.Context) ([]model.AlarmMetricInfo, error)
	EvaluateAlarms(ctx context.Context) error
}
