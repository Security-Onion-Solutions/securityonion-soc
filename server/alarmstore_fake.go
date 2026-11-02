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

type FakeAlarmstore struct {
	Alarms   []model.Alarm
	States   []model.AlarmState
	Metrics  []model.AlarmMetricInfo
	Err      error
	Evaluated bool
}

func NewFakeAlarmstore() *FakeAlarmstore {
	return &FakeAlarmstore{
		Alarms:  make([]model.Alarm, 0),
		States:  make([]model.AlarmState, 0),
		Metrics: make([]model.AlarmMetricInfo, 0),
	}
}

func (f *FakeAlarmstore) GetAlarms(ctx context.Context) ([]model.Alarm, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Alarms, nil
}

func (f *FakeAlarmstore) GetAlarm(ctx context.Context, id string) (*model.Alarm, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	for _, a := range f.Alarms {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, errors.New("alarm not found")
}

func (f *FakeAlarmstore) CreateAlarm(ctx context.Context, alarm *model.Alarm) (*model.Alarm, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if alarm == nil {
		return nil, errors.New("alarm cannot be nil")
	}
	if alarm.ID == "" {
		alarm.ID = "generated-alarm-id"
	}
	f.Alarms = append(f.Alarms, *alarm)
	return alarm, nil
}

func (f *FakeAlarmstore) UpdateAlarm(ctx context.Context, id string, alarm *model.Alarm) (*model.Alarm, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	for i, a := range f.Alarms {
		if a.ID == id {
			alarm.ID = id
			f.Alarms[i] = *alarm
			return alarm, nil
		}
	}
	return nil, errors.New("alarm not found")
}

func (f *FakeAlarmstore) DeleteAlarm(ctx context.Context, id string) error {
	if f.Err != nil {
		return f.Err
	}
	for i, a := range f.Alarms {
		if a.ID == id {
			f.Alarms = append(f.Alarms[:i], f.Alarms[i+1:]...)
			var remainingStates []model.AlarmState
			for _, s := range f.States {
				if s.AlarmID != id {
					remainingStates = append(remainingStates, s)
				}
			}
			f.States = remainingStates
			return nil
		}
	}
	return errors.New("alarm not found")
}

func (f *FakeAlarmstore) GetAlarmStates(ctx context.Context) ([]model.AlarmState, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.States, nil
}

func (f *FakeAlarmstore) GetAlarmMetrics(ctx context.Context) ([]model.AlarmMetricInfo, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Metrics, nil
}

func (f *FakeAlarmstore) EvaluateAlarms(ctx context.Context) error {
	if f.Err != nil {
		return f.Err
	}
	f.Evaluated = true
	return nil
}
