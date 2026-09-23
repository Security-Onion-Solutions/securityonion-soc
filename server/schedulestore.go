// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

const (
	ConfigSettingServerSchedules = "soc.config.server.schedules"
)

var (
	ErrScheduleNotFound    = errors.New("schedule not found")
	ErrInvalidScheduleID   = errors.New("invalid schedule ID")
	ErrDuplicateScheduleID = errors.New("schedule with this ID already exists")
)

type Schedulestore interface {
	GetSchedules(ctx context.Context) ([]model.Schedule, error)
	GetSchedule(ctx context.Context, id string) (*model.Schedule, error)
	CreateSchedule(ctx context.Context, schedule *model.Schedule) (*model.Schedule, error)
	UpdateSchedule(ctx context.Context, id string, schedule *model.Schedule) (*model.Schedule, error)
	DeleteSchedule(ctx context.Context, id string) error
	EvaluateSchedule(ctx context.Context, schedule *model.Schedule, evalTime time.Time) (bool, error)
	IsScheduleActive(ctx context.Context, scheduleID string, evalTime time.Time) (bool, error)
}

//go:generate mockgen -destination mock/mock_schedulestore.go -package mock . Schedulestore

type SchedulestoreImpl struct {
	server *Server
}

func NewSchedulestore(srv *Server) *SchedulestoreImpl {
	return &SchedulestoreImpl{
		server: srv,
	}
}

func (s *SchedulestoreImpl) getConfigstore() Configstore {
	if s.server != nil {
		return s.server.Configstore
	}
	return nil
}

func (s *SchedulestoreImpl) checkAuth(ctx context.Context, op string) error {
	if s.server != nil {
		return s.server.CheckAuthorized(ctx, op, "config")
	}
	return nil
}

func (s *SchedulestoreImpl) loadSchedulesRaw(ctx context.Context) ([]model.Schedule, error) {
	store := s.getConfigstore()
	if store == nil {
		return []model.Schedule{}, nil
	}
	setting, err := store.GetSetting(ctx, ConfigSettingServerSchedules)
	if err != nil {
		return nil, err
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return []model.Schedule{}, nil
	}
	return model.UnmarshalSchedules(setting.Value)
}

func (s *SchedulestoreImpl) saveSchedules(ctx context.Context, schedules []model.Schedule) error {
	store := s.getConfigstore()
	if store == nil {
		return errors.New("config store not available")
	}
	valBytes, err := json.Marshal(schedules)
	if err != nil {
		return err
	}
	setting := &model.Setting{
		Id:    ConfigSettingServerSchedules,
		Value: string(valBytes),
	}
	return store.UpdateSetting(ctx, setting, false)
}

func (s *SchedulestoreImpl) GetSchedules(ctx context.Context) ([]model.Schedule, error) {
	if err := s.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}
	return s.loadSchedulesRaw(ctx)
}

func (s *SchedulestoreImpl) GetSchedule(ctx context.Context, id string) (*model.Schedule, error) {
	if err := s.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}

	if !model.IsValidScheduleID(id) {
		return nil, ErrInvalidScheduleID
	}

	schedules, err := s.loadSchedulesRaw(ctx)
	if err != nil {
		return nil, err
	}

	for _, sched := range schedules {
		if sched.ID == id {
			return &sched, nil
		}
	}

	return nil, ErrScheduleNotFound
}

func (s *SchedulestoreImpl) CreateSchedule(ctx context.Context, schedule *model.Schedule) (*model.Schedule, error) {
	if err := s.checkAuth(ctx, "write"); err != nil {
		return nil, err
	}

	if schedule == nil {
		return nil, errors.New("schedule cannot be nil")
	}

	if err := model.ValidateScheduleName(schedule.Name); err != nil {
		return nil, err
	}

	if err := model.ValidateScheduleDescription(schedule.Description); err != nil {
		return nil, err
	}

	if schedule.ID == "" {
		schedule.ID = uuid.NewString()
	} else if !model.IsValidScheduleID(schedule.ID) {
		return nil, ErrInvalidScheduleID
	}

	schedules, err := s.loadSchedulesRaw(ctx)
	if err != nil {
		return nil, err
	}

	for _, existing := range schedules {
		if existing.ID == schedule.ID {
			return nil, ErrDuplicateScheduleID
		}
	}

	if err := model.ValidateScheduleDAG(schedule, schedules); err != nil {
		return nil, err
	}

	schedules = append(schedules, *schedule)
	if err := s.saveSchedules(ctx, schedules); err != nil {
		return nil, err
	}

	return schedule, nil
}

func (s *SchedulestoreImpl) UpdateSchedule(ctx context.Context, id string, schedule *model.Schedule) (*model.Schedule, error) {
	if err := s.checkAuth(ctx, "write"); err != nil {
		return nil, err
	}

	if schedule == nil {
		return nil, errors.New("schedule cannot be nil")
	}

	if !model.IsValidScheduleID(id) {
		return nil, ErrInvalidScheduleID
	}

	if err := model.ValidateScheduleName(schedule.Name); err != nil {
		return nil, err
	}

	if err := model.ValidateScheduleDescription(schedule.Description); err != nil {
		return nil, err
	}

	schedule.ID = id

	schedules, err := s.loadSchedulesRaw(ctx)
	if err != nil {
		return nil, err
	}

	foundIndex := -1
	for i, existing := range schedules {
		if existing.ID == id {
			foundIndex = i
			break
		}
	}

	if foundIndex == -1 {
		return nil, ErrScheduleNotFound
	}

	if err := model.ValidateScheduleDAG(schedule, schedules); err != nil {
		return nil, err
	}

	schedules[foundIndex] = *schedule
	if err := s.saveSchedules(ctx, schedules); err != nil {
		return nil, err
	}

	return schedule, nil
}

func (s *SchedulestoreImpl) DeleteSchedule(ctx context.Context, id string) error {
	if err := s.checkAuth(ctx, "write"); err != nil {
		return err
	}

	if !model.IsValidScheduleID(id) {
		return ErrInvalidScheduleID
	}

	schedules, err := s.loadSchedulesRaw(ctx)
	if err != nil {
		return err
	}

	foundIndex := -1
	for i, existing := range schedules {
		if existing.ID == id {
			foundIndex = i
			break
		}
	}

	if foundIndex == -1 {
		return ErrScheduleNotFound
	}

	schedules = append(schedules[:foundIndex], schedules[foundIndex+1:]...)
	return s.saveSchedules(ctx, schedules)
}

func (s *SchedulestoreImpl) EvaluateSchedule(ctx context.Context, schedule *model.Schedule, evalTime time.Time) (bool, error) {
	if err := s.checkAuth(ctx, "read"); err != nil {
		return false, err
	}

	if schedule == nil {
		return false, errors.New("schedule cannot be nil")
	}

	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	schedules, _ := s.loadSchedulesRaw(ctx)
	lookup := model.BuildScheduleLookup(schedules)
	if schedule.ID != "" {
		lookup[schedule.ID] = schedule
	}

	return model.IsScheduleActive(schedule, evalTime, lookup)
}

func (s *SchedulestoreImpl) IsScheduleActive(ctx context.Context, scheduleID string, evalTime time.Time) (bool, error) {
	if scheduleID == "" {
		return true, nil
	}

	schedules, err := s.loadSchedulesRaw(ctx)
	if err != nil || len(schedules) == 0 {
		return true, err
	}

	active, _ := model.IsScheduleIDActive(schedules, scheduleID, evalTime)
	return active, nil
}

// IsScheduleActiveInConfig checks if a given schedule ID is active according to the schedules stored in Configstore.
// If scheduleID is empty, store is nil, or schedule data is missing/corrupt, it fails open and returns (true, ...).
func IsScheduleActiveInConfig(ctx context.Context, store Configstore, scheduleID string, evalTime time.Time) (bool, error) {
	if scheduleID == "" || store == nil {
		return true, nil
	}
	setting, err := store.GetSetting(ctx, ConfigSettingServerSchedules)
	if err != nil {
		return true, err
	}
	if setting == nil || setting.Value == "" {
		return true, nil
	}
	schedules, err := model.UnmarshalSchedules(setting.Value)
	if err != nil {
		return true, err
	}
	active, _ := model.IsScheduleIDActive(schedules, scheduleID, evalTime)
	return active, nil
}
