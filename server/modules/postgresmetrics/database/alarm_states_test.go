// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database_test

import (
	"context"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestStore_Migrate(t *testing.T) {
	t.Run("nil db", func(t *testing.T) {
		s := database.New(nil)
		err := s.Migrate(context.Background())
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		mDB := new(mockdb.MockDB)
		mDB.On("Migrate", mock.Anything, mock.Anything, "postgresmetrics").Return(nil).Once()
		s := database.New(mDB)
		err := s.Migrate(context.Background())
		assert.NoError(t, err)
		mDB.AssertExpectations(t)
	})
}

func TestStore_UpsertAlarmState(t *testing.T) {
	t.Run("nil state", func(t *testing.T) {
		s := database.New(nil)
		err := s.UpsertAlarmState(context.Background(), nil)
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		mDB := new(mockdb.MockDB)
		s := database.New(mDB)

		now := time.Now().UTC()
		state := &model.AlarmState{
			AlarmID:               "alarm-1",
			NodeID:                "node-1",
			Status:                "alarm",
			CurrentValue:          "85.5",
			Threshold:             "80",
			Operator:              "gt",
			Metric:                "cpu",
			MetricKey:             "cpu_used",
			TriggeredAt:           &now,
			ClearedAt:             nil,
			FirstBreachedAt:       &now,
			DurationActiveSeconds: 120,
			LastEvaluated:         now,
		}

		mDB.On("Exec", mock.Anything, mock.Anything,
			state.AlarmID, state.NodeID, state.Status, state.CurrentValue,
			state.Threshold, state.Operator, state.Metric, state.MetricKey,
			state.TriggeredAt, state.ClearedAt, state.FirstBreachedAt,
			state.DurationActiveSeconds, mock.Anything, mock.Anything,
		).Return(nil).Once()

		err := s.UpsertAlarmState(context.Background(), state)
		assert.NoError(t, err)
		mDB.AssertExpectations(t)
	})
}

func TestStore_GetAlarmStates(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := database.New(mDB)

	mockRows := new(mockdb.MockRows)
	mDB.On("Query", mock.Anything, mock.Anything).Return(mockRows, nil).Once()

	now := time.Now().UTC()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		*args.Get(0).(*string) = "alarm-1"
		*args.Get(1).(*string) = "node-1"
		*args.Get(2).(*string) = "alarm"
		*args.Get(3).(*string) = "85.5"
		*args.Get(4).(*string) = "80"
		*args.Get(5).(*string) = "gt"
		*args.Get(6).(*string) = "cpu"
		*args.Get(7).(*string) = "cpu_used"
		*args.Get(8).(**time.Time) = &now
		*args.Get(9).(**time.Time) = nil
		*args.Get(10).(**time.Time) = &now
		*args.Get(11).(*int) = 120
		*args.Get(12).(*time.Time) = now
		*args.Get(13).(*time.Time) = now
	}).Return(nil).Once()

	mockRows.On("Next").Return(false).Once()
	mockRows.On("Err").Return(nil).Once()
	mockRows.On("Close").Return(nil).Once()

	states, err := s.GetAlarmStates(context.Background())
	assert.NoError(t, err)
	assert.Len(t, states, 1)
	assert.Equal(t, "alarm-1", states[0].AlarmID)
	assert.Equal(t, "node-1", states[0].NodeID)
	assert.Equal(t, "alarm", states[0].Status)
	mDB.AssertExpectations(t)
	mockRows.AssertExpectations(t)
}

func TestStore_GetAlarmState(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := database.New(mDB)

	mockRow := new(mockdb.MockRow)
	mDB.On("QueryRow", mock.Anything, mock.Anything, "alarm-1", "node-1").Return(mockRow).Once()

	now := time.Now().UTC()
	mockRow.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		*args.Get(0).(*string) = "alarm-1"
		*args.Get(1).(*string) = "node-1"
		*args.Get(2).(*string) = "alarm"
		*args.Get(3).(*string) = "85.5"
		*args.Get(4).(*string) = "80"
		*args.Get(5).(*string) = "gt"
		*args.Get(6).(*string) = "cpu"
		*args.Get(7).(*string) = "cpu_used"
		*args.Get(8).(**time.Time) = &now
		*args.Get(9).(**time.Time) = nil
		*args.Get(10).(**time.Time) = &now
		*args.Get(11).(*int) = 120
		*args.Get(12).(*time.Time) = now
		*args.Get(13).(*time.Time) = now
	}).Return(nil).Once()

	state, err := s.GetAlarmState(context.Background(), "alarm-1", "node-1")
	assert.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, "alarm-1", state.AlarmID)
	assert.Equal(t, "node-1", state.NodeID)
	mDB.AssertExpectations(t)
	mockRow.AssertExpectations(t)
}

func TestStore_DeleteAlarmStatesForAlarm(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := database.New(mDB)

	mDB.On("Exec", mock.Anything, "DELETE FROM alarm_states WHERE alarm_id = $1;", "alarm-1").Return(nil).Once()

	err := s.DeleteAlarmStatesForAlarm(context.Background(), "alarm-1")
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}
