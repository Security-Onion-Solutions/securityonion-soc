// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"

	pgvector "github.com/pgvector/pgvector-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func sqlContains(substr string) any {
	return mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, substr)
	})
}

func nilStringPtr() any {
	return mock.MatchedBy(func(s *string) bool {
		return s == nil
	})
}

func stringPtrTo(expected string) any {
	return mock.MatchedBy(func(s *string) bool {
		return s != nil && *s == expected
	})
}

type nearbyRowFixture struct {
	id, userId, memoryText, modelId string
	sessionId, targetUserId         *string
	lastUsedAt                      *time.Time
	embedding                       []float32
	similarity                      float64
	userDefined                     bool
	usageCount                      int
}

// expectNearbyRow scripts one Scan call on mRows, filling the thirteen out-params
// FindNearbyMemories reads per row. Uses Once so successive rows are consumed
// in order; pair each with an .On("Next").Return(true).Once().
func expectNearbyRow(mRows *mockdb.MockRows, row nearbyRowFixture) {
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = row.id
			*(args.Get(3).(**time.Time)) = row.lastUsedAt
			*(args.Get(4).(*string)) = row.userId
			*(args.Get(5).(*string)) = row.memoryText
			*(args.Get(6).(**string)) = row.sessionId
			*(args.Get(7).(*pgvector.Vector)) = pgvector.NewVector(row.embedding)
			*(args.Get(8).(*string)) = row.modelId
			*(args.Get(9).(**string)) = row.targetUserId
			*(args.Get(10).(*float64)) = row.similarity
			*(args.Get(11).(*bool)) = row.userDefined
			*(args.Get(12).(*int)) = row.usageCount
		}).Return(nil).Once()
}

func TestAddMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mem := &model.Memory{
		MemoryText:  "the user prefers dark mode",
		SessionId:   "session-1",
		Embedding:   []float32{0.1, 0.2},
		ModelID:     "embed-model",
		UserDefined: true,
	}
	mem.UserId = "user-1"

	created := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = "generated-id"
		*(args.Get(1).(**time.Time)) = &created
		*(args.Get(2).(**time.Time)) = &created
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("$7"),
		"user-1", "the user prefers dark mode", stringPtrTo("session-1"), mock.Anything, "embed-model", nilStringPtr(), true).
		Return(mRow)

	err := s.AddMemory(context.Background(), mem)

	assert.NoError(t, err)
	assert.Equal(t, "generated-id", mem.Id)
	assert.Equal(t, &created, mem.CreateTime)
	assert.Equal(t, &created, mem.UpdateTime)
	mDB.AssertExpectations(t)
	mRow.AssertExpectations(t)
}

func TestAddMemoryEmptySessionId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mem := &model.Memory{
		MemoryText: "seeded memory",
		Embedding:  []float32{0.1},
		ModelID:    "embed-model",
	}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, nilStringPtr(), mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mRow)

	err := s.AddMemory(context.Background(), mem)

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestUpdateMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mem := &model.Memory{
		MemoryText: "updated text",
		SessionId:  "session-2",
		Embedding:  []float32{0.3},
		ModelID:    "embed-model",
	}
	mem.Id = "mem-1"

	updated := time.Date(2026, 8, 6, 13, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 8, 6, 12, 30, 0, 0, time.UTC)

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(**time.Time)) = &updated
		*(args.Get(1).(**time.Time)) = &lastUsed
		*(args.Get(2).(*int)) = 4
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		"mem-1", "updated text", stringPtrTo("session-2"), mock.Anything, "embed-model", nilStringPtr(), false).
		Return(mRow)

	err := s.UpdateMemory(context.Background(), mem)

	assert.NoError(t, err)
	assert.Equal(t, &updated, mem.UpdateTime)
	assert.Equal(t, &lastUsed, mem.LastUsedAt)
	assert.Equal(t, 4, mem.UsageCount)
	mDB.AssertExpectations(t)
	mRow.AssertExpectations(t)
}

func TestUpdateMemoryEmptyId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	err := s.UpdateMemory(context.Background(), &model.Memory{MemoryText: "no id"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "without an id")
	mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateMemoryScanError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mem := &model.Memory{}
	mem.Id = "missing-id"

	scanErr := errors.New("no rows in result set")

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(scanErr)

	mDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mRow)

	err := s.UpdateMemory(context.Background(), mem)

	assert.ErrorIs(t, err, scanErr)
}

func TestDeleteMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Exec", mock.Anything, sqlContains("DELETE FROM memories"), "mem-1").Return(nil)

	err := s.DeleteMemory(context.Background(), "mem-1")

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestDeleteMemoryEmptyId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	err := s.DeleteMemory(context.Background(), "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "without an id")
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything)
}

func TestDeleteMemoryExecError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	execErr := errors.New("connection lost")

	mDB.On("Exec", mock.Anything, mock.Anything, mock.Anything).Return(execErr)

	err := s.DeleteMemory(context.Background(), "mem-1")

	assert.ErrorIs(t, err, execErr)
}

func TestCountMemoryUsage(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET usage_count = usage_count + 1, last_used_at = $2"), []string{"mem-1", "mem-2"}, mock.AnythingOfType("time.Time")).Return(nil)

	err := s.CountMemoryUsage(context.Background(), []string{"mem-1", "mem-2"})

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestCountMemoryUsageEmptyIds(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	err := s.CountMemoryUsage(context.Background(), []string{})

	assert.NoError(t, err)
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything)
}

func TestCountMemoryUsageExecError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	execErr := errors.New("connection lost")

	mDB.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(execErr)

	err := s.CountMemoryUsage(context.Background(), []string{"mem-1"})

	assert.ErrorIs(t, err, execErr)
}

func TestFindNearbyMemoriesUserScoped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Twice()
	mRows.On("Next").Return(false)
	expectNearbyRow(mRows, nearbyRowFixture{
		id: "mem-1", userId: "system", memoryText: "likes tea", modelId: "embed-model",
		sessionId: util.Ptr("sess-1"), targetUserId: util.Ptr("user-1"),
		embedding: []float32{0.5, 0.6}, similarity: 0.91, userDefined: true,
	})
	expectNearbyRow(mRows, nearbyRowFixture{
		id: "mem-2", userId: "system", memoryText: "drinks coffee", modelId: "embed-model",
		similarity: 0.85,
	})
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// args are appended in clause order: scope user, then similarity, then limit
	userOnly := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "target_user_id = $3") &&
			!strings.Contains(sql, "target_user_id IS NULL")
	})
	mDB.On("Query", mock.Anything, userOnly,
		mock.Anything, "embed-model", "user-1", 0.8, 5).
		Return(mRows, nil)

	got, err := s.FindNearbyMemories(context.Background(), []float32{0.5, 0.6}, "embed-model", UserMemories("user-1"), WithMinSimilarity(0.8), WithLimit(5))

	assert.NoError(t, err)
	assert.Len(t, got, 2)

	assert.Equal(t, 0.91, got[0].Similarity)
	assert.Equal(t, "mem-1", got[0].Memory.Id)
	assert.Equal(t, "memory", got[0].Memory.Kind)
	assert.Equal(t, "likes tea", got[0].Memory.MemoryText)
	assert.Equal(t, "sess-1", got[0].Memory.SessionId)
	assert.Equal(t, []float32{0.5, 0.6}, got[0].Memory.Embedding)
	assert.Equal(t, util.Ptr("user-1"), got[0].Memory.TargetUserId)
	assert.True(t, got[0].Memory.UserDefined)

	// NULL session_id stays empty
	assert.Equal(t, "", got[1].Memory.SessionId)
	assert.Nil(t, got[1].Memory.TargetUserId)
	assert.False(t, got[1].Memory.UserDefined)

	mDB.AssertExpectations(t)
	mRows.AssertExpectations(t)
}

func TestFindNearbyMemoriesGlobalScopeNoLimit(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// global scope only queries untargeted rows; no WithLimit means no LIMIT arg
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8).
		Return(mRows, nil)

	got, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", GlobalMemories(), WithMinSimilarity(0.8))

	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
	mDB.AssertExpectations(t)
}

func TestFindNearbyMemoriesUserOnlyScope(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// user-only scope must not pull in global rows
	userOnly := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "target_user_id = $3") &&
			!strings.Contains(sql, "target_user_id IS NULL")
	})
	mDB.On("Query", mock.Anything, userOnly,
		mock.Anything, "embed-model", "user-1", 2).
		Return(mRows, nil)

	got, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", UserMemories("user-1"), WithLimit(2))

	assert.NoError(t, err)
	assert.Empty(t, got)
	mDB.AssertExpectations(t)
}

func TestFindNearbyMemoriesAllUsersNoFilters(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// all-users scope has no target clause; no options means no similarity or LIMIT clauses
	unfiltered := mock.MatchedBy(func(sql string) bool {
		return !strings.Contains(sql, "target_user_id =") &&
			!strings.Contains(sql, "target_user_id IS NULL") &&
			!strings.Contains(sql, ">=") &&
			!strings.Contains(sql, "LIMIT")
	})
	mDB.On("Query", mock.Anything, unfiltered,
		mock.Anything, "embed-model").
		Return(mRows, nil)

	got, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", AllMemories())

	assert.NoError(t, err)
	assert.Empty(t, got)
	mDB.AssertExpectations(t)
}

func TestFindNearbyMemoriesUnspecifiedScope(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// the zero-value scope fails closed: no query, no results
	got, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", MemoryScope{})

	assert.ErrorIs(t, err, ErrInvalidMemoryScope)
	assert.Nil(t, got)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestFindNearbyMemoriesQueryError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	queryErr := errors.New("connection lost")

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mockdb.MockRows{}, queryErr)

	_, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", GlobalMemories(), WithMinSimilarity(0.8), WithLimit(5))

	assert.ErrorIs(t, err, queryErr)
}

func TestFindNearbyMemoriesScanError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	scanErr := errors.New("bad row")

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true)
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).
		Return(scanErr)
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mRows, nil)

	_, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", GlobalMemories(), WithMinSimilarity(0.8), WithLimit(5))

	assert.ErrorIs(t, err, scanErr)
	mRows.AssertCalled(t, "Close")
	mRows.AssertNotCalled(t, "Err")
}

func TestFindNearbyMemoriesRowsErr(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	rowsErr := errors.New("cursor failed")

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(rowsErr)
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mRows, nil)

	_, err := s.FindNearbyMemories(context.Background(), []float32{0.5}, "embed-model", GlobalMemories(), WithMinSimilarity(0.8), WithLimit(5))

	assert.ErrorIs(t, err, rowsErr)
}
