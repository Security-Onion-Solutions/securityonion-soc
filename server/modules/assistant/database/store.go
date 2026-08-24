// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/pgvector/pgvector-go"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const moduleName = "assistant"

var ErrInvalidMemoryScope = errors.New("memory scope not specified")

// Store encapsulates all Postgres operations for assistant memories.
type Store struct {
	db db.DB
}

// New wraps an existing DB connection and runs pending migrations.
func New(ctx context.Context, database db.DB) (*Store, error) {
	if err := database.Migrate(ctx, migrationFS, moduleName); err != nil {
		return nil, fmt.Errorf("database: migrate: %w", err)
	}
	return &Store{db: database}, nil
}

type memoryScopeKind int

const (
	scopeNone memoryScopeKind = iota // zero value: no scope specified — fail closed
	scopeUser
	scopeGlobal
	scopeAllUsers
)

// MemoryScope determines whose memories FindNearbyMemories searches. Build one
// with UserMemories, GlobalMemories, or AllMemories; the zero value is invalid
// and matches nothing. Each scope returns only its exact kind of memory —
// callers wanting both a user's memories and global memories make two calls.
type MemoryScope struct {
	kind         memoryScopeKind
	targetUserId string
}

// UserMemories scopes the search to memories targeting the given user.
func UserMemories(userId string) MemoryScope {
	return MemoryScope{kind: scopeUser, targetUserId: userId}
}

// GlobalMemories scopes the search to memories with no target user.
func GlobalMemories() MemoryScope {
	return MemoryScope{kind: scopeGlobal}
}

// AllMemories searches every memory regardless of target user, including other
// users' memories; reserved for superusers.
func AllMemories() MemoryScope {
	return MemoryScope{kind: scopeAllUsers}
}

type findNearbyMemoriesOpts struct {
	minSimilarity *float64 // nil = no similarity filter
	limit         *int     // nil = unlimited
}

type FindNearbyMemoriesOpt func(*findNearbyMemoriesOpts)

// WithMinSimilarity only returns memories at least this similar to the query
// embedding.
func WithMinSimilarity(threshold float64) FindNearbyMemoriesOpt {
	return func(opts *findNearbyMemoriesOpts) {
		opts.minSimilarity = &threshold
	}
}

// WithLimit caps the number of memories returned.
func WithLimit(limit int) FindNearbyMemoriesOpt {
	return func(opts *findNearbyMemoriesOpts) {
		opts.limit = &limit
	}
}

func (s *Store) FindNearbyMemories(ctx context.Context, embedding []float32, modelID string, scope MemoryScope, opts ...FindNearbyMemoriesOpt) ([]*model.NearbyMemory, error) {
	options := &findNearbyMemoriesOpts{}
	for _, opt := range opts {
		opt(options)
	}

	args := []any{pgvector.NewVector(embedding), modelID}

	stmt := `SELECT id, created_at, updated_at, last_used_at, user_id, memory_text, session_id, embedding, model_id, target_user_id, 1 - (embedding <=> $1) AS similarity, user_defined, usage_count
		FROM memories
		WHERE model_id = $2`

	switch scope.kind {
	case scopeUser:
		args = append(args, scope.targetUserId)
		stmt += fmt.Sprintf(` AND target_user_id = $%d`, len(args))
	case scopeGlobal:
		stmt += ` AND target_user_id IS NULL`
	case scopeAllUsers:
		// no target clause
	default:
		return nil, ErrInvalidMemoryScope
	}

	if options.minSimilarity != nil {
		args = append(args, *options.minSimilarity)
		stmt += fmt.Sprintf(` AND 1 - (embedding <=> $1) >= $%d`, len(args))
	}

	stmt += ` ORDER BY embedding <=> $1`

	if options.limit != nil {
		args = append(args, *options.limit)
		stmt += fmt.Sprintf(` LIMIT $%d`, len(args))
	}

	var rows db.Rows
	var err error

	rows, err = s.db.Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	mems := []*model.NearbyMemory{}

	for rows.Next() {
		mem := &model.Memory{
			Auditable: model.Auditable{
				Kind: "memory",
			},
		}

		var sessionId *string
		var vec pgvector.Vector
		var similarity float64

		err = rows.Scan(&mem.Id, &mem.CreateTime, &mem.UpdateTime, &mem.LastUsedAt, &mem.UserId, &mem.MemoryText, &sessionId, &vec, &mem.ModelID, &mem.TargetUserId, &similarity, &mem.UserDefined, &mem.UsageCount)
		if err != nil {
			return nil, err
		}

		if sessionId != nil {
			mem.SessionId = *sessionId
		}

		mem.Embedding = vec.Slice()

		mems = append(mems, &model.NearbyMemory{
			Similarity: similarity,
			Memory:     mem,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return mems, nil
}

func (s *Store) AddMemory(ctx context.Context, mem *model.Memory) error {
	var sessionId *string
	if mem.SessionId != "" {
		sessionId = &mem.SessionId
	}

	return s.db.QueryRow(ctx, `
		INSERT INTO memories (user_id, memory_text, session_id, embedding, model_id, target_user_id, user_defined)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		mem.UserId, mem.MemoryText, sessionId, pgvector.NewVector(mem.Embedding), mem.ModelID, mem.TargetUserId, mem.UserDefined).
		Scan(&mem.Id, &mem.CreateTime, &mem.UpdateTime)
}

func (s *Store) UpdateMemory(ctx context.Context, mem *model.Memory) error {
	if mem.Id == "" {
		return fmt.Errorf("cannot update memory without an id")
	}

	var sessionId *string
	if mem.SessionId != "" {
		sessionId = &mem.SessionId
	}

	return s.db.QueryRow(ctx, `
		UPDATE memories
		SET memory_text = $2, session_id = $3, embedding = $4, model_id = $5, target_user_id = $6, updated_at = now()
		WHERE id = $1
		RETURNING updated_at, last_used_at, usage_count`,
		mem.Id, mem.MemoryText, sessionId, pgvector.NewVector(mem.Embedding), mem.ModelID, mem.TargetUserId).
		Scan(&mem.UpdateTime, &mem.LastUsedAt, &mem.UsageCount)
}

func (s *Store) DeleteMemory(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("cannot delete memory without an id")
	}

	return s.db.Exec(ctx, `DELETE FROM memories WHERE id = $1`, id)
}

// CountMemoryUsage increments the usage count and stamps last_used_at for the
// given memory ids.
func (s *Store) CountMemoryUsage(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	return s.db.Exec(ctx, `UPDATE memories SET usage_count = usage_count + 1, last_used_at = $2 WHERE id = ANY($1)`, ids, time.Now())
}
