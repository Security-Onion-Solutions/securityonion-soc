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

var (
	ErrInvalidMemoryScope = errors.New("memory scope not specified")
	ErrMemoryNotFound     = errors.New("ERROR_MEMORY_NOT_FOUND")
)

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
		SET memory_text = $2, session_id = $3, embedding = $4, model_id = $5, target_user_id = $6, user_defined = $7, updated_at = now()
		WHERE id = $1
		RETURNING updated_at, last_used_at, usage_count`,
		mem.Id, mem.MemoryText, sessionId, pgvector.NewVector(mem.Embedding), mem.ModelID, mem.TargetUserId, mem.UserDefined).
		Scan(&mem.UpdateTime, &mem.LastUsedAt, &mem.UsageCount)
}

func (s *Store) DeleteMemory(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("cannot delete memory without an id")
	}

	return s.db.Exec(ctx, `DELETE FROM memories WHERE id = $1`, id)
}

const memoryColumns = `id, created_at, updated_at, last_used_at, user_id, memory_text, session_id, model_id, target_user_id, user_defined, usage_count`

// Reads the memoryColumns projection; similarity is scanned only when the
// caller selected it.
func scanMemoryRow(rows db.Rows, similarity *float64) (*model.Memory, error) {
	mem := &model.Memory{
		Auditable: model.Auditable{
			Kind: "memory",
		},
	}

	var sessionId *string

	dest := []any{&mem.Id, &mem.CreateTime, &mem.UpdateTime, &mem.LastUsedAt, &mem.UserId, &mem.MemoryText, &sessionId, &mem.ModelID, &mem.TargetUserId, &mem.UserDefined, &mem.UsageCount}
	if similarity != nil {
		dest = append(dest, similarity)
	}

	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}

	if sessionId != nil {
		mem.SessionId = *sessionId
	}

	return mem, nil
}

// Where and Args must already be limited to what the requestor may read. A
// non-nil Embedding orders by similarity and filters on EmbedModelId.
type MemoryQuery struct {
	Where        string
	Args         []any
	Embedding    []float32
	EmbedModelId string
	Limit        int
	Offset       int
}

func (s *Store) ListMemories(ctx context.Context, query MemoryQuery) (*model.MemoryResults, error) {
	where := query.Where
	args := query.Args
	simExpr := ""
	order := ` ORDER BY updated_at DESC, id`

	countArgs := args

	if query.Embedding != nil {
		args = append(args, query.EmbedModelId)
		where += fmt.Sprintf(` AND model_id = $%d`, len(args))

		// The count shares every arg up to here; the vector is appended after so
		// the count statement never binds a parameter it does not reference.
		countArgs = make([]any, len(args))
		copy(countArgs, args)

		args = append(args, pgvector.NewVector(query.Embedding))
		simExpr = fmt.Sprintf(`, 1 - (embedding <=> $%d) AS similarity`, len(args))
		order = fmt.Sprintf(` ORDER BY embedding <=> $%d`, len(args))
	}

	total := 0
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM memories WHERE `+where, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	args = append(args, query.Limit, query.Offset)
	stmt := `SELECT ` + memoryColumns + simExpr + ` FROM memories WHERE ` + where + order +
		fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(args)-1, len(args))

	rows, err := s.db.Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	results := &model.MemoryResults{
		Memories: []*model.MemoryRecord{},
		Total:    total,
		Offset:   query.Offset,
		Limit:    query.Limit,
	}

	for rows.Next() {
		var similarity float64

		var scanned *float64
		if simExpr != "" {
			scanned = &similarity
		}

		mem, err := scanMemoryRow(rows, scanned)
		if err != nil {
			return nil, err
		}

		record := model.NewMemoryRecord(mem)
		if scanned != nil {
			record.Similarity = &similarity
		}

		results.Memories = append(results.Memories, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *Store) GetMemory(ctx context.Context, id string) (*model.Memory, error) {
	rows, err := s.db.Query(ctx, `SELECT `+memoryColumns+` FROM memories WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return nil, ErrMemoryNotFound
	}

	return scanMemoryRow(rows, nil)
}

func (s *Store) CountStaleMemories(ctx context.Context, modelId string) (int, error) {
	stale := 0
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM memories WHERE model_id <> $1`, modelId).Scan(&stale)

	return stale, err
}

// Returns the next batch of memories to re-embed.
func (s *Store) StaleMemoryBatch(ctx context.Context, modelId string, limit int) ([]*model.Memory, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, memory_text FROM memories WHERE model_id <> $1 ORDER BY created_at LIMIT $2`, modelId, limit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	batch := []*model.Memory{}

	for rows.Next() {
		mem := &model.Memory{}
		if err := rows.Scan(&mem.Id, &mem.MemoryText); err != nil {
			return nil, err
		}

		batch = append(batch, mem)
	}

	return batch, rows.Err()
}

// Re-vectorizes one memory, leaving its text, counts and user_defined flag alone.
func (s *Store) SetMemoryEmbedding(ctx context.Context, id string, embedding []float32, modelId string) error {
	return s.db.Exec(ctx, `UPDATE memories SET embedding = $2, model_id = $3 WHERE id = $1`,
		id, pgvector.NewVector(embedding), modelId)
}

// CountMemoryUsage increments the usage count and stamps last_used_at for the
// given memory ids.
func (s *Store) CountMemoryUsage(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	return s.db.Exec(ctx, `UPDATE memories SET usage_count = usage_count + 1, last_used_at = $2 WHERE id = ANY($1)`, ids, time.Now())
}
