// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// PostgresConfigstore satisfies the server.Configstore interface against the
// so_pillar.* schema deployed by salt/postgres/schema_pillar.sls. It is a thin
// override of the salt.Saltstore: GetSettings and UpdateSetting are served
// from Postgres; SyncSettings, SyncModule, and the GridMembersstore /
// AdminUserstore / AdminClientstore methods continue to flow through the
// embedded Saltstore (which talks to salt-master via shell exec, unrelated to
// pillar storage).
//
// Defaults and annotations still live on disk under
// /opt/so/saltstack/default/. Those are package-shipped; only the per-install
// "local" pillar overlay moves to Postgres.
//
// Wiring: the postgres module's Start() method constructs a PostgresConfigstore
// when configstore.backend == "postgres" and assigns it to server.Configstore,
// replacing the Saltstore-as-Configstore wiring done by the salt module.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/salt"
)

const PG_CONFIGSTORE_SCHEMA = "so_pillar"

// PostgresConfigstore embeds the existing Saltstore so it inherits every
// method on the Configstore / GridMembersstore / AdminUserstore /
// AdminClientstore interfaces, then overrides the two methods that touch
// the local-pillar filesystem.
type PostgresConfigstore struct {
	*salt.Saltstore
	pool   *pgxpool.Pool
	server *server.Server
}

func NewPostgresConfigstore(srv *server.Server, salt *salt.Saltstore, pool *pgxpool.Pool) *PostgresConfigstore {
	return &PostgresConfigstore{
		Saltstore: salt,
		pool:      pool,
		server:    srv,
	}
}

// pillarLocator translates a SOC setting (id + node id) into the
// (scope, role_name, minion_id, pillar_path) tuple addressed in the
// so_pillar.pillar_entry table. This mirrors the file-path mapping that
// Saltstore.UpdateSetting builds today (lines 766-808 of saltstore.go).
type pillarLocator struct {
	scope       string // 'global' | 'role' | 'minion'
	roleName    string // populated when scope='role'
	minionId    string // populated when scope='minion'
	pillarPath  string // e.g. 'soc.soc_soc' or 'minions.<id>'
	dottedKey   string // setting.Id with the leading section preserved
	isAdvanced  bool   // 'foo.advanced' or per-minion adv_<id>
}

func locateSetting(setting *model.Setting) (*pillarLocator, error) {
	sections := strings.Split(setting.Id, ".")
	if len(sections) == 0 || sections[0] == "" {
		return nil, fmt.Errorf("invalid setting id: %s", setting.Id)
	}

	advanced := false
	if len(sections) <= 2 && sections[len(sections)-1] == "advanced" {
		advanced = true
	}

	loc := &pillarLocator{
		dottedKey:  setting.Id,
		isAdvanced: advanced,
	}

	if setting.NodeId != "" {
		loc.scope = "minion"
		loc.minionId = setting.NodeId
		if advanced {
			loc.pillarPath = "minions.adv_" + setting.NodeId
		} else {
			loc.pillarPath = "minions." + setting.NodeId
		}
	} else {
		// Global section. Equivalent to Saltstore's local/pillar/<section>/{soc,adv}_<section>.sls path.
		loc.scope = "global"
		section := sections[0]
		if advanced {
			loc.pillarPath = section + ".adv_" + section
		} else {
			loc.pillarPath = section + ".soc_" + section
		}
	}

	return loc, nil
}

// GetSettings builds the same []*model.Setting tree that Saltstore.GetSettings
// produces, but reads the local pillar overlay from Postgres instead of from
// /opt/so/saltstack/local. Defaults + annotations still come from disk.
func (s *PostgresConfigstore) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	logger := log.FromContext(ctx)

	if err := s.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}

	// Phase 1: defaults + annotations from disk via the embedded Saltstore.
	// We invoke its GetSettings, then strip out any local-pillar values it
	// pulled (they shouldn't exist in a PG-only install, but for dual-write
	// installs we want the PG values to win).
	settings, err := s.Saltstore.GetSettings(ctx, true)
	if err != nil {
		return nil, err
	}

	// Phase 2: overlay local pillar values from Postgres.
	overlay, err := s.loadLocalPillarOverlay(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading pillar overlay from postgres: %w", err)
	}

	for _, setting := range settings {
		if v, ok := overlay[settingKey(setting)]; ok {
			setting.Value = v.value
			setting.NodeId = v.minionId
			if v.isAdvanced {
				setting.Advanced = true
			}
		}
	}

	logger.WithFields(log.Fields{
		"count":   len(settings),
		"overlay": len(overlay),
	}).Debug("PostgresConfigstore.GetSettings completed")

	return s.Saltstore.FilterAndSort(settings, advanced), nil
}

// UpdateSetting writes a SOC setting change to so_pillar.pillar_entry. The
// transaction sets so_pillar.change_reason so the audit trigger captures who
// requested the change.
func (s *PostgresConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	logger := log.FromContext(ctx)

	if err := s.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	loc, err := locateSetting(setting)
	if err != nil {
		return err
	}

	// Reject custom-file settings — those write to /opt/so/saltstack/local/salt/,
	// not to pillar at all. Fall through to the embedded Saltstore which handles
	// them on disk.
	if setting.File {
		return s.Saltstore.UpdateSetting(ctx, setting, remove)
	}

	actor := "soc-ui"
	if userId := contextUserId(ctx); userId != "" {
		actor = "soc-ui:" + userId
	}
	reason := actor + " UpdateSetting " + setting.Id

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, "SELECT set_config('so_pillar.change_reason', $1, true)", reason); err != nil {
		return fmt.Errorf("set change_reason: %w", err)
	}

	if loc.isAdvanced {
		// Advanced subtrees are stored as raw YAML in a single dotted key.
		// We persist them as a JSONB string under data->'_raw' so the importer
		// and so-yaml can round-trip them without re-parsing.
		err = s.upsertRaw(ctx, tx, loc, setting.Value, remove, reason)
	} else {
		err = s.upsertSetting(ctx, tx, loc, setting, remove, reason)
	}
	if err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	logger.WithFields(log.Fields{
		"settingId":  setting.Id,
		"scope":      loc.scope,
		"minionId":   loc.minionId,
		"pillarPath": loc.pillarPath,
	}).Info("PostgresConfigstore.UpdateSetting committed")

	return nil
}

// upsertSetting inserts or updates a single dotted-key setting inside the row's
// JSONB blob. Multiple settings can land in the same pillar_entry row; we use
// jsonb_set to mutate just the relevant subtree.
func (s *PostgresConfigstore) upsertSetting(ctx context.Context, tx pgx.Tx, loc *pillarLocator, setting *model.Setting, remove bool, reason string) error {
	// Convert SOC setting value to JSONB. For now, treat all values as strings
	// matching the on-disk YAML semantics; richer typing is a follow-up.
	value := setting.Value
	jsonValue, _ := json.WriteJson(value)

	// Build the JSON path from the dotted key. Skip the first section because
	// that's encoded in pillar_path.
	sections := strings.Split(setting.Id, ".")
	if len(sections) < 2 {
		return errors.New("setting id must have at least two dotted sections")
	}
	jsonPath := sections[1:]

	if remove {
		_, err := tx.Exec(ctx, fmt.Sprintf(`
			UPDATE %s.pillar_entry
			   SET data = data #- $4::text[],
			       change_reason = $3
			 WHERE scope = $1 AND pillar_path = $2
			   AND %s
		`, PG_CONFIGSTORE_SCHEMA, scopePredicate(loc)),
			loc.scope, loc.pillarPath, reason, jsonPath)
		return err
	}

	// UPSERT: ensure the row exists with at least an empty object, then jsonb_set.
	if err := s.ensureRow(ctx, tx, loc, reason); err != nil {
		return err
	}

	_, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE %s.pillar_entry
		   SET data = jsonb_set(data, $4::text[], $5::jsonb, true),
		       change_reason = $3
		 WHERE scope = $1 AND pillar_path = $2
		   AND %s
	`, PG_CONFIGSTORE_SCHEMA, scopePredicate(loc)),
		loc.scope, loc.pillarPath, reason, jsonPath, string(jsonValue))
	return err
}

// upsertRaw replaces the entire data column with a single _raw key holding
// the advanced YAML blob.
func (s *PostgresConfigstore) upsertRaw(ctx context.Context, tx pgx.Tx, loc *pillarLocator, raw string, remove bool, reason string) error {
	if remove {
		_, err := tx.Exec(ctx, fmt.Sprintf(`
			DELETE FROM %s.pillar_entry
			 WHERE scope = $1 AND pillar_path = $2
			   AND %s
		`, PG_CONFIGSTORE_SCHEMA, scopePredicate(loc)),
			loc.scope, loc.pillarPath)
		return err
	}

	rawJson, _ := json.WriteJson(raw)
	dataJson := fmt.Sprintf(`{"_raw": %s}`, string(rawJson))

	if err := s.ensureRow(ctx, tx, loc, reason); err != nil {
		return err
	}

	_, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE %s.pillar_entry
		   SET data = $3::jsonb,
		       change_reason = $4
		 WHERE scope = $1 AND pillar_path = $2
		   AND %s
	`, PG_CONFIGSTORE_SCHEMA, scopePredicate(loc)),
		loc.scope, loc.pillarPath, dataJson, reason)
	return err
}

// ensureRow creates an empty data row at (scope, pillar_path, …) if one does
// not yet exist. ON CONFLICT prevents races between concurrent SOC writes.
func (s *PostgresConfigstore) ensureRow(ctx context.Context, tx pgx.Tx, loc *pillarLocator, reason string) error {
	if loc.scope == "minion" {
		// Make sure the minion row exists first; FK forces this.
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s.minion (minion_id) VALUES ($1)
			ON CONFLICT (minion_id) DO NOTHING
		`, PG_CONFIGSTORE_SCHEMA), loc.minionId); err != nil {
			return fmt.Errorf("ensure minion row: %w", err)
		}
	}

	_, err := tx.Exec(ctx, fmt.Sprintf(`
		INSERT INTO %s.pillar_entry (scope, role_name, minion_id, pillar_path, data, change_reason)
		VALUES ($1, $2, $3, $4, '{}'::jsonb, $5)
		ON CONFLICT %s DO NOTHING
	`, PG_CONFIGSTORE_SCHEMA, conflictTarget(loc)),
		loc.scope, nullable(loc.roleName), nullable(loc.minionId), loc.pillarPath, reason)
	return err
}

func scopePredicate(loc *pillarLocator) string {
	switch loc.scope {
	case "global":
		return "role_name IS NULL AND minion_id IS NULL"
	case "role":
		return "role_name = $5 AND minion_id IS NULL"
	case "minion":
		return "minion_id = $5"
	}
	return "false"
}

func conflictTarget(loc *pillarLocator) string {
	switch loc.scope {
	case "global":
		return "(pillar_path) WHERE scope='global'"
	case "role":
		return "(role_name, pillar_path) WHERE scope='role'"
	case "minion":
		return "(minion_id, pillar_path) WHERE scope='minion'"
	}
	return ""
}

func nullable(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// overlayValue captures the local-pillar override for a single setting.
type overlayValue struct {
	value      string
	minionId   string
	isAdvanced bool
}

// loadLocalPillarOverlay reads every pillar_entry row that's part of the local
// overlay and flattens each row's JSONB into one overlayValue per dotted key.
func (s *PostgresConfigstore) loadLocalPillarOverlay(ctx context.Context) (map[string]overlayValue, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT scope, role_name, minion_id, pillar_path, data
		  FROM %s.pillar_entry
		 WHERE is_secret = false
	`, PG_CONFIGSTORE_SCHEMA))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]overlayValue)
	for rows.Next() {
		var scope, pillarPath string
		var roleName, minionId *string
		var data []byte
		if err := rows.Scan(&scope, &roleName, &minionId, &pillarPath, &data); err != nil {
			return nil, err
		}

		// pillar_path takes the form '<section>.<file>' (e.g. 'soc.soc_soc'
		// or 'minions.<id>'); the YAML stored under data already has the
		// section as its top-level key, so flatten with an empty prefix.
		sectionParts := strings.SplitN(pillarPath, ".", 2)
		if len(sectionParts) < 2 {
			continue
		}
		section := sectionParts[0]
		fileName := sectionParts[1]

		isAdvanced := strings.HasPrefix(fileName, "adv_")

		var mid string
		if minionId != nil {
			mid = *minionId
		}

		var parsed map[string]interface{}
		if err := json.LoadJson(data, &parsed); err != nil {
			log.WithFields(log.Fields{
				"pillarPath": pillarPath,
			}).WithError(err).Warn("Failed to parse data column as JSON; skipping row")
			continue
		}

		// Advanced rows store the raw YAML blob under {"_raw": "..."}.
		if isAdvanced {
			if raw, ok := parsed["_raw"]; ok {
				key := section + ".advanced"
				if mid != "" {
					key = "advanced"
				}
				out[overlayKey(key, mid)] = overlayValue{
					value:      fmt.Sprintf("%v", raw),
					minionId:   mid,
					isAdvanced: true,
				}
				continue
			}
		}

		flatten(parsed, "", mid, out)
	}

	return out, rows.Err()
}

// flatten walks a JSON object and emits one overlayKey per leaf with its
// dotted setting id and stringified value.
func flatten(node interface{}, prefix, minionId string, out map[string]overlayValue) {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, child := range v {
			next := prefix
			if next != "" {
				next += "."
			}
			next += k
			flatten(child, next, minionId, out)
		}
	case []interface{}:
		var b strings.Builder
		for _, item := range v {
			s, _ := json.WriteJson(item)
			b.WriteString(string(s))
			b.WriteByte('\n')
		}
		out[overlayKey(prefix, minionId)] = overlayValue{
			value:    b.String(),
			minionId: minionId,
		}
	default:
		out[overlayKey(prefix, minionId)] = overlayValue{
			value:    fmt.Sprintf("%v", v),
			minionId: minionId,
		}
	}
}

func overlayKey(settingId, minionId string) string {
	if minionId == "" {
		return settingId
	}
	return settingId + "@" + minionId
}

func settingKey(s *model.Setting) string {
	return overlayKey(s.Id, s.NodeId)
}

func contextUserId(ctx context.Context) string {
	if v, ok := ctx.Value("userId").(string); ok {
		return v
	}
	return ""
}
