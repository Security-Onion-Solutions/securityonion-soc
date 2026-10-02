// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
	"golang.org/x/mod/semver"
)

// MigrationsDir holds soup's <engine>-migration-<version> state files: "0" pending, "1" applied.
const MigrationsDir = "/opt/so/conf/soc/migrations/"

// RunMigrations runs the engine's requested migrations in version order, halting at the first failure.
func RunMigrations(iom IOManager, engine model.EngineName, migrations map[string]func(string) error, state *model.EngineState) {
	logger := log.WithField("detectionEngine", engine)
	logger.Info("checking for migrations")

	prefix := string(engine) + "-migration-"

	items, err := iom.ReadDir(MigrationsDir)
	if err != nil {
		logger.WithError(err).Error("unable to read directory")
		return
	}

	versions := []string{}

	for _, item := range items {
		if item.IsDir() {
			continue
		}

		ver, ok := strings.CutPrefix(item.Name(), prefix)
		if !ok {
			continue
		}

		versions = append(versions, ver)
	}

	// semver requires the "v" prefix
	slices.SortFunc(versions, func(a, b string) int {
		return semver.Compare("v"+a, "v"+b)
	})

	if len(versions) == 0 {
		logger.Info("no migrations found")
	} else {
		logger.WithField("migrationCount", len(versions)).Info("found migrations")
	}

	for _, key := range versions {
		state.Migrating = true

		migFunc, ok := migrations[key]
		if !ok {
			logger.WithField("migrationVersion", key).Error("migration function not found")
			continue
		}

		logger.WithField("migrationVersion", key).Info("attempting migration")

		err := migFunc(filepath.Join(MigrationsDir, prefix+key))
		if err != nil {
			logger.WithError(err).WithField("migrationVersion", key).Error("unable to apply migration, halting migrations")
			state.MigrationFailure = true
			break
		}
	}

	state.Migrating = false

	logger.Info("done checking for migrations")
}

// ReadMigrationState reports whether a state file marks its migration pending.
func ReadMigrationState(iom IOManager, path string) (pending bool, err error) {
	raw, err := iom.ReadFile(path)
	if err != nil {
		return false, err
	}

	switch s := strings.TrimSpace(string(raw)); s {
	case "0":
		return true, nil
	case "1":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected state file content: %s", s)
	}
}

// MarkMigrationDone records in its state file that a migration has been applied.
func MarkMigrationDone(iom IOManager, path string) error {
	return iom.WriteFile(path, []byte("1"), 0644)
}
