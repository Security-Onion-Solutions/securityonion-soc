// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package detections

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRunMigrations(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir(MigrationsDir).Return([]fs.DirEntry{
		&handmock.MockDirEntry{Filename: "suricata-migration-3.10.0"},
		&handmock.MockDirEntry{Filename: "suricata-migration-3.4.0"},
		&handmock.MockDirEntry{Filename: "strelka-migration-3.4.0"}, // another engine's
		&handmock.MockDirEntry{Filename: "suricata-migration-3.5.0", Dir: true},
	}, nil)

	applied := []string{}
	migration := func(ver string) func(string) error {
		return func(path string) error {
			applied = append(applied, ver+" "+path)
			return nil
		}
	}

	state := &model.EngineState{}
	RunMigrations(iom, model.EngineNameSuricata, map[string]func(string) error{
		"3.4.0":  migration("3.4.0"),
		"3.10.0": migration("3.10.0"),
		"3.5.0":  migration("3.5.0"),
	}, state)

	// semver order, only this engine's files, no directories
	assert.Equal(t, []string{
		"3.4.0 /opt/so/conf/soc/migrations/suricata-migration-3.4.0",
		"3.10.0 /opt/so/conf/soc/migrations/suricata-migration-3.10.0",
	}, applied)
	assert.False(t, state.Migrating)
	assert.False(t, state.MigrationFailure)
}

func TestRunMigrationsHaltsOnFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadDir(MigrationsDir).Return([]fs.DirEntry{
		&handmock.MockDirEntry{Filename: "suricata-migration-3.4.0"},
		&handmock.MockDirEntry{Filename: "suricata-migration-3.5.0"},
	}, nil)

	later := 0
	state := &model.EngineState{}
	RunMigrations(iom, model.EngineNameSuricata, map[string]func(string) error{
		"3.4.0": func(string) error { return errors.New("boom") },
		"3.5.0": func(string) error { later++; return nil },
	}, state)

	assert.Equal(t, 0, later)
	assert.False(t, state.Migrating)
	assert.True(t, state.MigrationFailure)
}

func TestReadMigrationState(t *testing.T) {
	tests := []struct {
		Name        string
		Content     string
		ReadErr     error
		ExpPending  bool
		ExpectedErr string
	}{
		{Name: "Pending", Content: "0\n", ExpPending: true},
		{Name: "Done", Content: "1"},
		{Name: "Unexpected", Content: "yes", ExpectedErr: "unexpected state file content: yes"},
		{Name: "Unreadable", ReadErr: errors.New("missing"), ExpectedErr: "missing"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			iom := mock.NewMockIOManager(ctrl)
			iom.EXPECT().ReadFile("state").Return([]byte(test.Content), test.ReadErr)

			pending, err := ReadMigrationState(iom, "state")
			assert.Equal(t, test.ExpPending, pending)
			if test.ExpectedErr != "" {
				assert.EqualError(t, err, test.ExpectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMarkMigrationDone(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().WriteFile("state", []byte("1"), fs.FileMode(0644)).Return(nil)

	assert.NoError(t, MarkMigrationDone(iom, "state"))
}
