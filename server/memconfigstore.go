// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type MemConfigStore struct {
	settings []*model.Setting
}

func NewMemConfigStore(settings []*model.Setting) *MemConfigStore {
	return &MemConfigStore{
		settings: settings,
	}
}

func (m *MemConfigStore) GetSettings(ctx context.Context) ([]*model.Setting, error) {
	return m.settings, nil
}

func (m *MemConfigStore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	_, index, ok := lo.FindIndexOf(m.settings, func(s *model.Setting) bool {
		return s.Id == setting.Id
	})

	if remove {
		if ok {
			m.settings = append(m.settings[:index], m.settings[index+1:]...)
		}
	} else {
		if ok {
			m.settings[index] = setting
		} else {
			m.settings = append(m.settings, setting)
		}
	}

	return nil
}

func (m *MemConfigStore) SyncSettings(ctx context.Context) error {
	return nil
}
