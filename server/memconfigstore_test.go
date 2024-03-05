// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"testing"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestMemConfigStoreNew(t *testing.T) {
	origSettings := []*model.Setting{
		{Id: "1", Value: "one"},
		{Id: "2", Value: "two"},
		{Id: "3", Value: "three"},
	}
	mCfgStore := NewMemConfigStore(origSettings)

	assert.Implements(t, (*Configstore)(nil), mCfgStore)

	ctx := context.Background()

	set, err := mCfgStore.GetSettings(ctx)
	assert.NoError(t, err)
	assert.Same(t, &origSettings[0], &set[0])
}

func TestMemConfigStoreUpdate(t *testing.T) {
	origSettings := []*model.Setting{
		{Id: "1", Value: "one"},
		{Id: "2", Value: "two"},
		{Id: "3", Value: "three"},
	}

	ctx := context.Background()
	mCfgStore := NewMemConfigStore(origSettings)

	err := mCfgStore.UpdateSetting(ctx, &model.Setting{Id: "1", Value: "new"}, false)
	assert.NoError(t, err)

	set, err := mCfgStore.GetSettings(ctx)
	assert.NoError(t, err)
	assert.Len(t, set, 3)

	s, ok := lo.Find(set, func(s *model.Setting) bool {
		return s.Id == "1"
	})
	assert.True(t, ok)
	assert.Equal(t, "new", s.Value)
}

func TestMemConfigStoreUpdateAdd(t *testing.T) {
	origSettings := []*model.Setting{
		{Id: "1", Value: "one"},
		{Id: "2", Value: "two"},
		{Id: "3", Value: "three"},
	}

	ctx := context.Background()
	mCfgStore := NewMemConfigStore(origSettings)

	err := mCfgStore.UpdateSetting(ctx, &model.Setting{Id: "4", Value: "four"}, false)
	assert.NoError(t, err)

	set, err := mCfgStore.GetSettings(ctx)
	assert.NoError(t, err)
	assert.Len(t, set, 4)

	s, ok := lo.Find(set, func(s *model.Setting) bool {
		return s.Id == "4"
	})
	assert.True(t, ok)
	assert.Equal(t, "four", s.Value)
}

func TestMemConfigStoreUpdateRemove(t *testing.T) {
	origSettings := []*model.Setting{
		{Id: "1", Value: "one"},
		{Id: "2", Value: "two"},
		{Id: "3", Value: "three"},
	}

	ctx := context.Background()
	mCfgStore := NewMemConfigStore(origSettings)

	err := mCfgStore.UpdateSetting(ctx, &model.Setting{Id: "4"}, true)
	assert.NoError(t, err)

	set, err := mCfgStore.GetSettings(ctx)
	assert.NoError(t, err)
	assert.Len(t, set, 3)

	err = mCfgStore.UpdateSetting(ctx, &model.Setting{Id: "2"}, true)
	assert.NoError(t, err)

	set, err = mCfgStore.GetSettings(ctx)
	assert.NoError(t, err)
	assert.Len(t, set, 2)

	s, ok := lo.Find(set, func(s *model.Setting) bool {
		return s.Id == "2"
	})
	assert.False(t, ok)
	assert.Nil(t, s)
}

func TestMemConfigStoreSync(t *testing.T) {
	mCfgStore := NewMemConfigStore(nil)
	err := mCfgStore.SyncSettings(context.Background())
	assert.NoError(t, err)
}
