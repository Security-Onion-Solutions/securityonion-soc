// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

type dummyChannel struct {
	channelType string
}

func (d *dummyChannel) Type() string {
	return d.channelType
}

func (d *dummyChannel) ValidateConfig(params map[string]interface{}) error {
	return nil
}

func (d *dummyChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	return nil
}

func TestChannelRegistry_Licensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	assert.Empty(t, reg.RegisteredTypes())

	// Test register nil channel
	err := reg.Register(nil)
	assert.Error(t, err)

	// Test register empty type
	err = reg.Register(&dummyChannel{channelType: ""})
	assert.Error(t, err)

	// Test register valid channel
	ch1 := &dummyChannel{channelType: "slack"}
	err = reg.Register(ch1)
	assert.NoError(t, err)

	ch2 := &dummyChannel{channelType: "smtp"}
	err = reg.Register(ch2)
	assert.NoError(t, err)

	// Test get existing
	retrieved, found := reg.Get("slack")
	assert.True(t, found)
	assert.Equal(t, ch1, retrieved)

	// Test get non-existing
	_, found = reg.Get("nonexistent")
	assert.False(t, found)

	// Test registered types
	types := reg.RegisteredTypes()
	assert.Len(t, types, 2)
	assert.Contains(t, types, "slack")
	assert.Contains(t, types, "smtp")
}

func TestChannelRegistry_Unlicensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_API, 0, 0, "", "")

	reg := NewChannelRegistry()
	ch := &dummyChannel{channelType: "slack"}
	err := reg.Register(ch)
	assert.NoError(t, err)

	// Get should return nil, false when unlicensed
	retrieved, found := reg.Get("slack")
	assert.False(t, found)
	assert.Nil(t, retrieved)

	// RegisteredTypes should return nil when unlicensed
	types := reg.RegisteredTypes()
	assert.Nil(t, types)
}
