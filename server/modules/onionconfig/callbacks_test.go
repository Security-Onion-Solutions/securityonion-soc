// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

type recordingHandler struct {
	calls   []*model.Setting
	removed []bool
	panics  bool
}

func (h *recordingHandler) OnConfigSettingUpdated(ctx context.Context, setting *model.Setting, removed bool) {
	if h.panics {
		panic("boom")
	}
	h.calls = append(h.calls, setting)
	h.removed = append(h.removed, removed)
}

func TestRegisterAndNotifyConfigSettingCallbacks(t *testing.T) {
	ctx := context.Background()

	t.Run("notifies only handlers registered for the setting id", func(t *testing.T) {
		oc := NewOnionConfig(nil)

		hA := &recordingHandler{}
		hB := &recordingHandler{}
		oc.RegisterConfigSettingCallback("assistant.agents", hA)
		oc.RegisterConfigSettingCallback("some.other.setting", hB)

		oc.notifyConfigSettingCallbacks(ctx, &model.Setting{Id: "assistant.agents", Value: "v"}, false)

		assert.Len(t, hA.calls, 1)
		assert.Equal(t, "assistant.agents", hA.calls[0].Id)
		assert.Equal(t, []bool{false}, hA.removed)
		assert.Empty(t, hB.calls, "handler for a different setting id must not be called")
	})

	t.Run("supports multiple handlers for the same id and passes removed flag", func(t *testing.T) {
		oc := NewOnionConfig(nil)

		h1 := &recordingHandler{}
		h2 := &recordingHandler{}
		oc.RegisterConfigSettingCallback("assistant.agents", h1)
		oc.RegisterConfigSettingCallback("assistant.agents", h2)

		oc.notifyConfigSettingCallbacks(ctx, &model.Setting{Id: "assistant.agents"}, true)

		assert.Equal(t, []bool{true}, h1.removed)
		assert.Equal(t, []bool{true}, h2.removed)
	})

	t.Run("recovers from a panicking handler and still calls the others", func(t *testing.T) {
		oc := NewOnionConfig(nil)

		bad := &recordingHandler{panics: true}
		good := &recordingHandler{}
		oc.RegisterConfigSettingCallback("assistant.agents", bad)
		oc.RegisterConfigSettingCallback("assistant.agents", good)

		assert.NotPanics(t, func() {
			oc.notifyConfigSettingCallbacks(ctx, &model.Setting{Id: "assistant.agents"}, false)
		})
		assert.Len(t, good.calls, 1, "a panicking handler must not prevent later handlers from running")
	})

	t.Run("ignores nil handler, empty id, and nil setting", func(t *testing.T) {
		oc := NewOnionConfig(nil)

		oc.RegisterConfigSettingCallback("", &recordingHandler{})
		oc.RegisterConfigSettingCallback("assistant.agents", nil)

		assert.NotPanics(t, func() {
			oc.notifyConfigSettingCallbacks(ctx, nil, false)
			oc.notifyConfigSettingCallbacks(ctx, &model.Setting{Id: "unregistered"}, false)
		})
	})
}
