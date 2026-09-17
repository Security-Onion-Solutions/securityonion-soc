// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultDestinationSOCBellConfig(t *testing.T) {
	cfg := DefaultDestinationSOCBellConfig()
	assert.Equal(t, DefaultDestinationSOCBell, cfg.ID)
	assert.Equal(t, "", cfg.Name)
	assert.Equal(t, ChannelTypeSOC, cfg.Type)
	assert.True(t, cfg.Enabled)
}

func TestDefaultDestinationsMap(t *testing.T) {
	dests := DefaultDestinationsMap()
	assert.Len(t, dests, 1)
	assert.Contains(t, dests, DefaultDestinationSOCBell)
}

func TestIsValidDestinationID(t *testing.T) {
	validIDs := []string{
		"soc-bell",
		"email_alerts-1",
		"123e4567-e89b-12d3-a456-426614174000",
		"pagerduty.prod",
		"custom-123",
	}
	for _, id := range validIDs {
		assert.True(t, IsValidDestinationID(id), "expected valid: %s", id)
	}

	invalidIDs := []string{
		"",
		" ",
		"soc bell",
		"dest/with/slash",
		"dest?query",
		"dest#hash",
		"dest$special",
		string(make([]byte, MAX_DESTINATION_ID_LEN+1)), // too long
	}
	for _, id := range invalidIDs {
		assert.False(t, IsValidDestinationID(id), "expected invalid: %s", id)
	}
}

func TestValidateDestinationName(t *testing.T) {
	assert.NoError(t, ValidateDestinationName(""))
	assert.NoError(t, ValidateDestinationName("SOC Alert Bell"))
	assert.NoError(t, ValidateDestinationName(string(make([]byte, MAX_DESTINATION_NAME_LEN))))

	// Exceeds max length
	assert.Error(t, ValidateDestinationName(string(make([]byte, MAX_DESTINATION_NAME_LEN+1))))
}
