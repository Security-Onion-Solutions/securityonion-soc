// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit tests have no Postgres, so these pin the SQL text and run its regular
// expressions through Go, whose syntax matches Postgres for these patterns.
func netDropsMigration(t *testing.T) string {
	t.Helper()

	sql, err := migrationFS.ReadFile("migrations/3_net_drops_threshold_pps.sql")
	require.NoError(t, err)

	return string(sql)
}

func TestNetDropsMigrationTargetsOnlyNetDropsAlarms(t *testing.T) {
	sql := netDropsMigration(t)

	assert.Contains(t, sql, "WHERE setting_id = 'soc.config.server.modules.postgresmetrics.alarms'")
	assert.NotContains(t, sql, "node_id = ''")
	assert.Contains(t, sql, "lower(btrim(elem->>'metric')) = 'net_drops'")
	assert.Contains(t, sql, "ELSE elem")
	assert.NotContains(t, sql, "audit_settings")
}

func TestNetDropsMigrationFactor(t *testing.T) {
	sql := netDropsMigration(t)

	bytesToMb := 8.0 / (1000.0 * 1000.0)
	assert.Equal(t, 125000.0, 1/bytesToMb)
	assert.Contains(t, sql, "::numeric * 125000)")
}

func TestNetDropsMigrationHandlesBothEncodings(t *testing.T) {
	sql := netDropsMigration(t)

	assert.Contains(t, sql, "IF jsonb_typeof(rec.value) = 'string' THEN\n                alarms := (rec.value #>> '{}')::jsonb;")
	assert.Contains(t, sql, "ELSE\n                alarms := rec.value;")
	assert.Contains(t, sql, "WHEN jsonb_typeof(rec.value) = 'string' THEN to_jsonb(converted::text)\n                            ELSE converted")
	assert.Contains(t, sql, "EXCEPTION WHEN others THEN")
}

func TestNetDropsMigrationNumericThresholdPattern(t *testing.T) {
	sql := netDropsMigration(t)

	match := regexp.MustCompile(`btrim\(elem->>'threshold'\) ~ '([^']+)'`).FindStringSubmatch(sql)
	require.Len(t, match, 2)
	numeric := regexp.MustCompile(match[1])

	for _, value := range []string{"0", "5", "-2", "+3", "0.5", "1.", ".25", "1e-3", "2E6"} {
		assert.True(t, numeric.MatchString(value), value)
	}
	for _, value := range []string{"", "fault", "NaN", "Infinity", "1,000", "5 mbs", "e5", ".", "1e"} {
		assert.False(t, numeric.MatchString(value), value)
	}
}

func TestNetDropsMigrationFormatsPlainDecimal(t *testing.T) {
	sql := netDropsMigration(t)

	patterns := regexp.MustCompile(`'([^']*)',\s*'([^']*)'\)`).FindAllStringSubmatch(sql, -1)
	require.Len(t, patterns, 2)

	format := func(value string) string {
		for _, p := range patterns {
			value = regexp.MustCompile(p[1]).ReplaceAllString(value, strings.ReplaceAll(p[2], `\1`, `${1}`))
		}
		return value
	}

	tests := map[string]string{
		"125000":        "125000",
		"62500.0":       "62500",
		"0.0125000":     "0.0125",
		"125000.000000": "125000",
		"1500000.50":    "1500000.5",
		"-250000.0":     "-250000",
	}
	for numericText, expected := range tests {
		assert.Equal(t, expected, format(numericText), numericText)
	}
}
