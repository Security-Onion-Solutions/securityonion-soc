// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
)

func TestLookupEventValue(t *testing.T) {
	ev := &model.EventRecord{
		Id: "soc-doc-1",
		Payload: map[string]interface{}{
			"event_data.process.executable": "c:\\evil.exe", // original event nests under event_data.*
			"rule.uuid":                     "abc-123",      // alert metadata at top level
		},
	}

	// event_data.-nested field resolves when the binding path is the bare ECS name
	v, ok := lookupEventValue(ev, "process.executable")
	assert.True(t, ok)
	assert.Equal(t, "c:\\evil.exe", v)

	// also resolves when the path already carries the event_data. prefix (legacy global map)
	v, ok = lookupEventValue(ev, "event_data.process.executable")
	assert.True(t, ok)
	assert.Equal(t, "c:\\evil.exe", v)

	// alert-level (non event_data) field resolves via the bare fallback
	v, ok = lookupEventValue(ev, "rule.uuid")
	assert.True(t, ok)
	assert.Equal(t, "abc-123", v)

	// the document id bridges to EventRecord.Id (not a Payload field)
	v, ok = lookupEventValue(ev, socIdPayloadKey)
	assert.True(t, ok)
	assert.Equal(t, "soc-doc-1", v)

	// absent field
	_, ok = lookupEventValue(ev, "no.such.field")
	assert.False(t, ok)

	// nil event -> not found, no panic
	_, ok = lookupEventValue(nil, "anything")
	assert.False(t, ok)

	// present-but-null field is treated as absent (some sources ship explicit nulls)
	evNull := &model.EventRecord{Payload: map[string]interface{}{
		"event_data.some.field": nil,
		"some.field":            nil,
	}}
	_, ok = lookupEventValue(evNull, "some.field")
	assert.False(t, ok, "a present-but-null field must not resolve")

	// a null event_data.X must not shadow a real bare X
	evShadow := &model.EventRecord{Payload: map[string]interface{}{
		"event_data.dst_ip": nil,
		"dst_ip":            "1.2.3.4",
	}}
	v, ok = lookupEventValue(evShadow, "dst_ip")
	assert.True(t, ok)
	assert.Equal(t, "1.2.3.4", v)
}

func TestMergePlaceholderMaps(t *testing.T) {
	global := map[string]string{"a": "field.a", "b": "field.b.global"}
	user := map[string]string{"b": "field.b.override", "c": "field.c"} // overrides b, adds c

	got := mergePlaceholderMaps(global, user)
	assert.Equal(t, "field.a", got["a"], "global-only token survives")
	assert.Equal(t, "field.b.override", got["b"], "user map wins on conflict")
	assert.Equal(t, "field.c", got["c"], "user map adds custom vocabulary")

	// inputs are not mutated
	assert.Equal(t, "field.b.global", global["b"], "global input is left untouched")
	_, globalHasC := global["c"]
	assert.False(t, globalHasC, "global input is left untouched")

	// nil inputs are treated as empty; the non-nil side passes through as a copy
	assert.Empty(t, mergePlaceholderMaps(nil, nil))
	assert.Equal(t, user, mergePlaceholderMaps(nil, user))
	assert.Equal(t, global, mergePlaceholderMaps(global, nil))
}

func TestBuildVarsFromEvent(t *testing.T) {
	pdm := &PlaybookDiskManager{}
	ev := &model.EventRecord{Payload: map[string]interface{}{
		"event_data.process.executable": "c:\\evil.exe",
		"event_data.actor":              "alice", // a flat undeclared token can hit this directly
	}}

	bindings := map[string]string{
		"Image":    "process.executable", // declared, present -> resolves
		"hostname": "host.name",          // declared, ABSENT on this event -> NODATA
	}
	used := map[string]bool{
		"Image":              true,
		"hostname":           true,
		"actor":              true, // undeclared but resolvable directly via event_data.actor
		"undeclared_missing": true, // undeclared + not a field -> omitted (loud fail downstream)
	}

	vars := pdm.buildVarsFromEvent(ev, bindings, used)

	assert.Equal(t, "c:\\evil.exe", vars["Image"])
	assert.Equal(t, missingValueFallback, vars["hostname"])
	assert.Equal(t, "alice", vars["actor"], "undeclared token resolves directly from a flat event field")
	_, present := vars["undeclared_missing"]
	assert.False(t, present, "undeclared+missing token must be omitted so convert fails loudly")
}

func TestExtractPlaceholders(t *testing.T) {
	used := extractPlaceholders(
		"Image|expand: '%Image%'",
		"rule.uuid|expand: '%rule_uuid%'",
		`CommandLine|contains: 'literal \%escaped\% text'`,       // escaped -> not a placeholder
		"dotted|expand: '%rule.uuid%'",                           // dotted token IS surfaced ([^%\s]+)
		"hyphen|expand: '%my-token%'",                            // hyphenated token IS surfaced
		"CommandLine|contains: 'progress 100% then %actor% ran'", // literal % must not eat %actor%
	)

	assert.True(t, used["Image"])
	assert.True(t, used["rule_uuid"])
	assert.True(t, used["rule.uuid"], "dotted token is surfaced by the broader name class")
	assert.True(t, used["my-token"], "hyphenated token is surfaced")
	assert.True(t, used["actor"], "a literal percent must not cannibalize an adjacent placeholder")
	assert.False(t, used["escaped"], "escaped placeholder is literal, not a placeholder")
	assert.False(t, used[" then "], "whitespace is excluded, so a literal percent cannot match across it")
}
