// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"regexp"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/apex/log"
	"gopkg.in/yaml.v3"
)

// eventDataPrefix is where a Sigma (Elastalert) alert document nests the original triggering event.
// Alert-level metadata (rule.uuid, soc_id) sits at the top level; the fired event's own
// fields live under event_data.*
const eventDataPrefix = "event_data."

var placeholderUseRe = regexp.MustCompile(`%([^%\s]+)%`)

// extractPlaceholders returns the set of resolvable %token% names used across the given
// query strings, skipping escaped \%name%\.
func extractPlaceholders(queries ...string) map[string]bool {
	used := map[string]bool{}
	for _, q := range queries {
		for _, idx := range placeholderUseRe.FindAllStringSubmatchIndex(q, -1) {
			if idx[0] > 0 && q[idx[0]-1] == '\\' {
				continue // escaped \%name% is literal text, not a placeholder
			}
			used[q[idx[2]:idx[3]]] = true
		}
	}
	return used
}

// lookupEventValue resolves a field path against the alert document, trying the
// event_data.-nested original-event location first, then the bare alert-level path, then
// the document-id bridge (the SOC _id lives on EventRecord.Id, not in Payload). A
// present-but-null field is treated as absent, so it degrades to the NODATA fallback
// instead of injecting a null value (some sources ship explicit nulls)
func lookupEventValue(event *model.EventRecord, key string) (interface{}, bool) {
	if event == nil {
		return nil, false
	}
	if v, ok := event.Payload[eventDataPrefix+key]; ok && v != nil {
		return v, true
	}
	if v, ok := event.Payload[key]; ok && v != nil {
		return v, true
	}
	if key == socIdPayloadKey && event.Id != "" {
		return event.Id, true
	}
	return nil, false
}

// effectiveBindings returns the binding set a playbook resolves against: the global map
// overlaid with the playbook's own repo config-file bindings (config file wins on conflict).
func (pdm *PlaybookDiskManager) effectiveBindings(playbookID string) map[string]string {
	out := make(map[string]string, len(pdm.placeholderMap)+8)
	for k, v := range pdm.placeholderMap {
		out[k] = v
	}
	pdm.pbUpdateMutex.RLock()
	for k, v := range pdm.playbookBindings[playbookID] {
		out[k] = v
	}
	pdm.pbUpdateMutex.RUnlock()
	return out
}

// missingValueFallback fills a mapped placeholder whose value is absent from
// the event, so `sigma convert` doesn't raise on an unresolved placeholder.
// Unmapped placeholders get no var and still fail.
const missingValueFallback = "NODATA"

// loadPlaceholderMap reads the placeholder map YAML (Sigma placeholder name ->
// event.Payload key). A missing/malformed/empty file is non-fatal
func (pdm *PlaybookDiskManager) loadPlaceholderMap(path string) map[string]string {
	m := map[string]string{}

	raw, err := pdm.ReadFile(path)
	if err != nil {
		log.WithError(err).WithField("path", path).Warn("unable to read playbook placeholder map; continuing with an empty map (playbook %placeholder% resolution disabled until present)")
		return m
	}

	if err := yaml.Unmarshal(raw, &m); err != nil {
		log.WithError(err).WithField("path", path).Warn("unable to parse playbook placeholder map; continuing with an empty map (playbook %placeholder% resolution disabled until fixed)")
		return map[string]string{}
	}

	if len(m) == 0 {
		log.WithField("path", path).Warn("playbook placeholder map is empty; playbook %placeholder% resolution disabled until populated")
	}

	return m
}

// socIdPayloadKey is the field name %document_id% resolves to (lookupEventValue bridges it
// to EventRecord.Id). Matches the soc_id name the case/escalation handlers give event.Id.
const socIdPayloadKey = "soc_id"

// buildVarsFromEvent builds the `vars:` block for `sigma convert` from the alert event.
//
//	(1) Every declared token (effective bindings = global map + repo config file) resolves to
//	    its event value via lookupEventValue, else the NODATA fallback
//	(2) A token USED in a query but undeclared is tried as a direct field name; a hit
//	    covers "named the placeholder after a flat field", a miss is left ABSENT so
//	    value_placeholders fails rather than silently resolving to the fallback.
//
// List values pass through as-is; the backend renders them as an OR-list.
func (pdm *PlaybookDiskManager) buildVarsFromEvent(event *model.EventRecord, bindings map[string]string, used map[string]bool) map[string]interface{} {
	vars := make(map[string]interface{}, len(bindings)+len(used))

	for token, field := range bindings {
		if v, ok := lookupEventValue(event, field); ok {
			vars[token] = v
		} else {
			vars[token] = missingValueFallback
		}
	}

	for token := range used {
		if _, declared := bindings[token]; declared {
			continue
		}
		if v, ok := lookupEventValue(event, token); ok {
			vars[token] = v
		}
	}

	return vars
}
