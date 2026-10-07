// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// sortedKeys returns a sorted slice of map keys.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// defaultSeverityAndTitle extracts and defaults severity and title from a payload.
func defaultSeverityAndTitle(payload *model.NotificationPayload) (string, string) {
	if payload == nil {
		return "INFO", NOTIFICATION_DEFAULT_TITLE
	}
	sev := strings.ToUpper(strings.TrimSpace(payload.Severity))
	if sev == "" {
		sev = "INFO"
	}
	title := strings.TrimSpace(payload.Title)
	if title == "" {
		title = NOTIFICATION_DEFAULT_TITLE
	}
	return sev, title
}
