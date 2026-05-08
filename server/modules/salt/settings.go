// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// FlattenPillar recursively walks a pillar map and flattens it into a map of setting ID to string value.
// It handles nested maps and lists by converting them to appropriate string representations.
func FlattenPillar(mapped map[string]interface{}, prefix string, result map[string]string) {
	for id, value := range mapped {
		newPrefix := prefix
		if newPrefix != "" {
			newPrefix = newPrefix + "."
		}
		newId := newPrefix + id

		switch v := value.(type) {
		case map[string]interface{}:
			FlattenPillar(v, newId, result)
		case []interface{}:
			var newValue string
			for _, item := range v {
				var str string
				switch item.(type) {
				case []interface{}, map[string]interface{}:
					bytes, _ := json.WriteJson(item)
					str = string(bytes)
				default:
					str = fmt.Sprintf("%v", item)
				}
				if str != "" {
					newValue = newValue + str + "\n"
				}
			}
			result[newId] = newValue
		default:
			result[newId] = fmt.Sprintf("%v", value)
		}
	}
}

// Filter removes advanced settings if not requested.
func Filter(settings []*model.Setting, advanced bool) []*model.Setting {
	if advanced {
		return settings
	}
	return slices.DeleteFunc(settings, func(setting *model.Setting) bool {
		return setting.Advanced
	})
}

// Sort orders settings by ID, ensuring advanced settings are pushed to the end.
func Sort(settings []*model.Setting) []*model.Setting {
	sort.Slice(settings, func(idx_a, idx_b int) bool {
		return (settings[idx_a].Id < settings[idx_b].Id && !strings.HasSuffix(settings[idx_a].Id, "advanced")) ||
			strings.HasSuffix(settings[idx_b].Id, "advanced")
	})
	return settings
}

