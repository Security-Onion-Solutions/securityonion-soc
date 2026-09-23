// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const (
	DEFAULT_GLOBAL_SILENCE_WINDOW_SECONDS = 0
	DEFAULT_DISMISSED_PRUNE_DAYS          = 30
)

// LoadConfigFromStore reads notification destinations configuration from onionconfig.
// Returns the destinations map and true if destinations were found in the store.
func LoadConfigFromStore(ctx context.Context, store server.Configstore) (map[string]model.DestinationConfig, bool) {
	if store == nil {
		return nil, false
	}

	if setting, err := store.GetSetting(ctx, ConfigSettingNotificationDestinations); err == nil && setting != nil && setting.Value != "" {
		if dests, err := unmarshalDestinations(setting.Value); err == nil && len(dests) > 0 {
			return dests, true
		}
	}

	return nil, false
}

// ParseConfig parses and validates module configuration, ensuring default destinations
// (such as soc-bell) are set on new or empty configurations.
func ParseConfig(cfg module.ModuleConfig) (model.NotificationConfig, error) {
	config := model.NotificationConfig{
		Enabled:                    module.GetBoolDefault(cfg, "enabled", true),
		GlobalSilenceWindowSeconds: module.GetIntDefault(cfg, "globalSilenceWindowSeconds", DEFAULT_GLOBAL_SILENCE_WINDOW_SECONDS),
		DismissedPruneDays:         module.GetIntDefault(cfg, "dismissedPruneDays", DEFAULT_DISMISSED_PRUNE_DAYS),
		Destinations:               make(map[string]model.DestinationConfig),
	}

	if destinationsRaw, ok := cfg["destinations"]; ok && destinationsRaw != nil {
		switch dests := destinationsRaw.(type) {
		case map[string]interface{}:
			for destKey, destVal := range dests {
				if destMap, ok := destVal.(map[string]interface{}); ok {
					destName := module.GetStringDefault(destMap, "name", "")
					destType := module.GetStringDefault(destMap, "type", "")
					destEnabled := module.GetBoolDefault(destMap, "enabled", true)
					destScheduleIDs := module.GetStringArrayDefault(destMap, "scheduleIds", nil)
					destSeverities := module.GetStringArrayDefault(destMap, "severities", nil)
					var params map[string]interface{}
					if p, ok := destMap["params"].(map[string]interface{}); ok {
						params = p
					} else {
						params = make(map[string]interface{})
					}
					config.Destinations[destKey] = model.DestinationConfig{
						ID:          destKey,
						Name:        destName,
						Type:        destType,
						Enabled:     destEnabled,
						ScheduleIDs: destScheduleIDs,
						Severities:  destSeverities,
						Params:      params,
					}
				}
			}
		case map[string]model.DestinationConfig:
			for k, v := range dests {
				if v.ID == "" {
					v.ID = k
				}
				config.Destinations[k] = v
			}
		}
	}

	// If no destinations are defined, configure default soc-bell destination
	if len(config.Destinations) == 0 {
		config.Destinations = model.DefaultDestinationsMap()
	}

	return config, nil
}
