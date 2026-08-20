// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
)

const (
	DEFAULT_GLOBAL_SILENCE_WINDOW_SECONDS = 300
	DEFAULT_DESTINATION_NAME              = "SOC Notification Bell"
)

// ParseConfig parses and validates module configuration, ensuring default destinations
// (such as soc-bell) are set on new or empty configurations.
func ParseConfig(cfg module.ModuleConfig) (model.NotificationConfig, error) {
	config := model.NotificationConfig{
		Enabled:                    module.GetBoolDefault(cfg, "enabled", true),
		DefaultDestinations:        module.GetStringArrayDefault(cfg, "defaultDestinations", []string{model.DefaultDestinationSOCBell}),
		GlobalSilenceWindowSeconds: module.GetIntDefault(cfg, "globalSilenceWindowSeconds", DEFAULT_GLOBAL_SILENCE_WINDOW_SECONDS),
		Destinations:               make(map[string]model.DestinationConfig),
	}

	if destinationsRaw, ok := cfg["destinations"]; ok && destinationsRaw != nil {
		switch dests := destinationsRaw.(type) {
		case map[string]interface{}:
			for destKey, destVal := range dests {
				if destMap, ok := destVal.(map[string]interface{}); ok {
					destName := module.GetStringDefault(destMap, "name", destKey)
					destType := module.GetStringDefault(destMap, "type", "")
					destEnabled := module.GetBoolDefault(destMap, "enabled", true)
					var params map[string]interface{}
					if p, ok := destMap["params"].(map[string]interface{}); ok {
						params = p
					} else {
						params = make(map[string]interface{})
					}
					config.Destinations[destKey] = model.DestinationConfig{
						Name:    destName,
						Type:    destType,
						Enabled: destEnabled,
						Params:  params,
					}
				}
			}
		case map[string]model.DestinationConfig:
			config.Destinations = dests
		}
	}

	// If no destinations are defined, configure default soc-bell destination
	if len(config.Destinations) == 0 {
		config.Destinations[model.DefaultDestinationSOCBell] = model.DestinationConfig{
			Name:    DEFAULT_DESTINATION_NAME,
			Type:    model.ChannelTypeSOC,
			Enabled: true,
			Params: map[string]interface{}{
				"storeInPostgres": true,
				"attachmentMode":  model.AttachmentModeLink,
			},
		}
	}

	// Ensure default destinations list has at least soc-bell if empty
	if len(config.DefaultDestinations) == 0 {
		config.DefaultDestinations = []string{model.DefaultDestinationSOCBell}
	}

	return config, nil
}
