// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type OnionConfig struct {
	server        *server.Server
	saltstackDir  string
	bypassEnabled bool
	annotations   map[string]map[string]interface{}
}

func NewOnionConfig(server *server.Server) *OnionConfig {
	return &OnionConfig{
		server: server,
	}
}

func (c *OnionConfig) Init(saltstackDir string, bypassEnabled bool) error {
	c.saltstackDir = strings.TrimSuffix(saltstackDir, "/")
	c.bypassEnabled = bypassEnabled

	if c.bypassEnabled {
		go c.PreloadConfiguration()
	} else {
		return c.PreloadConfiguration()
	}

	return nil
}

func (c *OnionConfig) PreloadConfiguration() error {
	// Pre-load annotations and default settings from the default pillar directory
	var err error
	defaultDir := c.saltstackDir + "/default"
	if _, statErr := os.Stat(defaultDir); statErr == nil {
		var defaults map[string]string
		c.annotations, defaults, err = LoadStaticConfiguration(defaultDir, ParseYaml)
		if err == nil {
			HydrateAnnotations(c.annotations, defaults, func(id string) (string, bool) {
				relpath := RelPathFromId(id)
				content, err := ReadFile(fmt.Sprintf("%s/default/salt/%s", c.saltstackDir, relpath))
				return content, err == nil
			})
		}
	}

	if err != nil {
		log.WithError(err).Warn("Failed to load pillar data")
		if !c.bypassEnabled {
			return err
		}
	}

	return nil
}

func (c *OnionConfig) GetSetting(ctx context.Context, id string) (*model.Setting, error) {
	settings, err := LoadLocalSettings(c.saltstackDir, id, c.annotations, c.bypassEnabled)
	if err != nil {
		return nil, err
	}
	if len(settings) > 0 {
		return settings[0], nil
	}
	return nil, nil
}

func (c *OnionConfig) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}

	settings, err := LoadLocalSettings(c.saltstackDir, "", c.annotations, c.bypassEnabled)
	if err != nil {
		return nil, err
	}

	return Sort(Filter(settings, advanced)), err
}

func (c *OnionConfig) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) (err error) {
	logger := log.FromContext(ctx)

	if err = c.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	settingDef, err := c.GetSetting(ctx, setting.Id)
	if err != nil {
		return err
	} else {
		if settingDef == nil {
			logger.WithFields(log.Fields{
				"settingId": setting.Id,
			}).Info("Setting definition not found; assuming new, undefined setting")
		} else {
			if settingDef.Readonly {
				return errors.New("Unable to modify or remove a readonly setting")
			}
			setting.Syntax = settingDef.Syntax
			setting.Description = settingDef.Description
			setting.Title = settingDef.Title
			setting.Multiline = settingDef.Multiline
			setting.Advanced = settingDef.Advanced
			setting.ForcedType = settingDef.ForcedType
			setting.Default = settingDef.Default
			setting.DefaultAvailable = settingDef.DefaultAvailable
			setting.File = settingDef.File
			setting.JinjaEscaped = settingDef.JinjaEscaped
			setting.UiElements = settingDef.UiElements
		}
	}

	return UpdatePillarSetting(c.saltstackDir, setting, remove)
}
