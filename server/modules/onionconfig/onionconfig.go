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
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type OnionConfig struct {
	server        *server.Server
	saltstackDir  string
	bypassEnabled bool
	annotations   map[string]map[string]interface{}
	store         *database.Store
	ready         chan struct{}
}

func NewOnionConfig(server *server.Server) *OnionConfig {
	return &OnionConfig{
		server: server,
		ready:  make(chan struct{}),
	}
}

func (c *OnionConfig) Init(saltstackDir string, bypassEnabled bool) {
	c.saltstackDir = strings.TrimSuffix(saltstackDir, "/")
	c.bypassEnabled = bypassEnabled
}

func (c *OnionConfig) Start(store *database.Store) error {
	c.store = store
	err := c.PreloadConfiguration()
	close(c.ready)
	return err
}

func (c *OnionConfig) waitReady() {
	<-c.ready
}

func (c *OnionConfig) PreloadConfiguration() error {
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
	c.waitReady()
	settings, err := c.loadAllSettings(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(settings) > 0 {
		return settings[0], nil
	}
	return nil, nil
}

func (c *OnionConfig) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	c.waitReady()
	if err := c.server.CheckAuthorized(ctx, "read", "config"); err != nil {
		return nil, err
	}

	settings, err := c.loadAllSettings(ctx, "")
	if err != nil {
		return nil, err
	}

	return Sort(Filter(settings, advanced)), err
}

func (c *OnionConfig) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) (err error) {
	c.waitReady()
	logger := log.FromContext(ctx)

	if err = c.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	settingDef, err := c.GetSetting(ctx, setting.Id)
	if err != nil {
		return err
	}

	var oldValue string
	if settingDef == nil {
		logger.WithFields(log.Fields{
			"settingId": setting.Id,
		}).Info("Setting definition not found; assuming new, undefined setting")
	} else {
		if settingDef.Readonly {
			return errors.New("Unable to modify or remove a readonly setting")
		}
		oldValue = settingDef.Value
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
		// Carry the origin forward so we know where to route the write.
		setting.Origin = settingDef.Origin
		setting.DuplicatedFromID = settingDef.DuplicatedFromID
	}

	return c.routeUpdate(ctx, setting, oldValue, remove, logger)
}

// routeUpdate dispatches a setting write to DB or yaml based on origin rules:
//   - db origin → DB
//   - yaml or unassigned origin → yaml
func (c *OnionConfig) routeUpdate(ctx context.Context, setting *model.Setting, oldValue string, remove bool, logger log.Interface) error {
	userID := userIDFromContext(ctx)

	if setting.Origin == model.SettingOriginDB {
		if c.store == nil {
			return errors.New("database not configured; cannot update DB setting")
		}
		return updateSettingInDB(ctx, c.store, setting, oldValue, remove, userID)
	}

	err := UpdatePillarSetting(c.saltstackDir, setting, remove)
	if err == nil && c.store != nil {
		if auditErr := auditSettingOnly(ctx, c.store, setting, oldValue, remove, userID); auditErr != nil {
			logger.WithError(auditErr).Warn("Failed to record YAML setting update audit")
		}
	}
	return err
}

// loadAllSettings merges DB settings on top of yaml settings then applies annotations.
func (c *OnionConfig) loadAllSettings(ctx context.Context, filterId string) ([]*model.Setting, error) {
	// 1. Load yaml settings (existing flow).
	yamlSettings, err := LoadLocalSettings(c.saltstackDir, filterId, c.annotations, c.bypassEnabled)
	if err != nil {
		return nil, err
	}

	// 2. Load DB settings (if available) and merge on top of yaml.
	if c.store != nil {
		dbSettings, dbErr := loadDBSettings(ctx, c.store)
		if dbErr != nil {
			log.WithError(dbErr).Warn("Failed to load settings from database; falling back to yaml-only")
		} else {
			// Filter DB settings when a specific ID is requested.
			if filterId != "" {
				filtered := dbSettings[:0]
				for _, s := range dbSettings {
					if s.Id == filterId {
						filtered = append(filtered, s)
					}
				}
				dbSettings = filtered
			}
			yamlSettings = mergeDBIntoYaml(dbSettings, yamlSettings)
		}
	}

	// 3. Re-apply annotations and masks to all settings to ensure DB-sourced values
	// are properly decorated and sensitive values are masked.
	for _, s := range yamlSettings {
		if ann, ok := c.annotations[s.Id]; ok {
			ApplyAnnotations(s, ann, nil)
		}
		if s.DuplicatedFromID != "" {
			if ann, ok := c.annotations[s.DuplicatedFromID]; ok {
				ApplyAnnotations(s, ann, nil)
			}
		}
		ApplySensitiveMask(s)
	}

	PostProcess(yamlSettings)

	return yamlSettings, nil
}

// userIDFromContext extracts a user identifier from the context, returning "unknown" if unavailable.
func userIDFromContext(ctx context.Context) string {
	if uid, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok && uid != "" {
		return uid
	}
	return "unknown"
}
