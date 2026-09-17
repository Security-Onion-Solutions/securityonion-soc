// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/notify/database"
)

const (
	ConfigSettingNotificationDestinations = "soc.config.server.modules.notification.destinations"
	ConfigSettingNotificationEnabled      = "soc.config.server.modules.notification.enabled"
)

type NotificationModule struct {
	server    *server.Server
	config    module.ModuleConfig
	registry  *ChannelRegistry
	notifier  *NotifierImpl
	store     *database.Store
	isRunning bool
	mu        sync.RWMutex
}

func NewNotificationModule(srv *server.Server) *NotificationModule {
	return &NotificationModule{
		server:   srv,
		registry: NewChannelRegistry(),
	}
}

func (mod *NotificationModule) PrerequisiteModules() []string {
	return nil
}

func (mod *NotificationModule) Init(cfg module.ModuleConfig) error {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.Debug("No active license with notifications enabled; skipping initialization")
		return nil
	}

	mod.config = cfg

	parsedConfig, err := ParseConfig(cfg)
	if err != nil {
		log.WithError(err).Error("Failed to parse notification module configuration")
		return err
	}

	if mod.server != nil && mod.server.DB != nil {
		ctx := mod.server.Context
		if ctx == nil {
			ctx = context.Background()
		}
		var err error
		mod.store, err = database.New(ctx, mod.server.DB)
		if err != nil {
			log.WithError(err).Error("Failed to initialize notification database")
			return err
		}
	}

	// Register core SOC channel driver
	socChannel := NewSOCChannel(mod.server, mod.store)
	if err := mod.registry.Register(socChannel); err != nil {
		log.WithError(err).Error("Failed to register SOC notification channel")
		return err
	}

	mod.notifier = NewNotifier(mod.server, mod.registry, parsedConfig)
	if mod.server != nil {
		mod.server.Notifier = mod.notifier
		mod.server.Notificationstore = NewNotificationstore(mod.server, mod.store)
		mod.registerConfigCallbacks()
	}

	log.WithFields(log.Fields{
		"defaultDestinations": parsedConfig.DefaultDestinations,
		"destinationCount":    len(parsedConfig.Destinations),
	}).Info("Notification module initialized")

	return nil
}

func (mod *NotificationModule) registerConfigCallbacks() {
	if mod.server == nil || mod.server.Configstore == nil {
		return
	}
	registrar, ok := mod.server.Configstore.(server.ConfigSettingCallbackRegistrar)
	if !ok {
		return
	}
	registrar.RegisterConfigSettingCallback(ConfigSettingNotificationDestinations, mod)
	registrar.RegisterConfigSettingCallback(ConfigSettingNotificationEnabled, mod)
}

func (mod *NotificationModule) OnConfigSettingUpdated(ctx context.Context, setting *model.Setting, removed bool) {
	if setting == nil || mod.notifier == nil {
		return
	}

	log.FromContext(ctx).WithField("setting", setting.Id).Info("reloading notification configuration after config change")

	mod.mu.Lock()
	defer mod.mu.Unlock()

	mod.notifier.mu.RLock()
	cfg := mod.notifier.config
	mod.notifier.mu.RUnlock()

	switch setting.Id {
	case ConfigSettingNotificationDestinations:
		if removed || setting.Value == "" {
			cfg.Destinations = model.DefaultDestinationsMap()
		} else {
			var dests map[string]model.DestinationConfig
			if err := json.Unmarshal([]byte(setting.Value), &dests); err == nil {
				for k, v := range dests {
					if v.ID == "" {
						v.ID = k
					}
					dests[k] = v
				}
				cfg.Destinations = dests
			}
		}
	case ConfigSettingNotificationEnabled:
		if removed || setting.Value == "" {
			cfg.Enabled = true
		} else {
			cfg.Enabled = setting.Value == "true"
		}
	}

	mod.notifier.UpdateConfig(cfg)
}

func (mod *NotificationModule) Start() error {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.Debug("No active license with notifications enabled; skipping startup")
		return nil
	}

	mod.mu.Lock()
	mod.isRunning = true
	mod.mu.Unlock()
	log.Info("Notification module started")
	return nil
}

func (mod *NotificationModule) Stop() error {
	mod.mu.Lock()
	mod.isRunning = false
	mod.mu.Unlock()
	log.Info("Notification module stopped")
	return nil
}

func (mod *NotificationModule) IsRunning() bool {
	mod.mu.RLock()
	defer mod.mu.RUnlock()
	return mod.isRunning
}
