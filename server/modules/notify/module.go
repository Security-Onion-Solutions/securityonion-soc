// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/notify/database"
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
	}

	log.WithFields(log.Fields{
		"defaultDestinations": parsedConfig.DefaultDestinations,
		"destinationCount":    len(parsedConfig.Destinations),
	}).Info("Notification module initialized")

	return nil
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
