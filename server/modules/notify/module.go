// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/notify/database"
)

const (
	ConfigSettingNotificationDestinations              = "soc.config.server.modules.notification.destinations"
	ConfigSettingNotificationEnabled                   = "soc.config.server.modules.notification.enabled"
	ConfigSettingNotificationDismissedPruneDays        = "soc.config.server.modules.notification.dismissedPruneDays"
	ConfigSettingNotificationMaxListLimit              = "soc.config.server.modules.notification.maxListLimit"
	ConfigSettingNotificationConnectionTimeoutSeconds  = "soc.config.server.modules.notification.connectionTimeoutSeconds"
)

type NotificationModule struct {
	server        *server.Server
	config        module.ModuleConfig
	registry      *ChannelRegistry
	notifier      *NotifierImpl
	store         *database.Store
	stopChan      chan struct{}
	pruneInterval time.Duration
	isRunning     bool
	mu            sync.RWMutex
}

func NewNotificationModule(srv *server.Server) *NotificationModule {
	return &NotificationModule{
		server:   srv,
		registry: NewChannelRegistry(),
	}
}

func (mod *NotificationModule) PrerequisiteModules() []string {
	return []string{"onionconfig", "postgres"}
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

	if !parsedConfig.Enabled {
		log.Info("Notification module is disabled in configuration; skipping initialization")
		return nil
	}

	ctx := context.Background()
	if mod.server != nil && mod.server.Context != nil {
		ctx = mod.server.Context
	}

	if mod.server != nil && mod.server.DB != nil {
		var err error
		mod.store, err = database.New(ctx, mod.server.DB)
		if err != nil {
			log.WithError(err).Error("Failed to initialize notification database")
			return err
		}
	}

	// Register core notification channel drivers
	socChannel := NewSOCChannel(mod.server, mod.store)
	if err := mod.registry.Register(socChannel); err != nil {
		log.WithError(err).Error("Failed to register SOC notification channel")
		return err
	}

	smtpChannel := NewSMTPChannel(mod.server)
	if err := mod.registry.Register(smtpChannel); err != nil {
		log.WithError(err).Error("Failed to register SMTP notification channel")
		return err
	}

	webhookChannel := NewWebhookChannel(mod.server)
	if err := mod.registry.Register(webhookChannel); err != nil {
		log.WithError(err).Error("Failed to register Webhook notification channel")
		return err
	}

	slackChannel := NewSlackChannel(mod.server)
	if err := mod.registry.Register(slackChannel); err != nil {
		log.WithError(err).Error("Failed to register Slack notification channel")
		return err
	}

	matrixChannel := NewMatrixChannel(mod.server)
	if err := mod.registry.Register(matrixChannel); err != nil {
		log.WithError(err).Error("Failed to register Matrix notification channel")
		return err
	}

	timeout := time.Duration(parsedConfig.ConnectionTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second
	}
	smtpChannel.SetTimeout(timeout)
	webhookChannel.SetTimeout(timeout)
	slackChannel.SetTimeout(timeout)
	matrixChannel.SetTimeout(timeout)

	mod.notifier = NewNotifier(mod.server, mod.registry, parsedConfig)
	if mod.server != nil {
		mod.server.Notifier = mod.notifier
		notifStore := NewNotificationstore(mod.server, mod.store)
		if parsedConfig.MaxListLimit > 0 {
			notifStore.SetDefaultLimit(parsedConfig.MaxListLimit)
		}
		mod.server.Notificationstore = notifStore
	}

	log.Info("Notification module initialized")

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
	registrar.RegisterConfigSettingCallback(ConfigSettingNotificationDismissedPruneDays, mod)
	registrar.RegisterConfigSettingCallback(ConfigSettingNotificationMaxListLimit, mod)
	registrar.RegisterConfigSettingCallback(ConfigSettingNotificationConnectionTimeoutSeconds, mod)
}

func (mod *NotificationModule) OnConfigSettingUpdated(ctx context.Context, setting *model.Setting, removed bool) {
	if setting == nil || mod.notifier == nil {
		return
	}

	log.FromContext(ctx).WithField("setting", setting.Id).Info("reloading notification configuration after config change")

	mod.mu.Lock()
	defer mod.mu.Unlock()

	mod.notifier.mu.Lock()
	defer mod.notifier.mu.Unlock()

	switch setting.Id {
	case ConfigSettingNotificationDestinations:
		if removed || setting.Value == "" {
			parsed, _ := ParseConfig(mod.config)
			mod.notifier.config.Destinations = parsed.Destinations
		} else {
			if dests, err := unmarshalDestinations(setting.Value); err == nil {
				mod.notifier.config.Destinations = dests
			}
		}
	case ConfigSettingNotificationEnabled:
		if removed || setting.Value == "" {
			mod.notifier.config.Enabled = module.GetBoolDefault(mod.config, "enabled", true)
		} else {
			mod.notifier.config.Enabled = setting.Value == "true"
		}
	case ConfigSettingNotificationDismissedPruneDays:
		if removed || setting.Value == "" {
			mod.notifier.config.DismissedPruneDays = module.GetIntDefault(mod.config, "dismissedPruneDays", DEFAULT_DISMISSED_PRUNE_DAYS)
		} else if days, err := strconv.Atoi(setting.Value); err == nil && days > 0 {
			mod.notifier.config.DismissedPruneDays = days
		}
	case ConfigSettingNotificationMaxListLimit:
		if removed || setting.Value == "" {
			limit := module.GetIntDefault(mod.config, "maxListLimit", DEFAULT_MAX_LIST_LIMIT)
			if ns, ok := mod.server.Notificationstore.(*NotificationstoreImpl); ok {
				ns.SetDefaultLimit(limit)
			}
		} else if limit, err := strconv.Atoi(setting.Value); err == nil && limit > 0 {
			if ns, ok := mod.server.Notificationstore.(*NotificationstoreImpl); ok {
				ns.SetDefaultLimit(limit)
			}
		}
	case ConfigSettingNotificationConnectionTimeoutSeconds:
		timeout := time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second
		if removed || setting.Value == "" {
			sec := module.GetIntDefault(mod.config, "connectionTimeoutSeconds", DEFAULT_CONNECTION_TIMEOUT_SECONDS)
			timeout = time.Duration(sec) * time.Second
		} else if sec, err := strconv.Atoi(strings.TrimSpace(setting.Value)); err == nil && sec > 0 {
			timeout = time.Duration(sec) * time.Second
		}
		mod.setConnectionTimeout(timeout)
	}
}

func (mod *NotificationModule) setConnectionTimeout(d time.Duration) {
	if mod.registry == nil || d <= 0 {
		return
	}
	for _, t := range mod.registry.RegisteredTypes() {
		if ch, found := mod.registry.Get(t); found {
			if ts, ok := ch.(interface{ SetTimeout(time.Duration) }); ok {
				ts.SetTimeout(d)
			}
		}
	}
}

func (mod *NotificationModule) Start() error {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.Debug("No active license with notifications enabled; skipping startup")
		return nil
	}

	if mod.notifier == nil || !mod.notifier.config.Enabled {
		log.Debug("Notification module is disabled or not initialized; skipping startup")
		return nil
	}

	ctx := context.Background()
	var configstore server.Configstore
	if mod.server != nil {
		if mod.server.Context != nil {
			ctx = mod.server.Context
		}
		configstore = mod.server.Configstore
	}

	if storeDests, ok := LoadConfigFromStore(ctx, configstore); ok && mod.notifier != nil {
		mod.notifier.mu.Lock()
		mod.notifier.config.Destinations = storeDests
		mod.notifier.mu.Unlock()
	}

	mod.registerConfigCallbacks()

	mod.mu.Lock()
	mod.stopChan = make(chan struct{})
	mod.isRunning = true
	mod.mu.Unlock()

	go mod.pruneLoop()

	destCount := 0
	pruneDays := DEFAULT_DISMISSED_PRUNE_DAYS
	if mod.notifier != nil {
		mod.notifier.mu.RLock()
		destCount = len(mod.notifier.config.Destinations)
		pruneDays = mod.notifier.config.DismissedPruneDays
		mod.notifier.mu.RUnlock()
	}

	log.WithFields(log.Fields{
		"destinationCount": destCount,
		"pruneDays":        pruneDays,
	}).Info("Notification module started")
	return nil
}

func (mod *NotificationModule) Stop() error {
	mod.mu.Lock()
	if mod.isRunning {
		mod.isRunning = false
		if mod.stopChan != nil {
			close(mod.stopChan)
		}
	}
	mod.mu.Unlock()
	log.Info("Notification module stopped")
	return nil
}

func (mod *NotificationModule) IsRunning() bool {
	mod.mu.RLock()
	defer mod.mu.RUnlock()
	return mod.isRunning
}

// PruneDismissed removes dismissed notifications that were dismissed on or before the retention cutoff.
func (mod *NotificationModule) PruneDismissed(ctx context.Context) error {
	if mod.store == nil {
		return nil
	}

	mod.mu.RLock()
	days := DEFAULT_DISMISSED_PRUNE_DAYS
	if mod.notifier != nil {
		mod.notifier.mu.RLock()
		if mod.notifier.config.DismissedPruneDays > 0 {
			days = mod.notifier.config.DismissedPruneDays
		}
		mod.notifier.mu.RUnlock()
	}
	mod.mu.RUnlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	log.WithFields(log.Fields{
		"retentionDays": days,
		"cutoff":        cutoff,
	}).Debug("Pruning dismissed notifications older than retention cutoff")

	if err := mod.store.PruneDismissedNotifications(ctx, cutoff); err != nil {
		log.WithError(err).Error("Failed to prune dismissed notifications")
		return err
	}

	return nil
}

func (mod *NotificationModule) pruneLoop() {
	interval := mod.pruneInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx := context.Background()
	if mod.server != nil && mod.server.Context != nil {
		ctx = mod.server.Context
	}

	// Run an initial prune on startup
	_ = mod.PruneDismissed(ctx)

	for {
		select {
		case <-mod.stopChan:
			log.Debug("Notification prune loop exiting")
			return
		case <-ticker.C:
			_ = mod.PruneDismissed(ctx)
		}
	}
}
