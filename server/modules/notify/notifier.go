// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type NotifierImpl struct {
	server   *server.Server
	registry *ChannelRegistry
	config   model.NotificationConfig
	mu       sync.RWMutex
}

func NewNotifier(srv *server.Server, registry *ChannelRegistry, cfg model.NotificationConfig) *NotifierImpl {
	return &NotifierImpl{
		server:   srv,
		registry: registry,
		config:   cfg,
	}
}

func (n *NotifierImpl) Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}

	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.WithField("notificationId", payload.ID).Debug("No active license with notifications enabled; skipping dispatch")
		return nil
	}

	n.mu.RLock()
	enabled := n.config.Enabled
	defaultDests := make([]string, len(n.config.DefaultDestinations))
	copy(defaultDests, n.config.DefaultDestinations)
	destinationsMap := make(map[string]model.DestinationConfig, len(n.config.Destinations))
	for k, v := range n.config.Destinations {
		destinationsMap[k] = v
	}
	n.mu.RUnlock()

	if !enabled {
		log.WithField("notificationId", payload.ID).Debug("Notification system is disabled; skipping dispatch")
		return nil
	}

	targetDests := destinations
	if len(targetDests) == 0 {
		targetDests = defaultDests
	}
	if len(targetDests) == 0 {
		targetDests = []string{model.DefaultDestinationSOCBell}
	}

	var errs []error
	for _, destName := range targetDests {
		destCfg, found := destinationsMap[destName]
		if !found {
			err := fmt.Errorf("destination '%s' not found", destName)
			log.WithError(err).Warn("Failed to send notification")
			errs = append(errs, err)
			continue
		}

		if !destCfg.Enabled {
			log.WithField("destination", destName).Debug("Destination is disabled; skipping")
			continue
		}

		channel, found := n.registry.Get(destCfg.Type)
		if !found {
			err := fmt.Errorf("channel driver '%s' not found for destination '%s'", destCfg.Type, destName)
			log.WithError(err).Warn("Failed to send notification")
			errs = append(errs, err)
			continue
		}

		if err := channel.Send(ctx, destCfg.Params, payload); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"destination": destName,
				"channelType": destCfg.Type,
			}).Error("Channel driver failed to send notification")
			errs = append(errs, fmt.Errorf("destination '%s' send failed: %w", destName, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (n *NotifierImpl) SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error {
	if payload != nil && silence != nil && silence.SilenceKey != "" {
		payload.SilenceKey = silence.SilenceKey
	}
	return n.Send(ctx, payload, destinations...)
}

func (n *NotifierImpl) RegisterChannel(channel server.NotificationChannel) {
	if n.registry != nil && channel != nil {
		_ = n.registry.Register(channel)
	}
}

func (n *NotifierImpl) GetChannel(channelType string) (server.NotificationChannel, bool) {
	if n.registry == nil {
		return nil, false
	}
	return n.registry.Get(channelType)
}

func (n *NotifierImpl) GetDestinations() map[string]model.DestinationConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()
	dests := make(map[string]model.DestinationConfig, len(n.config.Destinations))
	for k, v := range n.config.Destinations {
		dests[k] = v
	}
	return dests
}

func (n *NotifierImpl) GetDefaultDestinations() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	dests := make([]string, len(n.config.DefaultDestinations))
	copy(dests, n.config.DefaultDestinations)
	return dests
}

func (n *NotifierImpl) UpdateConfig(cfg model.NotificationConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config = cfg
}
