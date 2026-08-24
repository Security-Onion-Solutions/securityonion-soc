// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"fmt"
	"sync"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type ChannelRegistry struct {
	mu       sync.RWMutex
	channels map[string]server.NotificationChannel
}

func NewChannelRegistry() *ChannelRegistry {
	return &ChannelRegistry{
		channels: make(map[string]server.NotificationChannel),
	}
}

func (r *ChannelRegistry) Register(channel server.NotificationChannel) error {
	if channel == nil {
		return fmt.Errorf("cannot register nil notification channel")
	}
	chType := channel.Type()
	if chType == "" {
		return fmt.Errorf("cannot register channel with empty type")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[chType] = channel
	return nil
}

func (r *ChannelRegistry) Get(channelType string) (server.NotificationChannel, bool) {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.Debug("No active license with notifications enabled; skipping lookup")
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	ch, ok := r.channels[channelType]
	return ch, ok
}

func (r *ChannelRegistry) RegisteredTypes() []string {
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.Debug("No active license with notifications enabled; skipping registered types lookup")
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.channels))
	for t := range r.channels {
		types = append(types, t)
	}
	return types
}
