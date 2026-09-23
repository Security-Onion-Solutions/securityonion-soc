// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type silencerEntry struct {
	lastDispatched time.Time
	triggerCount   int
	windowStart    time.Time
}

type NotifierImpl struct {
	server    *server.Server
	registry  *ChannelRegistry
	config    model.NotificationConfig
	mu        sync.RWMutex
	silenceMu sync.Mutex
	silenced  map[string]*silencerEntry
}

func NewNotifier(srv *server.Server, registry *ChannelRegistry, cfg model.NotificationConfig) *NotifierImpl {
	return &NotifierImpl{
		server:   srv,
		registry: registry,
		config:   cfg,
		silenced: make(map[string]*silencerEntry),
	}
}

func (n *NotifierImpl) Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) (int, error) {
	if payload == nil {
		return 0, errors.New("notification payload cannot be nil")
	}

	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		log.WithField("notificationId", payload.ID).Debug("No active license with notifications enabled; skipping dispatch")
		return 0, nil
	}

	n.mu.RLock()
	enabled := n.config.Enabled
	destinationsMap := make(map[string]model.DestinationConfig, len(n.config.Destinations))
	for k, v := range n.config.Destinations {
		destinationsMap[k] = v
	}
	n.mu.RUnlock()

	if !enabled {
		log.WithField("notificationId", payload.ID).Debug("Notification system is disabled; skipping dispatch")
		return 0, nil
	}

	targetDests := destinations
	if len(targetDests) == 0 {
		targetDests = make([]string, 0, len(destinationsMap))
		for destKey := range destinationsMap {
			targetDests = append(targetDests, destKey)
		}
	}

	var sentCount int
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

		if len(destCfg.Severities) > 0 {
			allowed := false
			for _, sev := range destCfg.Severities {
				if strings.EqualFold(sev, payload.Severity) {
					allowed = true
					break
				}
			}
			if !allowed {
				log.WithFields(log.Fields{
					"destination": destName,
					"severity":    payload.Severity,
				}).Debug("Notification severity filtered out by destination configuration; skipping")
				continue
			}
		}

		if !payload.BypassSchedules {
			if len(destCfg.ScheduleIDs) > 0 {
				if n.server != nil && n.server.Configstore != nil {
					now := time.Now().UTC()
					anyActive := false
					for _, schedID := range destCfg.ScheduleIDs {
						if schedID == "" {
							anyActive = true
							break
						}
						active, err := server.IsScheduleActiveInConfig(ctx, n.server.Configstore, schedID, now)
						if err != nil {
							log.WithError(err).WithField("scheduleId", schedID).Warn("Failed to evaluate destination schedule; failing open and treating as active")
							active = true
						}
						if active {
							anyActive = true
							break
						}
					}
					if !anyActive {
						log.WithFields(log.Fields{
							"destination": destName,
							"scheduleIds": destCfg.ScheduleIDs,
						}).Debug("None of the destination schedules are currently active; skipping")
						continue
					}
				}
			}
		}

		channel, found := n.registry.Get(destCfg.Type)
		if !found {
			err := fmt.Errorf("channel driver '%s' not found for destination '%s'", destCfg.Type, destName)
			log.WithError(err).Warn("Failed to send notification")
			errs = append(errs, err)
			continue
		}

		destPayload := payload

		if len(payload.Recipients) > 0 {
			recipientsEnabled := channel.SupportsRecipients()
			if destCfg.EnableRecipients != nil {
				recipientsEnabled = *destCfg.EnableRecipients && channel.SupportsRecipients()
			}
			if !recipientsEnabled {
				if destCfg.SkipIfRecipients {
					log.WithFields(log.Fields{
						"destination": destName,
						"recipients":  payload.Recipients,
					}).Debug("Destination does not have recipient support enabled and skipIfRecipients is active; skipping")
					continue
				}
				clone := *destPayload
				clone.Recipients = nil
				destPayload = &clone
			}
		}

		if len(payload.Attachments) > 0 && !channel.SupportsAttachments() {
			if destPayload == payload {
				clone := *payload
				destPayload = &clone
			}
			destPayload.Attachments = nil
		}

		if len(payload.Links) > 0 && !channel.SupportsLinks() {
			if destPayload == payload {
				clone := *payload
				destPayload = &clone
			}
			destPayload.Links = nil
		}

		if err := channel.Send(ctx, destCfg.Params, destPayload); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"destination": destName,
				"channelType": destCfg.Type,
			}).Error("Channel driver failed to send notification")
			errs = append(errs, fmt.Errorf("destination '%s' send failed: %w", destName, err))
		} else {
			sentCount++
		}
	}

	if len(errs) > 0 {
		return sentCount, errors.Join(errs...)
	}
	return sentCount, nil
}

func (n *NotifierImpl) SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}
	if silence != nil && silence.SilenceKey != "" {
		payload.SilenceKey = silence.SilenceKey

		shouldSuppress, err := n.checkSilence(payload.Source, silence)
		if err != nil {
			return err
		}
		if shouldSuppress {
			log.WithFields(log.Fields{
				"source":     payload.Source,
				"silenceKey": silence.SilenceKey,
			}).Debug("Notification suppressed by silencer")
			return nil
		}
	}
	_, err := n.Send(ctx, payload, destinations...)
	return err
}

func (n *NotifierImpl) checkSilence(source string, silence *model.SilenceParams) (bool, error) {
	n.silenceMu.Lock()
	defer n.silenceMu.Unlock()

	hasher := sha256.New()
	hasher.Write([]byte(source + ":" + silence.SilenceKey))
	key := hex.EncodeToString(hasher.Sum(nil))

	now := time.Now()
	entry, exists := n.silenced[key]

	if !exists {
		entry = &silencerEntry{
			windowStart: now,
		}
		n.silenced[key] = entry
	}

	duration := silence.SilenceDuration
	if duration <= 0 {
		n.mu.RLock()
		gsw := n.config.GlobalSilenceWindowSeconds
		n.mu.RUnlock()
		if gsw > 0 {
			duration = time.Duration(gsw) * time.Second
		}
	}

	if duration <= 0 {
		return false, nil
	}

	if now.Sub(entry.windowStart) >= duration {
		entry.windowStart = now
		entry.triggerCount = 0
	}

	entry.triggerCount++

	threshold := silence.ThresholdCount
	if threshold <= 0 {
		threshold = 1
	}

	if !entry.lastDispatched.IsZero() && now.Sub(entry.lastDispatched) < duration {
		return true, nil
	}

	if entry.triggerCount < threshold {
		return true, nil
	}

	entry.lastDispatched = now
	return false, nil
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

func (n *NotifierImpl) UpdateConfig(cfg model.NotificationConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config = cfg
}
