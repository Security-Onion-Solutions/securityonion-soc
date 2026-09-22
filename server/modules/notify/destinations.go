// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

func unmarshalDestinations(val string) (map[string]model.DestinationConfig, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return make(map[string]model.DestinationConfig), nil
	}

	// 1. Try standard JSON map format
	if strings.HasPrefix(val, "{") {
		var dests map[string]model.DestinationConfig
		if err := json.Unmarshal([]byte(val), &dests); err == nil {
			for k, v := range dests {
				if v.ID == "" {
					v.ID = k
				}
				dests[k] = v
			}
			return dests, nil
		}
	}

	// 2. Try JSON array format
	if strings.HasPrefix(val, "[") {
		var slice []model.DestinationConfig
		if err := json.Unmarshal([]byte(val), &slice); err == nil {
			dests := make(map[string]model.DestinationConfig, len(slice))
			for _, item := range slice {
				id := item.ID
				if id == "" {
					id = uuid.NewString()
					item.ID = id
				}
				dests[id] = item
			}
			return dests, nil
		}
	}

	// 3. Try newline-delimited JSON objects
	lines := strings.Split(val, "\n")
	dests := make(map[string]model.DestinationConfig)
	allLinesParsed := true
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item model.DestinationConfig
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			id := item.ID
			if id == "" {
				id = uuid.NewString()
				item.ID = id
			}
			dests[id] = item
		} else {
			allLinesParsed = false
			break
		}
	}
	if allLinesParsed && len(dests) > 0 {
		return dests, nil
	}

	return nil, errors.New("unable to parse destination configuration")
}

func (n *NotifierImpl) checkAuth(ctx context.Context, op string) error {
	if n.server != nil {
		return n.server.CheckAuthorized(ctx, op, "config")
	}
	return nil
}

func (n *NotifierImpl) loadDestinationsMap(ctx context.Context) (map[string]model.DestinationConfig, error) {
	if n.server == nil || n.server.Configstore == nil {
		return n.GetDestinations(), nil
	}

	setting, err := n.server.Configstore.GetSetting(ctx, ConfigSettingNotificationDestinations)
	if err != nil {
		return nil, err
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		dests := n.GetDestinations()
		if len(dests) > 0 {
			return dests, nil
		}
		return model.DefaultDestinationsMap(), nil
	}

	return unmarshalDestinations(setting.Value)
}

func (n *NotifierImpl) saveDestinationsMap(ctx context.Context, dests map[string]model.DestinationConfig) error {
	valBytes, err := json.Marshal(dests)
	if err != nil {
		return err
	}
	if n.server != nil && n.server.Configstore != nil {
		setting := &model.Setting{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(valBytes),
		}
		if err := n.server.Configstore.UpdateSetting(ctx, setting, false); err != nil {
			return err
		}
	}

	n.mu.Lock()
	n.config.Destinations = dests
	n.mu.Unlock()

	return nil
}

func (n *NotifierImpl) decorateDestinationCapabilities(dest *model.DestinationConfig) {
	if dest == nil || n.registry == nil {
		return
	}
	if ch, found := n.registry.Get(dest.Type); found {
		dest.RecipientsSupported = ch.SupportsRecipients()
		dest.AttachmentsSupported = ch.SupportsAttachments()
		dest.LinksSupported = ch.SupportsLinks()
	}
}

func (n *NotifierImpl) ListDestinations(ctx context.Context) ([]model.DestinationConfig, error) {
	if err := n.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}

	destsMap, err := n.loadDestinationsMap(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]model.DestinationConfig, 0, len(destsMap))
	for id, dest := range destsMap {
		if dest.ID == "" {
			dest.ID = id
		}
		n.decorateDestinationCapabilities(&dest)
		result = append(result, dest)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result, nil
}

func (n *NotifierImpl) GetDestination(ctx context.Context, id string) (*model.DestinationConfig, error) {
	if err := n.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}

	if !model.IsValidDestinationID(id) {
		return nil, server.ErrInvalidDestinationID
	}

	destsMap, err := n.loadDestinationsMap(ctx)
	if err != nil {
		return nil, err
	}

	dest, exists := destsMap[id]
	if !exists {
		return nil, server.ErrDestinationNotFound
	}

	if dest.ID == "" {
		dest.ID = id
	}
	n.decorateDestinationCapabilities(&dest)
	return &dest, nil
}

func (n *NotifierImpl) CreateDestination(ctx context.Context, dest *model.DestinationConfig) (*model.DestinationConfig, error) {
	if err := n.checkAuth(ctx, "write"); err != nil {
		return nil, err
	}

	if dest == nil {
		return nil, errors.New("destination cannot be nil")
	}

	if err := model.ValidateDestinationName(dest.Name); err != nil {
		return nil, err
	}

	if strings.TrimSpace(dest.Type) == "" {
		dest.Type = "soc"
	}

	if dest.ID == "" {
		dest.ID = uuid.NewString()
	} else if !model.IsValidDestinationID(dest.ID) {
		return nil, server.ErrInvalidDestinationID
	}

	if n.registry != nil {
		if ch, found := n.registry.Get(dest.Type); found {
			if err := ch.ValidateConfig(dest.Params); err != nil {
				return nil, fmt.Errorf("invalid channel parameters: %w", err)
			}
		}
	}

	destsMap, err := n.loadDestinationsMap(ctx)
	if err != nil {
		return nil, err
	}

	if _, exists := destsMap[dest.ID]; exists {
		return nil, server.ErrDuplicateDestinationID
	}

	destsMap[dest.ID] = *dest
	if err := n.saveDestinationsMap(ctx, destsMap); err != nil {
		return nil, err
	}

	n.decorateDestinationCapabilities(dest)
	return dest, nil
}

func (n *NotifierImpl) UpdateDestination(ctx context.Context, id string, dest *model.DestinationConfig) (*model.DestinationConfig, error) {
	if err := n.checkAuth(ctx, "write"); err != nil {
		return nil, err
	}

	if dest == nil {
		return nil, errors.New("destination cannot be nil")
	}

	if !model.IsValidDestinationID(id) {
		return nil, server.ErrInvalidDestinationID
	}

	if err := model.ValidateDestinationName(dest.Name); err != nil {
		return nil, err
	}

	if strings.TrimSpace(dest.Type) == "" {
		dest.Type = "soc"
	}

	dest.ID = id

	if n.registry != nil {
		if ch, found := n.registry.Get(dest.Type); found {
			if err := ch.ValidateConfig(dest.Params); err != nil {
				return nil, fmt.Errorf("invalid channel parameters: %w", err)
			}
		}
	}

	destsMap, err := n.loadDestinationsMap(ctx)
	if err != nil {
		return nil, err
	}

	if _, exists := destsMap[id]; !exists {
		return nil, server.ErrDestinationNotFound
	}

	destsMap[id] = *dest
	if err := n.saveDestinationsMap(ctx, destsMap); err != nil {
		return nil, err
	}

	n.decorateDestinationCapabilities(dest)
	return dest, nil
}

func (n *NotifierImpl) DeleteDestination(ctx context.Context, id string) error {
	if err := n.checkAuth(ctx, "write"); err != nil {
		return err
	}

	if !model.IsValidDestinationID(id) {
		return server.ErrInvalidDestinationID
	}

	if id == model.DefaultDestinationSOCBell {
		return server.ErrCannotDeleteDefaultDestination
	}

	destsMap, err := n.loadDestinationsMap(ctx)
	if err != nil {
		return err
	}

	if _, exists := destsMap[id]; !exists {
		return server.ErrDestinationNotFound
	}

	delete(destsMap, id)
	return n.saveDestinationsMap(ctx, destsMap)
}
