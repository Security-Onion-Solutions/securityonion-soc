// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type FakeNotifier struct {
	srv                *Server
	InputContexts      []context.Context
	InputPayloads      []*model.NotificationPayload
	InputDestinations  [][]string
	InputSilences      []*model.SilenceParams
	RegisteredChannels []NotificationChannel
	Err                error
	Destinations       map[string]model.DestinationConfig
	SendCount          int
}

func NewFakeNotifier() *FakeNotifier {
	return &FakeNotifier{
		Destinations: map[string]model.DestinationConfig{},
	}
}

func (notifier *FakeNotifier) checkAuth(ctx context.Context, op string) error {
	if notifier.srv != nil {
		return notifier.srv.CheckAuthorized(ctx, op, "config")
	}
	return nil
}

func (notifier *FakeNotifier) Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) (int, error) {
	notifier.InputContexts = append(notifier.InputContexts, ctx)
	notifier.InputPayloads = append(notifier.InputPayloads, payload)
	notifier.InputDestinations = append(notifier.InputDestinations, destinations)
	if notifier.Err != nil {
		return 0, notifier.Err
	}
	if payload == nil {
		return 0, nil
	}
	if notifier.SendCount > 0 {
		return notifier.SendCount, nil
	}
	if len(destinations) > 0 {
		return len(destinations), nil
	}
	return 1, nil
}

func (notifier *FakeNotifier) SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error {
	notifier.InputSilences = append(notifier.InputSilences, silence)
	_, err := notifier.Send(ctx, payload, destinations...)
	return err
}

func (notifier *FakeNotifier) RegisterChannel(channel NotificationChannel) {
	notifier.RegisteredChannels = append(notifier.RegisteredChannels, channel)
}

func (notifier *FakeNotifier) GetChannel(channelType string) (NotificationChannel, bool) {
	for _, channel := range notifier.RegisteredChannels {
		if channel != nil && channel.Type() == channelType {
			return channel, true
		}
	}
	return nil, false
}

func (notifier *FakeNotifier) GetDestinations() map[string]model.DestinationConfig {
	return notifier.Destinations
}

func (notifier *FakeNotifier) ListDestinations(ctx context.Context) ([]model.DestinationConfig, error) {
	if notifier.Err != nil {
		return nil, notifier.Err
	}
	if err := notifier.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}
	dests := notifier.Destinations
	if len(dests) == 0 {
		dests = model.DefaultDestinationsMap()
	}
	result := make([]model.DestinationConfig, 0, len(dests))
	for id, dest := range dests {
		if dest.ID == "" {
			dest.ID = id
		}
		if ch, found := notifier.GetChannel(dest.Type); found {
			dest.RecipientsSupported = ch.SupportsRecipients()
			dest.AttachmentsSupported = ch.SupportsAttachments()
			dest.LinksSupported = ch.SupportsLinks()
		}
		result = append(result, dest)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, nil
}

func (notifier *FakeNotifier) GetDestination(ctx context.Context, id string) (*model.DestinationConfig, error) {
	if notifier.Err != nil {
		return nil, notifier.Err
	}
	if err := notifier.checkAuth(ctx, "read"); err != nil {
		return nil, err
	}
	if !model.IsValidDestinationID(id) {
		return nil, ErrInvalidDestinationID
	}
	dest, exists := notifier.Destinations[id]
	if !exists {
		return nil, ErrDestinationNotFound
	}
	if dest.ID == "" {
		dest.ID = id
	}
	if ch, found := notifier.GetChannel(dest.Type); found {
		dest.RecipientsSupported = ch.SupportsRecipients()
		dest.AttachmentsSupported = ch.SupportsAttachments()
		dest.LinksSupported = ch.SupportsLinks()
	}
	return &dest, nil
}

func (notifier *FakeNotifier) CreateDestination(ctx context.Context, dest *model.DestinationConfig) (*model.DestinationConfig, error) {
	if notifier.Err != nil {
		return nil, notifier.Err
	}
	if err := notifier.checkAuth(ctx, "write"); err != nil {
		return nil, err
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
		return nil, ErrInvalidDestinationID
	}
	if _, exists := notifier.Destinations[dest.ID]; exists {
		return nil, ErrDuplicateDestinationID
	}
	if notifier.Destinations == nil {
		notifier.Destinations = make(map[string]model.DestinationConfig)
	}
	notifier.Destinations[dest.ID] = *dest
	return dest, nil
}

func (notifier *FakeNotifier) UpdateDestination(ctx context.Context, id string, dest *model.DestinationConfig) (*model.DestinationConfig, error) {
	if notifier.Err != nil {
		return nil, notifier.Err
	}
	if err := notifier.checkAuth(ctx, "write"); err != nil {
		return nil, err
	}
	if !model.IsValidDestinationID(id) {
		return nil, ErrInvalidDestinationID
	}
	if err := model.ValidateDestinationName(dest.Name); err != nil {
		return nil, err
	}
	if _, exists := notifier.Destinations[id]; !exists {
		return nil, ErrDestinationNotFound
	}
	dest.ID = id
	notifier.Destinations[id] = *dest
	return dest, nil
}

func (notifier *FakeNotifier) DeleteDestination(ctx context.Context, id string) error {
	if notifier.Err != nil {
		return notifier.Err
	}
	if err := notifier.checkAuth(ctx, "write"); err != nil {
		return err
	}
	if !model.IsValidDestinationID(id) {
		return ErrInvalidDestinationID
	}
	if id == model.DefaultDestinationSOCBell {
		return ErrCannotDeleteDefaultDestination
	}
	if _, exists := notifier.Destinations[id]; !exists {
		return ErrDestinationNotFound
	}
	delete(notifier.Destinations, id)
	return nil
}
