// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type FakeNotifier struct {
	InputContexts      []context.Context
	InputPayloads      []*model.NotificationPayload
	InputDestinations  [][]string
	InputSilences      []*model.SilenceParams
	RegisteredChannels []NotificationChannel
	Err                error
	Destinations       map[string]model.DestinationConfig
}

func NewFakeNotifier() *FakeNotifier {
	return &FakeNotifier{
		Destinations: map[string]model.DestinationConfig{},
	}
}

func (notifier *FakeNotifier) Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) error {
	notifier.InputContexts = append(notifier.InputContexts, ctx)
	notifier.InputPayloads = append(notifier.InputPayloads, payload)
	notifier.InputDestinations = append(notifier.InputDestinations, destinations)
	return notifier.Err
}

func (notifier *FakeNotifier) SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error {
	notifier.InputSilences = append(notifier.InputSilences, silence)
	return notifier.Send(ctx, payload, destinations...)
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
