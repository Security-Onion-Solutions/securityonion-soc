// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

var (
	ErrDestinationNotFound            = errors.New("destination not found")
	ErrInvalidDestinationID           = errors.New("invalid destination ID")
	ErrDuplicateDestinationID         = errors.New("destination with this ID already exists")
	ErrCannotDeleteDefaultDestination = errors.New("cannot delete default notification destination")
)

// Notifier defines the interface for sending notifications across channels and managing destinations.
type Notifier interface {
	Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) error
	SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error
	RegisterChannel(channel NotificationChannel)
	GetChannel(channelType string) (NotificationChannel, bool)
	GetDestinations() map[string]model.DestinationConfig
	ListDestinations(ctx context.Context) ([]model.DestinationConfig, error)
	GetDestination(ctx context.Context, id string) (*model.DestinationConfig, error)
	CreateDestination(ctx context.Context, dest *model.DestinationConfig) (*model.DestinationConfig, error)
	UpdateDestination(ctx context.Context, id string, dest *model.DestinationConfig) (*model.DestinationConfig, error)
	DeleteDestination(ctx context.Context, id string) error
}

//go:generate mockgen -destination mock/mock_notifier.go -package mock . Notifier

// NotificationChannel is the interface implemented by all destination drivers.
type NotificationChannel interface {
	Type() string
	ValidateConfig(params map[string]interface{}) error
	Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error
	SupportsRecipients() bool
	SupportsAttachments() bool
	SupportsLinks() bool
}
