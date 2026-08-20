// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type Attachment = model.Attachment
type NotificationPayload = model.NotificationPayload
type SilenceParams = model.SilenceParams
type DestinationConfig = model.DestinationConfig
type NotificationConfig = model.NotificationConfig
type NotificationChannel = server.NotificationChannel
type Notifier = server.Notifier
