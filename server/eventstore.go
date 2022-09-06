// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type Eventstore interface {
	Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error)
	Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error)
	Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
	Delete(context context.Context, index string, id string) error
	Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error)
}
