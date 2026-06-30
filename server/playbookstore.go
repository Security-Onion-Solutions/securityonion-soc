// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type Playbookstore interface {
	Interrupt(ctx context.Context, force bool) error
	GetPlaybooksForDetection(ctx context.Context, detectId string, detectCategory string, detectEngine model.EngineName) ([]*model.Playbook, error)
	GetPlaybookById(ctx context.Context, id string) (*model.Playbook, error)
	ConvertQuestions(ctx context.Context, queries []string, event *model.EventRecord, bindings map[string]string, used map[string]bool) ([]*model.ConvertedQuery, error)
	ExecutePlaybookSearches(ctx context.Context, event *model.EventRecord, pbs []*model.Playbook) error
	GetEventSpecificPlaybook(ctx context.Context, id string) ([]*model.Playbook, error)
}

//go:generate mockgen -destination mock/mock_playbookstore.go -package mock . Playbookstore
