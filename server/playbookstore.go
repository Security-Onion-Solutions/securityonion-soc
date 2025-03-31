// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import "github.com/security-onion-solutions/securityonion-soc/model"

type Playbookstore interface {
	Interrupt(force bool)
	GetPlaybooksForDetection(detectId string, detectCategory string, detectEngine model.EngineName) ([]*model.Playbook, error)
	GetPlaybookById(id string) (*model.Playbook, error)
}

//go:generate mockgen -destination mock/mock_playbookstore.go -package mock . Playbookstore
