// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
)

const (
	DEFAULT_APIKEY = ""
	DEFAULT_APIURL = "https://b7cdq33i55t73bzisq7gplzd340mvxgo.lambda-url.us-east-2.on.aws/"
	DEFAULT_MODEL  = "claude-sonnet"
)

type AssistantCoordinator struct {
	srv       *server.Server
	apiKey    string
	apiUrl    string
	model     string
	isRunning bool

	detections.IOManager
}

func NewAssistantManager(srv *server.Server) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv:       srv,
		IOManager: &detections.ResourceManager{Config: srv.Config},
	}
}

func (am *AssistantCoordinator) PrerequisiteModules() []string {
	return nil
}

func (am *AssistantCoordinator) Init(config module.ModuleConfig) (err error) {
	am.srv.AssistantManager = am

	am.apiKey = module.GetStringDefault(config, "apiKey", DEFAULT_APIKEY)
	am.apiUrl = module.GetStringDefault(config, "apiUrl", DEFAULT_APIURL)
	am.model = module.GetStringDefault(config, "model", DEFAULT_MODEL)

	return nil
}

func (am *AssistantCoordinator) Start() error {
	am.isRunning = true

	return nil
}

func (am *AssistantCoordinator) Stop() error {
	am.isRunning = false

	return nil
}

func (am *AssistantCoordinator) IsRunning() bool {
	return am.isRunning
}
