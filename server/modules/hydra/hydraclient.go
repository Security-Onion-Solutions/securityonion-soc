// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type HydraClient struct {
	Id         string          `json:"client_id"`
	CreateDate time.Time       `json:"created_at"`
	UpdateDate time.Time       `json:"updated_at"`
	Name       string          `json:"name"`
	Secret     string          `json:"client_secret"`
	Metadata   *ClientMetadata `json:"metadata"`
}

type ClientMetadata struct {
	Note string `json:"note"`
}

func NewHydraClient(name string) *HydraClient {
	hydraClient := &HydraClient{
		Name: name,
	}
	return hydraClient
}

func (hydraClient *HydraClient) copyToClient(client *model.Client) {
	client.Id = hydraClient.Id
	client.Name = hydraClient.Name
	client.Secret = hydraClient.Secret
	if hydraClient.Metadata != nil {
		client.Note = hydraClient.Metadata.Note
	}
}

func (hydraClient *HydraClient) copyFromClient(client *model.Client) {
	metadata := ClientMetadata{
		Note: client.Note,
	}
	hydraClient.Name = client.Name
	hydraClient.Secret = client.Secret
	hydraClient.Metadata = &metadata
}
