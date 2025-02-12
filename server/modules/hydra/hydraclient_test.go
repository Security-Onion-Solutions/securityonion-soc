// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestCopyFromClient(tester *testing.T) {
	hydraClient := &HydraClient{}
	client := model.NewClient()
	client.Name = "test"
	client.SearchUsername = "sn"
	client.Note = "notes"
	hydraClient.copyFromClient(client)
	assert.Equal(tester, client.Name, hydraClient.Name)
	assert.Equal(tester, client.SearchUsername, hydraClient.Metadata.SearchUsername)
	assert.Equal(tester, client.Note, hydraClient.Metadata.Note)
}

func TestCopyToClient(tester *testing.T) {
	hydraClient := NewHydraClient("test")
	hydraClient.Metadata = &ClientMetadata{
		Note:           "notes",
		SearchUsername: "sn",
	}
	client := model.NewClient()
	hydraClient.copyToClient(client)
	assert.Equal(tester, hydraClient.Name, client.Name)
	assert.Equal(tester, hydraClient.Metadata.SearchUsername, client.SearchUsername)
	assert.Equal(tester, hydraClient.Metadata.Note, client.Note)
}
