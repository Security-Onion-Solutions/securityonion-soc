// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	hydraClient.copyFromClient(client)
	assert.Equal(tester, client.Name, hydraClient.Name)
}

func TestCopyToClient(tester *testing.T) {
	hydraClient := NewHydraClient("test")
	client := model.NewClient()
	hydraClient.copyToClient(client)
	assert.Equal(tester, hydraClient.Name, client.Name)
}
