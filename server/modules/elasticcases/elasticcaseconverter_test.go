// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elasticcases

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestConvertFromElasticCase(tester *testing.T) {
	elasticCase := NewElasticCase()
	elasticCase.Title = "my title"
	elasticCase.Description = "my description.\nline 2.\n"
	elasticCase.Id = "a123"
	elasticCase.ModifiedDate = nil
	tm, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	elasticCase.CreatedDate = &tm
	elasticCase.ClosedDate = nil

	socCase, err := convertFromElasticCase(elasticCase)
	assert.Nil(tester, err)
	assert.Equal(tester, elasticCase.Title, socCase.Title)
	assert.Equal(tester, elasticCase.Description, socCase.Description)
	assert.Equal(tester, elasticCase.Id, socCase.Id)
	assert.Equal(tester, &tm, socCase.CreateTime)
	assert.Nil(tester, socCase.StartTime)
	assert.Nil(tester, socCase.CompleteTime)
}

func TestConvertToElasticCase(tester *testing.T) {
	socCase := model.NewCase()
	socCase.Title = "my title"
	socCase.Description = "my description.\nline 2.\n"
	socCase.Id = "my id"

	elasticCase, err := convertToElasticCase(socCase)
	assert.Nil(tester, err)

	assert.Equal(tester, elasticCase.Title, socCase.Title)
	assert.Equal(tester, elasticCase.Description, socCase.Description)
	assert.Len(tester, elasticCase.Tags, 1)
	assert.Equal(tester, "securitySolution", elasticCase.Owner)
	assert.Equal(tester, "none", elasticCase.Connector.Id)
	assert.Equal(tester, "none", elasticCase.Connector.Name)
	assert.Equal(tester, ".none", elasticCase.Connector.Type)
	assert.Nil(tester, elasticCase.Connector.Fields)
	assert.Equal(tester, true, elasticCase.Settings.SyncAlerts)
}
