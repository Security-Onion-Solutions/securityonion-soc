// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elasticcases

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func convertToElasticCase(inputCase *model.Case) (*ElasticCase, error) {
	outputCase := NewElasticCase()
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Tags = append(outputCase.Tags, "SecurityOnion")
	outputCase.Connector = &ElasticConnector{
		Id:     "none",
		Name:   "none",
		Type:   ".none",
		Fields: nil,
	}
	outputCase.Settings = &ElasticSettings{
		SyncAlerts: true,
	}
	outputCase.Owner = "securitySolution"
	return outputCase, nil
}

func convertFromElasticCase(inputCase *ElasticCase) (*model.Case, error) {
	outputCase := model.NewCase()
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Id = inputCase.Id
	outputCase.Status = inputCase.Status
	if inputCase.CreatedDate != nil {
		outputCase.CreateTime = inputCase.CreatedDate
	}
	if inputCase.ModifiedDate != nil {
		outputCase.UpdateTime = inputCase.ModifiedDate
	}
	if inputCase.ClosedDate != nil {
		outputCase.CompleteTime = inputCase.ClosedDate
	}
	return outputCase, nil
}
