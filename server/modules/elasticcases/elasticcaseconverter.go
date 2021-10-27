// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
		outputCase.CreateTime = *inputCase.CreatedDate
	}
	if inputCase.ModifiedDate != nil {
		outputCase.StartTime = *inputCase.ModifiedDate
	}
	if inputCase.ClosedDate != nil {
		outputCase.CompleteTime = *inputCase.ClosedDate
	}
	return outputCase, nil
}
