// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package thehive

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"strconv"
	"time"
)

func convertToTheHiveCase(inputCase *model.Case) (*TheHiveCase, error) {
	outputCase := NewTheHiveCase()
	outputCase.Severity = inputCase.Severity
	if outputCase.Severity > CASE_SEVERITY_HIGH {
		outputCase.Severity = CASE_SEVERITY_HIGH
	} else if outputCase.Severity < CASE_SEVERITY_LOW {
		outputCase.Severity = CASE_SEVERITY_LOW
	}
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Tags = append(outputCase.Tags, "SecurityOnion")
	outputCase.Tlp = CASE_TLP_AMBER
	outputCase.Template = inputCase.Template
	return outputCase, nil
}

func convertFromTheHiveCase(inputCase *TheHiveCase) (*model.Case, error) {
	outputCase := model.NewCase()
	outputCase.Severity = inputCase.Severity
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Id = strconv.Itoa(inputCase.Id)
	outputCase.Status = inputCase.Status
	createTime := time.Unix(inputCase.CreateDate/1000, 0)
	outputCase.CreateTime = &createTime
	startTime := time.Unix(inputCase.StartDate/1000, 0)
	outputCase.StartTime = &startTime
	completeTime := time.Unix(inputCase.EndDate/1000, 0)
	outputCase.CompleteTime = &completeTime
	return outputCase, nil
}
