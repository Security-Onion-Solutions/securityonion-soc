// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
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
	"strings"
	"time"
)

func convertSeverity(sev string) int {
	severity := 3

	if len(sev) != 0 {
		switch strings.ToLower(sev) {
		case "low", "1":
			severity = 1
		case "medium", "2":
			severity = 2
		case "high", "3":
			severity = 3
		case "critical", "4":
			severity = 4
		default:
			severity = 3
		}
	}
	return severity
}

func convertToTheHiveCase(inputCase *model.Case) (*TheHiveCase, error) {
	outputCase := NewTheHiveCase()
	outputCase.Severity = convertSeverity(inputCase.Severity)
	outputCase.Title = inputCase.Title
	outputCase.Description = inputCase.Description
	outputCase.Tags = append(outputCase.Tags, "SecurityOnion")
	outputCase.Tlp = CASE_TLP_AMBER
	outputCase.Template = inputCase.Template
	return outputCase, nil
}

func convertFromTheHiveCase(inputCase *TheHiveCase) (*model.Case, error) {
	outputCase := model.NewCase()
	outputCase.Severity = strconv.Itoa(inputCase.Severity)
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
