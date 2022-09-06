// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
