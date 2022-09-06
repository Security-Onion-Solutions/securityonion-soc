// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package thehive

const CASE_STATUS_OPEN = "Open"
const CASE_STATUS_RESOLVED = "Resolved"
const CASE_STATUS_DELETED = "Deleted"
const CASE_TLP_WHITE = 0
const CASE_TLP_GREN = 1
const CASE_TLP_AMBER = 2
const CASE_TLP_RED = 3
const CASE_SEVERITY_LOW = 1
const CASE_SEVERITY_MEDIUM = 2
const CASE_SEVERITY_HIGH = 3

type TheHiveCase struct {
  Id          int      `json:"caseId,omitempty"`
  CreateDate  int64    `json:"createdAt,omitempty"`
  StartDate   int64    `json:"startDate,omitempty"`
  EndDate     int64    `json:"endDate,omitempty"`
  Title       string   `json:"title"`
  Description string   `json:"description"`
  Severity    int      `json:"severity"`
  Status      string   `json:"status,omitempty"`
  Tags        []string `json:"tags"`
  Tlp         int      `json:"tlp"`
  Flag        bool     `json:"flag"`
  Template    string   `json:"template"`
}

func NewTheHiveCase() *TheHiveCase {
  newCase := &TheHiveCase{}
  return newCase
}
