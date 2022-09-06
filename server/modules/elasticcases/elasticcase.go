// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elasticcases

import (
  "time"
)

const CASE_STATUS_OPEN = "open"
const CASE_STATUS_RESOLVED = "closed"
const CASE_STATUS_DELETED = "in_progress"

type ElasticUser struct {
  Email    string `json:"email"`
  Name     string `json:"full_name"`
  Username string `json:"username"`
}

type ElasticComment struct {
}

type ElasticSettings struct {
  SyncAlerts bool `json:"syncAlerts"`
}

type ElasticFields struct {
}

type ElasticConnector struct {
  Id     string         `json:"id"`
  Name   string         `json:"name"`
  Type   string         `json:"type"`
  Fields *ElasticFields `json:"fields"`
}

type ElasticCase struct {
  Id            string            `json:"id,omitempty"`
  CreatedDate   *time.Time        `json:"created_at,omitempty"`
  CreatedBy     *ElasticUser      `json:"created_by,omitempty"`
  ModifiedDate  *time.Time        `json:"updated_at,omitempty"`
  ModifiedBy    *ElasticUser      `json:"updated_by,omitempty"`
  ClosedDate    *time.Time        `json:"closed_at,omitempty"`
  ClosedBy      *ElasticUser      `json:"closed_by,omitempty"`
  Status        string            `json:"status,omitempty"`
  Comments      []*ElasticComment `json:"comments,omitempty"`
  TotalComments int               `json:"totalComments,omitempty"`
  Settings      *ElasticSettings  `json:"settings,omitempty"`
  Connector     *ElasticConnector `json:"connector,omitempty"`
  Title         string            `json:"title"`
  Description   string            `json:"description"`
  Tags          []string          `json:"tags"`
  Owner         string            `json:"owner"`
}

func NewElasticCase() *ElasticCase {
  newCase := &ElasticCase{}
  return newCase
}
