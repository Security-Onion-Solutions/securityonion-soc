// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "github.com/security-onion-solutions/securityonion-soc/config"
)

type Info struct {
  Version        string                   `json:"version"`
  License        string                   `json:"license"`
  Parameters     *config.ClientParameters `json:"parameters"`
  ElasticVersion string                   `json:"elasticVersion"`
  WazuhVersion   string                   `json:"wazuhVersion"`
  UserId         string                   `json:"userId"`
  Timezones      []string                 `json:"timezones"`
  SrvToken       string                   `json:"srvToken"`
}
