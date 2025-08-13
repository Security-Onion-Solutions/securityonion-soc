// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"github.com/security-onion-solutions/securityonion-soc/licensing"
)

type Info struct {
	// The version of the Security Onion grid
	Version string `json:"version" example:"2.4.110"`
	// The copyright license applicable to the Security Onion software
	License string `json:"license" example:"Elastic License 2.0 (ELv2)"`
	// Web UI parameters; unavailable to API clients
	Parameters *ClientParameters `json:"parameters"`
	// The version of the Elasticsearch cluster
	ElasticVersion string `json:"elasticVersion" example:"8.14.3"`
	// The authenticated API client ID
	UserId string `json:"userId" example:"socl_my_so_api_client"`
	// The timezones that are configured for this server.
	Timezones []string `json:"timezones" example:"Africa/Abidjan"`
	// The server token; unavailable to API clients
	SrvToken string `json:"srvToken"`
	// The configured license key; available only if this is a Security Onion Pro grid
	LicenseKey *licensing.LicenseKey `json:"licenseKey"`
	// The license status of the grid: active = Valid Security Onion Pro license, unprovisioned = Community license
	LicenseStatus string `json:"licenseStatus" example:"active"`
	// OTP indicator; unavailable to API clients
	ForceUserOtp bool `json:"forceUserOtp"`
	// The MAC address assigned to the management interface.
	MgmtMac string `json:"mgmtMac" example:"11:22:33:AA:BB:CC"`
	// The list of custom reports configured for this grid. The key is the filename and the value is the report title.
	CustomReports map[string]string `json:"customReports"`
	// The list of subordinate grids configured for this grid.
	Subgrids []*Subgrid `json:"subgrids"`
}
