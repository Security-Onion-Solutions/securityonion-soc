// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
)

// Re-export types from base package for backward compatibility
type Rule = base.Rule
type LogSource = base.LogSource
type Detection = base.Detection
type Pipeline = base.Pipeline
type Converter = base.Converter
type ConvertedQuery = base.ConvertedQuery
type Override = base.Override
type ConditionNode = base.ConditionNode