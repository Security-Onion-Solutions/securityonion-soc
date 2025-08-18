// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
)

// Re-export AST node types from base package
type OperatorNode = base.OperatorNode
type SelectionNode = base.SelectionNode
type PatternNode = base.PatternNode
type ValueNode = base.ValueNode