// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type CompilationReport struct {
	Timestamp         string   `json:"timestamp"`
	Success           []string `json:"success"`
	Failure           []string `json:"failure"`
	CompiledRulesHash string   `json:"compiled_sha256"`
}
