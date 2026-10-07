// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

// RuleError pairs a validation error with a UI-localized code; only the code reaches the client.
type RuleError struct {
	Code error
	Err  error
}

// NewRuleError tags err with code; a nil err stays nil.
func NewRuleError(code, err error) error {
	if err == nil {
		return nil
	}

	return &RuleError{Code: code, Err: err}
}

func (e *RuleError) Error() string {
	return e.Err.Error()
}

func (e *RuleError) Unwrap() []error {
	return []error{e.Code, e.Err}
}
