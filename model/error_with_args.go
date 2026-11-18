// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// An error whose code is sent to the client as JSON along with the values the UI
// substitutes into the code's message, e.g. {"code":"ERROR_MALFORMED_YAML_LINE","line":3}.
type ErrorWithArgs struct {
	// The error code; an i18n key in the UI
	Code string `json:"code" example:"ERROR_SESSION_ATTACHED_TO_CASES"`
	// Code-specific values, sent as top-level fields alongside code
	Args map[string]interface{} `json:"-"`
	err  error
}

func NewErrorWithArgs(err error, args map[string]interface{}) *ErrorWithArgs {
	return &ErrorWithArgs{
		Code: err.Error(),
		Args: args,
		err:  err,
	}
}

func (e *ErrorWithArgs) Error() string {
	keys := make([]string, 0, len(e.Args))
	for k := range e.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := []string{e.Code}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, e.Args[k]))
	}

	return strings.Join(parts, " ")
}

func (e *ErrorWithArgs) Unwrap() error {
	return e.err
}

func (e *ErrorWithArgs) MarshalJSON() ([]byte, error) {
	body := make(map[string]interface{}, len(e.Args)+1)
	for k, v := range e.Args {
		body[k] = v
	}
	body["code"] = e.Code

	return json.Marshal(body)
}
