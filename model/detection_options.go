// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "fmt"

type GetAllOption func(query string, schemaPrefix string) string

func WithEngine(engine EngineName) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.engine:"%s"`, query, schemaPrefix, engine)
	}
}

func WithEnabled(isEnabled bool) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.isEnabled:"%t"`, query, schemaPrefix, isEnabled)
	}
}

func WithCommunity(isCommunity bool) GetAllOption {
	return func(query string, schemaPrefix string) string {
		return fmt.Sprintf(`%s AND %sdetection.isCommunity:"%t"`, query, schemaPrefix, isCommunity)
	}
}
