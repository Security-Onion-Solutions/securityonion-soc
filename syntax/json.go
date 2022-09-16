// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"errors"
	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"strings"
)

func ValidateJson(value string) error {
	var err error

	log.WithFields(log.Fields{
		"length": len(value),
	}).Debug("Parsing JSON to verify good syntax")

	mapped := make(map[string]interface{})
	err = json.LoadJson([]byte(value), &mapped)
	if err != nil {
		log.WithFields(log.Fields{
			"length": len(value),
		}).WithError(err).Error("Unable to parse valid JSON from value")

		// Clean up error string
		errMsg := strings.Replace(err.Error(), " into map[string]interface {}", "", 1)

		// Prepend error message with ERROR_ to ensure the string does not get replaced by the safestring method in BaseHandler.
		err = errors.New("ERROR_MALFORMED_JSON -> " + errMsg)
	}

	return err
}
