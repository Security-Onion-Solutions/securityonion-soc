// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"errors"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/json"
)

func ValidateJson(value string) error {
	var err error

	log.WithFields(log.Fields{
		"length": len(value),
	}).Debug("Parsing JSON to verify good syntax")

	var mapped interface{}
	err = json.LoadJson([]byte(value), &mapped)
	if err != nil {
		log.WithFields(log.Fields{
			"length": len(value),
		}).WithError(err).Error("Unable to parse valid JSON from value")

		err = errors.New("ERROR_MALFORMED_JSON")
	}

	return err
}
