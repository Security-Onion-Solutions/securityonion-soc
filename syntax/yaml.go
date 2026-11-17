// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package syntax

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/apex/log"
	"gopkg.in/yaml.v3"
)

var ErrMalformedYaml = errors.New("ERROR_MALFORMED_YAML")

// yaml.v3 exports no error type carrying the line, only text such as
// "yaml: line N: ..." or "yaml: unmarshal errors:\n  line N: ...".
var yamlErrorLine = regexp.MustCompile(`\bline ([0-9]+):`)

func ValidateYaml(value string) error {
	var err error

	log.WithFields(log.Fields{
		"length": len(value),
	}).Debug("Parsing YAML to verify good syntax")

	var mapped interface{}
	err = yaml.Unmarshal([]byte(value), &mapped)
	if err != nil {
		log.WithFields(log.Fields{
			"length": len(value),
		}).WithError(err).Error("Unable to parse valid YAML from value")

		if m := yamlErrorLine.FindStringSubmatch(err.Error()); m != nil {
			return fmt.Errorf("%w %s", ErrMalformedYaml, m[1])
		}

		err = ErrMalformedYaml
	}

	return err
}
