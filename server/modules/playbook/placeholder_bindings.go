// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package playbook

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Placeholder-binding mappings let a playbook repo extend the global placeholder set
// A config file is any
// *.placeholders.yaml / .yml file in a playbook repo; it is a flat map of
//
//	token: field.path        # %token% in a query  ->  the event field to read the value from
//
// The field path is written WITHOUT the event_data. prefix;
// the resolver (lookupEventValue) tries the nested and bare locations. Bindings are
// scoped to the repo they ship in and overlay the global map for that repo's playbooks.
//
//	# webapp.placeholders.yaml
//	actor:  webapp.audit.actor
//	target: webapp.audit.target

const (
	bindingFileSuffixYaml = ".placeholders.yaml"
	bindingFileSuffixYml  = ".placeholders.yml"
)

// isBindingFile reports whether the file name is a placeholder-binding
// config file rather than a playbook document.
func isBindingFile(name string) bool {
	return strings.HasSuffix(name, bindingFileSuffixYaml) || strings.HasSuffix(name, bindingFileSuffixYml)
}

// parseBindings unmarshals a placeholder config file into a token->field map. Blank
// entries are skipped. An empty/parseless file is an error.
func parseBindings(contents []byte) (map[string]string, []error) {
	raw := map[string]string{}
	if err := yaml.Unmarshal(contents, &raw); err != nil {
		return nil, []error{fmt.Errorf("unable to parse placeholder binding file: %w", err)}
	}

	if len(raw) == 0 {
		return nil, []error{fmt.Errorf("placeholder binding file has no bindings")}
	}

	bindings := make(map[string]string, len(raw))
	for token, field := range raw {
		token = strings.TrimSpace(token)
		field = strings.TrimSpace(field)
		if token == "" || field == "" {
			continue
		}
		bindings[token] = field
	}

	return bindings, nil
}
