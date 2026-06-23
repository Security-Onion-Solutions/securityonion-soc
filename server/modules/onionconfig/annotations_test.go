// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHydrateAnnotations_NonFileListDefault(t *testing.T) {
	annotations := map[string]map[string]interface{}{
		"myapp.my_def": {
			"description": "Test list default annotation",
		},
	}
	defaults := map[string]interface{}{
		"myapp.my_def": []interface{}{"item1", "item2"},
	}

	HydrateAnnotations(annotations, defaults, nil)

	// Verify that the default value has been formatted as a newline-separated string
	assert.Equal(t, "item1\nitem2\n", annotations["myapp.my_def"]["default"])
	// Verify that multiline annotation is automatically set to true
	assert.True(t, annotations["myapp.my_def"]["multiline"].(bool))
}

func TestHydrateAnnotations_FileListDefaultPreserved(t *testing.T) {
	annotations := map[string]map[string]interface{}{
		"myapp.foo__txt": {
			"description": "Test file annotation",
			"file":        true,
		},
	}
	defaults := map[string]interface{}{}

	fileReader := func(id string) (string, bool) {
		return "file_content", true
	}

	HydrateAnnotations(annotations, defaults, fileReader)

	// File defaults should not be affected by the list logic
	assert.Equal(t, "file_content", annotations["myapp.foo__txt"]["default"])
	assert.Nil(t, annotations["myapp.foo__txt"]["multiline"])
}

func TestHydrateAnnotations_OtherTypesFormattedToString(t *testing.T) {
	annotations := map[string]map[string]interface{}{
		"myapp.bool_def": {
			"description": "Test boolean default",
		},
		"myapp.int_def": {
			"description": "Test integer default",
		},
	}
	defaults := map[string]interface{}{
		"myapp.bool_def": true,
		"myapp.int_def":  123,
	}

	HydrateAnnotations(annotations, defaults, nil)

	assert.Equal(t, "true", annotations["myapp.bool_def"]["default"])
	assert.Equal(t, "123", annotations["myapp.int_def"]["default"])
}

