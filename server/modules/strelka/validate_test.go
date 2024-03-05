// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
)

func TestMetaSet(t *testing.T) {
	t.Parallel()

	meta := Metadata{}
	assert.True(t, meta.IsEmpty())

	meta.Set("author", "John Doe")

	assert.Equal(t, "John Doe", *meta.Author)
	assert.False(t, meta.IsEmpty())

	meta.Author = nil

	assert.True(t, meta.IsEmpty())

	meta.Set("date", "2023-12-27")
	meta.Set("version", "1.0")
	meta.Set("reference", "http://somewhere.invalid")
	meta.Set("description", "Example Rule")
	meta.Set("my_identifier_1", "Some string data")

	assert.Nil(t, meta.Author)
	assert.Equal(t, "2023-12-27", *meta.Date)
	assert.Equal(t, "1.0", *meta.Version)
	assert.Equal(t, "http://somewhere.invalid", *meta.Reference)
	assert.Equal(t, "Example Rule", *meta.Description)
	assert.Equal(t, "Some string data", meta.Rest["my_identifier_1"])
	assert.False(t, meta.IsEmpty())
}

func TestValidate(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name string
		Rule *YaraRule
		Err  *string
	}{
		{
			Name: "Minimally Valid Rule",
			Rule: &YaraRule{
				Identifier: "ExampleRule",
				Condition:  "false",
			},
		},
		{
			Name: "Missing Identifier",
			Rule: &YaraRule{
				Condition: "false",
			},
			Err: util.Ptr("missing required fields: identifier"),
		},
		{
			Name: "Missing Condition",
			Rule: &YaraRule{
				Identifier: "ExampleRule",
			},
			Err: util.Ptr("missing required fields: condition"),
		},
		{
			Name: "Missing Multiple Fields",
			Rule: &YaraRule{},
			Err:  util.Ptr("missing required fields: identifier, condition"),
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			err := test.Rule.Validate()
			if test.Err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, *test.Err, err.Error())
			}
		})
	}
}
