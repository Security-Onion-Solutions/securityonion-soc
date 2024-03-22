// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package module

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
)

func TestGetString(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetString(options, "MyKey")
	assert.Error(tester, err)

	options["MyKey"] = "MyValue"
	actual, err := GetString(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "MyValue", actual)
	}

}

func TestGetStringDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringDefault(options, "MyKey", "MyValue")
	assert.Equal(tester, "MyValue", actual)
	options["MyKey"] = "YourValue"
	actual = GetStringDefault(options, "MyKey", "MyValue")
	assert.Equal(tester, "YourValue", actual)
}

func TestGetInt(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetInt(options, "MyKey")
	assert.Error(tester, err)
	options["MyKey"] = float64(123)
	actual, err := GetInt(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, 123, actual)
	}

}

func TestGetIntDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetIntDefault(options, "MyKey", 123)
	assert.Equal(tester, 123, actual)
	options["MyKey"] = float64(1234)
	actual = GetIntDefault(options, "MyKey", 123)
	assert.Equal(tester, 1234, actual)
}

func TestGetBool(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetBool(options, "MyKey")
	assert.Error(tester, err)
	options["MyKey"] = true
	actual, err := GetBool(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.True(tester, actual)
	}
}

func TestGetBoolDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetBoolDefault(options, "MyKey", true)
	assert.True(tester, actual)
	options["MyKey"] = false
	actual = GetBoolDefault(options, "MyKey", true)
	assert.False(tester, actual)
}

func TestGetStringArray(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetStringArray(options, "MyKey")
	assert.Error(tester, err)
	array := make([]interface{}, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual, err := GetStringArray(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "MyValue1", actual[0])
		assert.Equal(tester, "MyValue2", actual[1])
	}
}

func TestGetStringArrayDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	assert.Len(tester, actual, 0)

	array := make([]interface{}, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual = GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	assert.Equal(tester, "MyValue1", actual[0])
	assert.Equal(tester, "MyValue2", actual[1])
}

func TestGetRepos(t *testing.T) {
	t.Parallel()

	dflt := []*RuleRepo{
		{
			Repo:    "https://github.com/Security-Onion-Solutions/securityonion-resources",
			License: "DRL",
		},
	}

	table := []struct {
		Name     string
		Config   map[string]interface{}
		Expected []*RuleRepo
		Error    *string
	}{
		{
			Name: "Valid",
			Config: map[string]interface{}{
				"rulesRepos": []interface{}{
					map[string]interface{}{
						"repo":    "repo1",
						"license": "MIT",
					},
					map[string]interface{}{
						"repo":    "repo2",
						"license": "GPL2",
					},
					map[string]interface{}{
						"repo":    "repo3",
						"license": "DRL",
					},
				},
			},
			Expected: []*RuleRepo{
				{
					Repo:    "repo1",
					License: "MIT",
				},
				{
					Repo:    "repo2",
					License: "GPL2",
				},
				{
					Repo:    "repo3",
					License: "DRL",
				},
			},
		},
		{
			Name:     "Empty",
			Config:   map[string]interface{}{},
			Expected: dflt,
		},
		{
			Name: "Missing License",
			Config: map[string]interface{}{
				"rulesRepos": []interface{}{
					map[string]interface{}{
						"repo": "repo1",
					},
				},
			},
			Error: util.Ptr(`missing "license" from "rulesRepos" entry`),
		},
		{
			Name: "Missing Repo",
			Config: map[string]interface{}{
				"rulesRepos": []interface{}{
					map[string]interface{}{
						"license": "DRL",
					},
				},
			},
			Error: util.Ptr(`missing "repo" link from "rulesRepos" entry`),
		},
		{
			Name: "Wrong Structure A",
			Config: map[string]interface{}{
				"rulesRepos": "repo",
			},
			Error: util.Ptr(`top level config value "rulesRepos" is not an array of objects`),
		},
		{
			Name: "Wrong Structure B",
			Config: map[string]interface{}{
				"rulesRepos": []interface{}{
					"github",
				},
			},
			Error: util.Ptr(`"rulesRepos" entry is not an object`),
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			repos, err := GetReposDefault(test.Config, "rulesRepos", dflt)
			if test.Error == nil {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), *test.Error)
			}

			assert.Equal(t, test.Expected, repos)
		})
	}
}
