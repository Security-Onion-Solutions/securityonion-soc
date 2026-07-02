// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
)

func TestGetRepos(t *testing.T) {
	t.Parallel()

	dflt := []*Repo{
		{
			RepoUrl: "https://github.com/Security-Onion-Solutions/securityonion-resources",
			License: "DRL",
		},
	}

	table := []struct {
		Name     string
		Config   map[string]interface{}
		Expected []*Repo
		Error    *string
	}{
		{
			Name: "Valid",
			Config: map[string]interface{}{
				"rulesRepos": []interface{}{
					map[string]interface{}{
						"repo":      "repo1",
						"license":   "MIT",
						"community": "1",
					},
					map[string]interface{}{
						"repo":      "repo2",
						"license":   "GPL2",
						"folder":    "sigma/stable",
						"branch":    "published",
						"community": 0,
					},
					map[string]interface{}{
						"repo":      "repo3",
						"license":   "DRL",
						"community": true,
					},
					map[string]interface{}{
						"repo":      "repo4",
						"license":   "DRL",
						"community": "no",
					},
				},
			},
			Expected: []*Repo{
				{
					RepoUrl:   "repo1",
					License:   "MIT",
					Community: true,
				},
				{
					RepoUrl: "repo2",
					License: "GPL2",
					Folder:  util.Ptr("sigma/stable"),
					Branch:  util.Ptr("published"),
				},
				{
					RepoUrl:   "repo3",
					License:   "DRL",
					Community: true,
				},
				{
					RepoUrl: "repo4",
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

			repos, err := GetReposDefault(test.Config, "rulesRepos", true, dflt)
			if test.Error == nil {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), *test.Error)
			}

			assert.Equal(t, test.Expected, repos)
		})
	}
}
