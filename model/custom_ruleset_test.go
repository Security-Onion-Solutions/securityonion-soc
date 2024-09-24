// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCustomRulesetsDefault(t *testing.T) {
	tests := []struct {
		Name     string
		Cfg      map[string]interface{}
		Default  []*CustomRuleset
		Expected []*CustomRuleset
		ExpError string
	}{
		{
			Name: "Missing",
			Cfg:  map[string]interface{}{},
			Default: []*CustomRuleset{
				{
					Ruleset: "default",
					License: "DRL",
					File:    "default.rules",
				},
			},
			Expected: []*CustomRuleset{
				{
					Ruleset: "default",
					License: "DRL",
					File:    "default.rules",
				},
			},
		},
		{
			Name: "Empty",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{},
			},
			Default: []*CustomRuleset{
				{
					Ruleset: "default",
					License: "DRL",
					File:    "default.rules",
				},
			},
			Expected: []*CustomRuleset{},
		},
		{
			Name: "Nil",
			Cfg: map[string]interface{}{
				"customRulesets": nil,
			},
			Default: []*CustomRuleset{
				{
					Ruleset: "default",
					License: "DRL",
					File:    "default.rules",
				},
			},
			Expected: []*CustomRuleset{
				{
					Ruleset: "default",
					License: "DRL",
					File:    "default.rules",
				},
			},
		},
		{
			Name: "Valid",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"community":   true,
						"url":         "https://example.com",
						"target-file": "example.rules",
						"ruleset":     "example",
						"license":     "MIT",
					},
					map[string]interface{}{
						"community": 1,
						"file":      "example2.rules",
						"ruleset":   "example2",
						"license":   "MIT",
					},
					map[string]interface{}{
						"community":   "T",
						"url":         "https://example3.com",
						"target-file": "example3.rules",
						"ruleset":     "example3",
						"license":     "MIT",
					},
					map[string]interface{}{
						"community":   "definitely",
						"url":         "https://example4.com",
						"target-file": "example4.rules",
						"ruleset":     "example4",
						"license":     "DRL",
					},
				},
			},
			Default: []*CustomRuleset{},
			Expected: []*CustomRuleset{
				{
					Community:  true,
					Url:        "https://example.com",
					TargetFile: "example.rules",
					Ruleset:    "example",
					License:    "MIT",
				},
				{
					Community: true,
					File:      "example2.rules",
					Ruleset:   "example2",
					License:   "MIT",
				},
				{
					Community:  true,
					Url:        "https://example3.com",
					TargetFile: "example3.rules",
					Ruleset:    "example3",
					License:    "MIT",
				},
				{
					Community:  false,
					Url:        "https://example4.com",
					TargetFile: "example4.rules",
					Ruleset:    "example4",
					License:    "DRL",
				},
			},
		},
		{
			Name: "Invalid Type",
			Cfg: map[string]interface{}{
				"customRulesets": "invalid",
			},
			Default:  []*CustomRuleset{},
			ExpError: `top level config value "customRulesets" is not an array of objects`,
		},
		{
			Name: "Invalid Entry",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					"invalid",
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `"customRulesets" entry is not an object`,
		},
		{
			Name: "Invalid Key/Value Pairs",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"wrong": "key/value",
					},
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `missing "file" or "url"+"target-file" from "customRulesets" entry`,
		},
		{
			Name: "Missing URL",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"target-file": "example.rules",
						"ruleset":     "example",
						"license":     "MIT",
					},
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `missing "url" from "customRulesets" entry`,
		},
		{
			Name: "Missing Target",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"url":     "https://example.com",
						"ruleset": "example",
						"license": "MIT",
					},
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `missing "target-file" from "customRulesets" entry`,
		},
		{
			Name: "Missing Ruleset",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"url":         "https://example.com",
						"target-file": "example.rules",
						"license":     "MIT",
					},
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `missing "ruleset" from "customRulesets" entry`,
		},
		{
			Name: "Missing License",
			Cfg: map[string]interface{}{
				"customRulesets": []interface{}{
					map[string]interface{}{
						"url":         "https://example.com",
						"target-file": "example.rules",
						"ruleset":     "example",
					},
				},
			},
			Default:  []*CustomRuleset{},
			ExpError: `missing "license" from "customRulesets" entry`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			out, err := GetCustomRulesetsDefault(test.Cfg, "customRulesets", test.Default)
			if test.ExpError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.Expected, out)
		})
	}
}
