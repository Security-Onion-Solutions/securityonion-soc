// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestApplyAnnotations(t *testing.T) {
	setting := model.NewSetting("myapp.some_file__txt")
	annotations := map[string]interface{}{
		"multiline":               true,
		"sensitive":               true,
		"global":                  true,
		"node":                    true,
		"file":                    true,
		"advanced":                true,
		"readonly":                true,
		"readonlyUi":              true,
		"description":             "My Desc",
		"title":                   "My Title",
		"regex":                   "My Regex",
		"regexFailureMessage":     "My Failure Message",
		"helpLink":                "My help link",
		"syntax":                  "yaml",
		"duplicates":              true,
		"jinjaEscaped":            true,
		"uiElementsDeleteMessage": "hi",
	}

	fileLoader := func(id string) (string, string, bool) {
		if id == "myapp.some_file__txt" {
			return "some default", "some local", true
		}
		return "", "", false
	}

	assert.False(t, setting.Multiline)
	ApplyAnnotations(setting, annotations, fileLoader)
	assert.True(t, setting.Multiline)
	assert.True(t, setting.Sensitive)
	assert.True(t, setting.Global)
	assert.True(t, setting.Node)
	assert.True(t, setting.File)
	assert.True(t, setting.Advanced)
	assert.True(t, setting.Readonly)
	assert.True(t, setting.ReadonlyUi)
	assert.Equal(t, "My Desc", setting.Description)
	assert.Equal(t, "My Title", setting.Title)
	assert.Equal(t, "My Regex", setting.Regex)
	assert.Equal(t, "My Failure Message", setting.RegexFailureMessage)
	assert.Equal(t, "My help link", setting.HelpLink)
	assert.True(t, setting.DefaultAvailable)
	assert.Equal(t, "some default", setting.Default)
	assert.Equal(t, "some local", setting.Value)
	assert.Equal(t, "yaml", setting.Syntax)
	assert.True(t, setting.Duplicates)
	assert.True(t, setting.JinjaEscaped)
	assert.Equal(t, "hi", setting.UiElementsDeleteMessage)
}

func TestRecursivelyParseAnnotations(t *testing.T) {
	settings := []*model.Setting{
		model.NewSetting("myapp.foo"),
	}
	mapped := map[string]interface{}{
		"myapp": map[string]interface{}{
			"foo": map[string]interface{}{
				"title": "Foo Title",
			},
			"bar": map[string]interface{}{
				"title": "Bar Title",
			},
		},
	}

	applyFn := func(s *model.Setting, a map[string]interface{}) {
		ApplyAnnotations(s, a, nil)
	}

	updatedSettings, _ := RecursivelyParseAnnotations(settings, mapped, "", applyFn)

	assert.Len(t, updatedSettings, 2)
	assert.Equal(t, "Foo Title", updatedSettings[0].Title)
	assert.Equal(t, "Bar Title", updatedSettings[1].Title)
}
