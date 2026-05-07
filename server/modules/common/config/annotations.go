// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"fmt"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// ApplyAnnotations updates a setting with values from an annotation map.
// An optional fileLoader can be provided to handle "file" annotations.
func ApplyAnnotations(setting *model.Setting, annotations map[string]interface{}, fileLoader func(id string) (string, string, bool)) {
	for key, value := range annotations {
		switch key {
		case "title":
			setting.Title = fmt.Sprintf("%v", value)
		case "description":
			setting.Description = fmt.Sprintf("%v", value)
		case "readonly":
			setting.Readonly = value.(bool)
		case "readonlyUi":
			setting.ReadonlyUi = value.(bool)
		case "global":
			setting.Global = value.(bool)
		case "multiline":
			setting.Multiline = value.(bool)
		case "node":
			setting.Node = value.(bool)
		case "sensitive":
			setting.Sensitive = value.(bool)
		case "regex":
			setting.Regex = fmt.Sprintf("%v", value)
		case "regexFailureMessage":
			setting.RegexFailureMessage = fmt.Sprintf("%v", value)
		case "advanced":
			setting.Advanced = value.(bool)
		case "helpLink":
			setting.HelpLink = fmt.Sprintf("%v", value)
		case "syntax":
			setting.Syntax = fmt.Sprintf("%v", value)
		case "forcedType":
			setting.ForcedType = fmt.Sprintf("%v", value)
		case "file":
			setting.File = value.(bool)
			if setting.File {
				setting.Multiline = true
				if fileLoader != nil {
					defaultValue, value, ok := fileLoader(setting.Id)
					if ok {
						setting.Default = defaultValue
						setting.DefaultAvailable = true
						setting.Value = value
						if setting.Value == "" {
							setting.Value = setting.Default
						}
					}
				}
			}
		case "duplicates":
			setting.Duplicates = value.(bool)
		case "jinjaEscaped":
			setting.JinjaEscaped = value.(bool)
		case "options":
			setting.Options = CastToStringArray(value)
		case "optionSeparator":
			setting.OptionSeparator = value.(string)
		case "required":
			setting.Required = value.(bool)
		case "uiElements":
			tmpElements := value.([]interface{})
			for _, tmp := range tmpElements {
				if tmpMap, ok := tmp.(map[string]interface{}); ok {
					var element model.UiElement
					for key, value := range tmpMap {
						switch key {
						case "field":
							element.Field = value.(string)
						case "label":
							element.Label = value.(string)
						case "forcedType":
							element.ForcedType = value.(string)
						case "multiline":
							element.Multiline = value.(bool)
						case "options":
							element.Options = CastToStringArray(value)
						case "default":
							element.Default = value
						case "required":
							element.Required = value.(bool)
						case "readonly":
							element.Readonly = value.(bool)
						case "regex":
							element.Regex = fmt.Sprintf("%v", value)
						case "regexFailureMessage":
							element.RegexFailureMessage = value.(string)
						}
					}
					setting.UiElements = append(setting.UiElements, element)
				} else {
					log.Error("Invalid annotation; cannot cast to map")
				}
			}
		case "uiElementsDeleteMessage":
			setting.UiElementsDeleteMessage = value.(string)
		}
	}
}

// RecursivelyParseAnnotations parses a nested map of annotations and applies them to the provided settings list.
func RecursivelyParseAnnotations(
	settings []*model.Setting,
	mapped map[string]interface{},
	prefix string,
	applyFn func(setting *model.Setting, annotations map[string]interface{}),
) ([]*model.Setting, bool) {

	foundAnnotation := false
	for id, value := range mapped {

		newPrefix := prefix
		if newPrefix != "" {
			newPrefix = newPrefix + "."
		}

		newId := newPrefix + id

		switch value := value.(type) {
		case map[string]interface{}:
			var endOfBranch bool
			settings, endOfBranch = RecursivelyParseAnnotations(settings, value, newId, applyFn)
			if endOfBranch {
				foundExisting := false
				for _, setting := range settings {
					if setting.Id == newId {
						applyFn(setting, value)

						// Do not allow settings that are marked as sensitive to be transmitted to remote API clients.
						if setting.Sensitive {
							setting.Value = "******"
							setting.Default = ""
						}
						foundExisting = true
					}
				}
				if !foundExisting {
					// Add a new setting since there is no existing setting for this annotation
					setting := model.NewSetting(newId)
					applyFn(setting, value)
					settings = append(settings, setting)
					log.WithFields(log.Fields{
						"id": newId,
					}).Debug("Found annotation without a setting")
				}
			}
		default:
			foundAnnotation = true
		}
	}
	return settings, foundAnnotation
}
