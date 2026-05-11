// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/syntax"
)

// PostProcess performs final adjustments to a list of settings after annotations have been applied.
func PostProcess(settings []*model.Setting) {
	for _, setting := range settings {
		// Mark all settings missing descriptions as advanced
		if len(setting.Description) == 0 {
			setting.Advanced = true
		}

		if setting.File || setting.SupportsJinja() {
			setting.Value = syntax.UnescapeJinja(setting.Value)
		}
	}
}

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
		case "default":
			setting.Default = fmt.Sprintf("%v", value)
			setting.DefaultAvailable = true
			if setting.Value == "" {
				setting.Value = setting.Default
			}
		case "file":
			setting.File = value.(bool)
			if setting.File {
				setting.Multiline = true
				if fileLoader != nil {
					_, value, ok := fileLoader(setting.Id)
					if ok {
						if value != "" {
							setting.Value = value
						}
					}
				}
				if setting.Value == "" {
					setting.Value = setting.Default
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

// FlattenAnnotations recursively walks a nested map of annotations and flattens it into a map of setting ID to annotation properties.
func FlattenAnnotations(mapped map[string]interface{}, prefix string, result map[string]map[string]interface{}) bool {
	foundAnnotation := false
	for id, value := range mapped {
		newPrefix := prefix
		if newPrefix != "" {
			newPrefix = newPrefix + "."
		}
		newId := newPrefix + id

		if m, ok := value.(map[string]interface{}); ok {
			if FlattenAnnotations(m, newId, result) {
				result[newId] = m
			}
		} else {
			foundAnnotation = true
		}
	}
	return foundAnnotation
}

// ApplySensitiveMask applies a mask to sensitive settings and clears their default values.
func ApplySensitiveMask(setting *model.Setting) {
	if setting.Sensitive {
		setting.Value = "******"
		setting.Default = ""
	}
}

// LoadStaticConfiguration walks a directory tree and collects both annotations and default values in a single pass.
func LoadStaticConfiguration(dir string, parseYaml func(string) (map[string]interface{}, error)) (map[string]map[string]interface{}, map[string]string, error) {
	annotations := make(map[string]map[string]interface{})
	defaults := make(map[string]string)

	subdirs := []string{"pillar", "salt"}
	for _, subdir := range subdirs {
		base := filepath.Join(dir, subdir)
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			module := entry.Name()
			modulePath := filepath.Join(base, module)
			files, err := os.ReadDir(modulePath)
			if err != nil {
				continue
			}

			for _, file := range files {
				if file.IsDir() {
					continue
				}

				name := file.Name()
				isAnnotation := strings.HasPrefix(name, "soc_") && strings.HasSuffix(name, ".yaml")
				isDefault := name == "defaults.yaml"

				if isAnnotation || isDefault {
					info, err := file.Info()
					if err != nil || info.Size() == 0 {
						continue
					}
					path := filepath.Join(modulePath, name)
					mapped, err := parseYaml(path)
					if err == nil {
						if isAnnotation {
							FlattenAnnotations(mapped, "", annotations)
						} else {
							FlattenPillar(mapped, "", defaults)
						}
					}
				}
			}
		}
	}

	return annotations, defaults, nil
}

// HydrateAnnotations merges default pillar values and file-based defaults into the annotations map.
func HydrateAnnotations(annotations map[string]map[string]interface{}, defaults map[string]string, fileReader func(id string) (string, bool)) {
	// 1. Ensure all defaults have at least a blank annotation map
	for id := range defaults {
		if _, exists := annotations[id]; !exists {
			annotations[id] = make(map[string]interface{})
		}
	}

	// 2. Apply defaults to annotations
	for id, ann := range annotations {
		// If it's a file-based setting, load the default content from the filesystem
		if isFile, _ := ann["file"].(bool); isFile && fileReader != nil {
			if defVal, ok := fileReader(id); ok {
				ann["default"] = defVal
			}
		} else if defVal, exists := defaults[id]; exists {
			ann["default"] = defVal
		}
	}
}
