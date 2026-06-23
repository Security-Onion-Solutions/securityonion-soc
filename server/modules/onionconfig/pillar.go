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
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/syntax"
	"gopkg.in/yaml.v3"
)

// LoadLocalSettings loads settings from the local pillar directory and applies annotations.
func LoadLocalSettings(saltstackDir string, filterId string, annotations map[string]map[string]interface{}, bypassEnabled bool) ([]*model.Setting, error) {
	settings := make([]*model.Setting, 0)

	paths := []string{saltstackDir + "/local/pillar"}
	if filterId != "" {
		sections := strings.Split(filterId, ".")
		paths = []string{
			fmt.Sprintf("%s/local/pillar/%s", saltstackDir, sections[0]),
			fmt.Sprintf("%s/local/pillar/minions", saltstackDir),
		}
	}

	var err error
	for _, walkPath := range paths {
		if filterId != "" {
			if _, statErr := os.Stat(walkPath); statErr != nil {
				continue
			}
		}

		walkErr := TraversePillars(walkPath, &settings, bypassEnabled)
		if walkErr != nil {
			err = walkErr
			if !bypassEnabled {
				return nil, err
			}
		}
	}

	// Apply the static pillar annotations, to provide supporting details to the parsed settings above.
	fileLoader := func(id string) (string, string, bool) {
		relpath := RelPathFromId(id)
		// Default is already pre-loaded in the annotations, so we only need to load the local override here.
		value, _ := ReadFile(fmt.Sprintf("%s/local/salt/%s", saltstackDir, relpath))
		return "", value, true
	}

	if filterId != "" {
		if ann, ok := annotations[filterId]; ok {
			found := false
			for _, setting := range settings {
				if setting.Id == filterId {
					ApplyAnnotations(setting, ann, fileLoader)
					ApplySensitiveMask(setting)
					found = true
				}
			}
			if !found {
				// Add a new setting since there is no existing setting for this annotation
				setting := model.NewSetting(filterId)
				setting.Origin = model.SettingOriginDefault
				ApplyAnnotations(setting, ann, fileLoader)
				ApplySensitiveMask(setting)
				settings = append(settings, setting)
			}
		}
		// If a filterId was provided, narrow the result to only that ID.
		settings = slices.DeleteFunc(settings, func(s *model.Setting) bool {
			return s.Id != filterId
		})
	} else {
		for id, ann := range annotations {
			found := false
			for _, setting := range settings {
				if setting.Id == id {
					ApplyAnnotations(setting, ann, fileLoader)
					ApplySensitiveMask(setting)
					found = true
				}
			}
			if !found {
				// Add a new setting since there is no existing setting for this annotation
				setting := model.NewSetting(id)
				setting.Origin = model.SettingOriginDefault
				ApplyAnnotations(setting, ann, fileLoader)
				ApplySensitiveMask(setting)
				settings = append(settings, setting)
			}
		}
	}

	PostProcess(settings)
	return settings, err
}

func TraversePillars(basePath string, settings *[]*model.Setting, bypassEnabled bool) error {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(basePath, entry.Name())
		if entry.IsDir() {
			subEntries, err := os.ReadDir(path)
			if err != nil {
				if !bypassEnabled {
					return err
				}
				continue
			}
			for _, subEntry := range subEntries {
				if !subEntry.IsDir() && strings.HasSuffix(subEntry.Name(), ".sls") {
					subPath := filepath.Join(path, subEntry.Name())
					info, _ := subEntry.Info()
					ProcessPillarFile(subPath, info, settings)
				}
			}
		} else if strings.HasSuffix(entry.Name(), ".sls") {
			info, _ := entry.Info()
			ProcessPillarFile(path, info, settings)
		}
	}
	return nil
}

func ProcessPillarFile(path string, info os.FileInfo, settings *[]*model.Setting) {
	setting_id := strings.TrimSuffix(info.Name(), ".sls")
	minion_id := ""

	is_minion := strings.Contains(path, "/minions/")

	if strings.HasPrefix(setting_id, "adv_") {
		setting_id = strings.TrimPrefix(setting_id, "adv_")

		if is_minion {
			minion_id = setting_id
			setting_id = "advanced"
		} else {
			setting_id = setting_id + ".advanced"
		}

		if info.Size() == 0 {
			// Optimization: avoid reading 0-byte file, just create the empty setting
			setting := model.NewSetting(setting_id)
			if minion_id != "" {
				setting.Global = false
				setting.Node = true
			} else {
				setting.Global = true
				setting.Node = false
			}
			setting.Value = ""
			setting.NodeId = minion_id
			setting.Multiline = true
			setting.Syntax = "yaml"
			setting.Origin = model.SettingOriginYaml
			*settings = append(*settings, setting)
		} else {
			*settings = ParseAdvanced(path, *settings, minion_id, setting_id)
		}
	} else if (strings.HasPrefix(setting_id, "soc_") || is_minion) && info.Size() > 0 {
		if is_minion {
			minion_id = setting_id
		}
		var mapped map[string]interface{}
		mapped, _ = ParseYaml(path)
		if mapped != nil {
			*settings = RecursivelyParseSettings(*settings, mapped, "", minion_id)
		}
	}
}

func RecursivelyParseSettings(
	settings []*model.Setting,
	mapped map[string]interface{},
	prefix string,
	minion string,
) []*model.Setting {

	for id, value := range mapped {
		foundSetting := true
		newValue := ""
		multiline := false

		newPrefix := prefix
		if newPrefix != "" {
			newPrefix = newPrefix + "."
		}

		switch val := value.(type) {
		case map[string]interface{}:
			foundSetting = false
			settings = RecursivelyParseSettings(settings, val, newPrefix+id, minion)
		case []interface{}:
			multiline = true
			newValue = FlattenInterfaceSliceToString(val)
		default:
			newValue = fmt.Sprintf("%v", value)
		}

		if foundSetting {
			newId := newPrefix + id

			merged := false
			if minion == "" {
				for _, existing := range settings {
					if existing.Id == newId && existing.NodeId == "" {
						existing.Value = newValue
						if existing.Multiline != multiline {
							log.WithFields(log.Fields{
								"newId":        newId,
								"newMultiline": multiline,
								"oldMultiline": existing.Multiline,
							}).Warn("Existing/Default setting's multiline attribute conflicts with override multiline attribute")
							existing.Multiline = multiline
						}
						merged = true
					}
				}
			}

			if !merged {
				setting := model.NewSetting(newId)
				setting.Value = newValue
				setting.NodeId = minion
				setting.Multiline = multiline
				setting.Origin = model.SettingOriginYaml
				settings = append(settings, setting)
			}
		}
	}
	return settings
}

func ParseAdvanced(path string, settings []*model.Setting, minion string, id string) []*model.Setting {
	content, err := ReadFile(path)
	if err == nil {
		setting := model.NewSetting(id)
		if minion != "" {
			setting.Global = false
			setting.Node = true
		} else {
			setting.Global = true
			setting.Node = false
		}
		setting.Value = content
		setting.NodeId = minion
		setting.Multiline = true
		setting.Syntax = "yaml"
		setting.Origin = model.SettingOriginYaml
		settings = append(settings, setting)
	}

	return settings
}

func UpdatePillarSetting(saltstackDir string, setting *model.Setting, remove bool) error {
	sections := strings.Split(setting.Id, ".")
	if len(sections) == 0 {
		return fmt.Errorf("invalid setting id: %s", setting.Id)
	}

	if !remove {
		if setting.SupportsJinja() {
			setting.Value = syntax.EscapeJinja(setting.Value)
		}

		if !strings.HasPrefix(setting.ForcedType, "[]") && !setting.File {
			err := syntax.Validate(setting.Value, setting.Syntax)
			if err != nil {
				return err
			}
		}
	}

	if len(sections) <= 2 && sections[len(sections)-1] == "advanced" {
		var path string
		if setting.NodeId == "" {
			path = fmt.Sprintf("%s/local/pillar/%s/adv_%s.sls", saltstackDir, sections[0], sections[0])
		} else {
			path = fmt.Sprintf("%s/local/pillar/minions/adv_%s.sls", saltstackDir, setting.NodeId)
		}
		return os.WriteFile(path, []byte(setting.Value), 0600)

	} else if setting.File {
		path := fmt.Sprintf("%s/local/salt/%s", saltstackDir, RelPathFromId(setting.Id))
		if !remove {
			return os.WriteFile(path, []byte(setting.Value), 0600)
		} else {
			return os.Remove(path)
		}
	} else {
		var path string
		if setting.NodeId == "" {
			path = fmt.Sprintf("%s/local/pillar/%s/soc_%s.sls", saltstackDir, sections[0], sections[0])
		} else {
			path = fmt.Sprintf("%s/local/pillar/minions/%s.sls", saltstackDir, setting.NodeId)
		}

		mapped, err := ParseYaml(path)
		if err == nil {
			if !remove {
				err = UpdateSettingMap(mapped, sections, setting)
			} else {
				_, err = DeleteSettingMap(mapped, sections)
			}

			if err == nil {
				err = WriteYaml(path, mapped)
			}
		} else if os.IsNotExist(err) && !remove {
			// Create new file if it doesn't exist
			mapped = make(map[string]interface{})
			err = UpdateSettingMap(mapped, sections, setting)
			if err == nil {
				// Ensure parent directory exists
				os.MkdirAll(filepath.Dir(path), 0700)
				err = WriteYaml(path, mapped)
			}
		}
		return err
	}
}

func UpdateSettingMap(mapped map[string]interface{}, sections []string, setting *model.Setting) error {
	if mapped == nil || len(sections) == 0 {
		return fmt.Errorf("settings map to section id mismatch")
	}

	name := sections[0]
	child := mapped[name]
	if child == nil && len(sections) > 1 {
		// This is a new override so the parent hierarchy doesn't yet exist. Create it.
		child = make(map[string]interface{})
		mapped[name] = child
	}

	if child != nil {
		switch c := child.(type) {
		case map[string]interface{}:
			if len(sections) == 1 {
				return fmt.Errorf("unexpected setting value of map type during update")
			}
			return UpdateSettingMap(c, sections[1:], setting)
		}
	}

	value := setting.Value

	var err error
	if len(sections) == 1 {
		if setting.ForcedType != "" {
			mapped[name], err = ForceType(value, setting.ForcedType)
			if err == nil && setting.ForcedType == "[]{}" {
				if mapList, ok := mapped[name].([]map[string]any); ok {
					mapped[name], err = CoerceMapListFieldTypes(mapList, setting.UiElements)
				}
			}
		} else {
			currentValue := mapped[name]
			if currentValue == nil && setting.DefaultAvailable {
				currentValue = AlignBestGuess(setting.Default)
			}
			value = strings.TrimSpace(value)
			mapped[name], err = AlignType(currentValue, value)
		}
	}

	return err
}

func DeleteSettingMap(mapped map[string]interface{}, sections []string) (bool, error) {
	if mapped == nil || len(sections) == 0 {
		return false, fmt.Errorf("settings map to section id mismatch")
	}

	var err error
	name := sections[0]
	child := mapped[name]
	if child != nil {
		switch c := child.(type) {
		case map[string]interface{}:
			if len(sections) == 1 {
				return false, fmt.Errorf("unexpected setting value of map type during delete")
			}

			var empty bool
			empty, err = DeleteSettingMap(c, sections[1:])
			if empty && err == nil {
				delete(mapped, name)
			}
		default:
			delete(mapped, name)
		}
	}

	empty := len(mapped) == 0

	return empty, err
}

func ParseYaml(path string) (map[string]interface{}, error) {
	var mapped map[string]interface{}
	log.WithFields(log.Fields{
		"path": path,
	}).Debug("Parsing yaml file")
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	mapped = make(map[string]interface{})
	err = yaml.Unmarshal(content, &mapped)
	return mapped, err
}

func WriteYaml(path string, mapped map[string]interface{}) error {
	contents, err := yaml.Marshal(mapped)
	if err != nil {
		return err
	}
	return os.WriteFile(path, contents, 0600)
}

func ReadFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
