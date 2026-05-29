// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"cmp"
	"fmt"
	"os/exec"
	"slices"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

const TMP_SALTSTACK_PATH = "/tmp/gotest-soc-onionconfig"
const TEST_SETTINGS_COUNT = 28

func Cleanup() {
	exec.Command("rm", "-fr", TMP_SALTSTACK_PATH).Run()
}

func SetupTestPillar() string {
	Cleanup()
	exec.Command("mkdir", "-p", TMP_SALTSTACK_PATH).Run()
	exec.Command("cp", "-fr", "./test_resources/saltstack", TMP_SALTSTACK_PATH).Run()
	return TMP_SALTSTACK_PATH + "/saltstack"
}

func findSetting(settings []*model.Setting, id string, nodeId string) *model.Setting {
	for _, setting := range settings {
		if setting.Id == id && setting.NodeId == nodeId {
			return setting
		}
	}
	return nil
}

func TestLoadLocalSettings(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, err := LoadStaticConfiguration(defaultDir, ParseYaml)
	assert.NoError(tester, err)

	HydrateAnnotations(annotations, defaults, func(id string) (string, bool) {
		relpath := RelPathFromId(id)
		content, err := ReadFile(fmt.Sprintf("%s/default/salt/%s", saltstackDir, relpath))
		return content, err == nil
	})

	settings, err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, err)

	slices.SortFunc(settings,
		func(a, b *model.Setting) int {
			r := cmp.Compare(a.Id, b.Id)
			if r == 0 {
				r = cmp.Compare(a.NodeId, b.NodeId)
			}
			return r
		})

	count := 0

	assert.Equal(tester, "myapp.advanced", settings[count].Id)
	assert.Equal(tester, "myapp:\n  global: advanced\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.bar", settings[count].Id)
	assert.Equal(tester, "minion-override", settings[count].Value)
	assert.Equal(tester, "normal_import", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.bool", settings[count].Id)
	assert.Equal(tester, "true", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_bool", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_float", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_int", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_list_str", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_map_str", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.empty_lists.list_str", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.float", settings[count].Id)
	assert.Equal(tester, "3.5", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.foo", settings[count].Id)
	assert.Equal(tester, "minion-born", settings[count].Value)
	assert.Equal(tester, "normal_import", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.foo__txt", settings[count].Id)
	assert.Equal(tester, "old", settings[count].Value)
	assert.Equal(tester, true, settings[count].File)
	count++

	assert.Equal(tester, "myapp.int", settings[count].Id)
	assert.Equal(tester, "123", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	assert.Equal(tester, "([0-9]+){3}", settings[count].Regex)
	assert.Equal(tester, "Invalid!", settings[count].RegexFailureMessage)
	assert.Equal(tester, "test desc", settings[count].Description)
	assert.Equal(tester, true, settings[count].Global)
	assert.Equal(tester, false, settings[count].Readonly)
	count++

	assert.Equal(tester, "myapp.int_list_nodefault", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	assert.Equal(tester, "no default provided", settings[count].Description)
	assert.Equal(tester, true, settings[count].Global)
	assert.Equal(tester, "[]int", settings[count].ForcedType)
	count++

	assert.Equal(tester, "myapp.int_nodefault", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	assert.Equal(tester, "no default provided", settings[count].Description)
	assert.Equal(tester, true, settings[count].Global)
	assert.Equal(tester, "int", settings[count].ForcedType)
	count++

	assert.Equal(tester, "myapp.lists.list_bool", settings[count].Id)
	assert.Equal(tester, "true\nfalse\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.lists.list_float", settings[count].Id)
	assert.Equal(tester, "1.24\n2.2\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.lists.list_int", settings[count].Id)
	assert.Equal(tester, "3\n24\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.lists.list_list_str", settings[count].Id)
	assert.Equal(tester, "[\"item1\",\"item2\"]\n[\"item3\",\"item4\"]\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.lists.list_map_str", settings[count].Id)
	assert.Equal(tester, "{\"key1\":\"value1\",\"key2\":\"value2\"}\n{\"key1\":\"value3\",\"key2\":\"value4\"}\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.lists.list_str", settings[count].Id)
	assert.Equal(tester, "foo\nbar\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.my_def", settings[count].Id)
	assert.Equal(tester, "item1\nitem2\n", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.ro", settings[count].Id)
	assert.Equal(tester, true, settings[count].Readonly)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.str", settings[count].Id)
	assert.Equal(tester, "my_str", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.ui_json", settings[count].Id)
	assert.Equal(tester, "{\"something\":\"here\",\"another\":\"else\"},{\"something\":\"here2\",\"another\":\"else2\"}", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.ui_map_typed", settings[count].Id)
	assert.Equal(tester, "", settings[count].Value)
	assert.Equal(tester, "", settings[count].NodeId)
	assert.Equal(tester, "[]{}", settings[count].ForcedType)
	assert.Equal(tester, 3, len(settings[count].UiElements))
	count++

	assert.Equal(tester, "myapp.zdef", settings[count].Id)
	assert.Equal(tester, "chocolate", settings[count].Value)
	assert.Equal(tester, "vanilla", settings[count].Default)
	assert.Equal(tester, "", settings[count].NodeId)
	count++

	assert.Equal(tester, "myapp.zdef", settings[count].Id)
	assert.Equal(tester, "strawberry", settings[count].Value)
	assert.Equal(tester, "normal_import", settings[count].NodeId)
	count++

	assert.Equal(tester, count, len(settings))
}

func TestLoadLocalSettings_BadSaltstackPath(tester *testing.T) {
	_, err := LoadLocalSettings("/invalid/path", "", nil, false)
	assert.ErrorContains(tester, err, "open /invalid/path/local/pillar: no such file or directory")
}

func TestUpdatePillarSetting_Readonly(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()
	srv := server.NewFakeAuthorizedServer(nil)
	oc := NewOnionConfig(srv)
	oc.Init(saltstackDir, true)
	oc.Start(nil)

	setting := model.NewSetting("myapp.ro")
	err := oc.UpdateSetting(srv.Context, setting, false)
	assert.EqualError(tester, err, "Unable to modify or remove a readonly setting")
}

func TestUpdatePillarSetting_MissingSettingFile(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()
	setting := model.NewSetting("some.setting")
	err := UpdatePillarSetting(saltstackDir, setting, true) // Pass true to remove to force error
	assert.ErrorContains(tester, err, "no such file or directory")
}

func TestUpdatePillarSetting_OverrideDefault(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Add new setting
	setting := model.NewSetting("myapp.my_def")
	setting.Value = "new setting"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.my_def", "")
	assert.Equal(tester, "new setting", new_setting.Value)
}

func TestUpdatePillarSetting_OverrideWithJinjaEscaped(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Add new setting
	setting := model.NewSetting("myapp.my_def")
	setting.Value = "new setting {{foo}} {# comment #} {% multiline %}"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.my_def", "")
	assert.Equal(tester, "new setting {{foo}} {# comment #} {% multiline %}", new_setting.Value)
}

func TestUpdatePillarSetting_FileWithJinja(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Add new setting
	setting := model.NewSetting("myapp.foo__txt")
	setting.File = true
	setting.Value = "new setting {{foo}} {# comment #} {% multiline %}"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.foo__txt", "")
	assert.Equal(tester, "new setting {{foo}} {# comment #} {% multiline %}", new_setting.Value)
}

func TestUpdatePillarSetting_AddGlobal(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Add new setting
	setting := model.NewSetting("myapp.setting")
	setting.Value = "new setting"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT+1, len(settings))

	new_setting := findSetting(settings, "myapp.setting", "")
	assert.Equal(tester, "new setting", new_setting.Value)
}

func TestUpdatePillarSetting_AddToNode(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Add new setting
	setting := model.NewSetting("myapp.setting")
	setting.Value = "new setting"
	setting.NodeId = "normal_import"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT+1, len(settings))

	new_setting := findSetting(settings, "myapp.setting", "normal_import")
	assert.Equal(tester, "new setting", new_setting.Value)
}

func TestUpdatePillarSetting_DeleteGlobal(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Delete setting
	setting := model.NewSetting("myapp.str")
	setting.NodeId = ""
	err := UpdatePillarSetting(saltstackDir, setting, true)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT-1, len(settings))
	delete_setting := findSetting(settings, "myapp.str", "")
	assert.Nil(tester, delete_setting)
}

func TestUpdatePillarSetting_DeleteFromNode(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Delete setting
	setting := model.NewSetting("myapp.foo")
	setting.NodeId = "normal_import"
	err := UpdatePillarSetting(saltstackDir, setting, true)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT-1, len(settings))
	delete_setting := findSetting(settings, "myapp.foo", "normal_import")
	assert.Nil(tester, delete_setting)
}

func TestUpdatePillarSetting_DeleteAdvanced(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Delete setting
	setting := model.NewSetting("myapp.advanced")
	err := UpdatePillarSetting(saltstackDir, setting, true)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT, len(settings))
	deleted_setting := findSetting(settings, "myapp.advanced", "")
	assert.Equal(tester, "", deleted_setting.Value)
}

func TestUpdatePillarSetting_UpdateGlobal(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Update setting
	setting := model.NewSetting("myapp.str")
	setting.NodeId = ""
	setting.Value = "new value\n" // ensure value is trimmed of whitespace
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT, len(settings))
	updated_setting := findSetting(settings, "myapp.str", "")
	assert.Equal(tester, "new value", updated_setting.Value)
}

func TestUpdatePillarSetting_UpdateForNode(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Update setting
	setting := model.NewSetting("myapp.foo")
	setting.NodeId = "normal_import"
	setting.Value = "new value"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.foo", "normal_import")
	assert.Equal(tester, "new value", updated_setting.Value)
}

func TestUpdatePillarSetting_UpdateAdvanced(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Update setting
	setting := model.NewSetting("myapp.advanced")
	setting.Value = "something: new"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.advanced", "")
	assert.Equal(tester, "something: new", updated_setting.Value)
}

func TestUpdatePillarSetting_UpdateFile(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	
	fileLoader := func(id string) (string, bool) {
		relpath := RelPathFromId(id)
		content, err := ReadFile(fmt.Sprintf("%s/default/salt/%s", saltstackDir, relpath))
		return content, err == nil
	}
	HydrateAnnotations(annotations, defaults, fileLoader)

	// Update setting
	setting := model.NewSetting("myapp.foo__txt")
	setting.File = true
	setting.Value = "something"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.foo__txt", "")
	
	// Re-load with proper file loader for annotations to get default
	fileLoader2 := func(id string) (string, string, bool) {
		relpath := RelPathFromId(id)
		val, err := ReadFile(fmt.Sprintf("%s/local/salt/%s", saltstackDir, relpath))
		return "", val, err == nil
	}
	ApplyAnnotations(updated_setting, annotations["myapp.foo__txt"], fileLoader2)
	
	assert.Equal(tester, "anything", updated_setting.Default)
	assert.Equal(tester, "something", updated_setting.Value)

	// Delete setting
	err = UpdatePillarSetting(saltstackDir, setting, true)
	assert.NoError(tester, err)

	settings, get_err = LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.foo__txt", "")
	ApplyAnnotations(updated_setting, annotations["myapp.foo__txt"], fileLoader2)
	assert.Equal(tester, "anything", updated_setting.Default)
	assert.Equal(tester, "anything", updated_setting.Value)
}

func TestUpdatePillarSetting_UpdateAdvancedFailToParse(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.advanced")
	setting.Value = "[s new advanced"
	setting.Syntax = "yaml"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, "ERROR_MALFORMED_YAML -> yaml: line 1: did not find expected ',' or ']'")
}

func TestUpdatePillarSetting_AlignIntType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.int")
	setting.Value = "44"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int", "")
	assert.Equal(tester, "44", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignIntType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.int")
	setting.Value = "not an int"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, "strconv.ParseInt: parsing \"not an int\": invalid syntax")
}

func TestUpdatePillarSetting_AlignIntListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_int")
	setting.Value = "44\n2\n1"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_int", "")
	assert.Equal(tester, "44\n2\n1\n", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignIntListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_int")
	setting.Value = "1\n2\ninvalid"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseInt: parsing "invalid": invalid syntax`)
}

func TestUpdatePillarSetting_AlignEmptyListIntType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Prime the empty list setting with int
	setting := model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "123\n456"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more ints
	setting = model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "123\n456\n23"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_int", "")
	assert.Equal(tester, "123\n456\n23\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "cannot set string on int list"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseInt: parsing "cannot set string on int list": invalid syntax`)
}

func TestUpdatePillarSetting_ForceIntType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.int_nodefault")
	setting.ForcedType = "int"
	setting.Value = "44"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int_nodefault", "")
	assert.Equal(tester, "44", updated_setting.Value)
}

func TestUpdatePillarSetting_ForceListIntType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.int_list_nodefault")
	setting.ForcedType = "[]int"
	setting.Value = "44\n55"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int_list_nodefault", "")
	assert.Equal(tester, "44\n55\n", updated_setting.Value)
}

func TestUpdatePillarSetting_AlignFloatType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.float")
	setting.Value = "44.2"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.float", "")
	assert.Equal(tester, "44.2", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignFloatType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.float")
	setting.Value = "not a float"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, "strconv.ParseFloat: parsing \"not a float\": invalid syntax")
}

func TestUpdatePillarSetting_AlignFloatListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_float")
	setting.Value = "44.3\n2.1\n1.2"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_float", "")
	assert.Equal(tester, "44.3\n2.1\n1.2\n", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignFloatListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_float")
	setting.Value = "1.2\nnope"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseFloat: parsing "nope": invalid syntax`)
}

func TestUpdatePillarSetting_AlignEmptyListFloatType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Prime the empty list setting with float
	setting := model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "1.23\n4.56"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more floats
	setting = model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "1.23\n4.56\n2.3"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_float", "")
	assert.Equal(tester, "1.23\n4.56\n2.3\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "cannot set string on float list"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseFloat: parsing "cannot set string on float list": invalid syntax`)
}

func TestUpdatePillarSetting_AlignBoolType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.bool")
	setting.Value = "false"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.bool", "")
	assert.Equal(tester, "false", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignBoolType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.bool")
	setting.Value = "not a bool"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, "strconv.ParseBool: parsing \"not a bool\": invalid syntax")
}

func TestUpdatePillarSetting_AlignBoolListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_bool")
	setting.Value = "true\nfalse\ntrue"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_bool", "")
	assert.Equal(tester, "true\nfalse\ntrue\n", updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignBoolListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_bool")
	setting.Value = "true\nfalse\nhi"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseBool: parsing "hi": invalid syntax`)
}

func TestUpdatePillarSetting_AlignEmptyListBoolType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Prime the empty list setting with bools
	setting := model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "true\nfalse"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	setting = model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "true\ntrue\nfalse"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_bool", "")
	assert.Equal(tester, "true\ntrue\nfalse\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "cannot set string on bool list"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `strconv.ParseBool: parsing "cannot set string on bool list": invalid syntax`)
}

func TestUpdatePillarSetting_AlignListListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	expected := "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]\n[\"item5\",\"item6\"]\n"
	setting := model.NewSetting("myapp.lists.list_list_str")
	setting.Value = expected
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_list_str", "")
	assert.Equal(tester, expected, updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignListListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting (can't change list of lists to list of bools)
	setting := model.NewSetting("myapp.lists.list_list_str")
	setting.Value = "true\nfalse"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `json: cannot unmarshal bool into Go value of type []interface {}`)
}

func TestUpdatePillarSetting_AlignEmptyListListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Prime the empty list setting with list of strings
	setting := model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	expected := "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]\n[\"item5\",\"item6\"]\n"
	setting = model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = expected
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_list_str", "")
	assert.Equal(tester, expected, updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = "cannot set list of strings\non list of lists"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `invalid character 'c' looking for beginning of value`)
}

func TestUpdatePillarSetting_AlignMapListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	expected := "{\"key1\":\"value1\",\"key2\":\"value2\"}\n{\"key1\":\"value3\",\"key2\":\"value4\"}\n{\"key1\":\"value5\",\"key2\":\"value6\"}\n"
	setting := model.NewSetting("myapp.lists.list_map_str")
	setting.Value = expected
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_map_str", "")
	assert.Equal(tester, expected, updated_setting.Value)
}

func TestUpdatePillarSetting_FailToAlignMapListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting (can't change list of maps to list of bools)
	setting := model.NewSetting("myapp.lists.list_map_str")
	setting.Value = "true\nfalse"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `json: cannot unmarshal bool into Go value of type map[string]interface {}`)
}

func TestUpdatePillarSetting_AlignEmptyListMapType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Prime the empty list setting with list of maps
	setting := model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = "{\"key1\":\"value1\",\"key2\":\"value2\"}"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	expected := "{\"key1\":\"value1\",\"key2\":\"value2\"}\n{\"key1\":\"value3\",\"key2\":\"value4\"}\n"
	setting = model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = expected
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_map_str", "")
	assert.Equal(tester, expected, updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = "cannot set list of strings\non list of maps"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.EqualError(tester, err, `invalid character 'c' looking for beginning of value`)
}

func TestUpdatePillarSetting_AlignNonStringType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.str")
	setting.Value = "123"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.str", "")
	assert.Equal(tester, "123", updated_setting.Value)
}

func TestUpdatePillarSetting_AlignNonStringListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_str")
	setting.Value = "123\n456"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_str", "")
	assert.Equal(tester, "123\n456\n", updated_setting.Value)
}

func TestUpdatePillarSetting_AlignBlankStringListType(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// default should be an empty list
	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "", updated_setting.Value)

	// Update empty setting with non-blank value
	setting := model.NewSetting("myapp.empty_lists.list_str")
	setting.Value = "foo"
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// should now contain non-blank value
	settings, get_err = LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "foo\n", updated_setting.Value)

	// Update empty setting with empty lines value
	setting = model.NewSetting("myapp.empty_lists.list_str")
	setting.Value = "\n"
	err = UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	// should be an empty list again
	settings, get_err = LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "", updated_setting.Value)
}

func TestUpdatePillarSetting_ForceMapListFieldTypes_StringInput(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// UI sends int and bool fields as strings inside the JSON objects
	setting := model.NewSetting("myapp.ui_map_typed")
	setting.Value = "{\"enabled\":\"true\",\"name\":\"alpha\",\"port\":\"8080\"}\n{\"enabled\":\"false\",\"name\":\"beta\",\"port\":\"9090\"}"
	setting.ForcedType = "[]{}"
	setting.UiElements = []model.UiElement{
		{Field: "enabled", ForcedType: "bool"},
		{Field: "name", ForcedType: "string"},
		{Field: "port", ForcedType: "int"},
	}
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated := findSetting(settings, "myapp.ui_map_typed", "")
	// After coercion, port must be a JSON number and enabled a JSON bool (not quoted strings)
	assert.Equal(tester, "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}\n{\"enabled\":false,\"name\":\"beta\",\"port\":9090}\n", updated.Value)
}

func TestUpdatePillarSetting_ForceMapListFieldTypes_NumericInput(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// UI sends properly-typed JSON (numbers as numbers, bools as bools)
	setting := model.NewSetting("myapp.ui_map_typed")
	setting.Value = "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}"
	setting.ForcedType = "[]{}"
	setting.UiElements = []model.UiElement{
		{Field: "enabled", ForcedType: "bool"},
		{Field: "name", ForcedType: "string"},
		{Field: "port", ForcedType: "int"},
	}
	err := UpdatePillarSetting(saltstackDir, setting, false)
	assert.NoError(tester, err)

	settings, get_err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, get_err)
	updated := findSetting(settings, "myapp.ui_map_typed", "")
	// float64(8080) from JSON parse must be coerced to int64 so YAML stores it as an integer
	assert.Equal(tester, "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}\n", updated.Value)
}

func TestReadSetting_UiElements(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()
	
	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	settings, err := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.NoError(tester, err)

	setting := findSetting(settings, "myapp.ui_json", "")
	assert.Equal(tester, 3, len(setting.UiElements))
	assert.Equal(tester, "something", setting.UiElements[0].Field)
	assert.Equal(tester, "something nice", setting.UiElements[0].Label)
	assert.Equal(tester, "bool", setting.UiElements[0].ForcedType)
	assert.Equal(tester, false, setting.UiElements[0].Multiline)
	assert.Equal(tester, false, setting.UiElements[0].Required)
	assert.Equal(tester, true, setting.UiElements[0].Readonly)

	assert.Equal(tester, "another", setting.UiElements[1].Field)
	assert.Equal(tester, "another thing", setting.UiElements[1].Label)
	assert.Equal(tester, "red", setting.UiElements[1].Default)
	assert.Equal(tester, "[]string", setting.UiElements[1].ForcedType)
	assert.Equal(tester, []string{"blue", "red", "green"}, setting.UiElements[1].Options)

	assert.Equal(tester, "one more", setting.UiElements[2].Field)
	assert.Equal(tester, "But wait there's more", setting.UiElements[2].Label)
	assert.Equal(tester, true, setting.UiElements[2].Required)
	assert.Equal(tester, true, setting.UiElements[2].Multiline)
	assert.Equal(tester, "^abc$", setting.UiElements[2].Regex)
	assert.Equal(tester, "must conform", setting.UiElements[2].RegexFailureMessage)
}

func TestCoerceMapListFieldTypes(tester *testing.T) {
	testCases := []struct {
		name            string
		list            []map[string]any
		uiElements      []model.UiElement
		wantEmptyResult bool   // assert result is empty (empty list case)
		checkField      string // field in result[0] to assert on
		expected        any
		errContains     string // non-empty → expect error containing this
	}{
		// skip / trivial
		{name: "empty list", list: []map[string]any{}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int"}}, wantEmptyResult: true},
		{name: "empty uiElements unchanged", list: []map[string]any{{"port": "8080"}}, uiElements: []model.UiElement{}, checkField: "port", expected: "8080"},
		{name: "uiElement no ForcedType skipped", list: []map[string]any{{"port": "8080"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: ""}}, checkField: "port", expected: "8080"},
		{name: "uiElement no Field skipped", list: []map[string]any{{"port": "8080"}}, uiElements: []model.UiElement{{Field: "", ForcedType: "int"}}, checkField: "port", expected: "8080"},
		{name: "field missing from map skipped", list: []map[string]any{{"name": "alpha"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int"}}, checkField: "name", expected: "alpha"},

		// string → scalar (primary focus: UI sends everything as a string)
	}

	for _, tc := range testCases {
		tester.Run(tc.name, func(t *testing.T) {
			result, err := CoerceMapListFieldTypes(tc.list, tc.uiElements)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			} else {
				assert.NoError(t, err)
				if tc.wantEmptyResult {
					assert.Empty(t, result)
				} else if tc.checkField != "" {
					assert.Equal(t, tc.expected, result[0][tc.checkField])
				}
			}
		})
	}
}

func TestGetFilteredSettings(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()
	
	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, _, _ := LoadStaticConfiguration(defaultDir, ParseYaml)

	// Test with no filter
	settings, err := LoadLocalSettings(saltstackDir, "", nil, false)
	assert.NoError(tester, err)
	assert.NotEmpty(tester, settings)

	// Test with specific filter
	settings, err = LoadLocalSettings(saltstackDir, "myapp.foo__txt", annotations, false)
	assert.NoError(tester, err)
	assert.Len(tester, settings, 1)
	assert.Equal(tester, "myapp.foo__txt", settings[0].Id)

	// Test with non-existent filter
	settings, err = LoadLocalSettings(saltstackDir, "nonexistent.setting", nil, false)
	assert.NoError(tester, err)
	assert.Empty(tester, settings)
}

func TestUpdatePillarSetting_Delete(tester *testing.T) {
	defer Cleanup()
	saltstackDir := SetupTestPillar()

	// Load annotations
	defaultDir := saltstackDir + "/default"
	annotations, defaults, _ := LoadStaticConfiguration(defaultDir, ParseYaml)
	HydrateAnnotations(annotations, defaults, nil)

	// Delete setting
	setting := model.NewSetting("myapp.str")
	err := UpdatePillarSetting(saltstackDir, setting, true)
	assert.NoError(tester, err)

	settings, _ := LoadLocalSettings(saltstackDir, "", annotations, false)
	assert.Equal(tester, TEST_SETTINGS_COUNT-1, len(settings))
	deleted_setting := findSetting(settings, "myapp.str", "")
	assert.Nil(tester, deleted_setting)
}
