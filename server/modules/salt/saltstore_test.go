// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

const TMP_SALTSTACK_PATH = "/tmp/gotest-soc-saltstore"
const TMP_QUEUE_DIR = "/tmp/gotest-soc-salt-relay-queue"
const TMP_REQUEST_FILE = "req"
const TEST_SETTINGS_COUNT = 28

func Cleanup() {
	exec.Command("rm", "-fr", TMP_SALTSTACK_PATH).Run()
	exec.Command("rm", "-fr", TMP_QUEUE_DIR).Run()
}

func NewTestSalt() *Saltstore {
	Cleanup()
	exec.Command("mkdir", "-p", TMP_SALTSTACK_PATH).Run()
	exec.Command("mkdir", "-p", TMP_QUEUE_DIR).Run()
	exec.Command("cp", "-fr", "./test_resources/saltstack", TMP_SALTSTACK_PATH).Run()

	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	salt.Init(123, 123, TMP_SALTSTACK_PATH+"/saltstack", TMP_QUEUE_DIR, false)
	return salt
}

func NewTestSaltRelayQueue(tester *testing.T, id string, mockedResponse string) *Saltstore {
	Cleanup()
	exec.Command("mkdir", "-p", TMP_SALTSTACK_PATH).Run()
	exec.Command("mkdir", "-p", TMP_QUEUE_DIR).Run()
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	salt.Init(10, 10, TMP_SALTSTACK_PATH+"/saltstack", TMP_QUEUE_DIR, false)

	filename := filepath.Join(TMP_QUEUE_DIR, id+".response")
	responseData, err := os.ReadFile("test_resources/queue/" + mockedResponse)
	assert.NoError(tester, err)
	err = os.WriteFile(filename, responseData, 0600)
	assert.NoError(tester, err)
	return salt
}

func ReadRequest(tester *testing.T, filename string) string {
	path := filepath.Join(TMP_QUEUE_DIR, filename)
	contents, err := os.ReadFile(path)
	assert.NoError(tester, err)
	os.Remove(path)
	return string(contents)
}

func TestSaltstoreInit(tester *testing.T) {
	salt := NewSaltstore(nil)
	salt.Init(123, 123, "saltstack/path", "salt/control", false)
	assert.Equal(tester, 123, salt.timeoutMs)
	assert.Equal(tester, "saltstack/path", salt.saltstackDir)
	assert.Equal(tester, "salt/control", salt.queueDir)
}

func TestGetMembersFromJson(tester *testing.T) {
	json := `
		{
	    "minions": {
        "minion_id": "fingerprint"
      }
		}
	`

	// Error supplied
	members, err := getMembersFromJson(errors.New("something bad"), []byte(json))
	assert.Error(tester, err)
	assert.Nil(tester, members)

	// Parse error
	members, err = getMembersFromJson(nil, []byte("{ds"))
	assert.EqualError(tester, err, "invalid character 'd' looking for beginning of object key string")
	assert.Nil(tester, members)

	// Good parse
	members, err = getMembersFromJson(nil, []byte(json))
	assert.NoError(tester, err)
	assert.Len(tester, members, 1)
	assert.Equal(tester, "minion_id", members[0].Id)
	assert.Equal(tester, "id", members[0].Role)
	assert.Equal(tester, "fingerprint", members[0].Fingerprint)
}

func ctx() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestId, "ctx")
}

func TestGetMembers_BadQueueDir(tester *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	salt.Init(123, 123, TMP_SALTSTACK_PATH+"/saltstack", "/invalid/path", false)
	_, err := salt.GetMembers(ctx())
	assert.ErrorContains(tester, err, "no such file or directory")
}

func TestGetMembersUnauthorized(tester *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	salt := NewSaltstore(srv)
	_, err := salt.GetMembers(ctx())
	assert.ErrorContains(tester, err, "Subject 'fake-subject' is not authorized to perform operation 'read' on target 'grid'")
}

func TestGetMembers(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_list-minions", "list_minions.resp")
	members, err := salt.GetMembers(ctx())
	assert.NoError(tester, err)
	assert.Equal(tester, 15, len(members))

	request := ReadRequest(tester, "ctx_list-minions")
	assert.Equal(tester, `{"command":"list-minions","command_id":"ctx_list-minions"}`, request)
}

func TestGetMembers_Failure(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_list-minions", "false.resp")
	members, err := salt.GetMembers(ctx())
	assert.EqualError(tester, err, "ERROR_SALT_MANAGE_MEMBER")
	assert.Equal(tester, 0, len(members))

	request := ReadRequest(tester, "ctx_list-minions")
	assert.Equal(tester, `{"command":"list-minions","command_id":"ctx_list-minions"}`, request)
}

func TestManageMemberUnauthorized(tester *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	salt := NewSaltstore(srv)

	for _, op := range []string{"add", "reject", "delete"} {
		err := salt.ManageMember(ctx(), op, "foo")
		assert.ErrorContains(tester, err, "Subject 'fake-subject' is not authorized to perform operation 'write' on target 'grid'")
	}
}

func TestManageMember_BadQueuePath(tester *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	salt.Init(123, 123, TMP_SALTSTACK_PATH+"/saltstack", "invalid/path", false)

	for _, op := range []string{"add", "reject", "delete"} {
		err := salt.ManageMember(ctx(), op, "foo")
		assert.ErrorContains(tester, err, "no such file or directory")
	}
}

func TestManageMember(tester *testing.T) {
	for _, op := range []string{"add", "reject", "delete"} {
		defer Cleanup()
		salt := NewTestSaltRelayQueue(tester, "ctx_manage-minion", "true.resp")
		err := salt.ManageMember(ctx(), op, "foo")
		assert.NoError(tester, err)

		request := ReadRequest(tester, "ctx_manage-minion")
		assert.Equal(tester, `{"command":"manage-minion","command_id":"ctx_manage-minion","id":"foo","operation":"`+op+`"}`, request)
	}
}

func TestManageMember_Failure(tester *testing.T) {
	for _, op := range []string{"add", "reject", "delete"} {
		defer Cleanup()
		salt := NewTestSaltRelayQueue(tester, "ctx_manage-minion", "false.resp")
		err := salt.ManageMember(ctx(), op, "foo")
		assert.EqualError(tester, err, "ERROR_SALT_MANAGE_MEMBER")

		request := ReadRequest(tester, "ctx_manage-minion")
		assert.Equal(tester, `{"command":"manage-minion","command_id":"ctx_manage-minion","id":"foo","operation":"`+op+`"}`, request)
	}
}

func TestGetSettings_BadSaltstackPath(tester *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	_, err := salt.GetSettings(ctx(), true)
	assert.EqualError(tester, err, "lstat /default: no such file or directory")
}

func TestGetSettings(tester *testing.T) {
	defer Cleanup()

	salt := NewTestSalt()
	settings, err := salt.GetSettings(ctx(), true)
	slices.SortFunc(settings,
		func(a, b *model.Setting) int {
			r := cmp.Compare(a.Id, b.Id)
			if r == 0 {
				r = cmp.Compare(a.NodeId, b.NodeId)
			}
			return r
		})
	assert.NoError(tester, err)

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

func TestUpdateSetting_Readonly(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()
	setting := model.NewSetting("myapp.ro")
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "Unable to modify or remove a readonly setting")
}

func TestUpdateSetting_MissingSettingFile(tester *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	setting := model.NewSetting("some.setting")
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "lstat /default: no such file or directory")
}

func findSetting(settings []*model.Setting, id string, nodeId string) *model.Setting {
	for _, setting := range settings {
		if setting.Id == id && setting.NodeId == nodeId {
			return setting
		}
	}
	return nil
}

func TestUpdateSetting_OverrideDefault(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Add new setting
	setting := model.NewSetting("myapp.my_def")
	setting.Value = "new setting"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.my_def", "")
	assert.Equal(tester, "new setting\n", new_setting.Value)
}

func TestUpdateSetting_OverrideWithJinjaEscaped(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Add new setting
	setting := model.NewSetting("myapp.my_def")
	setting.Value = "new setting {{foo}} {# comment #} {% multiline %}"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.my_def", "")
	assert.Equal(tester, "new setting {{foo}} {# comment #} {% multiline %}\n", new_setting.Value)
}

func TestUpdateSetting_FileWithJinja(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Add new setting
	setting := model.NewSetting("myapp.foo__txt")
	setting.Value = "new setting {{foo}} {# comment #} {% multiline %}"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)

	new_setting := findSetting(settings, "myapp.foo__txt", "")
	assert.Equal(tester, "new setting {{foo}} {# comment #} {% multiline %}", new_setting.Value)
}

func TestUpdateSetting_AddGlobal(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Add new setting
	setting := model.NewSetting("myapp.setting")
	setting.Value = "new setting"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT+1, len(settings))

	new_setting := findSetting(settings, "myapp.setting", "")
	assert.Equal(tester, "new setting", new_setting.Value)
	assert.Equal(tester, "", new_setting.NodeId)
	assert.Equal(tester, false, new_setting.Global)
	assert.Equal(tester, false, new_setting.Node)
}

func TestUpdateSetting_AddToNode(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Add new setting
	setting := model.NewSetting("myapp.setting")
	setting.Value = "new setting"
	setting.NodeId = "normal_import"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure there's an additional setting listed
	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT+1, len(settings))

	new_setting := findSetting(settings, "myapp.setting", "normal_import")
	assert.Equal(tester, "new setting", new_setting.Value)
	assert.Equal(tester, "normal_import", new_setting.NodeId)
	assert.Equal(tester, false, new_setting.Global)
	assert.Equal(tester, false, new_setting.Node)
}

// This isn't currently supported via the UI, but the API supports it.
func TestUpdateSetting_DeleteGlobal(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Delete setting
	setting := model.NewSetting("myapp.str")
	setting.NodeId = ""
	err := salt.UpdateSetting(ctx(), setting, true)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT-1, len(settings))
	delete_setting := findSetting(settings, "myapp.str", "")
	assert.Nil(tester, delete_setting)
}

func TestUpdateSetting_DeleteFromNode(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Delete setting
	setting := model.NewSetting("myapp.foo")
	setting.NodeId = "normal_import"
	err := salt.UpdateSetting(ctx(), setting, true)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT-1, len(settings))
	delete_setting := findSetting(settings, "myapp.foo", "normal_import")
	assert.Nil(tester, delete_setting)
}

func TestUpdateSetting_DeleteAdvanced(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Delete setting
	setting := model.NewSetting("myapp.advanced")
	err := salt.UpdateSetting(ctx(), setting, true)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT, len(settings))
	deleted_setting := findSetting(settings, "myapp.advanced", "")
	assert.Equal(tester, "", deleted_setting.Value)
}

func TestUpdateSetting_UpdateGlobal(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.str")
	setting.NodeId = ""
	setting.Value = "new value\n" // ensure value is trimmed of whitespace
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	assert.Equal(tester, TEST_SETTINGS_COUNT, len(settings))
	updated_setting := findSetting(settings, "myapp.str", "")
	assert.Equal(tester, "new value", updated_setting.Value)
	assert.Equal(tester, "", updated_setting.NodeId)
}

func TestUpdateSetting_UpdateForNode(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.foo")
	setting.NodeId = "normal_import"
	setting.Value = "new value"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.foo", "normal_import")
	assert.Equal(tester, "new value", updated_setting.Value)
	assert.Equal(tester, "normal_import", updated_setting.NodeId)
}

func TestUpdateSetting_UpdateAdvanced(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.advanced")
	setting.Value = "something: new"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.advanced", "")
	assert.Equal(tester, "something: new", updated_setting.Value)
	assert.Equal(tester, "", updated_setting.NodeId)
}

func TestUpdateSetting_UpdateFile(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.foo__txt")
	setting.File = true
	setting.Value = "something"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.foo__txt", "")
	assert.Equal(tester, "anything", updated_setting.Default)
	assert.Equal(tester, "something", updated_setting.Value)

	// Delete setting
	err = salt.UpdateSetting(ctx(), setting, true)
	assert.NoError(tester, err)

	settings, get_err = salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.foo__txt", "")
	assert.Equal(tester, "anything", updated_setting.Default)
	assert.Equal(tester, "anything", updated_setting.Value)
}

func TestUpdateSetting_UpdateAdvancedFailToParse(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.advanced")
	setting.Value = "[s new advanced"
	setting.Syntax = "yaml"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "ERROR_MALFORMED_YAML -> yaml: line 1: did not find expected ',' or ']'")
}

///// INT TYPE

func TestUpdateSetting_AlignIntType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.int")
	setting.Value = "44"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int", "")
	assert.Equal(tester, "44", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignIntType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.int")
	setting.Value = "not an int"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "strconv.ParseInt: parsing \"not an int\": invalid syntax")
}

func TestUpdateSetting_AlignIntListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_int")
	setting.Value = "44\n2\n1"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_int", "")
	assert.Equal(tester, "44\n2\n1\n", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignIntListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_int")
	setting.Value = "1\n2\ninvalid"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseInt: parsing "invalid": invalid syntax`)
}

func TestUpdateSetting_AlignEmptyListIntType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Prime the empty list setting with int
	setting := model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "123\n456"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more ints
	setting = model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "123\n456\n23"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_int", "")
	assert.Equal(tester, "123\n456\n23\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_int")
	setting.Value = "cannot set string on int list"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseInt: parsing "cannot set string on int list": invalid syntax`)
}

func TestUpdateSetting_ForceIntType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.int_nodefault")
	setting.Value = "44"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int_nodefault", "")
	assert.Equal(tester, "44", updated_setting.Value)
}

func TestUpdateSetting_ForceListIntType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.int_list_nodefault")
	setting.Value = "44\n55"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.int_list_nodefault", "")
	assert.Equal(tester, "44\n55\n", updated_setting.Value)
}

///// FLOAT TYPE

func TestUpdateSetting_AlignFloatType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.float")
	setting.Value = "44.2"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.float", "")
	assert.Equal(tester, "44.2", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignFloatType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.float")
	setting.Value = "not a float"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "strconv.ParseFloat: parsing \"not a float\": invalid syntax")
}

func TestUpdateSetting_AlignFloatListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_float")
	setting.Value = "44.3\n2.1\n1.2"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_float", "")
	assert.Equal(tester, "44.3\n2.1\n1.2\n", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignFloatListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_float")
	setting.Value = "1.2\nnope"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseFloat: parsing "nope": invalid syntax`)
}

func TestUpdateSetting_AlignEmptyListFloatType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Prime the empty list setting with float
	setting := model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "1.23\n4.56"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more floats
	setting = model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "1.23\n4.56\n2.3"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_float", "")
	assert.Equal(tester, "1.23\n4.56\n2.3\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_float")
	setting.Value = "cannot set string on float list"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseFloat: parsing "cannot set string on float list": invalid syntax`)
}

// BOOL TYPE

func TestUpdateSetting_AlignBoolType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.bool")
	setting.Value = "false"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.bool", "")
	assert.Equal(tester, "false", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignBoolType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.bool")
	setting.Value = "not a bool"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, "strconv.ParseBool: parsing \"not a bool\": invalid syntax")
}

func TestUpdateSetting_AlignBoolListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_bool")
	setting.Value = "true\nfalse\ntrue"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_bool", "")
	assert.Equal(tester, "true\nfalse\ntrue\n", updated_setting.Value)
}

func TestUpdateSetting_FailToAlignBoolListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_bool")
	setting.Value = "true\nfalse\nhi"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseBool: parsing "hi": invalid syntax`)
}

func TestUpdateSetting_AlignEmptyListBoolType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Prime the empty list setting with bools
	setting := model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "true\nfalse"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	setting = model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "true\ntrue\nfalse"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_bool", "")
	assert.Equal(tester, "true\ntrue\nfalse\n", updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_bool")
	setting.Value = "cannot set string on bool list"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `strconv.ParseBool: parsing "cannot set string on bool list": invalid syntax`)
}

// List of Lists TYPE

func TestUpdateSetting_AlignListListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	expected := "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]\n[\"item5\",\"item6\"]\n"
	setting := model.NewSetting("myapp.lists.list_list_str")
	setting.Value = expected
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_list_str", "")
	assert.Equal(tester, expected, updated_setting.Value)
}

func TestUpdateSetting_FailToAlignListListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting (can't change list of lists to list of bools)
	setting := model.NewSetting("myapp.lists.list_list_str")
	setting.Value = "true\nfalse"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `json: cannot unmarshal bool into Go value of type []interface {}`)
}

func TestUpdateSetting_AlignEmptyListListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Prime the empty list setting with list of strings
	setting := model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	expected := "[\"item1\",\"item2\"]\n[\"item3\",\"item3\"]\n[\"item5\",\"item6\"]\n"
	setting = model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = expected
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_list_str", "")
	assert.Equal(tester, expected, updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_list_str")
	setting.Value = "cannot set list of strings\non list of lists"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `invalid character 'c' looking for beginning of value`)
}

// List of Maps TYPE

func TestUpdateSetting_AlignMapListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	expected := "{\"key1\":\"value1\",\"key2\":\"value2\"}\n{\"key1\":\"value3\",\"key2\":\"value4\"}\n{\"key1\":\"value5\",\"key2\":\"value6\"}\n"
	setting := model.NewSetting("myapp.lists.list_map_str")
	setting.Value = expected
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_map_str", "")
	assert.Equal(tester, expected, updated_setting.Value)
}

func TestUpdateSetting_FailToAlignMapListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting (can't change list of maps to list of bools)
	setting := model.NewSetting("myapp.lists.list_map_str")
	setting.Value = "true\nfalse"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `json: cannot unmarshal bool into Go value of type map[string]interface {}`)
}

func TestUpdateSetting_AlignEmptyListMapType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Prime the empty list setting with list of maps
	setting := model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = "{\"key1\":\"value1\",\"key2\":\"value2\"}"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// Ensure we can update it with more bools
	expected := "{\"key1\":\"value1\",\"key2\":\"value2\"}\n{\"key1\":\"value3\",\"key2\":\"value4\"}\n"
	setting = model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = expected
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_map_str", "")
	assert.Equal(tester, expected, updated_setting.Value)

	// Now try to put the wrong type in it
	setting = model.NewSetting("myapp.empty_lists.list_map_str")
	setting.Value = "cannot set list of strings\non list of maps"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.EqualError(tester, err, `invalid character 'c' looking for beginning of value`)
}

// STRING TYPE

func TestUpdateSetting_AlignNonStringType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.str")
	setting.Value = "123"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.str", "")
	assert.Equal(tester, "123", updated_setting.Value)
}

func TestUpdateSetting_AlignNonStringListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// Update setting
	setting := model.NewSetting("myapp.lists.list_str")
	setting.Value = "123\n456"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.lists.list_str", "")
	assert.Equal(tester, "123\n456\n", updated_setting.Value)
}

func TestUpdateSetting_AlignBlankStringListType(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// default should be an empty list
	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting := findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "", updated_setting.Value)

	// Update empty setting with non-blank value
	setting := model.NewSetting("myapp.empty_lists.list_str")
	setting.Value = "foo"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// should now contain non-blank value
	settings, get_err = salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "foo\n", updated_setting.Value)

	// Update empty setting with empty lines value
	setting = model.NewSetting("myapp.empty_lists.list_str")
	setting.Value = "\n"
	err = salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	// should be an empty list again
	settings, get_err = salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated_setting = findSetting(settings, "myapp.empty_lists.list_str", "")
	assert.Equal(tester, "", updated_setting.Value)
}

func TestRelPathFromId(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	assert.Equal(tester, "foo/bar/test.md", salt.relPathFromId("foo.bar.test__md"))
	assert.Equal(tester, "____/____/____/etc/passwd", salt.relPathFromId("____.____.____.etc.passwd"))
	assert.Equal(tester, "____./____./____./etc/passwd", salt.relPathFromId("______.______.______.etc.passwd"))
}

func TestUpdateSettingWithAnnotation(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	setting := model.NewSetting("myapp.some_file__txt")
	annotations := make(map[string]interface{})
	annotations["multiline"] = true
	annotations["sensitive"] = true
	annotations["global"] = true
	annotations["node"] = true
	annotations["file"] = true
	annotations["advanced"] = true
	annotations["readonly"] = true
	annotations["readonlyUi"] = true
	annotations["description"] = "My Desc"
	annotations["title"] = "My Title"
	annotations["regex"] = "My Regex"
	annotations["regexFailureMessage"] = "My Failure Message"
	annotations["helpLink"] = "My help link"
	annotations["syntax"] = "yaml"
	annotations["duplicates"] = true
	annotations["jinjaEscaped"] = true
	annotations["uiElementsDeleteMessage"] = "hi"

	assert.False(tester, setting.Multiline)
	salt.updateSettingWithAnnotation(setting, annotations)
	assert.True(tester, setting.Multiline)
	assert.True(tester, setting.Sensitive)
	assert.True(tester, setting.Global)
	assert.True(tester, setting.Node)
	assert.True(tester, setting.File)
	assert.True(tester, setting.Advanced)
	assert.True(tester, setting.Readonly)
	assert.True(tester, setting.ReadonlyUi)
	assert.Equal(tester, "My Desc", setting.Description)
	assert.Equal(tester, "My Title", setting.Title)
	assert.Equal(tester, "My Regex", setting.Regex)
	assert.Equal(tester, "My Failure Message", setting.RegexFailureMessage)
	assert.Equal(tester, "My help link", setting.HelpLink)
	assert.True(tester, setting.DefaultAvailable)
	assert.Equal(tester, "some default", setting.Default)
	assert.Equal(tester, "some local", setting.Value)
	assert.Equal(tester, "yaml", setting.Syntax)
	assert.True(tester, setting.Duplicates)
	assert.True(tester, setting.JinjaEscaped)
	assert.Equal(tester, "hi", setting.UiElementsDeleteMessage)
}

func TestManageUser_AddUser(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	roles := make([]string, 0, 0)
	roles = append(roles, "analyst")
	user := &model.User{
		Email:     "user1@somewhere.invalid",
		Password:  "dontlook!",
		FirstName: "My First",
		LastName:  "My Last",
		Note:      "My Note",
		Roles:     roles,
	}
	err := salt.AddUser(ctx(), user)
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","firstName":"My First","lastName":"My Last","note":"My Note","operation":"add","password":"dontlook!","role":"analyst"}`, request)
}

func TestManageUser_EnableUser(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.EnableUser(ctx(), "user-id-1")
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"enable"}`, request)
}

func TestManageUser_DisableUser(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.DisableUser(ctx(), "user-id-1")
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"disable"}`, request)
}

func TestManageUser_DeleteUser(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.DeleteUser(ctx(), "user-id-1")
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"delete"}`, request)
}

func TestManageUser_UpdateProfile(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	roles := make([]string, 0, 0)
	roles = append(roles, "analyst")
	user := &model.User{
		Id:        "user-id-1",
		FirstName: "My First",
		LastName:  "My Last",
		Note:      "My Note",
	}
	err := salt.UpdateProfile(ctx(), user)
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","firstName":"My First","lastName":"My Last","note":"My Note","operation":"profile"}`, request)
}

func TestManageUser_UpdatePassword(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.ResetPassword(ctx(), "user-id-1", "newone#")
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"password","password":"newone#"}`, request)
}

func TestManageUser_AddRole(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.AddRole(ctx(), "user-id-1", "broker", false)
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"addrole","role":"broker"}`, request)
}

func TestManageUser_DeleteRole(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.DeleteRole(ctx(), "user-id-1", "broker")
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","email":"user1@somewhere.invalid","operation":"delrole","role":"broker"}`, request)
}

func TestSyncUsers(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	err := salt.SyncUsers(ctx())
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-user")
	assert.Equal(tester, `{"command":"manage-user","command_id":"ctx_manage-user","operation":"sync"}`, request)
}

func TestSyncSettings(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-salt", "true.resp")
	err := salt.SyncSettings(ctx())
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-salt")
	assert.JSONEq(tester, `{"command":"manage-salt","command_id":"ctx_manage-salt","operation":"highstate","minion":"*"}`, request)
}

func TestSyncModule(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-salt", "true.resp")
	err := salt.SyncModule(ctx(), "soc", false)
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-salt")
	assert.JSONEq(tester, `{"command":"manage-salt","command_id":"ctx_manage-salt","operation":"state","state":"soc"}`, request)
}

func TestSyncModule_Async(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-salt", "true.resp")
	err := salt.SyncModule(ctx(), "myapp", true)
	assert.NoError(tester, err)

	request := ReadRequest(tester, "ctx_manage-salt")
	assert.JSONEq(tester, `{"command":"manage-salt","command_id":"ctx_manage-salt","async":"true","operation":"state","state":"myapp"}`, request)
}

func TestSyncModule_Failure(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-salt", "false.resp")
	err := salt.SyncModule(ctx(), "soc", false)
	assert.EqualError(tester, err, "ERROR_SALT_STATE")

	request := ReadRequest(tester, "ctx_manage-salt")
	assert.JSONEq(tester, `{"command":"manage-salt","command_id":"ctx_manage-salt","operation":"state","state":"soc"}`, request)
}

func TestSyncModule_ErrorMessage(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-salt", "error.resp")
	err := salt.SyncModule(ctx(), "soc", false)
	assert.EqualError(tester, err, "ERROR_TEST_ERROR")

	request := ReadRequest(tester, "ctx_manage-salt")
	assert.JSONEq(tester, `{"command":"manage-salt","command_id":"ctx_manage-salt","operation":"state","state":"soc"}`, request)
}

func TestSyncModuleUnauthorized(tester *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	salt := NewSaltstore(srv)
	err := salt.SyncModule(ctx(), "soc", false)
	assert.ErrorContains(tester, err, "Subject 'fake-subject' is not authorized to perform operation 'write' on target 'config'")
}

func TestForceType(tester *testing.T) {
	store := NewTestSalt()

	testCases := []struct {
		value       string
		forcedType  string
		expected    interface{}
		errorString string
	}{
		{value: "44", forcedType: "int", expected: int64(44), errorString: ""},
		{value: "44", forcedType: "[]int", expected: []int64{44}, errorString: ""},
		{value: "44\n55", forcedType: "[]int", expected: []int64{44, 55}, errorString: ""},
		{value: "blah", forcedType: "[]int", expected: []int64{}, errorString: "invalid syntax"},
		{value: "44.4", forcedType: "float", expected: float64(44.4), errorString: ""},
		{value: "44.3", forcedType: "[]float", expected: []float64{44.3}, errorString: ""},
		{value: "44.2\n55", forcedType: "[]float", expected: []float64{44.2, 55}, errorString: ""},
		{value: "blah", forcedType: "[]float", expected: []float64{}, errorString: "invalid syntax"},
		{value: "true", forcedType: "bool", expected: true, errorString: ""},
		{value: "true", forcedType: "[]bool", expected: []bool{true}, errorString: ""},
		{value: "true\nfalse", forcedType: "[]bool", expected: []bool{true, false}, errorString: ""},
		{value: "blah", forcedType: "[]bool", expected: []bool{}, errorString: "invalid syntax"},
		{value: "hello", forcedType: "string", expected: "hello", errorString: ""},
		{value: "", forcedType: "[]string", expected: []string{}, errorString: ""},
		{value: "hello\nthere", forcedType: "[]string", expected: []string{"hello", "there"}, errorString: ""},
		{value: "blah", forcedType: "[]string", expected: []string{"blah"}, errorString: ""},
		{value: "[\"hello\"]", forcedType: "[][]", expected: [][]interface{}([][]interface{}{[]interface{}{"hello"}}), errorString: ""},
		{value: "[\"hello\"]\n[\"there\"]", forcedType: "[][]", expected: [][]interface{}([][]interface{}{[]interface{}{"hello"}, []interface{}{"there"}}), errorString: ""},
		{value: "{\"name\":\"hello\"}", forcedType: "[]{}", expected: []map[string]interface{}([]map[string]interface{}{map[string]interface{}{"name": "hello"}}), errorString: ""},
		{value: "{\"name\":\"hello\"}\n{\"name\":\"there\"}", forcedType: "[]{}", expected: []map[string]interface{}([]map[string]interface{}{map[string]interface{}{"name": "hello"}, map[string]interface{}{"name": "there"}}), errorString: ""},
	}

	for _, testCase := range testCases {
		actual, err := store.forceType(testCase.value, testCase.forcedType)
		if testCase.errorString != "" {
			assert.ErrorContains(tester, err, testCase.errorString)
		} else {
			assert.Equal(tester, testCase.expected, actual)
		}
	}
}

func TestSendFile(t *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(t, "ctx_send-file", "true.resp")
	err := salt.SendFile(ctx(), "manager_standalone", "/nsm/soc/uploads/processing/manager_standalone", "/nsm/soc/uploads/", true)
	assert.NoError(t, err)

	request := ReadRequest(t, "ctx_send-file")
	assert.JSONEq(t, `{"command":"send-file","command_id":"ctx_send-file","node":"manager_standalone","from":"/nsm/soc/uploads/processing/manager_standalone","to":"/nsm/soc/uploads/","cleanup":"true"}`, request)
}

func TestImportFile(t *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(t, "ctx_import-file", "url.resp")
	path, err := salt.Import(ctx(), "manager_standalone", "/nsm/soc/uploads/file.pcap", "pcap")
	assert.NoError(t, err)
	assert.NotNil(t, path)
	assert.Contains(t, *path, `#/dashboards`)

	request := ReadRequest(t, "ctx_import-file")
	assert.JSONEq(t, `{"command":"import-file","command_id":"ctx_import-file","node":"manager_standalone","file":"/nsm/soc/uploads/file.pcap","importer":"pcap"}`, request)
}

func TestUpdateSetting_ForceMapListFieldTypes_StringInput(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// UI sends int and bool fields as strings inside the JSON objects
	setting := model.NewSetting("myapp.ui_map_typed")
	setting.Value = "{\"enabled\":\"true\",\"name\":\"alpha\",\"port\":\"8080\"}\n{\"enabled\":\"false\",\"name\":\"beta\",\"port\":\"9090\"}"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated := findSetting(settings, "myapp.ui_map_typed", "")
	// After coercion, port must be a JSON number and enabled a JSON bool (not quoted strings)
	assert.Equal(tester, "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}\n{\"enabled\":false,\"name\":\"beta\",\"port\":9090}\n", updated.Value)
}

func TestUpdateSetting_ForceMapListFieldTypes_NumericInput(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()

	// UI sends properly-typed JSON (numbers as numbers, bools as bools)
	setting := model.NewSetting("myapp.ui_map_typed")
	setting.Value = "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}"
	err := salt.UpdateSetting(ctx(), setting, false)
	assert.NoError(tester, err)

	settings, get_err := salt.GetSettings(ctx(), true)
	assert.NoError(tester, get_err)
	updated := findSetting(settings, "myapp.ui_map_typed", "")
	// float64(8080) from JSON parse must be coerced to int64 so YAML stores it as an integer
	assert.Equal(tester, "{\"enabled\":true,\"name\":\"alpha\",\"port\":8080}\n", updated.Value)
}

func TestReadSetting_UiElements(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSalt()
	settings, err := salt.GetSettings(ctx(), true)
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
	store := &Saltstore{}

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
		{name: "string to int", list: []map[string]any{{"port": "8080"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int"}}, checkField: "port", expected: int64(8080)},
		{name: "string to bool true", list: []map[string]any{{"enabled": "true"}}, uiElements: []model.UiElement{{Field: "enabled", ForcedType: "bool"}}, checkField: "enabled", expected: true},
		{name: "string to bool false", list: []map[string]any{{"enabled": "false"}}, uiElements: []model.UiElement{{Field: "enabled", ForcedType: "bool"}}, checkField: "enabled", expected: false},
		{name: "string to float", list: []map[string]any{{"ratio": "3.14"}}, uiElements: []model.UiElement{{Field: "ratio", ForcedType: "float"}}, checkField: "ratio", expected: float64(3.14)},
		{name: "string to string", list: []map[string]any{{"name": "alpha"}}, uiElements: []model.UiElement{{Field: "name", ForcedType: "string"}}, checkField: "name", expected: "alpha"},

		// string → list types
		{name: "string to []int", list: []map[string]any{{"ports": "80\n443\n8080"}}, uiElements: []model.UiElement{{Field: "ports", ForcedType: "[]int"}}, checkField: "ports", expected: []int64{80, 443, 8080}},
		{name: "string to []bool", list: []map[string]any{{"flags": "true\nfalse\ntrue"}}, uiElements: []model.UiElement{{Field: "flags", ForcedType: "[]bool"}}, checkField: "flags", expected: []bool{true, false, true}},
		{name: "string to []float", list: []map[string]any{{"ratios": "1.1\n2.2\n3.3"}}, uiElements: []model.UiElement{{Field: "ratios", ForcedType: "[]float"}}, checkField: "ratios", expected: []float64{1.1, 2.2, 3.3}},
		{name: "string to []string", list: []map[string]any{{"tags": "a\nb\nc"}}, uiElements: []model.UiElement{{Field: "tags", ForcedType: "[]string"}}, checkField: "tags", expected: []string{"a", "b", "c"}},

		// non-string input (float64/bool from JSON parse) round-tripped through interfaceToString
		{name: "float64 to int", list: []map[string]any{{"port": float64(8080)}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int"}}, checkField: "port", expected: int64(8080)},
		{name: "float64 to float", list: []map[string]any{{"ratio": float64(3.14)}}, uiElements: []model.UiElement{{Field: "ratio", ForcedType: "float"}}, checkField: "ratio", expected: float64(3.14)},
		{name: "bool to bool", list: []map[string]any{{"enabled": true}}, uiElements: []model.UiElement{{Field: "enabled", ForcedType: "bool"}}, checkField: "enabled", expected: true},

		// error handling
		{name: "invalid int not required uses zero value", list: []map[string]any{{"port": "abc"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int", Required: false}}, checkField: "port", expected: int64(0)},
		{name: "invalid int required returns error", list: []map[string]any{{"port": "abc"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int", Required: true}}, errContains: "port"},
		{name: "invalid bool required returns error", list: []map[string]any{{"enabled": "maybe"}}, uiElements: []model.UiElement{{Field: "enabled", ForcedType: "bool", Required: true}}, errContains: "enabled"},
		{name: "required empty value returns error", list: []map[string]any{{"port": ""}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int", Required: true}}, errContains: "port"},
		{name: "unsupported type not required uses zero value", list: []map[string]any{{"id": "some-uuid"}}, uiElements: []model.UiElement{{Field: "id", ForcedType: "uuid", Required: false}}, checkField: "id", expected: nil},
		{name: "unsupported type required returns error", list: []map[string]any{{"id": "some-uuid"}}, uiElements: []model.UiElement{{Field: "id", ForcedType: "uuid", Required: true}}, errContains: "id"},
		{name: "error in second object", list: []map[string]any{{"port": "8080"}, {"port": "abc"}}, uiElements: []model.UiElement{{Field: "port", ForcedType: "int", Required: true}}, errContains: "port"},
	}

	for _, tc := range testCases {
		tester.Run(tc.name, func(t *testing.T) {
			result, err := store.coerceMapListFieldTypes(tc.list, tc.uiElements)
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

func TestCoerceMapListFieldTypes_MultipleFields_AllStrings(t *testing.T) {
	store := &Saltstore{}
	list := []map[string]any{
		{"port": "8080", "enabled": "true", "name": "alpha"},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
		{Field: "name"}, // no ForcedType — should remain a string
	}
	result, err := store.coerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)
	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, "alpha", result[0]["name"])
}

func TestCoerceMapListFieldTypes_MultipleObjects_AllStrings(t *testing.T) {
	store := &Saltstore{}
	list := []map[string]any{
		{"port": "8080", "enabled": "true", "name": "alpha"},
		{"port": "9090", "enabled": "false", "name": "beta"},
		{"port": "443", "enabled": "true", "name": "gamma"},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
	}
	result, err := store.coerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)

	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, "alpha", result[0]["name"])

	assert.Equal(t, int64(9090), result[1]["port"])
	assert.Equal(t, false, result[1]["enabled"])
	assert.Equal(t, "beta", result[1]["name"])

	assert.Equal(t, int64(443), result[2]["port"])
	assert.Equal(t, true, result[2]["enabled"])
	assert.Equal(t, "gamma", result[2]["name"])
}

func TestCoerceMapListFieldTypes_AllScalarStringTypes(t *testing.T) {
	store := &Saltstore{}
	list := []map[string]any{
		{
			"port":    "8080",
			"enabled": "true",
			"ratio":   "2.718",
			"name":    "delta",
		},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
		{Field: "ratio", ForcedType: "float"},
		{Field: "name", ForcedType: "string"},
	}
	result, err := store.coerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)
	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, float64(2.718), result[0]["ratio"])
	assert.Equal(t, "delta", result[0]["name"])
}

func TestZeroForType(t *testing.T) {
	testCases := []struct {
		typ      string
		expected any
	}{
		{typ: "float", expected: float64(0)},
		{typ: "int", expected: int64(0)},
		{typ: "bool", expected: false},
		{typ: "string", expected: ""},
		{typ: "[]int", expected: []int64{}},
		{typ: "[]bool", expected: []bool{}},
		{typ: "[]float", expected: []float64{}},
		{typ: "[]string", expected: []string{}},
		{typ: "[][]", expected: [][]interface{}{}},
		{typ: "[]{}", expected: []map[string]interface{}{}},
		{typ: "unknown", expected: nil},
		{typ: "", expected: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.typ, func(t *testing.T) {
			assert.Equal(t, tc.expected, zeroForType(tc.typ))
		})
	}
}
