// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

const TMP_SALTSTACK_PATH = "/tmp/gotest-soc-saltstore"
const TMP_QUEUE_DIR = "/tmp/gotest-soc-salt-relay-queue"

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
	salt.Init(123, 123, TMP_QUEUE_DIR)
	return salt
}

func NewTestSaltRelayQueue(tester *testing.T, id string, mockedResponse string) *Saltstore {
	Cleanup()
	exec.Command("mkdir", "-p", TMP_SALTSTACK_PATH).Run()
	exec.Command("mkdir", "-p", TMP_QUEUE_DIR).Run()
	srv := server.NewFakeAuthorizedServer(nil)
	salt := NewSaltstore(srv)
	salt.Init(10, 10, TMP_QUEUE_DIR)

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
	salt.Init(123, 123, "salt/control")
	assert.Equal(tester, 123, salt.timeoutMs)
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
	salt.Init(123, 123, "/invalid/path")
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
	salt.Init(123, 123, "invalid/path")

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

func TestManageUser_AddUser(tester *testing.T) {
	defer Cleanup()
	salt := NewTestSaltRelayQueue(tester, "ctx_manage-user", "true.resp")
	roles := []string{"analyst"}
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
