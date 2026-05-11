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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/salt/options"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

type Saltstore struct {
	server             *server.Server
	client             *web.Client
	timeoutMs          int
	longRelayTimeoutMs int
	queueDir           string
}

func NewSaltstore(server *server.Server) *Saltstore {
	return &Saltstore{
		server: server,
	}
}

func (store *Saltstore) Init(timeoutMs int, longRelayTimeoutMs int, queueDir string) error {
	store.timeoutMs = timeoutMs
	store.longRelayTimeoutMs = longRelayTimeoutMs
	store.queueDir = queueDir

	return nil
}

func (store *Saltstore) execCommand(ctx context.Context, args map[string]string) (string, error) {
	logger := log.FromContext(ctx)

	reqId := ctx.Value(web.ContextKeyRequestId).(string)
	cmd := args["command"]
	id := reqId + "_" + cmd
	args["command_id"] = id

	filename := filepath.Join(store.queueDir, id)
	logger.WithFields(log.Fields{
		"filename": filename,
	}).Info("Executing command via salt relay")

	err := json.WriteJsonFile(filename, args)
	if err != nil {
		logger.WithFields(log.Fields{
			"filename": filename,
		}).WithError(err).Error("Unable to write to file")

		return "", err
	}

	responseFilename := filename + ".response"
	logger.WithFields(log.Fields{
		"responseFilename": responseFilename,
		"timeoutMs":        store.timeoutMs,
	}).Info("Waiting for response")

	timeoutMs := store.timeoutMs
	optTimeoutMs := options.GetTimeoutMs(ctx)

	if optTimeoutMs > timeoutMs {
		timeoutMs = optTimeoutMs
	}

	var response string
	expiration := time.Duration(timeoutMs) * time.Millisecond
	for timeoutTime := time.Now().Add(expiration); time.Now().Before(timeoutTime); {
		if _, err = os.Stat(responseFilename); err == nil {
			var data []byte
			data, err = os.ReadFile(responseFilename)
			if err != nil {
				logger.WithFields(log.Fields{
					"filename": responseFilename,
				}).WithError(err).Error("Failed to read file")
			} else {
				response = strings.TrimSpace(string(data))
				os.Remove(responseFilename)
				break
			}
		}

		// Assume very short timeouts are used for testing, where the response is already mocked
		if store.timeoutMs > 10 {
			time.Sleep(1000 * time.Millisecond)
		}
	}

	if response == "" {
		return "", errors.New("ERROR_SALT_RELAY_DOWN")
	}

	logger.WithFields(log.Fields{
		"filename": responseFilename,
		"response": response,
	}).Debug("Finished reading response")

	return response, err
}

type ListResponse struct {
	Accepted   map[string]string `json:"minions"`
	Unaccepted map[string]string `json:"minions_pre"`
	Rejected   map[string]string `json:"minions_rejected"`
	Denied     map[string]string `json:"minions_denied"`
}

func getMembersFromJson(err error, output []byte) ([]*model.GridMember, error) {
	var members []*model.GridMember

	if err == nil {
		response := &ListResponse{}
		err = json.LoadJson(output, response)
		if err == nil {
			members = make([]*model.GridMember, 0)
			for id, fingerprint := range response.Accepted {
				members = append(members, model.NewGridMember(id, model.GridMemberAccepted, fingerprint))
			}
			for id, fingerprint := range response.Unaccepted {
				members = append(members, model.NewGridMember(id, model.GridMemberUnaccepted, fingerprint))
			}
			for id, fingerprint := range response.Rejected {
				members = append(members, model.NewGridMember(id, model.GridMemberRejected, fingerprint))
			}
			for id, fingerprint := range response.Denied {
				members = append(members, model.NewGridMember(id, model.GridMemberDenied, fingerprint))
			}
		}
	}

	return members, err
}

func (store *Saltstore) GetMembers(ctx context.Context) ([]*model.GridMember, error) {
	if err := store.server.CheckAuthorized(ctx, "read", "grid"); err != nil {
		return nil, err
	}

	var members []*model.GridMember
	args := make(map[string]string)
	args["command"] = "list-minions"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_MEMBER")
		}

		members, err = getMembersFromJson(err, []byte(output))
	}

	return members, err
}

func (store *Saltstore) ManageMember(ctx context.Context, operation string, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "grid"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-minion"
	args["operation"] = operation
	args["id"] = id
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_MEMBER")
		}
	}

	return err
}

func (store *Saltstore) SendFile(ctx context.Context, node string, from string, to string, cleanup bool) error {
	// TODO: re-evaluate necessary permissions when this feature is used for more
	// than importing pcap/evtx.
	if err := store.server.CheckAuthorized(ctx, "write", "events"); err != nil {
		return err
	}

	args := map[string]string{
		"command": "send-file",
		"node":    node,
		"from":    from,
		"to":      to,
		"cleanup": strconv.FormatBool(cleanup),
	}

	ctxTimeout := options.WithTimeoutMs(ctx, store.longRelayTimeoutMs)

	output, err := store.execCommand(ctxTimeout, args)
	if err == nil && output == "false" {
		err = errors.New("ERROR_SALT_SEND_FILE")
	}

	return err
}

func (store *Saltstore) Import(ctx context.Context, node string, file string, importer string) (*string, error) {
	if err := store.server.CheckAuthorized(ctx, "write", "events"); err != nil {
		return nil, err
	}

	args := map[string]string{
		"command":  "import-file",
		"node":     node,
		"file":     file,
		"importer": importer,
	}

	ctxTimeout := options.WithTimeoutMs(ctx, store.longRelayTimeoutMs)

	output, err := store.execCommand(ctxTimeout, args)
	if err == nil && output == "false" {
		err = errors.New("ERROR_SALT_IMPORT")
		return nil, err
	}

	return &output, err
}

func (store *Saltstore) lookupEmailFromId(ctx context.Context, id string) string {
	user, _ := store.server.Userstore.GetUserById(ctx, id)
	if user != nil && user.Id == id {
		return user.Email
	}
	return ""
}

func (store *Saltstore) AddUser(ctx context.Context, user *model.User) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "add"
	args["email"] = user.Email
	if len(user.Roles) > 0 {
		args["role"] = user.Roles[0]
	}
	args["firstName"] = user.FirstName
	args["lastName"] = user.LastName
	args["note"] = user.Note
	args["password"] = user.Password
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) DeleteUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "delete", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "delete"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) UpdateProfile(ctx context.Context, user *model.User) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "profile"
	args["email"] = store.lookupEmailFromId(ctx, user.Id)
	args["firstName"] = user.FirstName
	args["lastName"] = user.LastName
	args["note"] = user.Note
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) ResetPassword(ctx context.Context, id string, password string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "password"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["password"] = password
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) EnableUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "enable"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) DisableUser(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "disable"
	args["email"] = store.lookupEmailFromId(ctx, id)
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) AddRole(ctx context.Context, id string, role string, bypassAuthCheck bool) error {
	if bypassAuthCheck {
		logger := log.FromContext(ctx)
		logger.Debug("Adding role to user without authorization check")
	} else {
		if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
			return err
		}
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "addrole"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) DeleteRole(ctx context.Context, id string, role string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "delrole"
	args["email"] = store.lookupEmailFromId(ctx, id)
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) SyncUsers(ctx context.Context) error {
	if err := store.server.CheckAuthorized(ctx, "write", "users"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "sync"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_USER")
		}
	}

	return err
}

func (store *Saltstore) SyncSettings(ctx context.Context) error {
	if err := store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-salt"
	args["operation"] = "highstate"
	args["minion"] = "*"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_STATE")
		}
	}

	return err
}

func (store *Saltstore) SyncModule(ctx context.Context, module string, force bool) error {
	if err := store.server.CheckAuthorized(ctx, "write", "config"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-salt"
	args["operation"] = "state"
	args["state"] = module
	if force {
		args["async"] = strconv.FormatBool(force)
	}
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if matched, _ := regexp.MatchString("^ERROR_[A-Z_]+$", output); matched {
			err = errors.New(output)
		} else if output == "false" {
			err = errors.New("ERROR_SALT_STATE")
		}
	}

	return err
}
