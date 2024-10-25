// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"context"
	"errors"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

func (store *Saltstore) AddClient(ctx context.Context, client *model.Client) (string, error) {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return "", err
	}

	args := make(map[string]string)
	args["command"] = "manage-user"
	args["operation"] = "add-client"
	if len(client.Roles) > 0 {
		args["role"] = client.Roles[0]
	}
	args["name"] = client.Name
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	store.server.Rolestore.Reload()

	return output, err
}

func (store *Saltstore) DeleteClient(ctx context.Context, id string) error {
	if err := store.server.CheckAuthorized(ctx, "delete", "clients"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "delete"
	args["id"] = id
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	return err
}

func (store *Saltstore) UpdateClient(ctx context.Context, client *model.Client) error {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "update"
	args["id"] = client.Id
	args["name"] = client.Name
	args["note"] = client.Note
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	return err
}

func (store *Saltstore) GenerateSecret(ctx context.Context, id string) (string, error) {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return "", err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "generate-secret"
	args["id"] = id
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	return output, err
}

func (store *Saltstore) AddClientRole(ctx context.Context, id string, role string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "addrole"
	args["id"] = id
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) DeleteClientRole(ctx context.Context, id string, role string) error {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "delrole"
	args["id"] = id
	args["role"] = role
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	store.server.Rolestore.Reload()

	return err
}

func (store *Saltstore) SyncClients(ctx context.Context) error {
	if err := store.server.CheckAuthorized(ctx, "write", "clients"); err != nil {
		return err
	}

	args := make(map[string]string)
	args["command"] = "manage-client"
	args["operation"] = "sync"
	output, err := store.execCommand(ctx, args)
	if err == nil {
		if output == "false" {
			err = errors.New("ERROR_SALT_MANAGE_CLIENT")
		}
	}

	return err
}
