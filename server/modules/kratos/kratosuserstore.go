// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
	"context"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type KratosUserstore struct {
	server *server.Server
	client *web.Client
}

func NewKratosUserstore(server *server.Server) *KratosUserstore {
	return &KratosUserstore{
		server: server,
	}
}

func (kratos *KratosUserstore) Init(url string) error {
	kratos.client = web.NewClient(url, true)
	return nil
}

func (kratos *KratosUserstore) fetchUser(id string) (*KratosUser, error) {
	kratosUser := &KratosUser{}
	_, err := kratos.client.SendObject("GET", "/identities/"+id, "", &kratosUser, false)
	return kratosUser, err
}

func (kratos *KratosUserstore) GetUserById(ctx context.Context, id string) (*model.User, error) {
	var err error
	var user *model.User

	if err = kratos.server.CheckAuthorized(ctx, "read", "users"); err == nil {
		log.WithFields(log.Fields{
			"userId":    id,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Debug("Fetching user by ID")

		var kratosUser KratosUser
		_, err = kratos.client.SendObject("GET", "/identities/"+id, "", &kratosUser, false)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"userId":    id,
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).Error("Failed to fetch user from Kratos")
			return nil, err
		}

		user = model.NewUser()

		// If the requesting user has write access to all users, then also fetch the detailed
		// data about each user.
		if err := kratos.server.CheckAuthorized(ctx, "write", "users"); err == nil {
			kratos.populateUserDetails(ctx, &kratosUser)
		}

		kratosUser.copyToUser(user)
		if kratos.server.Rolestore != nil {
			kratos.server.Rolestore.PopulateUserRoles(ctx, user)
		}
	}

	return user, err
}

func (kratos *KratosUserstore) GetUsers(ctx context.Context) ([]*model.User, error) {
	users := make([]*model.User, 0, 0)
	myUserOnly := make([]*model.User, 0, 0)

	if requestorId, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		kratosUsers := make([]*KratosUser, 0, 0)
		_, err := kratos.client.SendObject("GET", "/identities", "", &kratosUsers, false)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).Error("Failed to fetch users from Kratos")
			return nil, err
		}

		// Convert the kratos users to SOC users
		enabledCount := 0
		for _, kratosUser := range kratosUsers {
			user := model.NewUser()

			// If the requesting user has write access to all users, then also fetch the detailed
			// data about each user.
			if err := kratos.server.CheckAuthorized(ctx, "write", "users"); err == nil {
				kratos.populateUserDetails(ctx, kratosUser)
			}

			kratosUser.copyToUser(user)
			if kratos.server.Rolestore != nil {
				kratos.server.Rolestore.PopulateUserRoles(ctx, user)
			}
			users = append(users, user)
			if user.Status != "locked" {
				enabledCount = enabledCount + 1
			}

			if user.Id == requestorId {
				myUserOnly = append(myUserOnly, user)
			}
		}

		licensing.ValidateUserCount(enabledCount)
	}

	if err := kratos.server.CheckAuthorized(ctx, "read", "users"); err != nil {
		// User does not have access to read all users, return only that user
		return myUserOnly, nil
	}

	return users, nil
}

func (kratos *KratosUserstore) populateUserDetails(ctx context.Context, kratosUser *KratosUser) {
	log.Info("Populating user details for " + kratosUser.Id)
	_, err := kratos.client.SendObject("GET", "/identities/"+kratosUser.Id, "", &kratosUser, false)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Error("Failed to fetch user details from Kratos")
	}
}

func (kratos *KratosUserstore) GetUser(ctx context.Context, id string) (*model.User, error) {
	var err error
	var user *model.User

	users, err := kratos.GetUsers(ctx)
	if err == nil {
		for _, testUser := range users {
			if testUser.Id == id {
				user = testUser
				break
			}
		}
	}
	return user, err
}
