// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type HydraClientstore struct {
	server *server.Server
	client *web.Client
}

type IntrospectedToken struct {
	Active            bool     `json:"active"`
	Audiences         []string `json:"aud"`
	ClientId          string   `json:"client_id"`
	Expiration        int64    `json:"exp"`
	Issued            int64    `json:"iat"`
	Issuer            string   `json:"issuer"`
	NotBefore         int64    `json:"nbf"`
	ObjuscatedSubject string   `json:"obfuscated_subject"`
	Scope             string   `json:"scope"`
	Subject           string   `json:"sub"`
	TokenType         string   `json:"token_type"`
	TokenUse          string   `json:"token_use"`
	Owner             string   `json:"username"`
}

func NewHydraClientstore(server *server.Server) *HydraClientstore {
	return &HydraClientstore{
		server: server,
	}
}

func (hydra *HydraClientstore) Init(url string) error {
	hydra.client = web.NewClient(url, true)
	return nil
}

func (hydra *HydraClientstore) fetchHydraClient(id string) (*HydraClient, error) {
	hydraClient := &HydraClient{}
	_, err := hydra.client.SendObject("GET", "/admin/clients/"+id, "", &hydraClient, false)
	return hydraClient, err
}

func (hydra *HydraClientstore) fetchClient(ctx context.Context, id string) (*model.Client, error) {
	log.WithFields(log.Fields{
		"apiClientId": id,
		"requestId":   ctx.Value(web.ContextKeyRequestId),
	}).Debug("Fetching API client by ID")

	hydraClient, err := hydra.fetchHydraClient(id)
	if err != nil {
		return nil, err
	}

	client := model.NewClient()

	hydraClient.copyToClient(client)
	if hydra.server.Rolestore != nil {
		_, client.Permissions = hydra.server.Rolestore.GetRolesForAuthId(ctx, client.Id)
	}
	return client, nil
}

func (hydra *HydraClientstore) GetClientByToken(ctx context.Context, token string) (*model.Client, error) {
	introspectedToken := IntrospectedToken{}
	resp, err := hydra.client.SendRequest("POST", "/admin/oauth2/introspect", "application/x-www-form-urlencoded", strings.NewReader("token="+token), false)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Error("Failed to instrospect token from Hydra")
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		bytes, _ := io.ReadAll(resp.Body)
		body := string(bytes)
		log.WithFields(log.Fields{
			"body": body,
		}).Debug("Response")
		err = errors.New("Token introspection failed (" + strconv.Itoa(resp.StatusCode) + "): " + resp.Status)
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&introspectedToken)
	if err != nil {
		return nil, err
	}

	if !introspectedToken.Active {
		log.WithError(err).WithFields(log.Fields{
			"requestId":         ctx.Value(web.ContextKeyRequestId),
			"introspectedToken": introspectedToken,
		}).Warn("Token is not active")
		return nil, errors.New("ERROR_INACTIVE_TOKEN")
	}
	return hydra.fetchClient(ctx, introspectedToken.ClientId)
}

func (hydra *HydraClientstore) GetClientById(ctx context.Context, id string) (*model.Client, error) {
	if err := hydra.server.CheckAuthorized(ctx, "read", "clients"); err != nil {
		return nil, err
	}

	return hydra.fetchClient(ctx, id)
}

func (hydra *HydraClientstore) GetClients(ctx context.Context) ([]*model.Client, error) {
	if err := hydra.server.CheckAuthorized(ctx, "read", "clients"); err != nil {
		log.WithFields(log.Fields{
			"requestId":   ctx.Value(web.ContextKeyRequestId),
			"requestorId": ctx.Value(web.ContextKeyRequestorId),
		}).Debug("Requestor does not have read access to clients")
		return nil, nil
	}

	clients := make([]*model.Client, 0)

	if _, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		hydraClients := make([]*HydraClient, 0)
		_, err := hydra.client.SendObject("GET", "/admin/clients", "", &hydraClients, false)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).Error("Failed to fetch API Clients from Hydra")
			return nil, err
		}

		// Convert the hydra clients to SOC clients
		for _, hydraClient := range hydraClients {
			client := model.NewClient()

			hydraClient.copyToClient(client)
			if hydra.server.Rolestore != nil {
				_, client.Permissions = hydra.server.Rolestore.GetRolesForAuthId(ctx, client.Id)
			}
			clients = append(clients, client)
		}
	}

	return clients, nil
}

func (hydra *HydraClientstore) GetClient(ctx context.Context, id string) (*model.Client, error) {
	var err error
	var client *model.Client

	clients, err := hydra.GetClients(ctx)
	if err == nil {
		for _, testClient := range clients {
			if testClient.Id == id {
				client = testClient
				break
			}
		}
	}
	return client, err
}
