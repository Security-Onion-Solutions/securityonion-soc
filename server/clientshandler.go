// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

var clientIdVerifier = regexp.MustCompile(`^[A-Za-z0-9_]{6,55}$`)
var permissionVerifier = regexp.MustCompile(`^[a-z]+/[a-z_]+$`)

type ClientsHandler struct {
	server *Server
}

func RegisterClientsRoutes(srv *Server, r chi.Router, prefix string) {
	h := &ClientsHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getClients)

		r.Post("/", h.postClient)
		r.Post("/{id}/permission/{resource}/{privilege}", h.postAddPermission)

		r.Put("/{id}", h.putClient)
		r.Put("/{id}/secret", h.putGeneratedSecret)

		r.Delete("/{id}", h.deleteClient)
		r.Delete("/{id}/permission/{resource}/{privilege}", h.deleteClientPermission)
	})
}

// @Summary      Get API Clients
// @Description  Returns all existing API clients.
// @Tags         Clients
// @Security     bearer[clients/read]
// @Produce      json
// @Success      200  {array}   model.Client		 "The array of Client objects"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/clients/ [get]
func (h *ClientsHandler) getClients(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	clients, err := h.server.Clientstore.GetClients(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, clients)
}

// @Summary      Create API Clients
// @Description  Creates a new API client with the given Client object
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        request body model.Client true "The Client object to create. Only the 'name' and 'note' properties are used."
// @Produce      json
// @Success      200  {object}  model.Client		 "The new Client object with its newly assigned ID and secret included"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/clients/ [post]
func (h *ClientsHandler) postClient(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	client := model.NewClient()

	err := web.ReadJson(r, client)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = client.Verify()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	var new_client *model.Client
	new_client, err = h.server.AdminClientstore.AddClient(ctx, client)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, new_client)
}

// @Summary      Assign Client Permission
// @Description  Assigns a permission to an existing API client.
// @Description  A new access token is not required. Future API calls will immediately be affected.
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        id  path  string  true  "The API client ID to which the permission will be assigned" example(socl_my_new_api_client)
// @param        perm  path  string  true  "The permission to assign" example(events/read)
// @Success      200                         "The permission was successfully assigned"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/clients/{id}/permission/{perm} [post]
func (h *ClientsHandler) postAddPermission(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	resource := chi.URLParam(r, "resource")
	privilege := chi.URLParam(r, "privilege")

	safe := clientIdVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	perm := resource + "/" + privilege
	safe = permissionVerifier.MatchString(perm)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid permission"))
		return
	}

	err := h.server.AdminClientstore.AddClientPermission(ctx, id, perm)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Regenerate Client Secret
// @Description  Regenerates a new client secret for the given API client ID.
// @Description  Pre-existing access tokens that have not yet expired will remain valid through their expiration.
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        id  path  string  true  "The API client ID" example(socl_my_new_api_client)
// @Produce      json
// @Success      200  {object}   model.Client		 "A client object with the new secret populated"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/clients/{id}/secret/ [put]
func (h *ClientsHandler) putGeneratedSecret(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := clientIdVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	client, err := h.server.AdminClientstore.GenerateSecret(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, client)
}

// @Summary      Update API Clients
// @Description  Updates an existing API client with the given Client object
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        request body model.Client true "The Client object to update. Only the 'name', and 'note' properties are used."
// @Produce      json
// @Success      200  {object}  model.Client		 "The updated Client object"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/clients/{id} [put]
func (h *ClientsHandler) putClient(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := clientIdVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	client := model.NewClient()
	err := web.ReadJson(r, client)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	client.Id = id
	err = client.Verify()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.AdminClientstore.UpdateClient(ctx, client)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, client)
}

// @Summary      Remove API Client
// @Description  Removes an API client. Future API requests from this client will immediately be rejected.
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        id  path  string  true  "The API client ID" example(socl_my_new_api_client)
// @Success      200                         "The API client was successfully removed"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/clients/{id}/ [delete]
func (h *ClientsHandler) deleteClient(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := clientIdVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	err := h.server.AdminClientstore.DeleteClient(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Remove Client Permission
// @Description  Removes a permission from an existing API client.
// @Description  A new access token is not required. Future API calls will immediately be affected.
// @Tags         Clients
// @Security     bearer[clients/write]
// @param        id  path  string  true  "The API client ID from which the permission will be removed" example(socl_my_new_api_client)
// @param        perm  path  string  true  "The permission to remove" example(events/read)
// @Success      200                         "The permission was successfully removed"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/clients/{id}/permission/{perm} [delete]
func (h *ClientsHandler) deleteClientPermission(w http.ResponseWriter, r *http.Request) {
	if !licensing.IsEnabled(licensing.FEAT_API) {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_LICENSE_INVALID")
		return
	}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	resource := chi.URLParam(r, "resource")
	privilege := chi.URLParam(r, "privilege")

	safe := clientIdVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	perm := resource + "/" + privilege
	safe = permissionVerifier.MatchString(perm)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid permission"))
		return
	}

	err := h.server.AdminClientstore.DeleteClientPermission(ctx, id, perm)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
