// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

var clientIdVerifier = regexp.MustCompile(`^[A-Za-z0-9_]{6,55}$`)
var permissionVerifier = regexp.MustCompile(`^[a-z]+/[a-z]+$`)

type ClientsHandler struct {
	server *Server
}

func RegisterClientsRoutes(srv *Server, r chi.Router, prefix string) {
	h := &ClientsHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getClients)
		r.Get("/{id}/secret", h.getGeneratedSecret)

		r.Post("/", h.postClient)
		r.Post("/{id}/permission/{resource}/{privilege}", h.postAddPermission)

		r.Put("/{id}", h.putClient)

		r.Delete("/{id}", h.deleteClient)
		r.Delete("/{id}/permission/{resource}/{privilege}", h.deleteClientPermission)
	})
}

func (h *ClientsHandler) getClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clients, err := h.server.Clientstore.GetClients(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, clients)
}

func (h *ClientsHandler) postClient(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientsHandler) postAddPermission(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientsHandler) getGeneratedSecret(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientsHandler) putClient(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientsHandler) deleteClient(w http.ResponseWriter, r *http.Request) {
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

func (h *ClientsHandler) deleteClientPermission(w http.ResponseWriter, r *http.Request) {
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
