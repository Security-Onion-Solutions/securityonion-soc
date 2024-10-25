// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

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
		r.Post("/{id}/role/{role}", h.postAddRole)

		r.Put("/sync", h.putSync)
		r.Put("/{id}", h.putClient)

		r.Delete("/{id}", h.deleteClient)
		r.Delete("/{id}/role/{role}", h.deleteClientRole)
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

	var secret string
	secret, err = h.server.AdminClientstore.AddClient(ctx, client)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	client.Secret = secret
	web.Respond(w, r, http.StatusOK, client)
}

func (h *ClientsHandler) postAddRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	role := chi.URLParam(r, "role")

	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	safe = roleVerifier.MatchString(role)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid role"))
		return
	}

	err := h.server.AdminClientstore.AddRole(ctx, id, role)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *ClientsHandler) getGeneratedSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	client := model.NewClient()
	err := web.ReadJson(r, client)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	client.Id = id

	var secret string
	secret, err = h.server.AdminClientstore.GenerateSecret(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	client.Secret = secret
	web.Respond(w, r, http.StatusOK, client)
}

func (h *ClientsHandler) putClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	client := model.NewClient()
	err := web.ReadJson(r, client)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	client.Id = id

	err = h.server.AdminClientstore.UpdateClient(ctx, client)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, client)
}

func (h *ClientsHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.AdminClientstore.SyncClients(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *ClientsHandler) deleteClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	safe := idVerifier.MatchString(id)
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

func (h *ClientsHandler) deleteClientRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	role := chi.URLParam(r, "role")

	safe := idVerifier.MatchString(id)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid id"))
		return
	}

	safe = roleVerifier.MatchString(role)
	if !safe {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid role"))
		return
	}

	err := h.server.AdminClientstore.DeleteRole(ctx, id, role)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
