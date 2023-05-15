// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/go-chi/chi"
)

type ConfigHandler struct {
	server *Server
}

func RegisterConfigRoutes(srv *Server, prefix string) {
	h := &ConfigHandler{
		server: srv,
	}

	r := chi.NewMux()

	r.Route(prefix, func(r chi.Router) {
		r.Use(Middleware(srv.Host))

		r.Get("/", h.getConfig)

		r.Put("/", h.putSetting)
		r.Post("/", h.putSetting)
		r.Put("/sync", h.putSync)
		r.Post("/sync", h.putSync)

		r.Delete("/", h.deleteConfig)
		r.Delete("/{id}", h.deleteConfig)
		r.Delete("/{id}/{minion}", h.deleteConfig)
	})

	srv.Host.RegisterRouter(prefix, r)
}

func (h *ConfigHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := h.server.Configstore.GetSettings(ctx)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	Respond(w, r, http.StatusOK, settings)
}

func (h *ConfigHandler) putSetting(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	setting := model.Setting{}

	err := json.NewDecoder(r.Body).Decode(&setting)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if !model.IsValidSettingId(setting.Id) || (setting.NodeId != "" && !model.IsValidMinionId(setting.NodeId)) {
		Respond(w, r, http.StatusBadRequest, errors.New("Invalid setting"))
		return
	}

	err = h.server.Configstore.UpdateSetting(ctx, &setting, false)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	Respond(w, r, http.StatusOK, nil)
}

func (h *ConfigHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.Configstore.SyncSettings(ctx)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	Respond(w, r, http.StatusOK, nil)
}

func (h *ConfigHandler) deleteConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	minion := chi.URLParam(r, "minion")

	if id == "" {
		id = r.URL.Query().Get("id")
	}

	if minion == "" {
		minion = r.URL.Query().Get("minion")
	}

	setting := model.NewSetting(id)
	setting.NodeId = minion

	var err error
	if !model.IsValidSettingId(setting.Id) || (setting.NodeId != "" && !model.IsValidMinionId(setting.NodeId)) {
		Respond(w, r, http.StatusBadRequest, errors.New("Invalid setting"))
		return
	}

	err = h.server.Configstore.UpdateSetting(ctx, setting, true)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
	}

	Respond(w, r, http.StatusOK, nil)
}
