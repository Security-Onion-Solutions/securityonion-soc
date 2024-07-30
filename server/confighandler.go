// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type ConfigHandler struct {
	server *Server
}

func RegisterConfigRoutes(srv *Server, r chi.Router, prefix string) {
	h := &ConfigHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.configEnabled)

		r.Get("/", h.getConfig)

		r.Put("/", h.putSetting)
		r.Post("/", h.putSetting)
		r.Put("/sync", h.putSync)
		r.Post("/sync", h.putSync)

		r.Delete("/", h.deleteConfig)
		r.Delete("/{id}", h.deleteConfig)
		r.Delete("/{id}/{minion}", h.deleteConfig)
	})
}

func (h *ConfigHandler) configEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Configstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("Config module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *ConfigHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	extended, err := strconv.ParseBool(r.URL.Query().Get("extended"))
	if err != nil {
		extended = false
	}
	settings, err := h.server.Configstore.GetSettings(ctx, extended)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, settings)
}

func (h *ConfigHandler) putSetting(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	setting := model.Setting{}

	err := json.NewDecoder(r.Body).Decode(&setting)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if !model.IsValidSettingId(setting.Id) || (setting.NodeId != "" && !model.IsValidMinionId(setting.NodeId)) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid setting"))
		return
	}

	err = h.server.Configstore.UpdateSetting(ctx, &setting, false)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *ConfigHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.Configstore.SyncSettings(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
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
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid setting"))
		return
	}

	err = h.server.Configstore.UpdateSetting(ctx, setting, true)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
