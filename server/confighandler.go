// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
		r.Put("/sync/{module}", h.putSyncModule)
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

// @Summary      Get Configuration
// @Description  Retrieves the full set of configuration settings and associated metadata.
// @Description  This response can be very large, particularly when the advanced parameter is set to 'true'.
// @Tags         Config
// @Security     bearer[config/read]
// @param        advanced  query  boolean  false  "If true, all configuration settings will be retrieved, otherwise only the commonly adjusted settings are retrieved" example(true)
// @Success      200  {array} model.Setting   "The configuration setting objects"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      405                         "Configuration module has not been loaded"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/config/ [get]
func (h *ConfigHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	advanced, err := strconv.ParseBool(r.URL.Query().Get("advanced"))
	if err != nil {
		advanced = false
	}
	settings, err := h.server.Configstore.GetSettings(ctx, advanced)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, settings)
}

// @Summary      Save Setting
// @Description  Sets a configuration setting to a new value.
// @Tags         Config
// @Security     bearer[config/read,config/write]
// @param        request  body  model.Setting  true  "The setting to update. Only non-metadata fields are required, specifically 'id' and 'value', and optionally the 'nodeId' field if this is being applied to a specific node"
// @Success      200                         "The new setting values has been saved"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      405                         "Configuration module has not been loaded"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/config/ [put]
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

// @Summary      Sync Configuration
// @Description  Synchronizes the grid to apply recent configuration changes to the grid. Internally this is queuing up a Salt highstate, which can take several minutes to complete, or longer if another highstate is already in progress.
// @Tags         Config
// @Security     bearer[config/write]
// @Success      200                         "The synchronization request has been successfully queued"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      405                         "Configuration module has not been loaded"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/config/sync [put]
func (h *ConfigHandler) putSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.Configstore.SyncSettings(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Sync Specific Module Configuration
// @Description  Synchronizes a specific module's state to apply recent configuration changes to the grid. If async is true, this will queue up a Salt state.apply, which can take several minutes to complete, or longer if another highstate is already in progress. If async is false and another state is already in progress, this will return an error.
// @Tags         Config
// @Security     bearer[config/write]
// @Param        module  path  string  true  "The module name to sync" example(soc)
// @Param        async  query  string  false "If true, runs the synchronization in the background" example(true)
// @Success      200                         "The synchronization request has been successfully queued"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      405                         "Configuration module has not been loaded"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/config/sync/{module} [put]
func (h *ConfigHandler) putSyncModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	module := chi.URLParam(r, "module")
	async := r.URL.Query().Get("async") == "true"

	err := h.server.Configstore.SyncModule(ctx, module, async)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Delete Setting
// @Description  Removes a custom setting value. This effectively reverts to the default setting value.
// @Tags         Config
// @Security     bearer[config/read,config/write]
// @Param        id  path  string  true  "The setting ID to remove" example(elastalert.alerter_parameters)
// @Param        minion  path  string  false  "The optional node ID from which to remove this setting. If omitted, the setting will be removed from the global grid and any node-specific setting values will remain in place." example(chi-so-001_standalone)
// @Success      200                         "The setting was successfully removed"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      405                         "Configuration module has not been loaded"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/config/{id}/{minion} [delete]
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
