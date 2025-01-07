// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"os"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type InfoHandler struct {
	server    *Server
	timezones []string
}

func RegisterInfoRoutes(srv *Server, r chi.Router, prefix string) {
	h := &InfoHandler{
		server:    srv,
		timezones: srv.GetTimezones(),
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getInfo)
	})
}

// @Summary      Get Server Information
// @Description  Requests the Security Onion grid general details.
// @Tags	     Grid
// @Security     bearer
// @Produce      json
// @Success      200  {object}  model.Info   "The retrieved Info object"
// @Failure      401         "Request was not properly authenticated"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/info/ [get]
func (h *InfoHandler) getInfo(w http.ResponseWriter, r *http.Request) {
	userId, ok := r.Context().Value(web.ContextKeyRequestorId).(string)
	if !ok {
		err := errors.New("Unable to determine logged in user from context")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	var srvToken string
	var forceUserOtp bool
	var params *config.ClientParameters
	exempt := r.Context().Value(web.ContextKeyRequestCSRFExempt).(bool)
	if !exempt {
		var err error
		srvToken, err = model.GenerateSrvToken(h.server.Config.SrvKeyBytes, userId, h.server.Config.SrvExpSeconds)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		user, err := h.server.Userstore.GetUserById(r.Context(), userId)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		forceUserOtp = user.TotpStatus != "enabled" && h.server.Config.ForceUserOtp
		params = &h.server.Config.ClientParams
	}

	info := &model.Info{
		Version:        h.server.Host.Version,
		License:        "Elastic License 2.0 (ELv2)",
		LicenseKey:     licensing.GetLicenseKey(),
		LicenseStatus:  licensing.GetStatus(),
		Parameters:     params,
		ElasticVersion: os.Getenv("ELASTIC_VERSION"),
		UserId:         userId,
		Timezones:      h.timezones,
		SrvToken:       srvToken,
		ForceUserOtp:   forceUserOtp,
	}

	web.Respond(w, r, http.StatusOK, info)
}
