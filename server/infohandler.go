// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

func (h *InfoHandler) getInfo(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(web.ContextKeyRequestor).(*model.User)
	if !ok {
		err := errors.New("Unable to determine logged in user from context")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	srvToken, err := model.GenerateSrvToken(h.server.Config.SrvKeyBytes, user.Id, h.server.Config.SrvExpSeconds)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	info := &model.Info{
		Version:        h.server.Host.Version,
		License:        "Elastic License 2.0 (ELv2)",
		LicenseKey:     licensing.GetLicenseKey(),
		LicenseStatus:  licensing.GetStatus(),
		Parameters:     &h.server.Config.ClientParams,
		ElasticVersion: os.Getenv("ELASTIC_VERSION"),
		UserId:         user.Id,
		Timezones:      h.timezones,
		SrvToken:       srvToken,
	}

	{
		detections := &info.Parameters.DetectionsParams

		detections.ViewEnabled = true
		detections.CreateLink = "/detection/create"
		detections.EventFetchLimit = 500
		detections.EventItemsPerPage = 50
		detections.GroupFetchLimit = 50
		detections.MostRecentlyUsedLimit = 5
		detections.SafeStringMaxLength = 100
		detections.QueryBaseFilter = "_index:\"*:so-case\" AND so_kind:detection"
		detections.EventFields = map[string][]string{
			"default": {
				"so_detection.title",
				"so_detection.isEnabled",
				"so_detection.engine",
				"@timestamp",
			},
		}
		detections.Queries = []*config.HuntingQuery{
			{
				Name:  "All",
				Query: "_id:*",
			},
		}
	}

	{
		detection := &info.Parameters.DetectionParams

		detection.Presets = map[string]config.PresetParameters{
			"severity": {
				CustomEnabled: false,
				Labels:        []string{"low", "medium", "high"},
			},
			"engine": {
				CustomEnabled: false,
				Labels:        []string{"suricata", "yara", "elastalert"},
			},
		}
	}

	{
		playbooks := &info.Parameters.PlaybooksParams

		playbooks.ViewEnabled = true
		playbooks.CreateLink = "/playbook/create"
		playbooks.EventFetchLimit = 500
		playbooks.EventItemsPerPage = 50
		playbooks.GroupFetchLimit = 50
		playbooks.MostRecentlyUsedLimit = 5
		playbooks.QueryBaseFilter = "_index:\"*:so-case\" AND so_kind:playbook"
		playbooks.SafeStringMaxLength = 100
		playbooks.Queries = []*config.HuntingQuery{
			{Query: "*"},
		}
		playbooks.EventFields = map[string][]string{
			"default": {
				"soc_timestamp",
				"so_playbook.title",
				"so_playbook.publicId",
				"so_playbook.mechanism",
			},
		}
	}

	web.Respond(w, r, http.StatusOK, info)
}
