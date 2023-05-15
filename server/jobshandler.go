// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/json"

	"github.com/go-chi/chi"
)

type JobsHandler struct {
	server *Server
}

func RegisterJobsRoutes(srv *Server, prefix string) {
	h := &JobsHandler{
		server: srv,
	}

	r := chi.NewMux()

	r.Route(prefix, func(r chi.Router) {
		r.Use(Middleware(srv.Host))

		r.Get("/", h.getJobs)
	})

	srv.Host.RegisterRouter(prefix, r)
}

func (h *JobsHandler) getJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kind := r.URL.Query().Get("kind")
	paramsStr := r.URL.Query().Get("parameters")

	params := map[string]interface{}{}
	if paramsStr != "" {
		err := json.LoadJson([]byte(paramsStr), &params)
		if err != nil {
			Respond(w, r, http.StatusBadRequest, err)
			return
		}
	}

	jobs := h.server.Datastore.GetJobs(ctx, kind, params)

	Respond(w, r, http.StatusOK, jobs)
}
