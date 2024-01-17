// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type JobLookupHandler struct {
	server *server.Server
	store  *ElasticEventstore
}

func RegisterJobLookupRoutes(srv *server.Server, store *ElasticEventstore, r chi.Router, prefix string) {
	h := &JobLookupHandler{
		server: srv,
		store:  store,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(web.Middleware(srv.Host, false))

		r.Get("/", h.getJobLookup)
	})
}

func (h *JobLookupHandler) getJobLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	timestampStr := r.URL.Query().Get("time") // Elastic doc timestamp

	idField := "_id"
	idValue := r.URL.Query().Get("esid") // Elastic doc ID
	if len(idValue) == 0 {
		idValue = r.URL.Query().Get("ncid") // Network community ID
		idField = "network.community_id"
	}

	job := h.server.Datastore.CreateJob(ctx)
	err := h.store.PopulateJobFromDocQuery(ctx, idField, idValue, timestampStr, job)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	err = h.server.Datastore.AddPivotJob(ctx, job)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	redirectUrl := h.server.Config.BaseUrl + "#/job/" + strconv.Itoa(job.Id)
	http.Redirect(w, r, redirectUrl, http.StatusFound)

	web.Respond(nil, r, http.StatusOK, nil)
}
