// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"net/http"
	"strconv"

	"github.com/apex/log"
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
		r.Get("/", h.getJobLookup)
	})
}

// @Summary      Create PCAP Job from Event
// @Description  Given a TCP or UDP network connection log event, create a PCAP lookup job that would best locate the PCAP from that event.
// @Tags         Jobs
// @Security     bearer[events/read, jobs/write]
// @Param        time  query  string  true  "Time timestamp of the event" example(2024-01-29T12:31:59.220Z)
// @Param        esid  query  string  false "The event document ID. If this is not specified then the ncid param is required." example(P5mgnpEB0JpjNDZz1bIN)
// @Param        ncid  query  string  false "The network.community_id value for the event. Ignored if the esid param is provided." example(1:URggUwcolUh/BgIWApL6rUUZUK4=)
// @Success      302       "Responds with a Location redirect header when the job was successfully created. Note that this does not necessarily mean that the job will find matching PCAP data."
// @Failure      404       "There was no document found that matched the provided input time and document or network community ID"
// @Failure      500       "Internal SOC error; review SOC logs"
// @Header       302  {string}  Location "The SOC UI URL to the newly created PCAP job. Note that the job may not yet be processed."
// @Router       /connect/joblookup/ [get]
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

	assignedGridId := r.URL.Query().Get("assignedGridId")
	if len(assignedGridId) > 0 {
		log.WithFields(log.Fields{
			"assignedGridId": assignedGridId,
		}).Debug("Using relative redirect for subgrid joblookup")
		redirectUrl = "/#/job/" + strconv.Itoa(job.Id) + "?gridId=" + assignedGridId
	}
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}
