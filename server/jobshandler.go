// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type JobsHandler struct {
	server *Server
}

func RegisterJobsRoutes(srv *Server, r chi.Router, prefix string) {
	h := &JobsHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getJobs)
	})
}

// @Summary      Get Jobs
// @Description  Retrieves the list of jobs that match the given parameters.
// @Tags         Jobs
// @Security     bearer[jobs/read]
// @Param        kind  query  string  true  "The job kind, such as 'analyze'. Specify an empty value for PCAP jobs" example(analyzer)
// @Param        parameters[artifact][id]  query  string  false  "Optional case ID to locate matching analyze jobs" example(P5mgnpEB0JpjNDZz1bIN)
// @Produce      json
// @Success      200  {array}  model.Job     "The array of retrieved jobs"
// @Failure      400       "The provided input object or parameters are malformed or invalid"
// @Failure      401       "Request was not properly authenticated"
// @Failure      500       "Internal SOC error; review SOC logs"
// @Router       /connect/jobs/ [get]
func (h *JobsHandler) getJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kind := r.URL.Query().Get("kind")
	paramsStr := r.URL.Query().Get("parameters")
	dateRange := r.URL.Query().Get("dateRange")
	dateRangeFormat := r.URL.Query().Get("dateRangeFormat")
	timezone := r.URL.Query().Get("timezone")

	var start, end *time.Time

	if dateRange != "" {
		datePieces := strings.SplitN(dateRange, " - ", 2)

		loc, err := time.LoadLocation(timezone)
		if err != nil {
			log.WithField("timezone", timezone).Info("invalid timezone provided by client")
			loc, _ = time.LoadLocation("UTC")
		}

		if len(datePieces) != 2 {
			web.Respond(w, r, http.StatusBadRequest, "invalid date range format")
			return
		}

		s, err := time.ParseInLocation(dateRangeFormat, strings.Trim(datePieces[0], " "), loc)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, "invalid start date")
			return
		}

		e, err := time.ParseInLocation(dateRangeFormat, strings.Trim(datePieces[1], " "), loc)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, "invalid end date")
			return
		}

		start = &s
		end = &e
	}

	params := map[string]interface{}{}
	if paramsStr != "" {
		err := json.LoadJson([]byte(paramsStr), &params)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}
	}

	jobs := h.server.Datastore.GetJobs(ctx, kind, params, start, end)

	web.Respond(w, r, http.StatusOK, jobs)
}
