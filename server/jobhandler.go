// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"
	"strconv"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type JobHandler struct {
	server *Server
}

func RegisterJobRoutes(srv *Server, r chi.Router, prefix string) {
	h := &JobHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getJob)
		r.Get("/{jobId}", h.getJob)

		r.Post("/", h.postJob)

		r.Put("/", h.putJob)

		r.Delete("/{jobId}", h.deleteJob)
	})
}

// @Summary      Get Job
// @Description  Retrieves a specific job that matches the given job ID.
// @Tags         Jobs
// @Security     bearer[jobs/read]
// @Param        jobId  path  integer  true  "The job ID" example(1004)
// @Produce      json
// @Success      200  {object}  model.Job    "The retrieved Job object"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      404         "The job was not found"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/job/{jobId} [get]
func (h *JobHandler) getJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rawId := chi.URLParam(r, "jobId")
	if rawId == "" {
		rawId = r.URL.Query().Get("jobId")
	}

	jobId, err := strconv.ParseInt(rawId, 10, 32)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	job := h.server.Datastore.GetJob(ctx, int(jobId))
	if job == nil {
		web.Respond(w, r, http.StatusNotFound, nil)
		return
	}

	web.Respond(w, r, http.StatusOK, job)
}

// @Summary      Create Job
// @Description  Create a new job.
// @Tags         Jobs
// @Security     bearer[jobs/write]
// @Param        request  body  model.Job  true  "The job details. The job ID, create timestamp, status, and other processing-related fields will be populated by the server. For a new analyze job, only the kind (analyze), nodeId, and parameters should be specified. For the parameters, the caseId, artifactType, and other relevant fields needed by the analyzers should be submitted."
// @Produce      json
// @Success      201  {object}  model.Job    "The created Job object"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/job/ [post]
func (h *JobHandler) postJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	job := h.server.Datastore.CreateJob(ctx)

	err := web.ReadJson(r, job)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.Datastore.AddJob(ctx, job)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	web.Respond(w, r, http.StatusCreated, job)
}

// @Summary      Update Job
// @Description  Update an existing job with the provided job details.
// @Tags         Jobs
// @Security     bearer[jobs/write]
// @Param        request  body  model.Job  true  "The job details. Any provided user ID or node ID will be ignored as those fields are read-only after initial job creation."
// @Produce      json
// @Success      200  {object}  model.Job    "The updated Job object"
// @Failure      400        "The provided input object or parameters are malformed or invalid"
// @Failure      401        "Request was not properly authenticated"
// @Failure      404        "The job was not found"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Router       /connect/job/ [put]
func (h *JobHandler) putJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	job := model.NewJob()

	err := web.ReadJson(r, job)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.Datastore.UpdateJob(ctx, job)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	web.Respond(w, r, http.StatusOK, job)
}

// @Summary      Delete Job
// @Description  Deletes an existing job and its related output results.
// @Tags         Jobs
// @Security     bearer[jobs/delete]
// @Param        jobId  path  integer  true  "The job ID" example(1004)
// @Success      200                         "The job was successfully deleted"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      404         "The job was not found"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/job/{jobId} [delete]
func (h *JobHandler) deleteJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "jobId")

	jobId, err := strconv.Atoi(id)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	job, err := h.server.Datastore.DeleteJob(ctx, int(jobId))
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	web.Respond(w, r, http.StatusOK, nil)
}
