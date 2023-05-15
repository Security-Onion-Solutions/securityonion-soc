// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"
	"strconv"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/go-chi/chi"
)

type JobHandler struct {
	server *Server
}

func RegisterJobRoutes(srv *Server, prefix string) {
	h := &JobHandler{
		server: srv,
	}

	r := chi.NewMux()

	r.Route(prefix, func(r chi.Router) {
		r.Use(Middleware(srv.Host))

		r.Get("/", h.getJob)
		r.Get("/{jobId}", h.getJob)

		r.Post("/", h.postJob)

		r.Put("/", h.putJob)

		r.Delete("/{jobId}", h.deleteJob)
	})

	srv.Host.RegisterRouter(prefix, r)
}

func (h *JobHandler) getJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rawId := chi.URLParam(r, "jobId")
	if rawId == "" {
		rawId = r.URL.Query().Get("jobId")
	}

	jobId, err := strconv.ParseInt(rawId, 10, 32)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	job := h.server.Datastore.GetJob(ctx, int(jobId))
	if job == nil {
		Respond(w, r, http.StatusNotFound, nil)
		return
	}

	Respond(w, r, http.StatusOK, job)
}

func (h *JobHandler) postJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	job := h.server.Datastore.CreateJob(ctx)

	err := ReadJson(r, job)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.Datastore.AddJob(ctx, job)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	Respond(w, r, http.StatusCreated, job)
}

func (h *JobHandler) putJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	job := model.NewJob()

	err := ReadJson(r, job)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
	}
	err = h.server.Datastore.UpdateJob(ctx, job)
	if err != nil {
		Respond(w, r, http.StatusNotFound, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	Respond(w, r, http.StatusOK, job)
}

func (h *JobHandler) deleteJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "jobId")

	jobId, err := strconv.Atoi(id)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	job, err := h.server.Datastore.DeleteJob(ctx, int(jobId))
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	h.server.Host.Broadcast("job", "jobs", job)

	Respond(w, r, http.StatusOK, nil)
}
