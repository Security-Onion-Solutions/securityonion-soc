// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type PlaybookHandler struct {
	server *Server
}

func NewPlaybookHandler(srv *Server) *PlaybookHandler {
	return &PlaybookHandler{
		server: srv,
	}
}

func RegisterPlaybookRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewPlaybookHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Get("/{id}", h.GetPlaybook)
		r.Get("/detection/{id}", h.GetPlaybooksForDetection)
		r.Post("/convert", h.ConvertPlaybook)
	})
}

func (h *PlaybookHandler) GetPlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	playbookId := chi.URLParam(r, "id")
	if playbookId == "" {
		logger.Error("playbook id required")
		web.Respond(w, r, http.StatusBadRequest, nil)

		return
	}

	pb, err := h.server.Playbookstore.GetPlaybookById(playbookId)
	if err != nil {
		logger.WithError(err).Error("unable to get playbook")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, pb)
}

func (h *PlaybookHandler) GetPlaybooksForDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	publicId := chi.URLParam(r, "id")
	if publicId == "" {
		logger.Error("detection id required")
		web.Respond(w, r, http.StatusBadRequest, nil)
		return
	}

	det, err := h.server.Detectionstore.GetDetectionByPublicId(ctx, publicId)
	if err != nil {
		logger.WithError(err).Error("unable to get detection")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	pbs, err := h.server.Playbookstore.GetPlaybooksForDetection(det.PublicID, det.Category, det.Engine)
	if err != nil {
		logger.WithError(err).Error("unable to get playbooks for detection")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, pbs)
}

func (h *PlaybookHandler) ConvertPlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	queries := []string{}
	err := web.ReadJson(r, &queries)
	if err != nil {
		logger.WithError(err).Error("unable to read queries")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	pbConverted, err := h.server.Playbookstore.ConvertQuestions(ctx, queries)
	if err != nil {
		logger.WithError(err).Error("unable to convert playbook")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, pbConverted)
}
