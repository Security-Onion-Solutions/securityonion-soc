// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
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

// @Summary      Get Playbook
// @Description  Retrieves playbooks given an internal playbook ID.
// @Tags         Playbooks
// @Param        id  path  string  true         "The playbook ID to retrieve" example(6F64990A-ACDA-40B6-AB71-134C073013B5)
// @Success      200  {object}  model.Playbook  "The playbook was successfully retrieved"
// @Failure      401                            "Request was not properly authenticated"
// @Failure      404                            "Playbook not found"
// @Failure      500                            "Internal SOC error; review SOC logs"
// @Router       /connect/playbook/{id} [get]
func (h *PlaybookHandler) GetPlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	playbookId := chi.URLParam(r, "id")
	if playbookId == "" {
		logger.Error("playbook id required")
		web.Respond(w, r, http.StatusBadRequest, nil)

		return
	}

	pb, err := h.server.Playbookstore.GetPlaybookById(ctx, playbookId)
	if err != nil {
		logger.WithError(err).Error("unable to get playbook")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	web.Respond(w, r, http.StatusOK, pb)
}

// @Summary      Get Playbook
// @Description  Retrieves playbooks that apply to the indicated detection.
// @Tags         Playbooks
// @Param        id  path  string  true        "The public Id for the detection" example(6F64990A-ACDA-40B6-AB71-134C073013B5)
// @Success      200  {array}  model.Playbook  "The playbook was successfully retrieved"
// @Failure      401                           "Request was not properly authenticated"
// @Failure      404                           "Playbook not found"
// @Failure      500                           "Internal SOC error; review SOC logs"
// @Router       /connect/playbook/detection/{id} [get]
func (h *PlaybookHandler) GetPlaybooksForDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

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

	engInt, ok := h.server.DetectionEngines.Load(det.Engine)
	if ok {
		eng := engInt.(DetectionEngine)

		err = eng.ExtractDetails(det)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"detectionEngine":   det.Engine,
				"detectionPublicId": publicId,
			}).Error("unable to extract details from detection")
		}
	} else {
		logger.WithFields(log.Fields{
			"detectionEngine":   det.Engine,
			"detectionPublicId": publicId,
		}).Error("retrieved detection with unsupported engine")
	}

	pbs, err := h.server.Playbookstore.GetPlaybooksForDetection(ctx, det.PublicID, det.Category, det.Engine)
	if err != nil {
		logger.WithError(err).Error("unable to get playbooks for detection")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if len(pbs) == 0 {
		pbs = []*model.Playbook{}
	}

	web.Respond(w, r, http.StatusOK, pbs)
}

// @Summary      Get Playbook
// @Description  Converts the questions of a playbook from Sigma to OQL.
// @Tags         Playbooks
// @Param        request body	[]string  true         "The variable substituted Sigma queries to convert"
// @Success      200  {array}  model.ConvertedQuery  "The playbook was successfully retrieved"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/playbook/convert [post]
func (h *PlaybookHandler) ConvertPlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	queries := []string{}
	err = web.ReadJson(r, &queries)
	if err != nil {
		logger.WithError(err).Error("unable to read queries")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	pbConverted := []*model.ConvertedQuery{}

	if len(queries) != 0 {
		pbConverted, err = h.server.Playbookstore.ConvertQuestions(ctx, queries)
		if err != nil {
			logger.WithError(err).Error("unable to convert playbook")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}
	}

	web.Respond(w, r, http.StatusOK, pbConverted)
}
