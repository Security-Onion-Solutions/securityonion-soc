// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
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
		r.Get("/event/{id}", h.GetEventSpecificPlaybook)
	})
}

// @Summary      Get Playbook by ID
// @Description  Retrieves playbooks given an internal playbook ID.
// @Tags         Playbooks
// @Security     bearer[playbooks/read]
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

// @Summary      Get Playbook For Detection
// @Description  Retrieves playbooks that apply to the indicated detection.
// @Tags         Playbooks
// @Security     bearer[playbooks/read, detections/read, events/read]
// @Param        id  path  string  true        "The public Id for the detection" example(6F64990A-ACDA-40B6-AB71-134C073013B5)
// @Param        raw query bool    false       "If true, return the playbook in raw YAML format"
// @Success      200  {array}  model.Playbook  "The playbook was successfully retrieved"
// @Failure      401                           "Request was not properly authenticated"
// @Failure      404                           "Detection not found"
// @Failure      500                           "Internal SOC error; review SOC logs"
// @Produce      application/json
// @Produce      application/x-yaml
// @Router       /connect/playbook/detection/{id} [get]
func (h *PlaybookHandler) GetPlaybooksForDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = h.server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = h.server.CheckAuthorized(ctx, "read", "events")
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

	raw := r.URL.Query().Get("raw")
	rawResponse, _ := strconv.ParseBool(raw)

	det, err := h.server.Detectionstore.GetDetectionByPublicId(ctx, publicId)
	if err != nil {
		logger.WithError(err).Error("unable to get detection")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	if det == nil {
		web.Respond(w, r, http.StatusNotFound, nil)
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

	if rawResponse {
		parts := make([]string, 0, len(pbs))
		for _, pb := range pbs {
			rawOutput, err := yaml.Marshal(pb)
			if err != nil {
				logger.WithError(err).Error("unable to marshal playbooks")
				web.Respond(w, r, http.StatusInternalServerError, err)

				return
			}
			parts = append(parts, strings.TrimSpace(string(rawOutput)))
		}

		w.Header().Set("Content-Type", "application/x-yaml")

		web.Respond(w, r, http.StatusOK, strings.Join(parts, "\n---\n"))
		return
	}

	web.Respond(w, r, http.StatusOK, pbs)
}

// @Summary      Get Event-Specific Playbook
// @Description	 Fetches the playbook for a specific event.
// @Tags         Playbooks
// @Security     bearer[playbooks/read, detections/read, events/read]
// @Param        id  path  string  true        "The SOC Id for the alert"
// @Success      200  {array}  model.Playbook  "The playbook was successfully retrieved"
// @Failure		 400                           "Malformed request"
// @Failure      401                           "Request was not properly authenticated"
// @Failure      404                           "Event not found"
// @Failure      500                           "Internal SOC error; review SOC logs"
// @Produce      application/json
// @Router       /connect/playbook/event/{id} [get]
func (h *PlaybookHandler) GetEventSpecificPlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = h.server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = h.server.CheckAuthorized(ctx, "read", "events")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	socId := chi.URLParam(r, "id")
	if socId == "" {
		logger.Error("detection id required")
		web.Respond(w, r, http.StatusBadRequest, nil)
		return
	}

	pbs, err := h.server.Playbookstore.GetEventSpecificPlaybook(ctx, socId)
	if err != nil {
		logger.WithError(err).Error("unable to get playbooks for event")
		if strings.Contains(err.Error(), "no alert found") {
			web.Respond(w, r, http.StatusNotFound, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	if len(pbs) == 0 {
		pbs = []*model.Playbook{}
	}

	web.Respond(w, r, http.StatusOK, pbs)
}
