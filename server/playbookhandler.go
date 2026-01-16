// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"encoding/json"
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
		r.Get("/", h.GetPlaybooksPaginated)
		r.Post("/", h.CreatePlaybook)
		r.Put("/", h.UpdatePlaybook)
		r.Get("/{id}", h.GetPlaybook)
		r.Delete("/{id}", h.DeletePlaybook)
		r.Get("/detection/{id}", h.GetPlaybooksForDetection)
		r.Get("/detection/{id}/grouped", h.GetPlaybooksForDetectionGrouped)
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

// @Summary      Get Playbooks For Detection (Grouped)
// @Description  Retrieves playbooks grouped by match level (detection-specific, category, engine).
// @Tags         Playbooks
// @Security     bearer[playbooks/read, detections/read, events/read]
// @Param        id  path  string  true        "The public Id for the detection" example(6F64990A-ACDA-40B6-AB71-134C073013B5)
// @Success      200  {object}  model.GroupedPlaybooks  "Playbooks grouped by match level"
// @Failure      401                           "Request was not properly authenticated"
// @Failure      404                           "Detection not found"
// @Failure      500                           "Internal SOC error; review SOC logs"
// @Produce      application/json
// @Router       /connect/playbook/detection/{id}/grouped [get]
func (h *PlaybookHandler) GetPlaybooksForDetectionGrouped(w http.ResponseWriter, r *http.Request) {
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

	grouped, err := h.server.Playbookstore.GetPlaybooksForDetectionGrouped(ctx, det.PublicID, det.Category, det.Engine)
	if err != nil {
		logger.WithError(err).Error("unable to get grouped playbooks for detection")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, grouped)
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

// @Summary      Get Playbooks (Paginated)
// @Description  Retrieves playbooks with pagination, filtering, and search support.
// @Tags         Playbooks
// @Security     bearer[playbooks/read]
// @Param        limit   query int    false "Number of playbooks to return (default 50, max 500)"
// @Param        offset  query int    false "Offset for pagination"
// @Param        search  query string false "Search query to filter by name, description, detection_id, or category"
// @Param        type    query string false "Filter by detection type (sigma, nids, yara, global)"
// @Param        source  query string false "Filter by source (community, custom)"
// @Success      200  {object}  model.PlaybookListResponse  "Playbooks successfully retrieved"
// @Failure      401                           "Request was not properly authenticated"
// @Failure      500                           "Internal SOC error; review SOC logs"
// @Produce      application/json
// @Router       /connect/playbook/ [get]
func (h *PlaybookHandler) GetPlaybooksPaginated(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	// Parse query parameters
	criteria := &model.PlaybookSearchCriteria{
		Search: r.URL.Query().Get("search"),
		Type:   r.URL.Query().Get("type"),
		Source: r.URL.Query().Get("source"),
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			criteria.Limit = limit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			criteria.Offset = offset
		}
	}

	response, err := h.server.Playbookstore.GetPlaybooksPaginated(ctx, criteria)
	if err != nil {
		logger.WithError(err).Error("unable to get playbooks")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, response)
}

// @Summary      Create Playbook
// @Description  Creates a new custom playbook.
// @Tags         Playbooks
// @Security     bearer[playbooks/write]
// @Param        playbook body model.Playbook true "The playbook to create"
// @Success      200  {object}  model.Playbook  "The playbook was successfully created"
// @Failure      400                            "Invalid playbook data"
// @Failure      401                            "Request was not properly authenticated"
// @Failure      500                            "Internal SOC error; review SOC logs"
// @Accept       application/json
// @Produce      application/json
// @Router       /connect/playbook/ [post]
func (h *PlaybookHandler) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	var playbook model.Playbook
	if err := json.NewDecoder(r.Body).Decode(&playbook); err != nil {
		logger.WithError(err).Error("unable to decode playbook request")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	created, err := h.server.Playbookstore.CreatePlaybook(ctx, &playbook)
	if err != nil {
		logger.WithError(err).Error("unable to create playbook")
		if strings.Contains(err.Error(), "community") || strings.Contains(err.Error(), "unexpected ID") || strings.Contains(err.Error(), "required") {
			web.Respond(w, r, http.StatusBadRequest, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, created)
}

// @Summary      Update Playbook
// @Description  Updates an existing custom playbook.
// @Tags         Playbooks
// @Security     bearer[playbooks/write]
// @Param        playbook body model.Playbook true "The playbook to update"
// @Success      200  {object}  model.Playbook  "The playbook was successfully updated"
// @Failure      400                            "Invalid playbook data or cannot update community playbooks"
// @Failure      401                            "Request was not properly authenticated"
// @Failure      404                            "Playbook not found"
// @Failure      500                            "Internal SOC error; review SOC logs"
// @Accept       application/json
// @Produce      application/json
// @Router       /connect/playbook/ [put]
func (h *PlaybookHandler) UpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	var playbook model.Playbook
	if err := json.NewDecoder(r.Body).Decode(&playbook); err != nil {
		logger.WithError(err).Error("unable to decode playbook request")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	updated, err := h.server.Playbookstore.UpdatePlaybook(ctx, &playbook)
	if err != nil {
		logger.WithError(err).Error("unable to update playbook")
		if strings.Contains(err.Error(), "not found") {
			web.Respond(w, r, http.StatusNotFound, err)
		} else if strings.Contains(err.Error(), "community") || strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "required") {
			web.Respond(w, r, http.StatusBadRequest, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, updated)
}

// @Summary      Delete Playbook
// @Description  Deletes a custom playbook.
// @Tags         Playbooks
// @Security     bearer[playbooks/write]
// @Param        id path string true "The playbook ID to delete"
// @Success      200                            "The playbook was successfully deleted"
// @Failure      400                            "Cannot delete community playbooks"
// @Failure      401                            "Request was not properly authenticated"
// @Failure      404                            "Playbook not found"
// @Failure      500                            "Internal SOC error; review SOC logs"
// @Router       /connect/playbook/{id} [delete]
func (h *PlaybookHandler) DeletePlaybook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "write", "playbooks")
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

	err = h.server.Playbookstore.DeletePlaybook(ctx, playbookId)
	if err != nil {
		logger.WithError(err).Error("unable to delete playbook")
		if strings.Contains(err.Error(), "not found") {
			web.Respond(w, r, http.StatusNotFound, err)
		} else if strings.Contains(err.Error(), "community") {
			web.Respond(w, r, http.StatusBadRequest, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
