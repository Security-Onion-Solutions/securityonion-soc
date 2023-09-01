// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi"
)

type DetectionHandler struct {
	server *Server
}

func RegisterDetectionRoutes(srv *Server, r chi.Router, prefix string) {
	h := &DetectionHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/{id}", h.getDetection)

		r.Post("/", h.postDetection)
		r.Post("/{id}/duplicate", h.duplicateDetection)

		r.Put("/", h.putDetection)

		r.Delete("/{id}", h.deleteDetection)

		r.Post("/bulk/{newStatus}", h.bulkUpdateDetection)
	})
}

func (h *DetectionHandler) getDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	detect, err := h.server.Casestore.GetDetection(ctx, detectId)
	if err != nil {
		if err.Error() == "Object not found" {
			web.Respond(w, r, http.StatusNotFound, nil)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}

		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) postDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detect := &model.Detection{}

	err := web.ReadJson(r, detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	detect, err = h.server.Casestore.CreateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = model.SyncDetections([]*model.Detection{detect})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) duplicateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	detect, err := h.server.Casestore.GetDetection(ctx, detectId)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	detect.Id = ""
	detect.PublicID = ""
	detect.Title = fmt.Sprintf("%s (copy)", detect.Title)
	detect.CreateTime = nil
	detect.UpdateTime = nil
	detect.IsEnabled = false
	detect.IsReporting = false
	detect.IsCommunity = false

	detect, err = h.server.Casestore.CreateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) putDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detect := &model.Detection{}

	err := web.ReadJson(r, detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	detect, err = h.server.Casestore.UpdateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	err = model.SyncDetections([]*model.Detection{detect})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) deleteDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	old, err := h.server.Casestore.DeleteDetection(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	err = model.SyncDetections([]*model.Detection{old})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *DetectionHandler) bulkUpdateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	newStatus := chi.URLParam(r, "newStatus") // "enable" or "disable"

	var enabled bool
	switch strings.ToLower(newStatus) {
	case "enable", "disable":
		enabled = strings.ToLower(newStatus) == "enable"
	default:
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid status; must be 'enable' or 'disable'"))
		return
	}

	body := []string{}
	err := web.ReadJson(r, body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	IDs := map[string]struct{}{}

	for _, id := range body {
		IDs[id] = struct{}{}
	}

	errMap := map[string]string{} // map[id]error
	modified := []*model.Detection{}

	for id := range IDs {
		det, mod, err := h.server.Casestore.UpdateDetectionField(ctx, id, "IsEnabled", enabled)
		if err != nil {
			errMap[id] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
			continue
		}

		if mod {
			modified = append(modified, det)
		}
	}

	err = model.SyncDetections(modified)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, errMap)
}
