// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
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

	detect, err := h.server.Detectionstore.GetDetection(ctx, detectId)
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

	if detect.IsCommunity {
		web.Respond(w, r, http.StatusBadRequest, errors.New("cannot create community detections using this endpoint"))
		return
	}

	detect, err = h.server.Detectionstore.CreateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	errMap, err := SyncLocalDetections(ctx, h.server, []*model.Detection{detect})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if len(errMap) != 0 {
		web.Respond(w, r, http.StatusInternalServerError, errMap)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) duplicateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	detect, err := h.server.Detectionstore.GetDetection(ctx, detectId)
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

	detect, err = h.server.Detectionstore.CreateDetection(ctx, detect)
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

	old, err := h.server.Detectionstore.GetDetection(ctx, detect.Id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if old.IsCommunity {
		// the only editable fields for community rules are IsEnabled, IsReporting, and Note
		old.IsEnabled = detect.IsEnabled
		old.IsReporting = detect.IsReporting
		old.Note = detect.Note

		detect = old

		log.Infof("existing detection %s is a community rule, only updating IsEnabled, IsReporting, and Note", detect.Id)
	} else if detect.IsCommunity {
		web.Respond(w, r, http.StatusBadRequest, errors.New("cannot update an existing non-community detection to make it a community detection"))
		return
	}

	detect, err = h.server.Detectionstore.UpdateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	errMap, err := SyncLocalDetections(ctx, h.server, []*model.Detection{detect})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if len(errMap) != 0 {
		web.Respond(w, r, http.StatusInternalServerError, errMap)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) deleteDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	old, err := h.server.Detectionstore.DeleteDetection(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	errMap, err := SyncLocalDetections(ctx, h.server, []*model.Detection{old})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, errMap)
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
		det, mod, err := h.server.Detectionstore.UpdateDetectionField(ctx, id, "IsEnabled", enabled)
		if err != nil {
			errMap[id] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
			continue
		}

		if mod {
			modified = append(modified, det)
		}
	}

	if len(modified) != 0 {
		addErrMap, err := SyncLocalDetections(ctx, h.server, modified)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		// merge error maps
		for k, v := range addErrMap {
			origK, hasK := errMap[k]
			if hasK {
				errMap[k] = fmt.Sprintf("%s; %s", origK, v)
			} else {
				errMap[k] = v
			}
		}
	}

	web.Respond(w, r, http.StatusOK, errMap)
}

func SyncLocalDetections(ctx context.Context, srv *Server, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	byEngine := map[model.EngineName][]*model.Detection{}
	for _, detect := range detections {
		byEngine[detect.Engine] = append(byEngine[detect.Engine], detect)
	}

	for name, engine := range srv.DetectionEngines {
		if len(byEngine[name]) != 0 {
			eMap, err := engine.SyncLocalDetections(ctx, byEngine[name])
			for sid, e := range eMap {
				errMap[sid] = e
			}
			if err != nil {
				return errMap, err
			}
		}
	}

	return errMap, nil
}
