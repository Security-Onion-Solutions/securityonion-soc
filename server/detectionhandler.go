// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
)

var errPublicIdExists = errors.New("publicId already exists for this engine")

type BulkOp struct {
	// The list of detection IDs to bulk update when a specific query is not provided
	IDs []string `json:"ids" example:"zC73PJABrNRFAsnEYkqy,XgaI6o8B-vS4HfrbYcce"`
	// The query string to use for matching detections, or leave empty if providing a list of internal detection IDs"
	Query     *string `json:"query" example:"severity: low AND ruleset: ETOPEN"`
	NewStatus bool    `json:"-"`
	Delete    bool    `json:"-"`
}

type BulkResp struct {
	// The count of detections that were submitted to be updated or deleted in bulk
	Count int `json:"count" example:"120"`
}

type ConvertContentResp struct {
	Query string `json:"query" example:"somefield: somevalue AND anotherfield: 123"`
}

type GenPublicIdResp struct {
	PublicId string `json:"publicId" example:"fb58abf3-0a6d-49af-b1a0-1eeabec07716"`
}

type DetectionHandler struct {
	server *Server
}

func NewDetectionHandler(srv *Server) *DetectionHandler {
	return &DetectionHandler{
		server: srv,
	}
}

func RegisterDetectionRoutes(srv *Server, r chi.Router, prefix string) {
	h := NewDetectionHandler(srv)

	r.Route(prefix, func(r chi.Router) {
		r.Get("/{id}", h.getDetection)
		r.Get("/public/{publicid}", h.getByPublicId)

		r.Post("/", h.createDetection)
		r.Post("/{id}/duplicate", h.duplicateDetection)

		r.Post("/{id}/comment", h.createComment)
		r.Get("/comment/{id}", h.getDetectionComment)
		r.Put("/comment/{id}", h.updateComment)
		r.Delete("/comment/{id}", h.deleteComment)
		r.Get("/{id}/comment", h.getDetectionComments)

		r.Get("/{id}/history", h.getDetectionHistory)
		r.Post("/convert", h.convertContent)

		r.Put("/", h.updateDetection)
		r.Put("/{id}/override/{overrideIndex}/note", h.updateOverrideNote)

		r.Delete("/{id}", h.deleteDetection)

		r.Post("/bulk/{newStatus}", h.bulkUpdateDetection)
		r.Post("/sync/{engine}/{type}", h.syncEngineDetections)

		r.Get("/{engine}/genpublicid", h.genPublicId)
	})
}

// @Summary      Get Detection
// @Description  Retrieves a specific detection given an internal detection ID. This ID is unique only to this particular grid.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read]
// @Param        id  path  string  true  "The detection ID to retrieve" example(zC73PJABrNRFAsnEYkqy)
// @Success      200  {object}  model.Detection  "The detection was successfully retrieved"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id} [get]
func (h *DetectionHandler) getDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

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

	eng, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		logger.WithFields(log.Fields{
			"detectionEngine":   detect.Engine,
			"detectionPublicId": detectId,
		}).Error("retrieved detection with unsupported engine")
	} else {
		err = eng.MergeAuxiliaryData(detect)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"detectionEngine":   detect.Engine,
				"detectionPublicId": detectId,
			}).Error("unable to merge auxiliary data into detection")
		}
	}

	web.Respond(w, r, http.StatusOK, detect)
}

// @Summary      Get Detection By Public ID
// @Description  Retrieves a specific detection given a public detection ID. This ID is assigned by the ruleset author.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read]
// @Param        id  path  string  true  "The detection public ID to retrieve" example(2038279)
// @Success      200  {object}  model.Detection  "The detection was successfully retrieved"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/public/{id} [get]
func (h *DetectionHandler) getByPublicId(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	publicId := chi.URLParam(r, "publicid")

	detect, err := h.server.Detectionstore.GetDetectionByPublicId(ctx, publicId)
	if err != nil {
		if err.Error() == "Object not found" {
			web.Respond(w, r, http.StatusNotFound, nil)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}

		return
	}

	if detect == nil {
		web.Respond(w, r, http.StatusNotFound, nil)
		return
	}

	eng, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		logger.WithFields(log.Fields{
			"detectionEngine":   detect.Engine,
			"detectionPublicId": publicId,
		}).Error("retrieved detection with unsupported engine")
	} else {
		err = eng.MergeAuxiliaryData(detect)
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"detectionEngine":   detect.Engine,
				"detectionPublicId": publicId,
			}).Error("unable to merge auxiliary data into detection")
		}
	}

	web.Respond(w, r, http.StatusOK, detect)
}

// @Summary      Create Detection
// @Description  Creates a new detection by providing the detection object as the request body, in JSON format.
// @Description  Detections marked as community detections cannot be created with this API.
// @Description  While the public ID is required for some engines, the internal ID will always be populated by the server.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write,events/write, users/read]
// @Param        request  body  model.Detection  true  "The detection object to create"
// @Success      200  {object}  model.Detection  "Returns the detection that was successfully created"
// @Success      205  {object}  model.Detection  "Returns the detection that was successfully created and the status has been modified by a filter"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      409                         "Public ID conflicts with existing detection"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/ [post]
func (h *DetectionHandler) createDetection(w http.ResponseWriter, r *http.Request) {
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

	for _, over := range detect.Overrides {
		if over.CreatedAt.IsZero() {
			over.CreatedAt = time.Now()
		}

		if over.UpdatedAt.IsZero() {
			over.UpdatedAt = time.Now()
		}
	}

	detect.Language = model.SigLanguage(strings.ToLower(string(detect.Language)))
	detect.Ruleset = detections.RULESET_CUSTOM

	switch detect.Language {
	case "sigma":
		detect.Engine = model.EngineNameElastAlert
	case "yara":
		detect.Engine = model.EngineNameStrelka
	case "suricata":
		detect.Engine = model.EngineNameSuricata
	}

	engine, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		web.Respond(w, r, http.StatusBadRequest, errors.New("unsupported engine"))
		return
	}

	_, err = engine.ValidateRule(detect.Content)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid rule: %w", err))
		return
	}

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = engine.ExtractDetails(detect)
	if err != nil {
		if err.Error() == "rule does not contain a public Id" {
			web.Respond(w, r, http.StatusBadRequest, "missingPublicIdErr")
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}

		return
	}

	// Don't trust the client to send the correct author, grab it from the context
	userID := ctx.Value(web.ContextKeyRequestorId).(string)
	user, err := h.server.Userstore.GetUserById(ctx, userID)
	if err != nil {
		return
	}
	detect.Author = detections.MakeUser(user)

	specifiedStatus := detect.IsEnabled

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	statusModifiedByFilter := detect.IsEnabled != specifiedStatus

	detect, err = h.server.Detectionstore.CreateDetection(ctx, detect)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			web.Respond(w, r, http.StatusConflict, "publicIdConflictErr")
			return
		}

		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	errMap, err := syncLocalDetections(ctx, h.server, []*model.Detection{detect})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if len(errMap) != 0 {
		web.Respond(w, r, http.StatusInternalServerError, errMap)
		return
	}

	if statusModifiedByFilter {
		// success, but the status was modified by a filter to not be what the user
		// submitted, send a unique code so the UI can display a message
		web.Respond(w, r, http.StatusResetContent, detect)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

// @Summary      Get Detection History
// @Description  Retrieves a specific detection's audit history given an internal detection ID.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read]
// @Param        id  path  string  true  "The detection ID to retrieve" example(zC73PJABrNRFAsnEYkqy)
// @Success      200  {array}  model.Auditable  "The array of history audit objects. Note that these objects will also contain either the Detection fields or a DetectionComment fields."
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id}/history [get]
func (h *DetectionHandler) getDetectionHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	obj, err := h.server.Detectionstore.GetDetectionHistory(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

// @Summary      Duplicate Detection
// @Description  Copies the detection associated with the given ID into a new detection. A new ID will be assigned to the duplicated detection.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The detection ID to duplicate" example(zC73PJABrNRFAsnEYkqy)
// @Success      200  {object}  model.Detection  "The duplicated detection object."
// @Failure      400                         "The detection engine specified in the detection object does not support duplicated detections"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id}/duplicate [post]
func (h *DetectionHandler) duplicateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	detect, err := h.server.Detectionstore.GetDetection(ctx, detectId)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	eng, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		web.Respond(w, r, http.StatusBadRequest, errors.New("unsupported engine"))
		return
	}

	dupe, err := eng.DuplicateDetection(ctx, detect)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	detect, err = h.server.Detectionstore.CreateDetection(ctx, dupe)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

// @Summary      Update Detection
// @Description  Updates an existing detection by providing the new detection object as the request body, in JSON format.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        request  body  model.Detection  true  "The detection object to create"
// @Success      200  {object}  model.Detection  "Returns the detection that was successfully updated"
// @Success      205  {object}  model.Detection  "Returns the detection that was successfully updated; note that the status has been modified by a filter"
// @Success      206  {object}  model.Detection  "Returns the detection that was successfully updated; note that the detection was disabled in order to complete the sync"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      409                         "Public ID conflicts with existing detection"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/ [put]
func (h *DetectionHandler) updateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	detect := &model.Detection{}

	err := web.ReadJson(r, detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = detect.Validate()
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	engine, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		web.Respond(w, r, http.StatusBadRequest, errors.New("unsupported engine"))
		return
	}

	_, err = engine.ValidateRule(detect.Content)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid rule: %w", err))
		return
	}

	specifiedStatus := detect.IsEnabled

	filterApplied, err := engine.ApplyFilters(detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = engine.ExtractDetails(detect)
	if err != nil {
		if err.Error() == "rule does not contain a public Id" {
			web.Respond(w, r, http.StatusBadRequest, "missingPublicIdErr")
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}

		return
	}

	statusModifiedByFilter := detect.IsEnabled != specifiedStatus

	err = h.PrepareForSave(ctx, detect, engine)
	if err != nil {
		if err.Error() == "Object not found" {
			web.Respond(w, r, http.StatusNotFound, nil)
		} else if errors.Is(err, errPublicIdExists) {
			web.Respond(w, r, http.StatusConflict, err)
		} else if err.Error() == "rule does not contain a public Id" {
			web.Respond(w, r, http.StatusBadRequest, "missingPublicIdErr")
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}

		return
	}

	detect, err = h.server.Detectionstore.UpdateDetection(ctx, detect)
	if err != nil {
		if strings.Contains(err.Error(), "existing non-community detection") {
			web.Respond(w, r, http.StatusBadRequest, err)
		} else if strings.Contains(err.Error(), "publicId already exists for this engine") {
			web.Respond(w, r, http.StatusConflict, err)
		} else {
			web.Respond(w, r, http.StatusNotFound, err)
		}

		return
	}

	detect.PersistChange = true

	errMap, err := syncLocalDetections(ctx, h.server, []*model.Detection{detect})
	if err != nil {
		fixed := false
		if detect.IsEnabled && !filterApplied {
			var uerr error
			logger.WithError(err).WithField("detection", detect).Error("unable to sync detection; attempting to disable and resync")

			detect.IsEnabled = false
			detect.Kind = ""

			detect, uerr = h.server.Detectionstore.UpdateDetection(ctx, detect)
			if uerr == nil {
				errMap, err = syncLocalDetections(ctx, h.server, []*model.Detection{detect})
				fixed = true
			}
		}

		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		} else if fixed {
			web.Respond(w, r, http.StatusPartialContent, detect)
			return
		}
	}

	if len(errMap) != 0 {
		web.Respond(w, r, http.StatusInternalServerError, errMap)
		return
	}

	if statusModifiedByFilter {
		// success, but the status was modified by a filter to not be what the user
		// submitted, send a unique code so the UI can display a message
		web.Respond(w, r, http.StatusResetContent, detect)
		return
	}

	web.Respond(w, r, http.StatusOK, detect)
}

// @Summary      Update Override Note
// @Description  Updates an existing override note.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The internal detection ID" example(zC73PJABrNRFAsnEYkqy)
// @Param        overrideIndex path number  true  "The 0-based index of the override within the detection" example(0)
// @Param        request body model.OverrideNoteUpdate true "The note object that will replace the existing override note"
// @Success      200         "The override note was updated successfully"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id}/override/{overrideIndex}/note [put]
func (h *DetectionHandler) updateOverrideNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")
	param := chi.URLParam(r, "overrideIndex")

	overrideIndex, err := strconv.Atoi(param)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	body := model.OverrideNoteUpdate{}

	err = web.ReadJson(r, &body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	valid, err := detections.UpdateOverrideNote(ctx, h.server.Detectionstore, detectId, overrideIndex, body.Note)
	if err != nil {
		status := http.StatusInternalServerError
		if !valid {
			status = http.StatusBadRequest
		}

		web.Respond(w, r, status, err)

		return
	}
}

// @Summary      Delete Detection
// @Description  Deletes an existing detection.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The internal detection ID" example(zC73PJABrNRFAsnEYkqy)
// @Success      200         "The override note was deleted successfully"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id} [delete]
func (h *DetectionHandler) deleteDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	det, err := h.server.Detectionstore.GetDetection(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if det.IsCommunity {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_DELETE_COMMUNITY")
		return
	}

	old, err := h.server.Detectionstore.DeleteDetection(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	old.IsEnabled = false
	old.PendingDelete = true

	errMap, err := syncLocalDetections(ctx, h.server, []*model.Detection{old})
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, errMap)
}

// @Summary      Manage Detections in Bulk
// @Description  Enables, disables, or deletes multiple detections asynchronously.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        newStatus  path  string  true  "The new status of the detection" Enums(enable, disable, delete)
// @Param        request  body  BulkOp  true  "The bulk detection search criteria"
// @Success      200  {object}  BulkResp "Returns the bulk operation response"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/bulk/{newStatus} [post]
func (h *DetectionHandler) bulkUpdateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	newStatus := chi.URLParam(r, "newStatus") // "enable" or "disable"

	var enabled bool
	var delete bool
	switch strings.ToLower(newStatus) {
	case "enable", "disable":
		enabled = strings.ToLower(newStatus) == "enable"
	case "delete":
		delete = true
	default:
		web.Respond(w, r, http.StatusBadRequest, fmt.Errorf("invalid status; must be 'enable' or 'disable'"))
		return
	}

	body := &BulkOp{}
	err := web.ReadJson(r, body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	body.NewStatus = enabled
	body.Delete = delete

	err = h.server.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	logger = logger.WithField("bulkUpdate", true)

	detects := []*model.Detection{}
	containsCommunity := false

	if body.Query != nil {
		query := fmt.Sprintf(`(%s) AND _index:"*:so-detection" AND so_kind:detection`, *body.Query)

		var results []interface{}

		results, err = h.server.Detectionstore.Query(ctx, query, -1)
		if err != nil {
			return
		}
		for _, d := range results {
			det := d.(*model.Detection)
			if det.IsCommunity {
				containsCommunity = true
				if delete {
					break
				}
			}

			detects = append(detects, det)
		}
	} else {
		for _, id := range body.IDs {
			det, err := h.server.Detectionstore.GetDetection(ctx, id)
			if err != nil {
				web.Respond(w, r, http.StatusInternalServerError, err)
				return
			}

			if det.IsCommunity {
				containsCommunity = true
				if delete {
					break
				}
			}

			detects = append(detects, det)
		}
	}

	if containsCommunity && body.Delete {
		web.Respond(w, r, http.StatusBadRequest, "ERROR_BULK_COMMUNITY")
		return
	}

	noTimeOutCtx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, ctx.Value(web.ContextKeyRunAsUsername).(string))
	noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId).(string))

	go h.bulkUpdateDetectionAsync(noTimeOutCtx, body, detects, logger)

	web.Respond(w, r, http.StatusAccepted, map[string]interface{}{
		"count": len(detects),
	})
}

func (h *DetectionHandler) bulkUpdateDetectionAsync(ctx context.Context, body *BulkOp, detects []*model.Detection, logger log.Interface) {
	totalTimeStart := time.Now()
	errMap := map[string]string{}
	updated := 0
	audited := 0
	deleted := 0
	filtered := 0

	updateDur := time.Duration(0)
	syncDur := time.Duration(0)

	defer func() {
		totalTime := time.Since(totalTimeStart)

		withStats := logger.WithFields(log.Fields{
			"errMap":     detections.TruncateMap(errMap, 5),
			"total":      len(detects),
			"modified":   updated,
			"deleted":    deleted,
			"filtered":   filtered,
			"updateTime": updateDur.Seconds(),
			"syncTime":   syncDur.Seconds(),
			"totalTime":  totalTime.Seconds(),
		})

		if len(errMap) != 0 {
			withStats.Error("bulk action Detections finished")
		} else {
			withStats.Info("bulk action Detections finished")
		}

		verb := "update"
		if body.Delete {
			verb = "delete"
		}

		h.server.Host.Broadcast("detections:bulkUpdate", "detections", map[string]interface{}{
			"error":    len(errMap),
			"verb":     verb,
			"total":    len(detects),
			"filtered": filtered,
			"modified": updated + deleted,
			"time":     totalTime.Seconds(),
		})
	}()

	start := time.Now()

	bulk, err := h.server.Detectionstore.BuildBulkIndexer(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("failed to create bulk indexer")
		return
	}

	action := "update"
	if body.Delete {
		action = "delete"
	}

	createAudit := []model.AuditInfo{}
	auditMut := sync.Mutex{}
	errMut := sync.Mutex{}

	for i := range detects {
		detect := detects[i]
		id := detect.Id

		if !body.Delete {
			detect.IsEnabled = body.NewStatus

			engine := h.server.DetectionEngines[detect.Engine]

			filterApplied, err := engine.ApplyFilters(detect)
			if err != nil {
				logger.WithError(err).WithFields(log.Fields{
					"detectionPublicId": detect.PublicID,
					"detectionEngine":   detect.Engine,
				}).Error("unable to apply engine filters to detection")

				return
			}

			if filterApplied && detect.IsEnabled != body.NewStatus {
				filtered++
			}
		}

		engine, ok := h.server.DetectionEngines[detect.Engine]
		if !ok {
			logger.WithFields(log.Fields{
				"publicId": detect.PublicID,
				"engine":   detect.Engine,
			}).Error("detection has unsupported engine, skipping")
			errMap[detect.PublicID] = "unsupported engine"

			continue
		}

		exErr := engine.ExtractDetails(detect)
		if exErr != nil {
			logger.WithField("publicId", detect.PublicID).WithError(exErr).Warn("unable to extract details from detection, skipping")
			errMap[detect.PublicID] = fmt.Sprintf("unable to extract details: %s", exErr.Error())

			continue
		}

		document, index, err := h.server.Detectionstore.ConvertObjectToDocument(ctx, "detection", detect, &detect.Auditable, !body.Delete, nil, nil)
		if err != nil {
			errMap[detect.PublicID] = err.Error()
			continue
		}

		work := esutil.BulkIndexerItem{
			Index:      index,
			Action:     action,
			DocumentID: id,
			OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
				auditMut.Lock()
				defer auditMut.Unlock()

				if action == "delete" {
					deleted++
				} else {
					updated++
				}

				createAudit = append(createAudit, model.AuditInfo{
					DocId:     resp.DocumentID,
					Op:        action,
					Detection: detect,
				})
			},
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
				errMut.Lock()
				defer errMut.Unlock()

				if err != nil {
					errMap[detect.PublicID] = err.Error()
				} else {
					errMap[detect.PublicID] = resp.Error.Reason
				}
			},
		}

		if !body.Delete {
			work.Body = bytes.NewReader(document)
		}

		err = bulk.Add(ctx, work)
		if err != nil {
			errMap[detect.PublicID] = err.Error()
			continue
		}
	}

	err = bulk.Close(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to close bulk indexer for detection changes")
		return
	}

	bulk, err = h.server.Detectionstore.BuildBulkIndexer(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("unable to create audit bulk indexer")
		return
	}

	dirty := make([]*model.Detection, 0, len(createAudit))

	for _, audit := range createAudit {
		document, index, err := h.server.Detectionstore.ConvertObjectToDocument(ctx, "detection", audit.Detection, &audit.Detection.Auditable, false, &audit.DocId, &audit.Op)
		if err != nil {
			errMap[audit.Detection.PublicID] = err.Error()
			continue
		}

		err = bulk.Add(ctx, esutil.BulkIndexerItem{
			Index:  index,
			Action: "create",
			Body:   bytes.NewReader(document),
			OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem) {
				auditMut.Lock()
				defer auditMut.Unlock()

				audited++
			},
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, resp esutil.BulkIndexerResponseItem, err error) {
				errMut.Lock()
				defer errMut.Unlock()

				if err != nil {
					errMap[audit.Detection.PublicID] = fmt.Sprintf("AUDIT: %s", err.Error())
				} else {
					errMap[audit.Detection.PublicID] = fmt.Sprintf("AUDIT: %s", resp.Error.Reason)
				}
			},
		})
		if err != nil {
			errMap[audit.Detection.PublicID] = err.Error()
			continue
		}

		det := audit.Detection

		if audit.Op == "delete" {
			det.IsEnabled = false
			det.PendingDelete = true
		}

		det.PersistChange = true

		dirty = append(dirty, det)
	}

	err = bulk.Close(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to close bulk indexer for audit history")
		return
	}

	updateDur = time.Since(start)

	logger.WithFields(log.Fields{
		"bulkUpdated": updated,
		"bulkAudited": audited,
		"errMap":      detections.TruncateMap(errMap, 5),
	}).Info("bulk operation complete")

	start = time.Now()

	errMap, err = syncLocalDetections(ctx, h.server, dirty)
	if err != nil {
		logger.WithError(err).WithField("errMap", detections.TruncateMap(errMap, 5)).Error("unable to sync detections after bulk update")
		return
	}

	postSync := logger.WithField("errMap", detections.TruncateMap(errMap, 5))

	if len(errMap) == 0 {
		postSync.Info("post-bulk sync finished")
	} else {
		postSync.Warn("post-bulk sync finished")
	}

	syncDur = time.Since(start)
}

func syncLocalDetections(ctx context.Context, srv *Server, detections []*model.Detection) (errMap map[string]string, err error) {
	errMap = map[string]string{} // map[det.PublicID]error
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, err
	}

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

// @Summary      Create Detection Comment
// @Description  Creates a new detection comment for the detection associated with the provided detection ID.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The internal detection ID" example(zC73PJABrNRFAsnEYkqy)
// @Param        request body model.DetectionComment true "A detection comment object with the new content; any provided detection ID will be ignored"
// @Success      200  {object}  model.DetectionComment       "The comment has been successfully created"
// @Failure      400                         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/comment/{id} [post]
func (h *DetectionHandler) createComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	body := &model.DetectionComment{}

	err := web.ReadJson(r, &body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	body.DetectionId = detectId

	obj, err := h.server.Detectionstore.CreateComment(ctx, body)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

// @Summary      Get Detection Comment
// @Description  Retrieves the comment associated with the given comment ID.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read]
// @Param        id  path  string  true  "The detection comment ID" example(MeEcnpMB4OVrR03M4und)
// @Success      200  {object}  model.DetectionComment         "The comment has been successfully retrieved"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection was not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/comment/{id} [get]
func (h *DetectionHandler) getDetectionComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")

	obj, err := h.server.Detectionstore.GetComment(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

// @Summary      Update Detection Comment
// @Description  Updates the comment associated with the given comment ID with the provided content.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The detection comment ID" example(MeEcnpMB4OVrR03M4und)
// @Param        request body model.DetectionComment true "A detection object with the new content"
// @Success      200         "The comment has been successfully deleted"
// @Failure      400                         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection was not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/comment/{id} [put]
func (h *DetectionHandler) updateComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commentId := chi.URLParam(r, "id")

	body := &model.DetectionComment{}

	err := web.ReadJson(r, &body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	body.Id = commentId

	obj, err := h.server.Detectionstore.UpdateComment(ctx, body)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

// @Summary      Delete Detection Comment
// @Description  Deletes the comment associated with the given comment ID.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read, detections/write, events/write]
// @Param        id  path  string  true  "The detection comment ID" example(MeEcnpMB4OVrR03M4und)
// @Success      200         "The comment has been successfully deleted"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection was not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/comment/{id} [delete]
func (h *DetectionHandler) deleteComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	commentId := chi.URLParam(r, "id")

	err := h.server.Detectionstore.DeleteComment(ctx, commentId)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Get Detection Comments
// @Description  Retrieves the comments associated with the given detection ID.
// @Tags	     Detections
// @Security     bearer[detections/read, events/read]
// @Param        id  path  string  true  "The internal detection ID" example(zC73PJABrNRFAsnEYkqy)
// @Success      200 {array}  model.DetectionComment  "The comments have been successfully retrieved"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      404                         "Detection was not found"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/{id}/comment [get]
func (h *DetectionHandler) getDetectionComments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	detectId := chi.URLParam(r, "id")

	obj, err := h.server.Detectionstore.GetComments(ctx, detectId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			web.Respond(w, r, http.StatusNotFound, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}

		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

// @Summary      Convert Rule Query
// @Description  Converts the given Sigma Detection rule into an Elasticsearch query.
// @Description  NOTE: The API method only works with Sigma rules.
// @Tags	     Detections
// @Security     bearer
// @Param        request  body  model.Detection  true  "The Sigma detection object with the Content and optional Overrides populated"
// @Success      200  {object}  ConvertContentResp  "The rule has been converted successfully"
// @Failure      400                         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/convert [post]
func (h *DetectionHandler) convertContent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	det := &model.Detection{}

	err := web.ReadJson(r, &det)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	eaQuery, err := h.server.DetectionEngines[model.EngineNameElastAlert].ConvertRule(ctx, det)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, ConvertContentResp{Query: eaQuery})
}

// @Summary      Sync Detections
// @Description  Initiates an asynchronous synchronization of the specified detection engine.
// @Tags	     Detections
// @Security     bearer[detections/write]
// @Param        engine  path  string  true  "The detection engine to sync" Enums(all, elastalert, suricata, strelka")
// @Param        type  path  string  true  "The type of sync to perform" Enums(full, update)
// @Success      200    "The sync has been queued"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Router       /connect/detection/sync/{engine}/{type} [post]
func (h *DetectionHandler) syncEngineDetections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.server.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	engine := strings.ToLower(chi.URLParam(r, "engine"))
	typ := strings.ToLower(chi.URLParam(r, "type"))

	fullUpgrade := typ == "full"

	if engine == "all" {
		for _, engine := range h.server.DetectionEngines {
			engine.InterruptSync(fullUpgrade, true)
		}
	} else {
		engine, ok := h.server.DetectionEngines[model.EngineName(engine)]
		if !ok {
			web.Respond(w, r, http.StatusBadRequest, errors.New("unknown engine"))
			return
		}

		engine.InterruptSync(fullUpgrade, true)
	}

	web.Respond(w, r, http.StatusOK, nil)
}

// @Summary      Generate Public ID
// @Description  Requests the server generate an unused public ID.
// @Tags	     Detections
// @Security     bearer
// @Param        engine  path  string  true  "The detection engine" Enums(elastalert, suricata")
// @Success      200  {object}  GenPublicIdResp  "The ID has been generated"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401                         "Request was not properly authenticated"
// @Failure      403                         "Insufficient permissions for this request"
// @Failure      500                         "Internal SOC error; review SOC logs"
// @Failure      501                         "The specified detection engine does not support public IDs"
// @Router       /connect/detection/{engine}/genpublicid [get]
func (h *DetectionHandler) genPublicId(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	engine := chi.URLParam(r, "engine")

	eng, ok := h.server.DetectionEngines[model.EngineName(engine)]
	if !ok {
		web.Respond(w, r, http.StatusBadRequest, errors.New("unsupported engine"))
		return
	}

	id, err := eng.GenerateUnusedPublicId(ctx)
	if err != nil {
		if err.Error() == "not implemented" {
			web.Respond(w, r, http.StatusNotImplemented, nil)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, GenPublicIdResp{PublicId: id})
}

func (h *DetectionHandler) PrepareForSave(ctx context.Context, detect *model.Detection, e DetectionEngine) error {
	logger := log.FromContext(ctx)

	err := e.ExtractDetails(detect)
	if err != nil {
		return err
	}

	var old *model.Detection

	if detect.PublicID != "" {
		dupe, err := h.server.Detectionstore.GetDetectionByPublicId(ctx, detect.PublicID)
		if err != nil {
			return err
		}

		if dupe != nil {
			if dupe.Id == detect.Id {
				old = dupe
			} else {
				return errPublicIdExists
			}
		}
	}

	if old == nil {
		old, err = h.server.Detectionstore.GetDetection(ctx, detect.Id)
		if err != nil {
			return err
		}
	}

	detect.CreateTime = old.CreateTime
	detect.Ruleset = old.Ruleset

	// Existing rules will preserve their Author and License for copyright reasons.
	if len(old.Author) > 0 {
		detect.Author = old.Author
	}
	if len(old.License) > 0 {
		detect.License = old.License
	}

	now := time.Now()

	for _, over := range detect.Overrides {
		if over.CreatedAt.IsZero() {
			over.CreatedAt = now
		}

		update := true
		for i, oldOver := range old.Overrides {
			if over.Equal(oldOver) {
				// Did the old detection contain an override with the EXACT same parameters?
				// If so, we don't need to update the UpdatedAt field.
				update = false

				// A match was found, the old override can be removed from the list so it
				// isn't compared to other overrides. i.e. removing it means it can only
				// match one override in the new list.
				old.Overrides = append(old.Overrides[:i], old.Overrides[i+1:]...)

				break
			}
		}

		if over.UpdatedAt.IsZero() || update {
			over.UpdatedAt = now
		}
	}

	if old.IsCommunity {
		// the only editable fields for community rules are IsEnabled, IsReporting, Note, and Overrides
		old.IsEnabled = detect.IsEnabled
		old.IsReporting = detect.IsReporting
		old.Overrides = detect.Overrides
		old.Tags = detect.Tags

		*detect = *old

		logger.Infof("existing detection %s is a community rule, only updating select fields", detect.Id)
	} else if detect.IsCommunity {
		return errors.New("cannot update an existing non-community detection to make it a community detection")
	}

	detect.Kind = ""

	return nil
}
