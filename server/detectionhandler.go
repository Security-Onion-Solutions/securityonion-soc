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
	IDs       []string `json:"ids"`
	Query     *string  `json:"query"`
	NewStatus bool     `json:"-"`
	Delete    bool     `json:"-"`
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

	eng, ok := h.server.DetectionEngines[detect.Engine]
	if !ok {
		log.WithFields(log.Fields{
			"detectionEngine":   detect.Engine,
			"detectionPublicId": detectId,
		}).Error("retrieved detection with unsupported engine")
	} else {
		err = eng.MergeAuxiliaryData(detect)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"detectionEngine":   detect.Engine,
				"detectionPublicId": detectId,
			}).Error("unable to merge auxiliary data into detection")
		}
	}

	web.Respond(w, r, http.StatusOK, detect)
}

func (h *DetectionHandler) getByPublicId(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	web.Respond(w, r, http.StatusOK, detect)
}

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

	err = engine.ExtractDetails(detect)
	if err != nil {
		if err.Error() == "rule does not contain a public Id" {
			web.Respond(w, r, http.StatusBadRequest, "missingPublicIdErr")
		} else {
			web.Respond(w, r, http.StatusBadRequest, err)
		}

		return
	}

	_, err = engine.ApplyFilters(detect)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
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

func (h *DetectionHandler) updateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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
			log.WithError(err).WithField("detection", detect).Error("unable to sync detection; attempting to disable and resync")

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

func (h *DetectionHandler) bulkUpdateDetection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	logger := log.WithField("bulkUpdate", true)

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

	noTimeOutCtx := context.WithValue(context.Background(), web.ContextKeyRequestor, ctx.Value(web.ContextKeyRequestor).(*model.User))
	noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId).(string))

	go h.bulkUpdateDetectionAsync(noTimeOutCtx, body, detects, logger)

	web.Respond(w, r, http.StatusAccepted, map[string]interface{}{
		"count": len(detects),
	})
}

func (h *DetectionHandler) bulkUpdateDetectionAsync(ctx context.Context, body *BulkOp, detects []*model.Detection, logger *log.Entry) {
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

		withStats := log.WithFields(log.Fields{
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

	web.Respond(w, r, http.StatusOK, map[string]string{
		"query": eaQuery,
	})
}

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

	web.Respond(w, r, http.StatusOK, map[string]string{
		"publicId": id,
	})
}

func (h *DetectionHandler) PrepareForSave(ctx context.Context, detect *model.Detection, e DetectionEngine) error {
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

		log.Infof("existing detection %s is a community rule, only updating select fields", detect.Id)
	} else if detect.IsCommunity {
		return errors.New("cannot update an existing non-community detection to make it a community detection")
	}

	detect.Kind = ""

	return nil
}
