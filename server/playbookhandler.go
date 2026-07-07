// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		r.Post("/question", h.ExecutePlaybookQuestion)
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

// alertTimestampLayouts are the timestamp formats a source event may carry.
var alertTimestampLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"}

// parseAlertTimestamp parses the ts query param against the accepted layouts.
func parseAlertTimestamp(raw string) (time.Time, error) {
	var ts time.Time
	var err error
	for _, layout := range alertTimestampLayouts {
		if ts, err = time.Parse(layout, raw); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, err
}

// @Summary      Execute Playbook Question
// @Description  Executes a single converted playbook question and returns it with queryResults populated. A question without a range is rejected: it is answered by the alert itself, not this route.
// @Tags         Playbooks
// @Security     bearer[playbooks/read, events/read]
// @Param        ts        query  string          true  "Alert timestamp that anchors the question's relative range (RFC3339 or '2006-01-02 15:04:05')"
// @Param        question  body   model.Question  true  "The question to execute; needs the range and converted oqlQuery, plus fields and isAggregate from conversion"
// @Success      200  {object}  model.Question  "The question was executed"
// @Failure      400                            "Malformed request"
// @Failure      401                            "Request was not properly authenticated"
// @Failure      500                            "Internal SOC error; review SOC logs"
// @Accept       application/json
// @Produce      application/json
// @Router       /connect/playbook/question [post]
func (h *PlaybookHandler) ExecutePlaybookQuestion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := h.server.CheckAuthorized(ctx, "read", "playbooks")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	err = h.server.CheckAuthorized(ctx, "read", "events")
	if err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	// ts anchors the question's relative range, so it's required
	ts, err := parseAlertTimestamp(r.URL.Query().Get("ts"))
	if err != nil {
		logger.WithError(err).Error("invalid or missing ts")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	question := &model.Question{}
	err = web.ReadJson(r, question)
	if err != nil {
		logger.WithError(err).Error("invalid question body")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if question.Range == nil || question.OqlQuery == "" {
		logger.Error("question range and oqlQuery required")
		web.Respond(w, r, http.StatusBadRequest, errors.New("question range and oqlQuery are required"))
		return
	}

	err = h.server.Playbookstore.ExecuteQuestionSearch(ctx, ts, question)
	if err != nil {
		logger.WithError(err).Error("unable to execute playbook question search")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, question)
}

// @Summary      Get Event-Specific Playbook
// @Description	 Fetches the playbook for a specific event.
// @Tags         Playbooks
// @Security     bearer[playbooks/read, detections/read, events/read]
// @Param        id  path  string  true        "The SOC Id for the alert"
// @Param        stage query string false      "How much of the query pipeline to run: skeleton (questions only), convert (questions with OQL queries), or full (queries executed; the default)" enums(skeleton,convert,full)
// @Param        ts    query string false      "Alert timestamp (RFC3339 or '2006-01-02 15:04:05') used to narrow the alert lookup; ignored if absent or unparseable"
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

	stage := model.PlaybookStage(r.URL.Query().Get("stage"))
	switch stage {
	case model.PlaybookStageSkeleton, model.PlaybookStageConvert, model.PlaybookStageFull:
	default:
		stage = model.PlaybookStageFull
	}

	// optional ts narrows the alert lookup; zero time means unbounded
	ts, _ := parseAlertTimestamp(r.URL.Query().Get("ts"))

	pbs, err := h.server.Playbookstore.GetEventSpecificPlaybook(ctx, socId, stage, ts)
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
