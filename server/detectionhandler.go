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
	"regexp"
	"strings"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/syntax"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi"
)

var sidExtracter = regexp.MustCompile(`\bsid: ?['"]?(.*?)['"]?;`)

const suricataModifyFromTo = `"flowbits" "noalert; flowbits"`

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

	errMap, err := SyncDetections(ctx, h.server.Configstore, []*model.Detection{detect})
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

	errMap, err := SyncDetections(ctx, h.server.Configstore, []*model.Detection{detect})
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

	old, err := h.server.Casestore.DeleteDetection(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	errMap, err := SyncDetections(ctx, h.server.Configstore, []*model.Detection{old})
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
		det, mod, err := h.server.Casestore.UpdateDetectionField(ctx, id, "IsEnabled", enabled)
		if err != nil {
			errMap[id] = fmt.Sprintf("unable to update detection; reason=%s", err.Error())
			continue
		}

		if mod {
			modified = append(modified, det)
		}
	}

	if len(modified) != 0 {
		addErrMap, err := SyncDetections(ctx, h.server.Configstore, modified)
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

func SyncDetections(ctx context.Context, cfgStore Configstore, detections []*model.Detection) (errMap map[string]string, err error) {
	defer func() {
		if len(errMap) == 0 {
			errMap = nil
		}
	}()

	byEngine := map[model.EngineName][]*model.Detection{}
	for _, detect := range detections {
		byEngine[detect.Engine] = append(byEngine[detect.Engine], detect)
	}

	if len(byEngine[model.EngineNameSuricata]) > 0 {
		errMap, err = syncSuricata(ctx, cfgStore, byEngine[model.EngineNameSuricata])
		if err != nil {
			return errMap, err
		}
	}

	return errMap, nil
}

func syncSuricata(ctx context.Context, cfgStore Configstore, detections []*model.Detection) (map[string]string, error) {
	allSettings, err := cfgStore.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	local := settingByID(allSettings, "idstools.rules.local__rules")
	if local == nil {
		return nil, fmt.Errorf("unable to find local rules setting")
	}

	enabled := settingByID(allSettings, "idstools.sids.enabled")
	if enabled == nil {
		return nil, fmt.Errorf("unable to find enabled setting")
	}

	modify := settingByID(allSettings, "idstools.sids.modify")
	if modify == nil {
		return nil, fmt.Errorf("unable to find modify setting")
	}

	localLines := strings.Split(local.Value, "\n")
	enabledLines := strings.Split(enabled.Value, "\n")
	modifyLines := strings.Split(modify.Value, "\n")

	localIndex := indexLocal(localLines)
	enabledIndex := indexEnabled(enabledLines)
	modifyIndex := indexModified(modifyLines)

	errMap := map[string]string{} // map[sid]error

	for _, detect := range detections {
		parsedRule, err := syntax.ParseSuricataRule(detect.Content)
		if err != nil {
			errMap[detect.PublicID] = fmt.Sprintf("unable to parse rule; reason=%s", err.Error())
			continue
		}

		opt, ok := parsedRule.GetOption("sid")
		if !ok || opt == nil {
			errMap[detect.PublicID] = fmt.Sprintf("rule does not contain a SID; rule=%s", detect.Content)
			continue
		}

		sid := *opt
		_, isFlowbits := parsedRule.GetOption("flowbits")

		lineNum, inLocal := localIndex[sid]
		if !inLocal {
			localLines = append(localLines, detect.Content)
			lineNum = len(localLines) - 1
			localIndex[sid] = lineNum
		} else {
			localLines[lineNum] = detect.Content
		}

		lineNum, inEnabled := enabledIndex[sid]
		if !inEnabled {
			line := detect.PublicID
			if !detect.IsEnabled && !isFlowbits {
				line = "# " + line
			}

			enabledLines = append(enabledLines, line)
			lineNum = len(enabledLines) - 1
			enabledIndex[sid] = lineNum
		} else {
			line := detect.PublicID
			if !detect.IsEnabled && !isFlowbits {
				line = "# " + line
			}

			enabledLines[lineNum] = line
		}

		if isFlowbits {
			lineNum, inModify := modifyIndex[sid]
			if !inModify && !detect.IsEnabled {
				// not in the modify file, but should be
				line := fmt.Sprintf("%s %s", detect.PublicID, suricataModifyFromTo)
				modifyLines = append(modifyLines, line)
				lineNum = len(modifyLines) - 1
				modifyIndex[sid] = lineNum
			} else if inModify && detect.IsEnabled {
				// in modify, but shouldn't be
				modifyLines = append(modifyLines[:lineNum], modifyLines[lineNum+1:]...)
				delete(modifyIndex, sid)
			}
		}
	}

	local.Value = strings.Join(localLines, "\n")
	enabled.Value = strings.Join(enabledLines, "\n")
	modify.Value = strings.Join(modifyLines, "\n")

	err = cfgStore.UpdateSetting(ctx, local, false)
	if err != nil {
		return errMap, err
	}

	err = cfgStore.UpdateSetting(ctx, enabled, false)
	if err != nil {
		return errMap, err
	}

	err = cfgStore.UpdateSetting(ctx, modify, false)
	if err != nil {
		return errMap, err
	}

	return errMap, nil
}

func settingByID(all []*model.Setting, id string) *model.Setting {
	found, ok := lo.Find(all, func(s *model.Setting) bool {
		return s.Id == id
	})
	if !ok {
		return nil
	}

	return found
}

func extractSID(rule string) *string {
	sids := sidExtracter.FindStringSubmatch(rule)
	if len(sids) != 2 { // 0: Full Match, 1: Capture Group
		return nil
	}

	return util.Ptr(strings.TrimSpace(sids[1]))
}

func indexLocal(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		sid := extractSID(line)
		if sid == nil {
			continue
		}

		index[*sid] = i
	}

	return index
}

func indexEnabled(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, "# \t"))
		if line != "" {
			index[line] = i
		}
	}

	return index
}

func indexModified(lines []string) map[string]int {
	index := map[string]int{}

	for i, line := range lines {
		line = strings.TrimSpace(strings.TrimLeft(line, " \t"))
		parts := strings.SplitN(line, " ", 2)

		if strings.Contains(line, suricataModifyFromTo) {
			index[parts[0]] = i
		}
	}

	return index
}
