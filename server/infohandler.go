// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type InfoHandler struct {
	server    *Server
	timezones []string
}

func RegisterInfoRoutes(srv *Server, r chi.Router, prefix string) {
	h := &InfoHandler{
		server:    srv,
		timezones: srv.GetTimezones(),
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getInfo)
	})
}

// @Summary      Get Server Information
// @Description  Requests the Security Onion grid general details.
// @Tags         Grid
// @Security     bearer
// @Produce      json
// @Success      200  {object}  model.Info   "The retrieved Info object"
// @Failure      401         "Request was not properly authenticated"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/info/ [get]
func (h *InfoHandler) getInfo(w http.ResponseWriter, r *http.Request) {
	userId, ok := r.Context().Value(web.ContextKeyRequestorId).(string)
	if !ok {
		err := errors.New("Unable to determine logged in user from context")
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	var srvToken string
	var forceUserOtp bool
	var params *model.ClientParameters
	exempt := r.Context().Value(web.ContextKeyRequestCSRFExempt).(bool)
	if !exempt {
		var err error
		srvToken, err = model.GenerateSrvToken(h.server.Config.SrvKeyBytes, userId, h.server.Config.SrvExpSeconds)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		user, err := h.server.Userstore.GetUserById(r.Context(), userId)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		forceUserOtp = user.TotpStatus != "enabled" && h.server.Config.ForceUserOtp
		params = &h.server.Config.ClientParams
	}

	mgmtMac := "unknown"
	if h.server.Datastore != nil {
		for _, node := range h.server.Datastore.GetNodes(h.server.Context) {
			if node.IsManager() {
				mgmtMac = node.MgmtMac
			}
		}
	}

	subgrids := make([]*model.Subgrid, 0)
	if licensing.ValidateSubgridCount(len(subgrids)) {
		subgrids = h.server.Config.Subgrids
	}

	info := &model.Info{
		Version:        h.server.Host.Version,
		License:        "Elastic License 2.0 (ELv2)",
		LicenseKey:     licensing.GetLicenseKey().LicenseKey,
		LicenseStatus:  licensing.GetStatus(),
		Parameters:     params,
		ElasticVersion: os.Getenv("ELASTIC_VERSION"),
		UserId:         userId,
		Timezones:      h.timezones,
		SrvToken:       srvToken,
		ForceUserOtp:   forceUserOtp,
		MgmtMac:        mgmtMac,
		Subgrids:       subgrids,
		CustomReports:  h.getCustomReports(h.server.Config.CustomReportsPath),
	}

	web.Respond(w, r, http.StatusOK, info)
}

func (h *InfoHandler) getCustomReports(path string) map[string]string {
	reports := make(map[string]string)

	// Iterate through the custom reports directory and populate the reports map.
	files, err := os.ReadDir(path)
	if err != nil {
		log.WithError(err).WithField("customReportsPath", path).Error("Failed to read custom reports directory")
		return reports
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".md") {
			filePath := path + "/" + file.Name()
			content, err := os.ReadFile(filePath)
			if err != nil {
				log.WithError(err).WithField("customReportFilePath", filePath).Error("Failed to read custom report file")
				continue
			}
			title := h.parseReportTitle(content, file.Name())
			reports[file.Name()] = title
		}
	}

	return reports
}

func (h *InfoHandler) parseReportTitle(content []byte, deflt string) string {
	title := deflt

	// Extract the title from the markdown content. We're looking for the first line that has a series of dashes underneath it.
	prevLine := ""
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "===") && prevLine != "" {
			title = strings.TrimSpace(prevLine)
			break
		}
		// If the line is not a title, we store it as the previous line.
		prevLine = strings.TrimSpace(line)
	}

	return title
}
