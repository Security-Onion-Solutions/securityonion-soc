// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type PacketHandler struct {
	server *Server
}

func RegisterPacketRoutes(srv *Server, r chi.Router, prefix string) {
	h := &PacketHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getPackets)
		r.Get("/{jobId}", h.getPackets)
	})
}

func (h *PacketHandler) getPackets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "jobId")
	if id == "" {
		id = r.URL.Query().Get("jobId")
	}

	jobId, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	unwrap, err := strconv.ParseBool(r.URL.Query().Get("unwrap"))
	if err != nil {
		unwrap = false
	}

	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 32)
	if offset <= 0 || err != nil {
		offset = 0
	}

	count := h.server.Config.MaxPacketCount
	count64, err := strconv.ParseInt(r.URL.Query().Get("count"), 10, 32)
	if err == nil {
		tmpCount := int(count64)
		if tmpCount > 0 && tmpCount < count {
			count = tmpCount
		}
	}

	packets, err := h.server.Datastore.GetPackets(ctx, int(jobId), int(offset), count, unwrap)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, packets)
}
