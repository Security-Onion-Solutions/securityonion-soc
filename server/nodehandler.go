// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
)

type NodeHandler struct {
	server *Server
}

func RegisterNodeRoutes(srv *Server, r chi.Router, prefix string) {
	h := &NodeHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Post("/", h.postNode)
	})
}

func (h *NodeHandler) postNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	node := model.NewNode("")

	err := web.ReadJson(r, node)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	node, err = h.server.Datastore.UpdateNode(ctx, node)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if h.server.Metrics != nil {
		h.server.Metrics.UpdateNodeMetrics(ctx, node)
	}
	h.server.Host.Broadcast("node", "nodes", node)
	job := h.server.Datastore.GetNextJob(ctx, node.Id)

	web.Respond(w, r, http.StatusOK, job)
}
