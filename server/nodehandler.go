// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

// @Summary      Node Check-in / Get Pending Jobs
// @Description  Used by Security Onion agent nodes to check-in with their current metrics and request any pending jobs assigned to it.
// @Tags         Grid, Jobs
// @Security     bearer[nodes/write,jobs/process]
// @Param        request body  model.Node  true  "The node object with recent metrics"
// @Produce      json
// @Success      200  {array}  model.Job       "The array of assigned, pending jobs that this node is responsible for processing, if any"
// @Failure      400       "The provided input object or parameters are malformed or invalid"
// @Failure      401       "Request was not properly authenticated"
// @Failure      500       "Internal SOC error; review SOC logs"
// @Router       /connect/node/{jobId} [post]
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
