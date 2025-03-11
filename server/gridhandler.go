// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type GridHandler struct {
	server *Server
}

func RegisterGridRoutes(srv *Server, r chi.Router, prefix string) {
	h := &GridHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getNodes)
	})
}

// @Summary      Get Grid Nodes
// @Description  Retrieves the list of nodes that have recently checked-in with SOC. Nodes are grid members that have recently checked in with SOC.
// @Description  Under certain scenarios this may not include nodes that are accepted members of the grid but currently offline.
// @Description  Effectively, the results of this API call will match the view of the Grid screen in SOC (Not the Grid Members screen).
// @Tags         Grid
// @Security     bearer[nodes/read]
// @Produce      json
// @Success      200  {array}  model.Node            "The list of grid nodes or an empty list is insufficient permissions"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/grid/ [get]
func (h *GridHandler) getNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nodes := h.server.Datastore.GetNodes(ctx)
	nodes = append(nodes, h.server.SubgridNodes...)

	web.Respond(w, r, http.StatusOK, nodes)
}
