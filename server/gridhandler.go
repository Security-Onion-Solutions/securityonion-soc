// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"net/http"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/model"
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
		r.Get("/status", h.getStatus)
		r.Get("/{id}/metrics", h.getNodeMetrics)
	})
}

// @Summary      Get Node Historical Metrics
// @Description  Retrieves historical performance metrics for a specific grid node.
// @Tags         Grid
// @Security     bearer[nodes/read]
// @Param        id path string true "The node ID"
// @Produce      json
// @Success      200  {object}  model.HistoricalMetrics "The node historical metrics"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Failure      503                                 "Metrics module not enabled"
// @Router       /connect/grid/{id}/metrics [get]
func (h *GridHandler) getNodeMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	duration := r.URL.Query().Get("range")

	if h.server.Metrics == nil {
		web.Respond(w, r, http.StatusServiceUnavailable, nil)
		return
	}

	metrics, err := h.server.Metrics.GetHistoricalMetrics(ctx, id, duration)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, metrics)
}

// @Summary      Get Grid Status
// @Description  Retrieves the status of the grid overall.
// @Description  Includes grid health status information related to nodes, alerts, detection engines, etc.
// @Tags         Grid
// @Security     bearer[grid/read]
// @Produce      json
// @Success      200  {array}  model.Status          "The grid Status summary"
// @Failure      401                                 "Request was not properly authenticated"
// @Failure      403                                 "Insufficient permissions for this request"
// @Failure      500                                 "Internal SOC error; review SOC logs"
// @Router       /connect/grid/status [get]
func (h *GridHandler) getStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.server.Statusstore.GetStatusSummary(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	assignedGridId := r.URL.Query().Get("assignedGridId")
	log.WithFields(log.Fields{
		"assignedGridId": assignedGridId,
	}).Debug("assigning grid id to status")
	statusCopy := *status
	statusCopy.GridId = assignedGridId

	web.Respond(w, r, http.StatusOK, statusCopy)
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
	newNodes := make([]model.Node, 0)

	assignedGridId := r.URL.Query().Get("assignedGridId")
	for _, node := range nodes {
		log.WithFields(log.Fields{
			"nodeId":         node.Id,
			"assignedGridId": assignedGridId,
		}).Debug("assigning grid id to node")
		nodeCopy := *node
		nodeCopy.GridId = assignedGridId
		newNodes = append(newNodes, nodeCopy)
	}

	web.Respond(w, r, http.StatusOK, newNodes)
}
