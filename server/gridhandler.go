// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
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
		r.Get("/metrics", h.getMetricsHistory)
	})
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

// @Summary      Get Historical Grid Metrics
// @Description  Retrieves historical time-series metrics for a specific node and metric type over a given time range.
// @Tags         Grid
// @Security     bearer[nodes/read]
// @Produce      json
// @Param        nodeId  query  string  false  "The optional node ID to retrieve metrics for"
// @Param        metric  query  string  true   "The name of the metric to retrieve (e.g., cpu, memory, load, disk, net)"
// @Param        range   query  string  true   "Date range, in the specified timezone" example(2024/12/03 03:09:31 PM - 2024/12/04 03:09:31 PM)
// @Param        zone    query  string  true   "Timezone of the date range" example(America/New_York)
// @Param        format  query  string  true   "Date range date format" example(2006/01/02 3:04:05 PM)
// @Success      200     {object}  map[string][]model.MetricSample "A map where keys are metric names/sources and values are arrays of metric samples"
// @Failure      400     "The provided input parameters are malformed or invalid"
// @Failure      401     "Request was not properly authenticated or authorized"
// @Failure      403     "Insufficient permissions for this request"
// @Failure      500     "Internal SOC error; review SOC logs"
// @Router       /connect/grid/metrics [get]
func (h *GridHandler) getMetricsHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	err := r.ParseForm()
	if err != nil {
		logger.WithError(err).Error("unable to parse query string")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	nodeId := r.Form.Get("nodeId")
	metricType := r.Form.Get("metric")
	rangeVal := r.Form.Get("range")
	format := r.Form.Get("format")
	zone := r.Form.Get("zone")

	if metricType == "" {
		web.Respond(w, r, http.StatusBadRequest, "metric is required")
		return
	}

	start, end, err := util.ParseDateRange(rangeVal, format, zone)
	if err != nil {
		logger.WithError(err).Error("unable to parse date range from query string")
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if h.server.Metrics == nil {
		web.Respond(w, r, http.StatusOK, make(map[string][]model.MetricSample))
		return
	}

	data, err := h.server.Metrics.GetTimeSeriesMetrics(ctx, nodeId, metricType, start, end)
	if err != nil {
		logger.WithError(err).Error("unable to get time series metrics")
		var unauthErr *model.Unauthorized
		if errors.As(err, &unauthErr) {
			web.Respond(w, r, http.StatusUnauthorized, err)
			return
		}
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	if data == nil {
		data = make(map[string][]model.MetricSample)
	}

	web.Respond(w, r, http.StatusOK, data)
}
