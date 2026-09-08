// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

// @Summary      Get PCAP Packets
// @Description  Retrieves the packets collected and attached to the job represented by the given job ID. This request assumes the job is a PCAP job.
// @Tags         Jobs
// @Security     bearer[jobs/read]
// @Param        jobId  path  integer  true  "The job ID" example(1004)
// @Param        unwrap  query  boolean  false  "If true, and if the stream data is eligible the stream data will be unwrapped. An example of wrapped stream data is VXLAN packet data." example(true)
// @Param        excludeErrors  query  boolean  false  "If true, packet decode failures will be excluded from the returned results." example(true)
// @Param        offset  query  integer  false  "The starting offset of the packet to retrieve; used for paging large packet results. Defaults to 0." example(100)
// @Param        count  query  integer  false  "The maximum number of packets to retrieve; used for paging large packet results. Defaults to 5000, or an optional server-side configuration value/" example(100)
// @Produce      json
// @Success      200  {array}  model.Packet       "The array of retrieved Packet objects"
// @Header       200  {string}  X-Decode-Errors-Present  "Indicates whether any packets in the PCAP capture encountered decode failures (true or false)"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      404         "The job was not found"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/packets/{jobId} [get]
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

	excludeErrors, err := strconv.ParseBool(r.URL.Query().Get("excludeErrors"))
	if err != nil {
		excludeErrors = false
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

	packets, hasErrors, err := h.server.Datastore.GetPackets(ctx, int(jobId), int(offset), count, unwrap, excludeErrors)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	if hasErrors {
		w.Header().Set("X-Decode-Errors-Present", "true")
	} else {
		w.Header().Set("X-Decode-Errors-Present", "false")
	}

	web.Respond(w, r, http.StatusOK, packets)
}
