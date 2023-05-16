// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/go-chi/chi"
)

var extensionVerifier = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

type StreamHandler struct {
	server *Server
}

func RegisterStreamRoutes(srv *Server, r chi.Router, prefix string) {
	h := &StreamHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getStream)
		r.Get("/{jobId}", h.getStream)

		r.Post("/", h.postStream)
		r.Post("/{jobId}", h.postStream)
	})
}

func (h *StreamHandler) getStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "jobId")
	if id == "" {
		id = r.URL.Query().Get("jobId")
	}

	jobId, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	unwrap, err := strconv.ParseBool(r.URL.Query().Get("unwrap"))
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	reader, filename, length, err := h.server.Datastore.GetPacketStream(ctx, int(jobId), unwrap)
	if err != nil {
		Respond(w, r, http.StatusNotFound, err)
		return
	}

	defer reader.Close()

	extension := r.URL.Query().Get("ext")
	if len(extension) > 0 {
		safe := extensionVerifier.MatchString(extension)
		if !safe {
			Respond(w, r, http.StatusBadRequest, errors.New("Invalid extension"))
			return
		}

		extension = "." + extension
		if !strings.HasSuffix(filename, extension) {
			filename = strings.TrimSuffix(filename, ".bin") + extension
		}
	}

	w.Header().Set("Content-Type", "vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
	w.Header().Set("Content-Transfer-Encoding", "binary")

	written, err := io.Copy(w, reader)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"name": filename,
		}).Error("Failed to copy stream")
		Respond(nil, r, http.StatusInternalServerError, err)

		return
	}

	log.WithFields(log.Fields{
		"name": filename,
		"size": written,
	}).Info("Copied stream to response")

	Respond(nil, r, http.StatusOK, nil)
}

func (h *StreamHandler) postStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "jobId")
	if id == "" {
		id = r.URL.Query().Get("jobId")
	}

	jobId, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		Respond(w, r, http.StatusBadRequest, err)
		return
	}

	err = h.server.Datastore.SavePacketStream(ctx, int(jobId), r.Body)
	if err != nil {
		Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	Respond(w, r, http.StatusOK, nil)
}
