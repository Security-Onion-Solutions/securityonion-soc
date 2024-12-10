// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
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

// @Summary      Download Job Output
// @Description  Returns the full job output stream for the given job ID. An example of a job stream is a packet capture (PCAP) file.
// @Tags	     Jobs
// @Security     bearer[jobs/read]
// @Param        jobId  path  integer  true  "The job ID" example(1004)
// @Param        ext  query  string  false  "Optional filename extension to use on the returned stream. Appends extension to stream name, unless stream name already contains '.bin' in which case it replaces that extension." example(pcap)
// @Param        unwrap  query  boolean  false  "If true, and if the stream data is eligible the stream data will be unwrapped. An example of wrapped stream data is VXLAN packet data." example(true)
// @Success      200                         "The job output stream has been successfully retrieved"
// @Failure      400        "The provided input object or parameters are malformed or invalid"
// @Failure      401        "Request was not properly authenticated"
// @Failure      403        "Insufficient permissions for this request"
// @Failure      404        "Job not found"
// @Failure      500        "Internal SOC error; review SOC logs"
// @Header       200  {string}  Content-Disposition  "The stream's file meta-data. Ex: inline; filename=foo.bin"
// @Header       200  {string}  Content-Transfer-Encoding  "The encoding type of the response stream. Ex: binary"vnd.tcpdump.pcap
// @Header       200  {string}  Content-Type  "The MIME type of the returned stream. For PCAP this will be vnd.tcpdump.pcap"
// @Router       /connect/stream/{jobId} [get]
func (h *StreamHandler) getStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

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
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	reader, filename, length, err := h.server.Datastore.GetPacketStream(ctx, int(jobId), unwrap)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	defer reader.Close()

	extension := r.URL.Query().Get("ext")
	if len(extension) > 0 {
		safe := extensionVerifier.MatchString(extension)
		if !safe {
			web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid extension"))
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
		logger.WithError(err).WithFields(log.Fields{
			"streamFilename": filename,
		}).Error("Failed to copy stream")
		web.Respond(nil, r, http.StatusInternalServerError, err)

		return
	}

	logger.WithFields(log.Fields{
		"streamFilename": filename,
		"streamSize":     written,
	}).Info("Copied stream to response")

	web.Respond(nil, r, http.StatusOK, nil)
}

// @Summary      Upload Job Output
// @Description  Sends the job output up to the server for posterity and future retrieval. Not all jobs will have binary job output to upload. The job ID is used to reference the job for this output stream.
// @Tags	     Jobs
// @Security     bearer[jobs/process]
// @Param        jobId  path  integer  true  "The job ID" example(1004)
// @Param        request body object  true  "The job output stream byte content"
// @Accept       octet-stream
// @Success      200                         "The job output stream was successfully saved"
// @Failure      400  {string}  string       "The provided input object or parameters are malformed or invalid"
// @Failure      401  {string}  string       "Request was not properly authenticated"
// @Failure      403  {string}  string       "Insufficient permissions for this request"
// @Failure      404  {string}  string       "Job not found"
// @Failure      500  {string}  string       "Internal SOC error; review SOC logs"
// @Router       /connect/stream/{jobId} [post]
func (h *StreamHandler) postStream(w http.ResponseWriter, r *http.Request) {
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

	err = h.server.Datastore.SavePacketStream(ctx, int(jobId), r.Body)
	if err != nil {
		if err.Error() == "Job not found" {
			web.Respond(w, r, http.StatusNotFound, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
