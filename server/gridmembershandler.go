// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi"
	"github.com/samber/lo"
)

type GridMembersHandler struct {
	server *Server
}

func RegisterGridMemberRoutes(srv *Server, r chi.Router, prefix string) {
	h := &GridMembersHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.gridMembersEnabled)

		r.Get("/", h.getGridMembers)

		r.Post("/{id}/import", h.postImport)
		r.Post("/{id}/{operation}", h.postManageMembers)
	})
}

func (h *GridMembersHandler) gridMembersEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.GridMembersstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("GridMembers module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *GridMembersHandler) getGridMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	members, err := h.server.GridMembersstore.GetMembers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, members)
}

func (h *GridMembersHandler) postImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if !model.IsValidMinionId(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid minion ID"))
		return
	}

	members, err := h.server.GridMembersstore.GetMembers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	_, gmExists := lo.Find(members, func(m *model.GridMember) bool {
		return strings.EqualFold(m.Id, id)
	})
	if !gmExists {
		web.Respond(w, r, http.StatusNotFound, errors.New("grid member not found"))
		return
	}

	err = r.ParseMultipartForm(int64(h.server.Config.MaxUploadSizeBytes))
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	file, header, err := r.FormFile("attachment")
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	if file == nil {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Attachment file not found"))
		return
	}
	defer file.Close()

	if header.Size < 7 {
		web.Respond(w, r, http.StatusBadRequest, errors.New("File too small to validate"))
		return
	}

	// pcap's magic number is 4 bytes long, evtx is 7
	magicBytes := make([]byte, 7)
	n, err := file.Read(magicBytes)
	if err != nil || n < 7 {
		if err == nil {
			err = errors.New("Unable to validate file")
		}

		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	ext := filepath.Ext(strings.ToLower(header.Filename))
	switch ext {
	case ".pcap":
		// wikipedia lists both endiannesses as correct
		if !canUploadPcap(id) {
			err = fmt.Errorf("this node (%s) does not support importing PCAP files", id)
		} else if !bytes.Equal(magicBytes[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) &&
			!bytes.Equal(magicBytes[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}) {
			err = errors.New("PCAP file missing magic bytes")
		}
	case ".evtx":
		if !canUploadEvtx(id) {
			err = fmt.Errorf("this node (%s) does not support importing EVTX files", id)
		} else if !bytes.Equal(magicBytes, []byte{0x45, 0x6c, 0x66, 0x46, 0x69, 0x6C, 0x65}) {
			err = errors.New("EVTX file missing magic bytes")
		}
	default:
		err = errors.New("Invalid extension")
	}

	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	ext = ext[1:]

	baseTargetDir := "/nsm/soc/uploads/"
	targetDir := filepath.Join(baseTargetDir, "processing", id)

	err = os.MkdirAll(targetDir, 0775)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	filename := strings.ReplaceAll(header.Filename, " ", "_")

	targetFile := filepath.Join(targetDir, filename)

	out, err := os.OpenFile(targetFile, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		_, check := os.Stat(targetFile)
		if check == nil {
			web.Respond(w, r, http.StatusConflict, err)
		} else {
			web.Respond(w, r, http.StatusInternalServerError, err)
		}
		return
	}

	outClosed := false
	needsCleanup := false
	defer func() {
		if !outClosed {
			out.Close()
		}

		if needsCleanup {
			os.Remove(targetFile)
		}
	}()

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		needsCleanup = true
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	_, err = io.Copy(out, file)
	if err != nil {
		needsCleanup = true
		web.Respond(w, r, http.StatusInternalServerError, err)

		return
	}

	out.Close()
	outClosed = true

	web.Respond(w, r, http.StatusAccepted, nil)

	go func() {
		err = h.server.GridMembersstore.SendFile(ctx, id, targetFile, baseTargetDir, true)
		if err != nil {
			needsCleanup = true
			web.Respond(nil, r, http.StatusInternalServerError, err)

			return
		}

		targetFile = filepath.Join(baseTargetDir, filename)

		dashboardURL, err := h.server.GridMembersstore.Import(ctx, id, targetFile, ext)
		if err != nil {
			web.Respond(nil, r, http.StatusInternalServerError, err)
			return
		}

		if dashboardURL != nil && *dashboardURL != "" {
			h.server.Host.Broadcast("import", "jobs", dashboardURL)
		} else {
			h.server.Host.Broadcast("import", "jobs", "no-changes")
		}
	}()
}

func (h *GridMembersHandler) postManageMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if !model.IsValidMinionId(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid minion ID"))
		return
	}

	op := chi.URLParam(r, "operation")
	if op != "add" && op != "reject" && op != "delete" && op != "test" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid operation"))
		return
	}

	err := h.server.GridMembersstore.ManageMember(ctx, op, id)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

var roleKeywords = map[string][]string{ // role => capabilities
	"eval":          {"elastic", "elasticsearch", "fleet", "forward", "ingest", "manager", "master", "search", "sensor", "sensoroni", "soc", "stenographer", "web"},
	"fleet":         {"fleet"},
	"heavynode":     {"elastic", "elasticsearch", "forward", "ingest", "search", "sensor", "sensoroni", "stenographer"},
	"helix":         {"helix", "sensor", "sensoroni", "stenographer"},
	"idh":           {"idh", "intrusion", "detection", "honeypot"},
	"import":        {"import", "manager", "master", "soc", "web"},
	"managersearch": {"elastic", "elasticsearch", "ingest", "manager", "master", "search", "soc", "web"},
	"manager":       {"manager", "master", "soc"},
	"node":          {"elastic", "elasticsearch", "ingest", "search"},
	"receiver":      {"receiver"},
	"search":        {"elastic", "elasticsearch", "ingest", "search"},
	"searchnode":    {"elastic", "elasticsearch", "ingest", "search"},
	"sensor":        {"forward", "sensor", "sensoroni", "stenographer"},
	"standalone":    {"elastic", "elasticsearch", "fleet", "forward", "ingest", "manager", "master", "search", "sensor", "sensoroni", "soc", "stenographer", "web"},
}

func canUploadPcap(node string) bool {
	parts := strings.Split(node, "_")
	if len(parts) < 2 {
		return false
	}

	keywords, ok := roleKeywords[parts[1]]
	if !ok {
		return false
	}

	return lo.Contains(keywords, "sensor") || lo.Contains(keywords, "import")
}

func canUploadEvtx(node string) bool {
	parts := strings.Split(node, "_")
	if len(parts) < 2 {
		return false
	}

	keywords, ok := roleKeywords[parts[1]]
	if !ok {
		return false
	}

	return lo.Contains(keywords, "manager")
}
