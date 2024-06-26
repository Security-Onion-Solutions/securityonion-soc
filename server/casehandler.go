// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
)

type CaseHandler struct {
	server *Server
}

func RegisterCaseRoutes(srv *Server, r chi.Router, prefix string) {
	h := &CaseHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.caseEnabled)

		r.Post("/", h.createCase)
		r.Post("/events", h.createEvent)
		r.Post("/comments", h.createComment)
		r.Post("/tasks", h.createArtifact)
		r.Post("/artifacts", h.createArtifact)

		r.Get("/comments", h.getComment)
		r.Get("/comments/{id}", h.getComment)
		r.Get("/events", h.getEvent)
		r.Get("/events/{id}", h.getEvent)
		r.Get("/tasks", h.getTask)
		r.Get("/tasks/{id}", h.getTask)
		r.Get("/artifactstream", h.getTask)
		r.Get("/artifactstream/{id}", h.getTask)
		r.Get("/artifacts/{groupType}", h.getArtifact)
		r.Get("/artifacts/{groupType}/{groupID}", h.getArtifact)
		r.Get("/artifacts/{groupType}/{groupID}/{id}", h.getArtifact)
		r.Get("/history", h.getHistory)
		r.Get("/", h.getCase)
		r.Get("/{id}", h.getCase)

		r.Put("/", h.updateCase)
		r.Put("/comments", h.updateComment)
		r.Put("/tasks", h.updateArtifact)
		r.Put("/artifacts", h.updateArtifact)

		r.Delete("/comments", h.deleteComment)
		r.Delete("/comments/{id}", h.deleteComment)
		r.Delete("/events", h.deleteEvent)
		r.Delete("/events/{id}", h.deleteEvent)
		r.Delete("/tasks", h.deleteArtifact)
		r.Delete("/tasks/{id}", h.deleteArtifact)
		r.Delete("/artifacts", h.deleteArtifact)
		r.Delete("/artifacts/{id}", h.deleteArtifact)
	})
}

func (h *CaseHandler) caseEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.Casestore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("ERROR_CASE_MODULE_NOT_ENABLED"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *CaseHandler) createCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputCase := model.NewCase()

	err := json.NewDecoder(r.Body).Decode(&inputCase)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.Create(ctx, inputCase)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) createEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputEvent := model.NewRelatedEvent()

	err := web.ReadJson(r, &inputEvent)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.CreateRelatedEvent(ctx, inputEvent)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) createComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputComment := model.NewComment()

	err := web.ReadJson(r, &inputComment)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.CreateComment(ctx, inputComment)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) createArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputArtifact := model.NewArtifact()

	contentType, ok := r.Header["Content-Type"]
	if !ok || !strings.Contains(contentType[0], "multipart") {
		// Fallback to plain JSON
		log.WithField("contentType", contentType).Debug("Multipart content type not found")
		err := json.NewDecoder(r.Body).Decode(&inputArtifact)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}
	} else {
		err := r.ParseMultipartForm(int64(h.server.Config.MaxUploadSizeBytes))
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		jsonData := r.FormValue("json")
		err = json.Unmarshal([]byte(jsonData), &inputArtifact)
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		log.Debug("Successfully parsed multipart form")

		// Try pulling an attachment file
		file, handler, err := r.FormFile("attachment")
		if err != nil {
			web.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if file == nil {
			web.Respond(w, r, http.StatusBadRequest, errors.New("Attachment file not found"))
			return
		}

		log.Debug("Found attachment")
		defer file.Close()

		if len(inputArtifact.Value) > 0 {
			web.Respond(w, r, http.StatusBadRequest, errors.New("Attachment artifacts must be provided without a value"))
			return
		}

		inputArtifact.Value = handler.Filename
		inputArtifact.ArtifactType = "file"

		artifactStream := model.NewArtifactStream()
		inputArtifact.StreamLen, inputArtifact.MimeType, inputArtifact.Md5, inputArtifact.Sha1, inputArtifact.Sha256, err = artifactStream.Write(file)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		if inputArtifact.StreamLen != int(handler.Size) {
			log.WithFields(log.Fields{
				"requestId": ctx.Value(web.ContextKeyRequestId),
				"mimeType":  inputArtifact.MimeType,
				"formLen":   handler.Size,
				"copyLen":   inputArtifact.StreamLen,
			}).Warn("Mismatch of stream size detected")
		} else {
			log.WithFields(log.Fields{
				"requestId":   ctx.Value(web.ContextKeyRequestId),
				"formFileLen": handler.Size,
				"streamLen":   inputArtifact.StreamLen,
				"mimeType":    inputArtifact.MimeType,
			}).Info("Successfully copied attachment bytes into new artifact stream object")
		}

		var artifactStreamId string
		artifactStreamId, err = h.server.Casestore.CreateArtifactStream(ctx, artifactStream)
		if err != nil {
			web.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		inputArtifact.StreamId = artifactStreamId
	}

	obj, err := h.server.Casestore.CreateArtifact(ctx, inputArtifact)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) updateCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputCase := model.NewCase()

	err := json.NewDecoder(r.Body).Decode(&inputCase)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.Update(ctx, inputCase)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) updateComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputComment := model.NewComment()

	err := json.NewDecoder(r.Body).Decode(&inputComment)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.UpdateComment(ctx, inputComment)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) updateArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inputArtifact := model.NewArtifact()

	err := json.NewDecoder(r.Body).Decode(&inputArtifact)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	obj, err := h.server.Casestore.UpdateArtifact(ctx, inputArtifact)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) deleteComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	err := h.server.Casestore.DeleteComment(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *CaseHandler) deleteEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	err := h.server.Casestore.DeleteRelatedEvent(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *CaseHandler) deleteArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	err := h.server.Casestore.DeleteArtifact(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}

func (h *CaseHandler) getCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	obj, err := h.server.Casestore.GetCase(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) getComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	obj, err := h.server.Casestore.GetComments(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) getEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	obj, err := h.server.Casestore.GetRelatedEvents(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) getTask(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	err := h.copyArtifactStream(ctx, w, id)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, nil)
		return
	}

	web.Respond(nil, r, http.StatusOK, nil)
}

func (h *CaseHandler) getArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	groupType := chi.URLParam(r, "groupType")
	groupId := chi.URLParam(r, "groupID")

	id := chi.URLParam(r, "id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	obj, err := h.server.Casestore.GetArtifacts(ctx, id, groupType, groupId)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (h *CaseHandler) getHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.URL.Query().Get("id")

	obj, err := h.server.Casestore.GetCaseHistory(ctx, id)
	if err != nil {
		web.Respond(w, r, http.StatusNotFound, err)
		return
	}

	web.Respond(w, r, http.StatusOK, obj)
}

func (caseHandler *CaseHandler) copyArtifactStream(ctx context.Context, writer http.ResponseWriter, artifactId string) error {
	artifact, err := caseHandler.server.Casestore.GetArtifact(ctx, artifactId)
	if err != nil {
		return err
	}

	stream, err := caseHandler.server.Casestore.GetArtifactStream(ctx, artifact.StreamId)
	if err != nil {
		return err
	}

	contentLength := int64(artifact.StreamLen)
	filename := artifact.Value
	content := stream.Read()

	if artifact.Protected {
		buf := bytes.NewBuffer([]byte{})
		zipw := zip.NewWriter(buf)

		filew, err := zipw.Create(filename)
		if err != nil {
			return err
		}

		_, err = io.Copy(filew, content)
		if err != nil {
			return err
		}

		err = zipw.Close()
		if err != nil {
			return err
		}

		content = buf
		contentLength = int64(buf.Len())
		filename += ".zip"
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	writer.Header().Set("Content-Transfer-Encoding", "binary")

	written, err := io.Copy(writer, content)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"artifactName": artifact.Value,
			"artifactId":   artifactId,
		}).Error("Failed to copy artifact stream")

		return err
	}

	log.WithFields(log.Fields{
		"artifactName":      artifact.Value,
		"artifactSize":      written,
		"artifactId":        artifactId,
		"artifactProtected": artifact.Protected,
	}).Info("Copied artifact stream to response")

	return nil
}
