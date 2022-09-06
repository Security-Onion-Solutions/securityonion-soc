// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
  "context"
  "encoding/json"
  "errors"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "io"
  "net/http"
  "strconv"
  "strings"
)

type CaseHandler struct {
  web.BaseHandler
  server *Server
}

func NewCaseHandler(srv *Server) *CaseHandler {
  handler := &CaseHandler{}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (caseHandler *CaseHandler) HandleNow(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  if caseHandler.server.Casestore == nil {
    return http.StatusMethodNotAllowed, nil, errors.New("ERROR_CASE_MODULE_NOT_ENABLED")
  }

  if caseHandler.server.Casestore != nil {
    switch request.Method {
    case http.MethodPost:
      return caseHandler.create(ctx, writer, request)
    case http.MethodPut:
      return caseHandler.update(ctx, writer, request)
    case http.MethodGet:
      return caseHandler.get(ctx, writer, request)
    case http.MethodDelete:
      return caseHandler.delete(ctx, writer, request)
    }
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (caseHandler *CaseHandler) create(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "events":
    inputEvent := model.NewRelatedEvent()
    err = json.NewDecoder(request.Body).Decode(&inputEvent)
    if err == nil {
      obj, err = caseHandler.server.Casestore.CreateRelatedEvent(ctx, inputEvent)
    }
  case "comments":
    inputComment := model.NewComment()
    err = json.NewDecoder(request.Body).Decode(&inputComment)
    if err == nil {
      obj, err = caseHandler.server.Casestore.CreateComment(ctx, inputComment)
    }
  case "tasks":
  case "artifacts":
    inputArtifact := model.NewArtifact()
    if contentType, ok := request.Header["Content-Type"]; !ok || !strings.Contains(contentType[0], "multipart") {
      // Fallback to plain JSON
      log.WithField("contentType", contentType).Debug("Multipart content type not found")
      err = json.NewDecoder(request.Body).Decode(&inputArtifact)
    } else {
      err = request.ParseMultipartForm(int64(caseHandler.server.Config.MaxUploadSizeBytes))
      if err == nil {
        jsonData := request.FormValue("json")
        err = json.NewDecoder(strings.NewReader(jsonData)).Decode(&inputArtifact)
        if err == nil {
          log.Debug("Successfully parsed multipart form")

          // Try pulling an attachment file
          file, handler, err := request.FormFile("attachment")
          if err == nil && file != nil {
            log.Debug("Found attachment")
            defer file.Close()

            if len(inputArtifact.Value) > 0 {
              err = errors.New("Attachment artifacts must be provided without a value")
            } else {
              inputArtifact.Value = handler.Filename
              inputArtifact.ArtifactType = "file"

              artifactStream := model.NewArtifactStream()
              inputArtifact.StreamLen, inputArtifact.MimeType, inputArtifact.Md5, inputArtifact.Sha1, inputArtifact.Sha256, err = artifactStream.Write(file)
              if err == nil {
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
                artifactStreamId, err = caseHandler.server.Casestore.CreateArtifactStream(ctx, artifactStream)
                if err == nil {
                  inputArtifact.StreamId = artifactStreamId
                }
              }
            }
          }
        }
      }
    }

    if err == nil {
      obj, err = caseHandler.server.Casestore.CreateArtifact(ctx, inputArtifact)
    }
  default:
    inputCase := model.NewCase()
    err = json.NewDecoder(request.Body).Decode(&inputCase)
    if err == nil {
      obj, err = caseHandler.server.Casestore.Create(ctx, inputCase)
    }
  }
  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) update(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "comments":
    inputComment := model.NewComment()
    err = json.NewDecoder(request.Body).Decode(&inputComment)
    if err == nil {
      obj, err = caseHandler.server.Casestore.UpdateComment(ctx, inputComment)
    }
  case "tasks":
  case "artifacts":
    inputArtifact := model.NewArtifact()
    err = json.NewDecoder(request.Body).Decode(&inputArtifact)
    if err == nil {
      obj, err = caseHandler.server.Casestore.UpdateArtifact(ctx, inputArtifact)
    }
  default:
    inputCase := model.NewCase()
    err = json.NewDecoder(request.Body).Decode(&inputCase)
    if err == nil {
      obj, err = caseHandler.server.Casestore.Update(ctx, inputCase)
    }
  }

  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) delete(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var err error
  var obj interface{}
  statusCode := http.StatusBadRequest
  id := request.URL.Query().Get("id")
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "comments":
    err = caseHandler.server.Casestore.DeleteComment(ctx, id)
  case "events":
    err = caseHandler.server.Casestore.DeleteRelatedEvent(ctx, id)
  case "tasks":
  case "artifacts":
    err = caseHandler.server.Casestore.DeleteArtifact(ctx, id)
  default:
    err = errors.New("Delete not supported")
  }

  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusBadRequest
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) get(ctx context.Context, writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  statusCode := http.StatusBadRequest
  id := request.URL.Query().Get("id")
  var err error
  var obj interface{}
  subpath := caseHandler.GetPathParameter(request.URL.Path, 2)
  switch subpath {
  case "events":
    obj, err = caseHandler.server.Casestore.GetRelatedEvents(ctx, id)
  case "comments":
    obj, err = caseHandler.server.Casestore.GetComments(ctx, id)
  case "tasks":
  case "artifactstream":
    err = caseHandler.copyArtifactStream(ctx, writer, id)
  case "artifacts":
    groupType := caseHandler.GetPathParameter(request.URL.Path, 3)
    groupId := caseHandler.GetPathParameter(request.URL.Path, 4)
    obj, err = caseHandler.server.Casestore.GetArtifacts(ctx, id, groupType, groupId)
  case "history":
    obj, err = caseHandler.server.Casestore.GetCaseHistory(ctx, id)
  default:
    obj, err = caseHandler.server.Casestore.GetCase(ctx, id)
  }
  if err == nil {
    statusCode = http.StatusOK
  } else {
    statusCode = http.StatusNotFound
  }
  return statusCode, obj, err
}

func (caseHandler *CaseHandler) copyArtifactStream(ctx context.Context, writer http.ResponseWriter, artifactId string) error {
  artifact, err := caseHandler.server.Casestore.GetArtifact(ctx, artifactId)
  if err == nil {
    var stream *model.ArtifactStream
    stream, err = caseHandler.server.Casestore.GetArtifactStream(ctx, artifact.StreamId)
    if err == nil {
      writer.Header().Set("Content-Type", artifact.MimeType)
      writer.Header().Set("Content-Length", strconv.FormatInt(int64(artifact.StreamLen), 10))
      writer.Header().Set("Content-Disposition", "inline; filename=\""+artifact.Value+"\"")
      writer.Header().Set("Content-Transfer-Encoding", "binary")
      written, err := io.Copy(writer, stream.Read())
      if err != nil {
        log.WithError(err).WithFields(log.Fields{
          "name":       artifact.Value,
          "artifactId": artifactId,
        }).Error("Failed to copy artifact stream")
      } else {
        log.WithFields(log.Fields{
          "name":       artifact.Value,
          "size":       written,
          "artifactId": artifactId,
        }).Info("Copied artifact stream to response")
      }
    }
  }
  return err
}
