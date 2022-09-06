// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
  "strconv"
  "strings"
)

type HttpCasestore struct {
  client       *web.Client
  server       *server.Server
  headers      []string
  createParams *GenericHttpParams
}

func NewHttpCasestore(srv *server.Server) *HttpCasestore {
  return &HttpCasestore{
    server: srv,
  }
}

func (store *HttpCasestore) Init(hostUrl string,
  verifyCert bool,
  headers []string,
  createParams *GenericHttpParams) error {
  store.client = web.NewClient(hostUrl, verifyCert)
  store.client.Auth = store
  store.headers = headers
  store.createParams = createParams
  return nil
}

func (store *HttpCasestore) Authorize(request *http.Request) error {
  for _, header := range store.headers {
    pieces := strings.SplitN(header, ":", 2)
    if len(pieces) == 2 {
      request.Header.Add(pieces[0], pieces[1])
    } else {
      request.Header.Add(header, "")
    }
  }
  return nil
}

func (store *HttpCasestore) Create(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var err error
  var response *http.Response
  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    var bodyReader *strings.Reader
    bodyReader, err = convertCaseToReader(store.createParams.Body, socCase)
    if err == nil {
      response, err = store.client.SendAuthorizedRequest(store.createParams.Method, store.createParams.Path, store.createParams.ContentType, bodyReader)
      if response.StatusCode != store.createParams.SuccessStatusCode {
        err = errors.New("Unexpected response for HTTP case creation: " + response.Status + " (" + strconv.Itoa(response.StatusCode) + ")")
      }
    }
  }
  return nil, err
}

func (store *HttpCasestore) Update(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetCase(ctx context.Context, caseId string) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) CreateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetComment(ctx context.Context, commentId string) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetComments(ctx context.Context, commentId string) ([]*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) DeleteComment(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) CreateRelatedEvent(ctx context.Context, event *model.RelatedEvent) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetRelatedEvent(ctx context.Context, id string) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetRelatedEvents(ctx context.Context, caseId string) ([]*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) DeleteRelatedEvent(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) CreateArtifact(ctx context.Context, attachment *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetArtifact(ctx context.Context, id string) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetArtifacts(ctx context.Context, caseId string, groupType string, groupId string) ([]*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) DeleteArtifact(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) UpdateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) CreateArtifactStream(ctx context.Context, artifactstream *model.ArtifactStream) (string, error) {
  return "", errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) GetArtifactStream(ctx context.Context, id string) (*model.ArtifactStream, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *HttpCasestore) DeleteArtifactStream(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}
