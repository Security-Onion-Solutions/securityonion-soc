// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package thehive

import (
  "context"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type TheHiveCasestore struct {
  client *web.Client
  server *server.Server
  apiKey string
}

func NewTheHiveCasestore(srv *server.Server) *TheHiveCasestore {
  return &TheHiveCasestore{
    server: srv,
  }
}

func (store *TheHiveCasestore) Init(hostUrl string,
  key string,
  verifyCert bool) error {
  store.client = web.NewClient(hostUrl, verifyCert)
  store.client.Auth = store
  store.apiKey = key
  return nil
}

func (store *TheHiveCasestore) Authorize(request *http.Request) error {
  request.Header.Add("Authorization", "Bearer "+store.apiKey)
  return nil
}

func (store *TheHiveCasestore) Create(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var newCase *model.Case
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    var outputCase TheHiveCase
    var inputCase *TheHiveCase
    inputCase, err = convertToTheHiveCase(socCase)
    if err != nil {
      return nil, err
    }
    _, err = store.client.SendAuthorizedObject("POST", "/api/case", inputCase, &outputCase)
    if err != nil {
      return nil, err
    }
    newCase, err = convertFromTheHiveCase(&outputCase)
  }
  return newCase, err
}

func (store *TheHiveCasestore) Update(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetCase(ctx context.Context, caseId string) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) CreateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetComment(ctx context.Context, commentId string) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetComments(ctx context.Context, commentId string) ([]*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) DeleteComment(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) CreateRelatedEvent(ctx context.Context, event *model.RelatedEvent) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetRelatedEvent(ctx context.Context, id string) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetRelatedEvents(ctx context.Context, caseId string) ([]*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) DeleteRelatedEvent(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) CreateArtifact(ctx context.Context, attachment *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetArtifact(ctx context.Context, id string) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetArtifacts(ctx context.Context, caseId string, groupType string, groupId string) ([]*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) DeleteArtifact(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) UpdateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) CreateArtifactStream(ctx context.Context, artifactstream *model.ArtifactStream) (string, error) {
  return "", errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) GetArtifactStream(ctx context.Context, id string) (*model.ArtifactStream, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *TheHiveCasestore) DeleteArtifactStream(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}
