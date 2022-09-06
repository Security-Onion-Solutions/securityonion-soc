// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elasticcases

import (
  "context"
  "encoding/base64"
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net/http"
)

type ElasticCasestore struct {
  client *web.Client
  server *server.Server
  token  string
}

func NewElasticCasestore(srv *server.Server) *ElasticCasestore {
  return &ElasticCasestore{
    server: srv,
  }
}

func (store *ElasticCasestore) Init(hostUrl string,
  username string,
  password string,
  verifyCert bool) error {
  store.token = base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
  store.client = web.NewClient(hostUrl, verifyCert)
  store.client.Auth = store
  return nil
}

func (store *ElasticCasestore) Authorize(request *http.Request) error {
  request.Header.Add("Authorization", "Basic "+store.token)
  request.Header.Add("kbn-xsrf", "false")
  return nil
}

func (store *ElasticCasestore) Create(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var newCase *model.Case
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    var outputCase ElasticCase
    var inputCase *ElasticCase
    inputCase, err = convertToElasticCase(socCase)
    if err != nil {
      return nil, err
    }
    _, err = store.client.SendAuthorizedObject("POST", "/api/cases", inputCase, &outputCase)
    if err != nil {
      return nil, err
    }
    newCase, err = convertFromElasticCase(&outputCase)
  }
  return newCase, err
}

func (store *ElasticCasestore) Update(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetCase(ctx context.Context, caseId string) (*model.Case, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) CreateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetComment(ctx context.Context, commentId string) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetComments(ctx context.Context, commentId string) ([]*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) DeleteComment(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) CreateRelatedEvent(ctx context.Context, event *model.RelatedEvent) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetRelatedEvent(ctx context.Context, id string) (*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetRelatedEvents(ctx context.Context, caseId string) ([]*model.RelatedEvent, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) DeleteRelatedEvent(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) CreateArtifact(ctx context.Context, attachment *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetArtifact(ctx context.Context, id string) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetArtifacts(ctx context.Context, caseId string, groupType string, groupId string) ([]*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) DeleteArtifact(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) UpdateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) CreateArtifactStream(ctx context.Context, artifactstream *model.ArtifactStream) (string, error) {
  return "", errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) GetArtifactStream(ctx context.Context, id string) (*model.ArtifactStream, error) {
  return nil, errors.New("Unsupported operation by this module")
}

func (store *ElasticCasestore) DeleteArtifactStream(ctx context.Context, id string) error {
  return errors.New("Unsupported operation by this module")
}
