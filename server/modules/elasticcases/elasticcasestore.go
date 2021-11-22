// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elasticcases

import (
  "context"
  "encoding/base64"
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
