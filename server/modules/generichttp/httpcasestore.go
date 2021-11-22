// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
