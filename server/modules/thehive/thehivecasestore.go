// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package thehive

import (
  "net/http"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type TheHiveCasestore struct {
  client            *web.Client
  apiKey            string
}

func NewTheHiveCasestore() *TheHiveCasestore {
  return &TheHiveCasestore{}
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
  request.Header.Add("Authorization", "Bearer " + store.apiKey)
  return nil
}

func (store *TheHiveCasestore) Create(socCase *model.Case) (*model.Case, error) {
  var outputCase TheHiveCase
  inputCase, err := convertToTheHiveCase(socCase)
  if err != nil {
    return nil, err
  }
  _, err = store.client.SendAuthorizedObject("POST", "/api/case", inputCase, &outputCase)
  if err != nil {
    return nil, err
  }
  newCase, err := convertFromTheHiveCase(&outputCase)
  return newCase, err
}

