// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
  "net"
  "net/http"
  "strings"
  "github.com/apex/log"
)

type StaticKeyAuthImpl struct {
  apiKey							string
  anonymousNetwork		*net.IPNet
}

func NewStaticKeyAuthImpl() *StaticKeyAuthImpl {
  return &StaticKeyAuthImpl {
  }
}

func (auth* StaticKeyAuthImpl) Init(apiKey string, anonymousCidr string) error {
  var err error
  auth.apiKey = apiKey
  _, auth.anonymousNetwork, err = net.ParseCIDR(anonymousCidr)
  return err
}

func (auth *StaticKeyAuthImpl) IsAuthorized(request *http.Request) bool {
  ipStr := request.RemoteAddr
  pieces := strings.Split(ipStr, ":")
  if pieces != nil && len(pieces) > 0 {
    ipStr = pieces[0]
  }
  remoteIp := net.ParseIP(ipStr)
  isAnonymousIp := auth.anonymousNetwork.Contains(remoteIp)
  isApiKeyAccepted := auth.validateApiKey(request.Header.Get("Authorization"))
  log.WithFields(log.Fields{
    "anonymousNetwork": auth.anonymousNetwork,
    "remoteIp": remoteIp,
    "isApiKeyAccepted": isApiKeyAccepted,
    "isAnonymousIp": isAnonymousIp,
  }).Debug("Authorization check")
  return isAnonymousIp || isApiKeyAccepted
}

func (auth *StaticKeyAuthImpl) validateApiKey(key string) bool {
  pieces := strings.Split(key, " ")
  if pieces != nil && len(pieces) > 0 {
    key = pieces[len(pieces) - 1]
  }
  return key == auth.apiKey
}
