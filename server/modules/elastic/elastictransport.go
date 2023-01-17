// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "crypto/tls"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "net"
  "net/http"
  "time"
)

type ElasticTransport struct {
  internal http.RoundTripper
}

func NewElasticTransport(user string, pass string, timeoutMs time.Duration, verifyCert bool) http.RoundTripper {
  httpTransport := &http.Transport{
    MaxIdleConnsPerHost:   10,
    ResponseHeaderTimeout: timeoutMs,
    DialContext:           (&net.Dialer{Timeout: timeoutMs}).DialContext,
    TLSClientConfig: &tls.Config{
      InsecureSkipVerify: !verifyCert,
    },
  }

  if len(user) > 0 && len(pass) > 0 {
    return &ElasticTransport{
      internal: httpTransport,
    }
  }

  return httpTransport
}

func (transport *ElasticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
  if user, ok := req.Context().Value(web.ContextKeyRequestor).(*model.User); ok {
    log.WithFields(log.Fields{
      "username":       user.Email,
      "searchUsername": user.SearchUsername,
      "requestId":      req.Context().Value(web.ContextKeyRequestId),
    }).Debug("Executing Elastic request on behalf of user")
    username := user.Email
    if user.SearchUsername != "" {
      username = user.SearchUsername
    }
    req.Header.Set("es-security-runas-user", username)
  } else {
    log.Warn("User not found in context")
  }
  return transport.internal.RoundTrip(req)
}
