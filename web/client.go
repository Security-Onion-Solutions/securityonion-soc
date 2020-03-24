// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "bytes"
  "crypto/tls"
  "encoding/json"
  "errors"
  "io"
  "net/http"
  "strconv"
  "strings"
  "github.com/apex/log"
)

type ClientAuth interface {
  Authorize(request *http.Request) error
}

type Client struct {
  Auth				ClientAuth
  hostUrl			string
  impl	    	*http.Client
}

func NewClient(url string, verifyCert bool) *Client {
  client := &Client {
    hostUrl: url,
  }
  transport := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyCert},
  }
  client.impl = &http.Client{Transport: transport}
  return client
}

func (client *Client) SendAuthorizedObject(method string, path string, obj interface{}, returnedObj interface{}) (bool, error) {
  objectAvailable := false
  data, err := json.Marshal(obj)
  if err == nil {
    var resp *http.Response
    resp, err = client.SendAuthorizedRequest(method, path, "application/json", bytes.NewReader(data))
    if err == nil {
      defer resp.Body.Close()
      if resp.StatusCode < 200 || resp.StatusCode > 299 {
        err = errors.New("Request did not complete successfully (" + strconv.Itoa(resp.StatusCode) + "): " + resp.Status)
      } else if returnedObj != nil && resp.Body != nil {
        err = json.NewDecoder(resp.Body).Decode(returnedObj)
        if err == nil {
          objectAvailable = true
        } else if err == io.ErrUnexpectedEOF {
          // No object returned
          err = nil
        }
      }
    }
  }
  return objectAvailable, err
}

func (client *Client) SendAuthorizedRequest(method string, path string, contentType string, reader io.Reader) (*http.Response, error) {
  var err error
  var resp *http.Response
  if client.Auth == nil {
    err = errors.New("Agent auth module has not been initialized; ensure a valid auth module has been defined in the configuration")
  } else {
    var req *http.Request
    formattedUrl := client.FormatUrl(client.hostUrl, path)
    req, err = http.NewRequest(method, formattedUrl, reader)
    req.Header.Add("Content-Type", contentType)
    if err == nil {
      err = client.Auth.Authorize(req)
      if err == nil {
        log.WithFields(log.Fields {
          "url": formattedUrl,
          "method": method,
        }).Debug("Sending authorized request")
        resp, err = client.impl.Do(req)
        if err != nil {
          log.WithError(err).Warn("Failed to submit request")
        }
      }
    }
  }
  return resp, err
}

func (client *Client) FormatUrl(url string, path string) string {
  formattedUrl := strings.TrimSuffix(url, "/")
  formattedUrl = formattedUrl + "/"
  formattedUrl = formattedUrl + strings.TrimPrefix(path, "/")
  return formattedUrl
}