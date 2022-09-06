// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "bytes"
  "crypto/tls"
  "encoding/json"
  "errors"
  "github.com/apex/log"
  "io"
  "io/ioutil"
  "net/http"
  "strconv"
  "strings"
)

type ClientAuth interface {
  Authorize(request *http.Request) error
}

type Client struct {
  Auth         ClientAuth
  hostUrl      string
  impl         *http.Client
  mock         bool
  mockResponse *http.Response
  mockError    error
}

func NewClient(url string, verifyCert bool) *Client {
  client := &Client{
    hostUrl: url,
  }
  transport := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyCert},
  }
  client.impl = &http.Client{Transport: transport}
  return client
}

func (client *Client) MockStringResponse(body string, statusCode int, mockError error) {
  mockResp := &http.Response{
    Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
    StatusCode:    statusCode,
    ContentLength: int64(len(body)),
    Header:        make(http.Header, 0),
  }
  client.MockResponse(mockResp, mockError)
}

func (client *Client) MockResponse(mockResponse *http.Response, mockError error) {
  client.mock = true
  client.mockResponse = mockResponse
  client.mockError = mockError
}

func (client *Client) SendAuthorizedObject(method string, path string, obj interface{}, returnedObj interface{}) (bool, error) {
  return client.SendObject(method, path, obj, returnedObj, true)
}

func (client *Client) SendObject(method string, path string, obj interface{}, returnedObj interface{}, auth bool) (bool, error) {
  objectAvailable := false
  data, err := json.Marshal(obj)
  if err == nil {
    var resp *http.Response
    resp, err = client.SendRequest(method, path, "application/json", bytes.NewReader(data), auth)
    if err == nil {
      defer resp.Body.Close()
      if resp.StatusCode < 200 || resp.StatusCode > 299 {
        bytes, _ := ioutil.ReadAll(resp.Body)
        body := string(bytes)
        log.WithFields(log.Fields{
          "body": body,
        }).Debug("Response")
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
  return client.SendRequest(method, path, contentType, reader, true)
}

func (client *Client) SendRequest(method string, path string, contentType string, reader io.Reader, auth bool) (*http.Response, error) {
  var err error
  var resp *http.Response
  if client.Auth == nil && auth {
    err = errors.New("Agent auth module has not been initialized; ensure a valid auth module has been defined in the configuration")
  } else {
    var req *http.Request
    formattedUrl := client.FormatUrl(client.hostUrl, path)
    req, err = http.NewRequest(method, formattedUrl, reader)
    req.Header.Add("Content-Type", contentType)
    if err == nil {
      if auth {
        err = client.Auth.Authorize(req)
        if err == nil {
          log.WithFields(log.Fields{
            "url":    formattedUrl,
            "method": method,
          }).Debug("Sending authorized request")
        }
      }

      if err == nil {
        if client.mock {
          resp = client.mockResponse
          err = client.mockError
        } else {
          resp, err = client.impl.Do(req)
        }
        if err != nil {
          log.WithError(err).Warn("Failed to submit request")
        } else {
          log.WithFields(log.Fields{
            "url":           formattedUrl,
            "method":        method,
            "statusCode":    resp.StatusCode,
            "status":        resp.Status,
            "contentLength": resp.ContentLength,
          }).Info("HTTP request finished")
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
