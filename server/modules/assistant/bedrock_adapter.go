// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/apex/log"
)

type BedrockAdapter struct {
	srv                  *server.Server
	apiUrl               string
	apiKey               string
	healthTimeoutSeconds int
	detections.IOManager
}

func NewBedrockAdapter(srv *server.Server, apiUrl string, apiKey string, healthTimeoutSeconds int) *BedrockAdapter {
	return &BedrockAdapter{
		srv:                  srv,
		apiUrl:               apiUrl,
		apiKey:               apiKey,
		healthTimeoutSeconds: healthTimeoutSeconds,
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}
}

func (a *BedrockAdapter) Name() string {
	return "bedrock"
}

func (a *BedrockAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(a.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", a.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/chat")
	endpoint := u.String()

	var buf bytes.Buffer

	err = json.NewEncoder(&buf).Encode(req)
	if err != nil {
		logger.WithError(err).WithField("chatrequest", req).Error("unable to encode ChatRequest")
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	a.prepareRequestHeaders(httpReq)

	res, err := a.MakeRequest(httpReq, false)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		logger.WithError(err).Error("unable to execute request")

		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("unable to read response body")

		return nil, err
	}

	logger.WithField("rawChatResponseBody", string(resBody)).Debug("chat response received")

	response := &model.Message{}

	err = json.Unmarshal(resBody, &response)
	if err != nil {
		logger.WithError(err).WithField("rawChatResponseBody", string(resBody)).Error("unable to unmarshal JSON response")
		return nil, err
	}

	return response, nil
}

func (a *BedrockAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(a.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", a.apiUrl).Error("unable to parse apiUrl")

		return nil, nil, err
	}

	u.Path = path.Join(u.Path, "/api/chat")
	endpoint := u.String()

	var buf bytes.Buffer

	err = json.NewEncoder(&buf).Encode(req)
	if err != nil {
		logger.WithError(err).WithField("chatrequest", req).Error("unable to encode ChatRequest")
		return nil, nil, err
	}

	logger.WithField("outgoingChatBodySize", buf.Len()).Info("outgoing chat request body")

	httpReq, err := http.NewRequest(http.MethodPost, endpoint, &buf)
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to make request object")

		return nil, nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Accept", "text/event-stream")
	a.prepareRequestHeaders(httpReq)

	res, err := a.MakeRequest(httpReq, true)
	if err != nil {
		if res != nil && res.Body != nil {
			defer res.Body.Close()
		}

		logger.WithError(err).Error("unable to execute request")

		return nil, nil, err
	}

	return res, nil, nil
}

func (a *BedrockAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(a.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", a.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/balance")
	endpoint := u.String()

	httpReq, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		logger.WithError(err).Error("unable to make request object")

		return nil, err
	}

	a.prepareRequestHeaders(httpReq)

	res, err := a.MakeRequest(httpReq, false)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to execute request")

		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("unable to read response body")

		return nil, err
	}

	logger.WithField("rawBalanceResponseBody", string(resBody)).Debug("balance response received")

	response := &model.BalanceResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawBalanceResponseBody", string(resBody)).Error("unable to unmarshal JSON response")
		return nil, err
	}

	return response, nil
}

func (a *BedrockAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	logger := log.FromContext(ctx)

	u, err := url.Parse(a.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", a.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/health")
	endpoint := u.String()

	shortLived, cancel := context.WithTimeout(ctx, time.Second*time.Duration(a.healthTimeoutSeconds))
	defer cancel()

	httpReq, err := http.NewRequestWithContext(shortLived, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.WithError(err).Error("unable to make request object")

		return nil, err
	}

	a.prepareRequestHeaders(httpReq)

	res, err := a.MakeRequest(httpReq, false)
	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}
	if err != nil {
		logger.WithError(err).WithField("apiEndpoint", endpoint).Error("unable to execute request")

		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("unable to read response body")

		return nil, err
	}

	logger.WithField("rawHealthResponseBody", string(resBody)).Debug("health response received")

	response := &model.HealthResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawHealthResponseBody", string(resBody)).Error("unable to unmarshal JSON response")
		return nil, err
	}

	return response, nil
}

func (a *BedrockAdapter) prepareRequestHeaders(httpReq *http.Request) {
	httpReq.Header.Add("x-api-key", a.apiKey)
	httpReq.Header.Add("x-so-version", a.srv.Host.Version)
}
