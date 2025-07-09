// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

const (
	DEFAULT_APIKEY = ""
	DEFAULT_APIURL = "https://b7cdq33i55t73bzisq7gplzd340mvxgo.lambda-url.us-east-2.on.aws/"
	DEFAULT_MODEL  = "claude-sonnet"
)

type AssistantCoordinator struct {
	srv       *server.Server
	apiKey    string
	apiUrl    string
	model     string
	isRunning bool

	detections.IOManager
}

func NewAssistantManager(srv *server.Server) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv:       srv,
		IOManager: &detections.ResourceManager{},
	}
}

func (am *AssistantCoordinator) PrerequisiteModules() []string {
	return nil
}

func (am *AssistantCoordinator) Init(config module.ModuleConfig) (err error) {
	am.srv.AssistantManager = am

	am.apiKey = module.GetStringDefault(config, "apiKey", DEFAULT_APIKEY)
	am.apiUrl = module.GetStringDefault(config, "apiUrl", DEFAULT_APIURL)
	am.model = module.GetStringDefault(config, "model", DEFAULT_MODEL)

	return nil
}

func (am *AssistantCoordinator) Start() error {
	am.isRunning = true

	return nil
}

func (am *AssistantCoordinator) Stop() error {
	am.isRunning = false

	return nil
}

func (am *AssistantCoordinator) IsRunning() bool {
	return am.isRunning
}

func (am *AssistantCoordinator) Chat(ctx context.Context, msg string) (*model.ChatResponse, error) {
	logger := log.FromContext(ctx)
	userID := ctx.Value(web.ContextKeyRequestorId).(string)

	req := &model.ChatRequest{
		Messages: []*model.ChatMessage{
			{
				Role:    "user",
				Content: msg,
			},
		},
		UserUUID: userID,
	}

	u, err := url.Parse(am.apiUrl)
	if err != nil {
		logger.WithError(err).WithField("apiUrl", am.apiUrl).Error("unable to parse apiUrl")

		return nil, err
	}

	u.Path = path.Join(u.Path, "/api/chat")

	var buf bytes.Buffer

	err = json.NewEncoder(&buf).Encode(req)
	if err != nil {
		logger.WithError(err).WithField("chatrequest", req).Error("unable to encode ChatRequest")
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, u.String(), &buf)
	if err != nil {
		logger.WithError(err).Error("unable to make request object")

		return nil, err
	}

	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", am.apiKey))

	res, err := am.MakeRequest(httpReq)
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

	response := &model.ChatResponse{}

	err = json.Unmarshal(resBody, response)
	if err != nil {
		logger.WithError(err).WithField("rawChatResponseBody", string(resBody)).Error("unable to unmarhsal JSON response")
		return nil, err
	}

	return response, nil
}
