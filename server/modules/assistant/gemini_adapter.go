// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"google.golang.org/genai"
)

type GeminiAdapter struct {
	srv    *server.Server
	client *genai.Client
	detections.IOManager
}

func NewGeminiAdapter(ctx context.Context, srv *server.Server, apiKey string) *GeminiAdapter {
	client, err := buildClientFromApiKey(ctx, apiKey)
	if err != nil {
		panic(err)
	}

	return &GeminiAdapter{
		srv:    srv,
		client: client,
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}
}

func buildClientFromApiKey(ctx context.Context, apikey string) (client *genai.Client, err error) {
	cfg := &genai.ClientConfig{
		APIKey:  apikey,
		Backend: genai.BackendGeminiAPI,
	}

	client, err = genai.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (a *GeminiAdapter) Name() string {
	return "gemini"
}

func (a *GeminiAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	return nil, nil
}

func (a *GeminiAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, error) {
	// %s = model
	const msgStart = `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":"%s","stop_reason":null,"stop_sequence":null}}` + "\n\n"
	// %s = model tokens
	const contentBlockDelta = `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"%s"}}` + "\n\n"
	const contentBlockStop = `data: {"type":"content_block_stop","index":0}` + "\n\n"
	// %s = stop reason
	const stopReason = `data: {"type":"message_delta","delta":{"stop_reason":"%s","stop_sequence":null}}` + "\n\n"
	// %d = input tokens, %d = output tokens
	const usage = `data: {"type":"message_delta","usage":{"input_tokens":%d,"output_tokens":%d}}` + "\n\n"
	const msgStop = `data: {"type":"message_stop"}` + "\n\n"
	const done = `data: [DONE]`

	history := convertHistory(req)

	latest := history[len(history)-1]
	history = history[:len(history)-1]

	session, err := a.client.Chats.Create(ctx, req.Model, &genai.GenerateContentConfig{
		SystemInstruction: &genai.Content{
			Parts: []*genai.Part{
				{Text: req.SystemAppend},
			},
		},
	}, history)
	if err != nil {
		return nil, err
	}

	bodyReader, bodyWriter := io.Pipe()

	res := &http.Response{
		StatusCode: http.StatusOK,
		Body:       bodyReader,
		Header:     make(http.Header),
	}

	res.Header.Add("Content-Type", "text/event-stream")

	go func() {
		defer bodyWriter.Close()

		// don't start writing the response until the first bit of content is received
		firstSend := true

		var finalResp *genai.GenerateContentResponse

		for resp, err := range session.SendMessageStream(ctx, *latest.Parts[0]) {
			if err != nil {
				panic(err)
			}

			finalResp = resp

			if firstSend {
				firstSend = false
				fmt.Fprintf(bodyWriter, msgStart, req.Model)
			}

			// escape quotes, but remove surrounding quotes added by strconv.Quote
			text := strings.TrimSuffix(strings.TrimPrefix(strconv.Quote(resp.Text()), "\""), "\"")

			fmt.Fprintf(bodyWriter, contentBlockDelta, text)
		}

		fmt.Fprint(bodyWriter, contentBlockStop)
		fmt.Fprintf(bodyWriter, stopReason, "end_turn")
		fmt.Fprintf(bodyWriter, usage, finalResp.UsageMetadata.PromptTokenCount, finalResp.UsageMetadata.CandidatesTokenCount)
		fmt.Fprint(bodyWriter, msgStop)
		fmt.Fprint(bodyWriter, done)
	}()

	return res, nil
}

func (a *GeminiAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: 100,
	}, nil
}

func (a *GeminiAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return &model.HealthResponse{
		Status: "healthy",
	}, nil
}

func convertHistory(req *model.ChatRequest) []*genai.Content {
	history := make([]*genai.Content, 0, len(req.Messages))

	for _, msg := range req.Messages {
		if msg.Role == "user" {
			history = append(history, &genai.Content{
				Role: genai.RoleUser,
				Parts: []*genai.Part{
					{
						Text: msg.ContentBlocks[0].Text,
					},
				},
			})
		} else {
			history = append(history, &genai.Content{
				Role: genai.RoleModel,
				Parts: []*genai.Part{
					{
						Text: msg.ContentBlocks[0].Text,
					},
				},
			})
		}
	}

	return history
}
