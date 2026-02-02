// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"iter"

	"google.golang.org/genai"
)

// GeminiClient is an interface that wraps the genai.Client functionality we use.
// This allows us to mock the Gemini client for testing.
type GeminiClient interface {
	// CreateSession creates a new chat session with the specified model and configuration.
	// This wraps the genai.Client.Chats.Create() method.
	CreateSession(
		ctx context.Context,
		model string,
		config *genai.GenerateContentConfig,
		history []*genai.Content,
	) (GeminiSession, error)

	// CheckHealth checks the health of the Gemini service.
	CheckHealth(ctx context.Context) string
}

//go:generate mockgen -source=gemini_client.go -destination=mock/mock_gemini_client.go -package=mock

// GeminiSession is an interface that wraps the session object returned by Chats.Create.
// It provides methods for sending messages and streaming responses.
type GeminiSession interface {
	// SendMessage sends a message and waits for the complete response.
	SendMessage(ctx context.Context, part genai.Part) (*genai.GenerateContentResponse, error)

	// SendMessageStream sends a message and returns an iterator that yields response chunks.
	SendMessageStream(ctx context.Context, part genai.Part) iter.Seq2[*genai.GenerateContentResponse, error]
}

// realGeminiClient is a wrapper around the actual genai.Client that implements GeminiClient.
type realGeminiClient struct {
	client *genai.Client
}

// NewGeminiClientWrapper wraps a real genai.Client to implement the GeminiClient interface.
func NewGeminiClientWrapper(client *genai.Client) GeminiClient {
	return &realGeminiClient{client: client}
}

// CreateSession wraps the client.Chats.Create call.
func (r *realGeminiClient) CreateSession(
	ctx context.Context,
	model string,
	config *genai.GenerateContentConfig,
	history []*genai.Content,
) (GeminiSession, error) {
	session, err := r.client.Chats.Create(ctx, model, config, history)
	if err != nil {
		return nil, err
	}
	return &realGeminiSession{session: session}, nil
}

func (r *realGeminiClient) CheckHealth(ctx context.Context) string {
	page, err := r.client.Models.List(ctx, &genai.ListModelsConfig{})
	if err != nil || len(page.Items) == 0 {
		return "unhealthy"
	}

	return "healthy"
}

// realGeminiSession wraps the actual session object.
type realGeminiSession struct {
	session *genai.Chat
}

// SendMessage wraps the session.SendMessage call.
func (r *realGeminiSession) SendMessage(ctx context.Context, part genai.Part) (*genai.GenerateContentResponse, error) {
	return r.session.SendMessage(ctx, part)
}

// SendMessageStream wraps the session.SendMessageStream call.
func (r *realGeminiSession) SendMessageStream(ctx context.Context, part genai.Part) iter.Seq2[*genai.GenerateContentResponse, error] {
	return r.session.SendMessageStream(ctx, part)
}
