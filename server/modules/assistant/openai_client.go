// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"fmt"
	"net/url"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/openai/openai-go/v3/packages/ssestream"
	"github.com/openai/openai-go/v3/responses"

	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// ResponseStream is an interface that wraps the streaming functionality we use.
// This allows us to mock streaming responses for testing without depending on
// the OpenAI SDK's concrete ssestream.Stream type.
type ResponseStream interface {
	// Next advances to the next event. Returns false when done or on error.
	Next() bool

	// Current returns the current event after a successful Next() call.
	Current() responses.ResponseStreamEventUnion

	// Err returns any error that occurred during streaming.
	Err() error
}

// ChatCompletionStream is an interface that wraps the ChatCompletion streaming functionality.
// This allows us to mock ChatCompletion streaming responses for testing.
type ChatCompletionStream interface {
	// Next advances to the next event. Returns false when done or on error.
	Next() bool

	// Current returns the current event after a successful Next() call.
	Current() openai.ChatCompletionChunk

	// Err returns any error that occurred during streaming.
	Err() error
}

// OpenAIClient is an interface that wraps the openai.Client functionality we use.
// This allows us to mock the OpenAI client for testing.
type OpenAIClient interface {
	// ModelsList wraps access to the Models.List API
	ModelsList(ctx context.Context) (*pagination.Page[openai.Model], error)

	// ResponsesNew wraps the Responses.New method for non-streaming calls
	ResponsesNew(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error)

	// ResponsesNewStreaming wraps the Responses.NewStreaming method for streaming calls
	ResponsesNewStreaming(ctx context.Context, params responses.ResponseNewParams) ResponseStream

	// ChatCompletionsNew wraps the Chat.Completions.New method for non-streaming calls
	ChatCompletionsNew(ctx context.Context, params openai.ChatCompletionNewParams) (*openai.ChatCompletion, error)

	// ChatCompletionsNewStreaming wraps the Chat.Completions.NewStreaming method for streaming calls
	ChatCompletionsNewStreaming(ctx context.Context, params openai.ChatCompletionNewParams) ChatCompletionStream

	// EmbeddingsNew wraps the Embeddings.New method for generating vector embeddings
	EmbeddingsNew(ctx context.Context, params openai.EmbeddingNewParams) (*openai.CreateEmbeddingResponse, error)
}

//go:generate mockgen -source=openai_client.go -destination=mock/mock_openai_client.go -package=mock

// realResponseStream wraps a concrete ssestream.Stream to implement ResponseStream interface
type realResponseStream struct {
	stream *ssestream.Stream[responses.ResponseStreamEventUnion]
}

func (r *realResponseStream) Next() bool {
	return r.stream.Next()
}

func (r *realResponseStream) Current() responses.ResponseStreamEventUnion {
	return r.stream.Current()
}

func (r *realResponseStream) Err() error {
	return r.stream.Err()
}

// realOpenAIClient is a wrapper around the actual openai.Client that implements OpenAIClient.
type realOpenAIClient struct {
	client openai.Client
}

// NewOpenAIClientWrapper wraps a real openai.Client to implement the OpenAIClient interface.
func NewOpenAIClientWrapper(client openai.Client) OpenAIClient {
	return &realOpenAIClient{client: client}
}

// ModelsList wraps the client.Models.List call.
func (r *realOpenAIClient) ModelsList(ctx context.Context) (*pagination.Page[openai.Model], error) {
	return r.client.Models.List(ctx)
}

// ResponsesNew wraps the client.Responses.New call.
func (r *realOpenAIClient) ResponsesNew(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
	return r.client.Responses.New(ctx, params)
}

// ResponsesNewStreaming wraps the client.Responses.NewStreaming call.
func (r *realOpenAIClient) ResponsesNewStreaming(ctx context.Context, params responses.ResponseNewParams) ResponseStream {
	stream := r.client.Responses.NewStreaming(ctx, params)
	return &realResponseStream{stream: stream}
}

// ChatCompletionsNew wraps the client.Chat.Completions.New call.
func (r *realOpenAIClient) ChatCompletionsNew(ctx context.Context, params openai.ChatCompletionNewParams) (*openai.ChatCompletion, error) {
	return r.client.Chat.Completions.New(ctx, params)
}

// ChatCompletionsNewStreaming wraps the client.Chat.Completions.NewStreaming call.
func (r *realOpenAIClient) ChatCompletionsNewStreaming(ctx context.Context, params openai.ChatCompletionNewParams) ChatCompletionStream {
	stream := r.client.Chat.Completions.NewStreaming(ctx, params)
	return &realChatCompletionStream{stream: stream}
}

// EmbeddingsNew wraps the client.Embeddings.New call.
func (r *realOpenAIClient) EmbeddingsNew(ctx context.Context, params openai.EmbeddingNewParams) (*openai.CreateEmbeddingResponse, error) {
	return r.client.Embeddings.New(ctx, params)
}

// realChatCompletionStream wraps a concrete ssestream.Stream to implement ChatCompletionStream interface
type realChatCompletionStream struct {
	stream *ssestream.Stream[openai.ChatCompletionChunk]
}

func (r *realChatCompletionStream) Next() bool {
	return r.stream.Next()
}

func (r *realChatCompletionStream) Current() openai.ChatCompletionChunk {
	return r.stream.Current()
}

func (r *realChatCompletionStream) Err() error {
	return r.stream.Err()
}

func buildOpenAIClientOptions(apiUrl, apiKey string) ([]option.RequestOption, error) {
	parsedUrl, err := url.Parse(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid apiUrl: %w", err)
	}

	opts := make([]option.RequestOption, 0)

	// Extract query params and add as WithQueryAdd options
	query := parsedUrl.Query()
	for key, values := range query {
		for _, val := range values {
			opts = append(opts, option.WithQueryAdd(key, val))
		}
	}

	// Remove query params from the URL
	parsedUrl.RawQuery = ""

	opts = append(opts, option.WithBaseURL(parsedUrl.String()))

	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}

	return opts, nil
}

func checkOpenAIHealth(ctx context.Context, client OpenAIClient, timeoutSeconds int) (*model.HealthResponse, error) {
	healthCtx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(timeoutSeconds))
	defer cancel()

	logger := log.FromContext(ctx)

	status := "unhealthy"

	res, err := client.ModelsList(healthCtx)
	if err != nil {
		logger.WithError(err).Error("error getting models list from OpenAI API")
	} else if len(res.Data) > 0 {
		modelNames := make([]string, len(res.Data))
		for i, m := range res.Data {
			modelNames[i] = m.ID
		}
		logger.WithFields(log.Fields{
			"models": modelNames,
		}).Info("OpenAI API is healthy")
		status = "healthy"
	}

	return &model.HealthResponse{
		Status: status,
	}, nil
}
