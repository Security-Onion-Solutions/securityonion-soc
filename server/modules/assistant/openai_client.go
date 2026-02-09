// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/openai/openai-go/v3/packages/ssestream"
	"github.com/openai/openai-go/v3/responses"
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

// OpenAIClient is an interface that wraps the openai.Client functionality we use.
// This allows us to mock the OpenAI client for testing.
type OpenAIClient interface {
	// ModelsList wraps access to the Models.List API
	ModelsList(ctx context.Context) (*pagination.Page[openai.Model], error)

	// ResponsesNew wraps the Responses.New method for non-streaming calls
	ResponsesNew(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error)

	// ResponsesNewStreaming wraps the Responses.NewStreaming method for streaming calls
	ResponsesNewStreaming(ctx context.Context, params responses.ResponseNewParams) ResponseStream
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
