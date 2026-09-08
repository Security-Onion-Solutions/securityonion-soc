// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenAIEmbeddingsAdapter(t *testing.T) {
	tests := []struct {
		name                  string
		config                map[string]any
		expectError           bool
		errorContains         string
		expectedHealthTimeout int
		validateHealthTimeout bool
	}{
		{
			name: "Success with all config values",
			config: map[string]any{
				"apiUrl":               "https://api.openai.com/v1",
				"apiKey":               "test-key",
				"healthTimeoutSeconds": float64(6),
			},
			expectError:           false,
			expectedHealthTimeout: 6,
			validateHealthTimeout: true,
		},
		{
			name: "Success uses default health timeout",
			config: map[string]any{
				"apiUrl": "https://api.openai.com/v1",
				"apiKey": "test-key",
			},
			expectError:           false,
			expectedHealthTimeout: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			validateHealthTimeout: true,
		},
		{
			name: "Missing apiUrl returns error",
			config: map[string]any{
				"apiKey": "test-key",
			},
			expectError:   true,
			errorContains: "apiUrl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := server.NewFakeUnauthorizedServer()
			adapter, err := NewOpenAIEmbeddingsAdapter(context.Background(), srv, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, adapter)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, adapter)

				if tt.validateHealthTimeout {
					embeddingsAdapter := adapter.(*OpenAIEmbeddingsAdapter)
					assert.Equal(t, tt.expectedHealthTimeout, embeddingsAdapter.healthTimeoutSeconds)
				}
			}
		})
	}
}

func TestOpenAIEmbeddingsAdapter_Protocol(t *testing.T) {
	adapter := &OpenAIEmbeddingsAdapter{}
	assert.Equal(t, "openai_embeddings", adapter.Protocol())
}

func newEmbeddingsAdapter(client OpenAIClient) *OpenAIEmbeddingsAdapter {
	srv := server.NewFakeUnauthorizedServer()
	return &OpenAIEmbeddingsAdapter{
		srv:    srv,
		client: client,
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}
}

func TestOpenAIEmbeddingsAdapter_Embed(t *testing.T) {
	upstreamErr := errors.New("upstream failure")

	tests := []struct {
		name         string
		mockResponse *openai.CreateEmbeddingResponse
		mockErr      error
		request      *model.EmbeddingRequest
		validate     func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams)
	}{
		{
			name: "single input returns single vector with usage",
			mockResponse: &openai.CreateEmbeddingResponse{
				Model: "text-embedding-3-small",
				Data: []openai.Embedding{
					{Index: 0, Embedding: []float64{0.1, 0.2, 0.3}},
				},
				Usage: openai.CreateEmbeddingResponseUsage{
					PromptTokens: 7,
					TotalTokens:  7,
				},
			},
			request: &model.EmbeddingRequest{
				Model: "text-embedding-3-small",
				Input: []string{"hello world"},
			},
			validate: func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams) {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, "text-embedding-3-small", resp.Model)
				require.Len(t, resp.Embeddings, 1)
				assert.Equal(t, []float32{0.1, 0.2, 0.3}, resp.Embeddings[0])
				require.NotNil(t, resp.Usage)
				assert.Equal(t, 7, resp.Usage.InputTokens)
				assert.Equal(t, 0, resp.Usage.OutputTokens)
			},
		},
		{
			name: "multiple inputs returned index-aligned regardless of order",
			// Return out of order to verify the adapter places by Index.
			mockResponse: &openai.CreateEmbeddingResponse{
				Model: "text-embedding-3-small",
				Data: []openai.Embedding{
					{Index: 2, Embedding: []float64{3.0}},
					{Index: 0, Embedding: []float64{1.0}},
					{Index: 1, Embedding: []float64{2.0}},
				},
				Usage: openai.CreateEmbeddingResponseUsage{PromptTokens: 9, TotalTokens: 9},
			},
			request: &model.EmbeddingRequest{
				Model: "text-embedding-3-small",
				Input: []string{"a", "b", "c"},
			},
			validate: func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams) {
				require.NoError(t, err)
				require.Len(t, resp.Embeddings, 3)
				assert.Equal(t, []float32{1.0}, resp.Embeddings[0])
				assert.Equal(t, []float32{2.0}, resp.Embeddings[1])
				assert.Equal(t, []float32{3.0}, resp.Embeddings[2])
			},
		},
		{
			name: "input and dimensions are forwarded to the client",
			mockResponse: &openai.CreateEmbeddingResponse{
				Model: "text-embedding-3-large",
				Data: []openai.Embedding{
					{Index: 0, Embedding: []float64{0.5}},
					{Index: 1, Embedding: []float64{0.6}},
				},
			},
			request: &model.EmbeddingRequest{
				Model:      "text-embedding-3-large",
				Input:      []string{"x", "y"},
				Dimensions: 256,
			},
			validate: func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams) {
				require.NoError(t, err)
				assert.Equal(t, "text-embedding-3-large", capturedParams.Model)
				assert.Equal(t, []string{"x", "y"}, capturedParams.Input.OfArrayOfStrings)
				require.True(t, capturedParams.Dimensions.Valid(), "dimensions should be set")
				assert.Equal(t, int64(256), capturedParams.Dimensions.Value)
			},
		},
		{
			name:         "dimensions omitted when not requested",
			mockResponse: &openai.CreateEmbeddingResponse{Data: []openai.Embedding{{Index: 0, Embedding: []float64{0.5}}}},
			request: &model.EmbeddingRequest{
				Model: "text-embedding-3-small",
				Input: []string{"x"},
			},
			validate: func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams) {
				require.NoError(t, err)
				assert.False(t, capturedParams.Dimensions.Valid(), "dimensions should be unset")
			},
		},
		{
			name:    "client error is propagated",
			mockErr: upstreamErr,
			request: &model.EmbeddingRequest{
				Model: "text-embedding-3-small",
				Input: []string{"hello"},
			},
			validate: func(t *testing.T, resp *model.EmbeddingResponse, err error, capturedParams openai.EmbeddingNewParams) {
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, upstreamErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured openai.EmbeddingNewParams
			mockClient := &mockOpenAIClient{
				embeddingsNewFunc: func(ctx context.Context, params openai.EmbeddingNewParams) (*openai.CreateEmbeddingResponse, error) {
					captured = params
					return tt.mockResponse, tt.mockErr
				},
			}

			adapter := newEmbeddingsAdapter(mockClient)

			resp, err := adapter.Embed(context.Background(), tt.request)

			tt.validate(t, resp, err, captured)
		})
	}
}

func TestOpenAIEmbeddingsAdapter_ChatUnsupported(t *testing.T) {
	adapter := newEmbeddingsAdapter(&mockOpenAIClient{})

	msg, err := adapter.SendMessage(context.Background(), &model.ChatRequest{Model: "x"})
	assert.Nil(t, msg)
	assert.ErrorIs(t, err, ErrChatUnsupported)

	resp, aux, err := adapter.SendMessageStream(context.Background(), &model.ChatRequest{Model: "x"})
	assert.Nil(t, resp)
	assert.Nil(t, aux)
	assert.ErrorIs(t, err, ErrChatUnsupported)
}

func TestOpenAIEmbeddingsAdapter_GetBalance(t *testing.T) {
	adapter := newEmbeddingsAdapter(&mockOpenAIClient{})

	balance, err := adapter.GetBalance(context.Background())
	require.NoError(t, err)
	require.NotNil(t, balance)
	assert.Equal(t, int64(UNUSED_BALANCE), balance.Balance)
}

func TestOpenAIEmbeddingsAdapter_GetHealth(t *testing.T) {
	// An error from the models list marks the service unhealthy; GetHealth itself
	// never returns an error.
	mockClient := &mockOpenAIClient{
		modelsListFunc: func(ctx context.Context) (*pagination.Page[openai.Model], error) {
			return nil, errors.New("connection refused")
		},
	}

	adapter := newEmbeddingsAdapter(mockClient)

	health, err := adapter.GetHealth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, health)
	assert.Equal(t, "unhealthy", health.Status)
}

// Existing non-embedding adapters must reject Embed so the interface stays honest.
func TestChatAdaptersRejectEmbed(t *testing.T) {
	req := &model.EmbeddingRequest{Model: "x", Input: []string{"hello"}}

	adapters := []server.AssistantAdapter{
		&OpenAIResponsesAdapter{},
		&OpenAIChatAdapter{},
	}

	for _, a := range adapters {
		resp, err := a.Embed(context.Background(), req)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, ErrEmbeddingsUnsupported)
	}
}
