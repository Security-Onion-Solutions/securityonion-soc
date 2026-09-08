package assistant

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/openai/openai-go/v3/responses"
)

type stubOpenAIClient struct {
	ModelsListFunc func(ctx context.Context) (*pagination.Page[openai.Model], error)
}

func (s *stubOpenAIClient) ModelsList(ctx context.Context) (*pagination.Page[openai.Model], error) {
	if s.ModelsListFunc != nil {
		return s.ModelsListFunc(ctx)
	}
	return nil, nil
}

func (s *stubOpenAIClient) ResponsesNew(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
	return nil, nil
}

func (s *stubOpenAIClient) ResponsesNewStreaming(ctx context.Context, params responses.ResponseNewParams) ResponseStream {
	return nil
}

func (s *stubOpenAIClient) ChatCompletionsNew(ctx context.Context, params openai.ChatCompletionNewParams) (*openai.ChatCompletion, error) {
	return nil, nil
}

func (s *stubOpenAIClient) ChatCompletionsNewStreaming(ctx context.Context, params openai.ChatCompletionNewParams) ChatCompletionStream {
	return nil
}

func (s *stubOpenAIClient) EmbeddingsNew(ctx context.Context, params openai.EmbeddingNewParams) (*openai.CreateEmbeddingResponse, error) {
	return nil, nil
}

func TestBuildOpenAIClientOptions(t *testing.T) {
	tests := []struct {
		name      string
		apiUrl    string
		apiKey    string
		expectErr bool
	}{
		{
			name:      "Valid URL with no query params and API key",
			apiUrl:    "https://api.openai.com/v1",
			apiKey:    "test-key",
			expectErr: false,
		},
		{
			name:      "Valid URL with query params",
			apiUrl:    "https://api.openai.com/v1/chat/completions?api-version=2024-02-15-preview&foo=bar",
			apiKey:    "test-key",
			expectErr: false,
		},
		{
			name:      "Invalid URL",
			apiUrl:    "://invalid-url",
			apiKey:    "",
			expectErr: true,
		},
		{
			name:      "Empty API key",
			apiUrl:    "https://api.openai.com/v1",
			apiKey:    "",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := buildOpenAIClientOptions(tt.apiUrl, tt.apiKey)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if opts == nil {
				t.Errorf("expected options, got nil")
				return
			}

			expectedOptsLen := 1 // BaseURL is always added
			if tt.apiKey != "" {
				expectedOptsLen++
			}

			parsedUrl, _ := url.Parse(tt.apiUrl)
			query := parsedUrl.Query()
			for _, values := range query {
				expectedOptsLen += len(values)
			}

			if len(opts) != expectedOptsLen {
				t.Errorf("expected %d options, got %d", expectedOptsLen, len(opts))
			}
		})
	}
}

func TestCheckOpenAIHealth(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		modelsListResult *pagination.Page[openai.Model]
		listErr          error
		wantStatus       string
	}{
		{
			name:       "API Error",
			listErr:    errors.New("api error"),
			wantStatus: "unhealthy",
		},
		{
			name: "API Success with models",
			modelsListResult: &pagination.Page[openai.Model]{
				Data: []openai.Model{
					{ID: "model1"},
					{ID: "model2"},
				},
			},
			wantStatus: "healthy",
		},
		{
			name: "API Success without models",
			modelsListResult: &pagination.Page[openai.Model]{
				Data: []openai.Model{},
			},
			wantStatus: "unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &stubOpenAIClient{
				ModelsListFunc: func(ctx context.Context) (*pagination.Page[openai.Model], error) {
					return tt.modelsListResult, tt.listErr
				},
			}

			health, err := checkOpenAIHealth(ctx, client, 5)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if health.Status != tt.wantStatus {
				t.Errorf("expected %s, got %s", tt.wantStatus, health.Status)
			}
		})
	}
}
