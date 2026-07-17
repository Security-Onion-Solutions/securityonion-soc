package assistant

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
)

// ErrEmbeddingsUnsupported is returned by chat-oriented adapters when asked to
// generate embeddings.
var ErrEmbeddingsUnsupported = errors.New("adapter does not support embeddings")

// ErrChatUnsupported is returned by the embeddings adapter when asked to perform
// a chat-style interaction.
var ErrChatUnsupported = errors.New("embeddings adapter does not support chat")

func init() {
	protocols[(&OpenAIEmbeddingsAdapter{}).Protocol()] = NewOpenAIEmbeddingsAdapter
}

type OpenAIEmbeddingsAdapter struct {
	srv                  *server.Server
	client               OpenAIClient
	healthTimeoutSeconds int
	detections.IOManager
}

func NewOpenAIEmbeddingsAdapter(ctx context.Context, srv *server.Server, config map[string]any) (server.AssistantAdapter, error) {
	apiUrl := module.GetStringDefault(config, "apiUrl", "")
	if apiUrl == "" {
		return nil, fmt.Errorf("openai_embeddings adapter requires apiUrl in config")
	}

	apiKey := module.GetStringDefault(config, "apiKey", "")
	opts, err := buildOpenAIClientOptions(apiUrl, apiKey)
	if err != nil {
		return nil, fmt.Errorf("openai_embeddings adapter config error: %w", err)
	}

	healthTimeoutSeconds := module.GetIntDefault(config, "healthTimeoutSeconds", DEFAULT_HEALTH_TIMEOUT_SECONDS)

	return &OpenAIEmbeddingsAdapter{
		srv:                  srv,
		healthTimeoutSeconds: healthTimeoutSeconds,
		client:               NewOpenAIClientWrapper(openai.NewClient(opts...)),
		IOManager: &detections.ResourceManager{
			Config: srv.Config,
		},
	}, nil
}

func (a *OpenAIEmbeddingsAdapter) Protocol() string {
	return "openai_embeddings"
}

// Embed generates a vector embedding for each input, index-aligned with req.Input.
func (a *OpenAIEmbeddingsAdapter) Embed(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	logger := log.FromContext(ctx)

	params := openai.EmbeddingNewParams{
		Model: req.Model,
		Input: openai.EmbeddingNewParamsInputUnion{
			OfArrayOfStrings: req.Input,
		},
	}

	// Dimensions is only honored by text-embedding-3 and later models; leave it
	// unset (provider default) unless the caller explicitly requested a size.
	if req.Dimensions > 0 {
		params.Dimensions = openai.Int(int64(req.Dimensions))
	}

	resp, err := a.client.EmbeddingsNew(ctx, params)
	if err != nil {
		logger.WithFields(log.Fields{
			"model": req.Model,
		}).WithError(err).Error("error calling OpenAI embeddings API")
		return nil, err
	}

	// Preserve request order. The API returns each embedding with its input
	// Index, so place vectors by index rather than trusting slice order.
	embeddings := make([][]float64, len(resp.Data))
	for _, item := range resp.Data {
		idx := int(item.Index)
		if idx < 0 || idx >= len(embeddings) {
			// Unexpected index from the provider; skip rather than panic.
			logger.WithFields(log.Fields{
				"index": idx,
				"count": len(embeddings),
			}).Warn("embedding index out of range, skipping")
			continue
		}
		embeddings[idx] = item.Embedding
	}

	return &model.EmbeddingResponse{
		Model:      resp.Model,
		Embeddings: embeddings,
		Usage: &model.Usage{
			InputTokens:  int(resp.Usage.PromptTokens),
			OutputTokens: 0,
		},
	}, nil
}

// SendMessage is part of the AssistantAdapter interface but is not meaningful for
// an embeddings provider.
func (a *OpenAIEmbeddingsAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	return nil, ErrChatUnsupported
}

// SendMessageStream is part of the AssistantAdapter interface but is not
// meaningful for an embeddings provider.
func (a *OpenAIEmbeddingsAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	return nil, nil, ErrChatUnsupported
}

func (a *OpenAIEmbeddingsAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{
		Balance: UNUSED_BALANCE,
	}, nil
}

func (a *OpenAIEmbeddingsAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return checkOpenAIHealth(ctx, a.client, a.healthTimeoutSeconds)
}
