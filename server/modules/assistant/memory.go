package assistant

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

func (ac *AssistantCoordinator) memoryWorker(ctx context.Context) {
	logger := log.FromContext(ctx)

	memoryAgent, memoryModel, err := ac.resolveAgent("Memory")
	if err != nil {
		logger.WithError(err).Error("unable to resolve Memory agent")
	}

	embedAgent, embedModel, err := ac.resolveAgent("Embed")
	if err != nil {
		logger.WithError(err).Error("unable to resolve Embed agent")
	}

	_, _, _, _ = memoryAgent, memoryModel, embedAgent, embedModel

	extract := sync.OnceFunc(func() {
		details := &model.AssistantSessionDetails{
			Session: &model.AssistantSession{
				LastMemoryScannedIndex: 0,
			},
			History: []*model.StoredMessage{
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "text",
								Text: "I keep getting OOM crashes on my Elasticsearch VM. I'm on Ubuntu and I run everything through Docker Compose. Our team standardized on Forgejo for CI last quarter. Btw I always use `any` in Go now, never interface{}.",
							},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "text",
								Text: "Have you tried capping the JVM heap? You could also enable AlwaysPreTouch.",
							},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "text",
								Text: "Yeah AlwaysPreTouch helped. I'll set the heap cap.",
							},
						},
					},
				},
			},
		}

		facts, err := ac.extractFacts(ctx, details, memoryAgent, memoryModel)
		if err != nil {
			logger.WithError(err).Error("unable to extract facts")
			return
		}

		logger.WithField("facts", len(facts)).Info("extracted facts")

		justFacts := make([]string, 0, len(facts))
		for _, f := range facts {
			justFacts = append(justFacts, f.Fact)
		}

		res, err := ac.Embed(ctx, embedModel.DisplayName, justFacts)
		if err != nil {
			logger.WithError(err).Error("unable to embed")
			return
		}

		_ = res
	})

	for {
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			logger.WithField("cause", err).Info("memory worker shutting down")

			return
		case <-time.After(ac.memoryScanInterval):
		}

		extract()
	}
}

func (ac *AssistantCoordinator) extractFacts(ctx context.Context, details *model.AssistantSessionDetails, memoryAgent *model.AgentParameters, memoryModel *model.ModelParameters) ([]*model.ExtractedFact, error) {
	ts := buildMemoryExtractTranscript(details)

	req := &model.ChatRequest{
		Messages: []*model.Message{
			{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: ts,
					},
				},
			},
		},
		UserId: server.SYSTEM_ID,
		Model:  memoryModel.ID,
	}

	err := ac.setupAgent(ctx, req, memoryAgent)
	if err != nil {
		return nil, err
	}

	adapter := ac.adapters[memoryModel.Adapter]

	msg, err := adapter.SendMessage(ctx, req)
	if err != nil {
		return nil, err
	}

	jsn := msg.ContentBlocks[0].Text

	extracted := []*model.ExtractedFact{}

	err = json.Unmarshal([]byte(jsn), &extracted)
	if err != nil {
		return nil, err
	}

	return extracted, nil
}

func buildMemoryExtractTranscript(details *model.AssistantSessionDetails) string {
	lines := []string{}

	begin := max(details.Session.LastMemoryScannedIndex-2, 0)

	if begin >= len(details.History) {
		return ""
	}

	for _, msg := range details.History[begin:] {
		line := strings.Builder{}
		line.WriteString(msg.Message.Role)
		line.WriteString(": ")
		for _, cb := range msg.Message.ContentBlocks {
			if strings.EqualFold(cb.Type, "text") {
				line.WriteString(cb.Text)
			}
		}

		lines = append(lines, line.String())
	}

	return strings.Join(lines, "\n\n")
}
