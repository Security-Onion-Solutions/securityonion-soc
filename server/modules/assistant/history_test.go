// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
)

func TestHistoryToContext(t *testing.T) {
	tests := []struct {
		name            string
		history         []*model.StoredMessage
		expectedContext []*model.Message
	}{
		{
			name: "simple history, no compression",
			history: []*model.StoredMessage{
				{
					Message: &model.Message{
						Role:          "user",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}},
					},
				},
				{
					Message: &model.Message{
						Role:          "assistant",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hi there! How can I assist you?"}},
					},
				},
			},
			expectedContext: []*model.Message{
				{
					Role:          "user",
					ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}},
				},
				{
					Role:          "assistant",
					ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hi there! How can I assist you?"}},
				},
			},
		},
		{
			name: "compressed history",
			history: []*model.StoredMessage{
				{
					Message: &model.Message{
						Role:          "user",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}},
					},
				},
				{
					Message: &model.Message{
						Role:          "assistant",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hi there! How can I assist you?"}},
					},
					Tags: []string{"something_else"},
				},
				{
					Message: &model.Message{
						Role:          "user",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Can you do a thing for me?"}},
					},
				},
				{
					Message: &model.Message{
						Role:          "assistant",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Sure thing, that generated a lot of data"}},
					},
				},
				{
					Message: &model.Message{
						Role:          "user",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Compress it"}},
					},
					Tags: []string{model.MessageTagContextCompression},
				},
				{
					Message: &model.Message{
						Role:          "assistant",
						ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Less data"}},
					},
				},
			},
			expectedContext: []*model.Message{
				{
					Role:          "user",
					ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Compress it"}},
				},
				{
					Role:          "assistant",
					ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Less data"}},
				},
			},
		},
		{
			name:            "empty history",
			history:         []*model.StoredMessage{},
			expectedContext: []*model.Message{},
		},
		{
			name: "compression tag on the last message keeps only that message",
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}}},
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hi"}}}},
				{
					Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Summary so far"}}},
					Tags:    []string{model.MessageTagContextCompression},
				},
			},
			expectedContext: []*model.Message{
				{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Summary so far"}}},
			},
		},
		{
			name: "multiple compression tags keep only the final segment",
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "First"}}}},
				{
					Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "First compression"}}},
					Tags:    []string{model.MessageTagContextCompression},
				},
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "mid"}}}},
				{
					Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Second compression"}}},
					Tags:    []string{model.MessageTagContextCompression},
				},
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "latest"}}}},
			},
			expectedContext: []*model.Message{
				{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Second compression"}}},
				{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "latest"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextMessages := HistoryToContext(tt.history)
			assert.Equal(t, tt.expectedContext, contextMessages)
		})
	}
}
