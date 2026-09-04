// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modmock "github.com/security-onion-solutions/securityonion-soc/server/modules/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestAssistantStoreInit(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)
	err := store.Init("chat-index", "session-index", "so_")
	assert.NoError(t, err)
	assert.Equal(t, "chat-index", store.chatIndex)
	assert.Equal(t, "session-index", store.sessionIndex)
	assert.Equal(t, "so_", store.schemaPrefix)
}

func TestValidateId(t *testing.T) {
	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), nil, 1000)
	store.Init("chat-index", "session-index", "so_")

	tests := []struct {
		name      string
		id        string
		wantError bool
	}{
		{"valid short id", "12345", false},
		{"valid with underscores and hyphens", "chat_1757086398900_ykhmndscn", false},
		{"valid with mixed separators", "a-b-c_d-e_f", false},
		{"valid max length", "12345678901234567890123456789012345678901234567890", false},
		{"empty id", "", true},
		{"too short", "1234", true},
		{"too long", "123456789012345678901234567890123456789012345678901", true},
		{"contains spaces", "invalid id", true},
		{"contains special chars", "invalid@id", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.validateId(tt.id, "test")
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateChat(t *testing.T) {
	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), nil, 1000)
	store.Init("chat-index", "session-index", "so_")

	tests := []struct {
		name      string
		chat      *model.StoredMessage
		wantError bool
	}{
		{
			name: "valid chat with ContentStr",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message: &model.Message{
					ContentStr: "Hello, world!",
				},
			},
			wantError: false,
		},
		{
			name: "valid chat with ContentBlocks",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message: &model.Message{
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "invalid session ID",
			chat: &model.StoredMessage{
				SessionId: "bad",
				Message: &model.Message{
					ContentStr: "Hello",
				},
			},
			wantError: true,
		},
		{
			name: "missing content",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message:   &model.Message{},
			},
			wantError: true,
		},
		{
			name: "both content types",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message: &model.Message{
					ContentStr: "Hello",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "World"},
					},
				},
			},
			wantError: true,
		},
		{
			name: "empty text in content block - allowed",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message: &model.Message{
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: ""},
					},
				},
			},
			wantError: false,
		},
		{
			name: "missing type in content block",
			chat: &model.StoredMessage{
				SessionId: "chat_123456",
				Message: &model.Message{
					ContentBlocks: []model.ContentBlock{
						{Text: "Hello"},
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.validateChat(tt.chat)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSession(t *testing.T) {
	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), nil, 1000)
	store.Init("chat-index", "session-index", "so_")

	tests := []struct {
		name      string
		session   *model.AssistantSession
		wantError bool
	}{
		{
			name: "valid session",
			session: &model.AssistantSession{
				SessionId: "chat_123456",
				Title:     "My Chat Session",
			},
			wantError: false,
		},
		{
			name: "invalid session ID",
			session: &model.AssistantSession{
				SessionId: "bad",
				Title:     "My Chat Session",
			},
			wantError: true,
		},
		{
			name: "empty title",
			session: &model.AssistantSession{
				SessionId: "chat_123456",
				Title:     "",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.validateSession(tt.session)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPopulateSessionUsage_Empty(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)
	store.Init("chat-index", "session-index", "so_")
	ctx := context.Background()

	tests := []struct {
		name     string
		sessions []*model.AssistantSession
	}{
		{"empty sessions", []*model.AssistantSession{}},
		{"nil sessions", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.populateSessionUsage(ctx, tt.sessions)
			assert.NoError(t, err)
		})
	}
}

func TestPopulateSessionUsage_Success(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	sessions := []*model.AssistantSession{
		{
			SessionId: "session1",
			Title:     "First Session",
		},
		{
			SessionId: "session2",
			Title:     "Second Session",
		},
	}

	// Mock MSearch response with usage data for both sessions
	msearchResponse := `{
		"responses": [
			{
				"hits": {
					"total": {
						"value": 10
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 1500.0
					},
					"total_output_tokens": {
						"value": 3000.0
					},
					"total_credits": {
						"value": 5.0
					},
					"total_messages": {
						"value": 10.0
					},
					"model_usage": {
						"buckets": [
							{
								"key": "claude-sonnet-4.5@SOAI",
								"model_input_tokens": {
									"value": 1000.0
								},
								"model_output_tokens": {
									"value": 2000.0
								},
								"model_credits": {
									"value": 3.0
								},
								"model_messages": {
									"value": 6.0
								}
							},
							{
								"key": "gpt-4@OpenAI",
								"model_input_tokens": {
									"value": 500.0
								},
								"model_output_tokens": {
									"value": 1000.0
								},
								"model_credits": {
									"value": 2.0
								},
								"model_messages": {
									"value": 4.0
								}
							}
						]
					}
				}
			},
			{
				"hits": {
					"total": {
						"value": 15
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 2500.0
					},
					"total_output_tokens": {
						"value": 4500.0
					},
					"total_credits": {
						"value": 8.0
					},
					"total_messages": {
						"value": 15.0
					},
					"model_usage": {
						"buckets": [
							{
								"key": "claude-sonnet-4.5@SOAI",
								"model_input_tokens": {
									"value": 2500.0
								},
								"model_output_tokens": {
									"value": 4500.0
								},
								"model_credits": {
									"value": 8.0
								},
								"model_messages": {
									"value": 15.0
								}
							}
						]
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	err := store.populateSessionUsage(ctx, sessions)
	assert.NoError(t, err)

	// Verify first session usage
	assert.NotNil(t, sessions[0].Usage)
	assert.Equal(t, 1500, sessions[0].Usage.TotalInputTokens)
	assert.Equal(t, 3000, sessions[0].Usage.TotalOutputTokens)
	assert.Equal(t, 5, sessions[0].Usage.TotalCredits)
	assert.Equal(t, 10, sessions[0].Usage.TotalMessages)

	// Verify first session model usage
	assert.NotNil(t, sessions[0].Usage.ModelUsage)
	assert.Len(t, sessions[0].Usage.ModelUsage, 2)

	claudeStats := sessions[0].Usage.ModelUsage["claude-sonnet-4.5@SOAI"]
	assert.NotNil(t, claudeStats)
	assert.Equal(t, 1000, claudeStats.ModelInputTokens)
	assert.Equal(t, 2000, claudeStats.ModelOutputTokens)
	assert.Equal(t, 3, claudeStats.ModelCredits)
	assert.Equal(t, 6, claudeStats.ModelMessages)

	gptStats := sessions[0].Usage.ModelUsage["gpt-4@OpenAI"]
	assert.NotNil(t, gptStats)
	assert.Equal(t, 500, gptStats.ModelInputTokens)
	assert.Equal(t, 1000, gptStats.ModelOutputTokens)
	assert.Equal(t, 2, gptStats.ModelCredits)
	assert.Equal(t, 4, gptStats.ModelMessages)

	// Verify second session usage
	assert.NotNil(t, sessions[1].Usage)
	assert.Equal(t, 2500, sessions[1].Usage.TotalInputTokens)
	assert.Equal(t, 4500, sessions[1].Usage.TotalOutputTokens)
	assert.Equal(t, 8, sessions[1].Usage.TotalCredits)
	assert.Equal(t, 15, sessions[1].Usage.TotalMessages)

	// Verify second session model usage
	assert.NotNil(t, sessions[1].Usage.ModelUsage)
	assert.Len(t, sessions[1].Usage.ModelUsage, 1)

	claudeStats2 := sessions[1].Usage.ModelUsage["claude-sonnet-4.5@SOAI"]
	assert.NotNil(t, claudeStats2)
	assert.Equal(t, 2500, claudeStats2.ModelInputTokens)
	assert.Equal(t, 4500, claudeStats2.ModelOutputTokens)
	assert.Equal(t, 8, claudeStats2.ModelCredits)
	assert.Equal(t, 15, claudeStats2.ModelMessages)
}

func TestPopulateSessionUsage_WithErrors(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	sessions := []*model.AssistantSession{
		{
			SessionId: "session1",
			Title:     "First Session",
		},
		{
			SessionId: "session2",
			Title:     "Second Session",
		},
	}

	// Mock MSearch response where first query has an error, second succeeds
	msearchResponse := `{
		"responses": [
			{
				"error": {
					"type": "index_not_found_exception",
					"reason": "no such index"
				}
			},
			{
				"hits": {
					"total": {
						"value": 15
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 2500.0
					},
					"total_output_tokens": {
						"value": 4500.0
					},
					"total_credits": {
						"value": 8.0
					},
					"total_messages": {
						"value": 15.0
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	err := store.populateSessionUsage(ctx, sessions)
	assert.NoError(t, err)

	// First session should not have usage (error occurred)
	assert.Nil(t, sessions[0].Usage)

	// Second session should have usage
	assert.NotNil(t, sessions[1].Usage)
	assert.Equal(t, 2500, sessions[1].Usage.TotalInputTokens)
	assert.Equal(t, 4500, sessions[1].Usage.TotalOutputTokens)
	assert.Equal(t, 8, sessions[1].Usage.TotalCredits)
	assert.Equal(t, 15, sessions[1].Usage.TotalMessages)
}

func TestPopulateSessionUsage_ZeroValues(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	sessions := []*model.AssistantSession{
		{
			SessionId: "session1",
			Title:     "Empty Session",
		},
	}

	// Mock MSearch response with zero values (no messages in session)
	msearchResponse := `{
		"responses": [
			{
				"hits": {
					"total": {
						"value": 0
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 0.0
					},
					"total_output_tokens": {
						"value": 0.0
					},
					"total_credits": {
						"value": 0.0
					},
					"total_messages": {
						"value": 0.0
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	err := store.populateSessionUsage(ctx, sessions)
	assert.NoError(t, err)

	// Verify session has usage struct with zero values
	assert.NotNil(t, sessions[0].Usage)
	assert.Equal(t, 0, sessions[0].Usage.TotalInputTokens)
	assert.Equal(t, 0, sessions[0].Usage.TotalOutputTokens)
	assert.Equal(t, 0, sessions[0].Usage.TotalCredits)
	assert.Equal(t, 0, sessions[0].Usage.TotalMessages)
}

func TestGetSessions_WithUsage(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock search response for sessions
	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Test Session",
							"userId": "test-user"
						}
					}
				},
				{
					"_id": "session2",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session2",
							"title": "Test Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	// Mock MSearch response for usage
	msearchResponse := `{
		"responses": [
			{
				"aggregations": {
					"total_input_tokens": {
						"value": 1000.0
					},
					"total_output_tokens": {
						"value": 2000.0
					},
					"total_credits": {
						"value": 3.0
					},
					"total_messages": {
						"value": 5.0
					}
				}
			},
			{
				"aggregations": {
					"total_input_tokens": {
						"value": 4000.0
					},
					"total_output_tokens": {
						"value": 5000.0
					},
					"total_credits": {
						"value": 6.0
					},
					"total_messages": {
						"value": 2.0
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			},
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithUsage(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 2)
	assert.NotNil(t, sessions[0].Usage)
	assert.Equal(t, 1000, sessions[0].Usage.TotalInputTokens)
	assert.Equal(t, 2000, sessions[0].Usage.TotalOutputTokens)
	assert.Equal(t, 3, sessions[0].Usage.TotalCredits)
	assert.Equal(t, 5, sessions[0].Usage.TotalMessages)
}

func TestGetSessions_WithoutUsage(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock search response for sessions
	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Test Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time) - always called
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	// No usage MSearch call should be made when usage is false
	sessions, err := store.GetSessions(ctx, model.GetSessionsWithUsage(false))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Nil(t, sessions[0].Usage)
}

func TestPrepareForSave(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)
	obj := &model.Auditable{
		Id: "test-id",
	}
	now := time.Now()
	obj.UpdateTime = &now

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	actualId := store.prepareForSave(ctx, obj)

	assert.Equal(t, "test-id", actualId)
	assert.Equal(t, "test-user", obj.UserId)
	assert.Equal(t, "", obj.Id)
	assert.Nil(t, obj.UpdateTime)
}

func TestTruncate(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 10)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short string", "short", "short"},
		{"exact length", "1234567890", "1234567890"},
		{"long string", "12345678901234567890", "1234567890..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.truncate(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDisableCrossClusterIndex(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"regular index", "my-index", "my-index"},
		{"cross-cluster index", "cluster1:my-index", "my-index"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.disableCrossClusterIndex(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSaveChat(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	chat := &model.StoredMessage{
		SessionId: "chat_123456",
		Message: &model.Message{
			ContentStr: "Hello, world!",
		},
	}

	// Mock index response
	indexResponse := `{
		"_index": "chat-index",
		"_id": "msg1",
		"_version": 1,
		"result": "created",
		"_shards": {
			"total": 2,
			"successful": 1,
			"failed": 0
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 201,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(indexResponse)),
	}, nil)

	// Mock UpdateByQuery response for the session messageCount increment
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"took": 1, "updated": 1, "version_conflicts": 0, "failures": []}`)),
	}, nil)

	err := store.SaveChat(ctx, chat)
	assert.NoError(t, err)
	assert.NotNil(t, chat.CreateTime)
	assert.Equal(t, "test-user", chat.UserId)

	// The save must also bump the session's denormalized messageCount so the
	// memory scanner can find the session in a single query.
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 2)
	assert.Contains(t, reqs[1].URL.Path, "_update_by_query")
	assert.Contains(t, reqs[1].URL.RawQuery, "conflicts=proceed")
	body, err := io.ReadAll(reqs[1].Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "messageCount")
	assert.Contains(t, string(body), "chat_123456")
	// New activity gives a session excluded for repeated scan failures another chance.
	assert.Contains(t, string(body), "s.memoryErrors = 0;")
}

func TestIncrementSessionMessageCount_ElasticsearchErrorResponse(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	addJsonResponse(transport, 500, `{"error":{"type":"script_exception","reason":"runtime error"},"status":500}`)

	err := store.incrementSessionMessageCount(context.Background(), "chat_123456")
	assert.ErrorContains(t, err, "script_exception")
}

func TestSaveChat_IncrementFailureNonFatal(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	chat := &model.StoredMessage{
		SessionId: "chat_123456",
		Message: &model.Message{
			ContentStr: "Hello, world!",
		},
	}

	transport.AddResponse(&http.Response{
		StatusCode: 201,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"_id": "msg1", "result": "created"}`)),
	}, nil)

	transport.AddResponse(nil, errors.New("update by query failed"))

	// The message is durably saved before the increment; a failed increment
	// must not fail the save.
	err := store.SaveChat(ctx, chat)
	assert.NoError(t, err)
}

func TestCreateSession(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	session := &model.AssistantSession{
		SessionId: "chat_123456",
		Title:     "My Chat Session",
		Model:     "AgentTest@MyAdapter",
	}

	// Mock index response
	indexResponse := `{
		"_index": "session-index",
		"_id": "session1",
		"_version": 1,
		"result": "created",
		"_shards": {
			"total": 2,
			"successful": 1,
			"failed": 0
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 201,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(indexResponse)),
	}, nil)

	err := store.CreateSession(ctx, session)
	assert.NoError(t, err)
	assert.NotNil(t, session.CreateTime)
	assert.Equal(t, "test-user", session.UserId)

	// The session's own model must be persisted so it can be resumed server-side
	// without trusting the client-supplied model.
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)
	body, err := io.ReadAll(reqs[0].Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "AgentTest@MyAdapter")
}

func TestDeleteSession(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock UpdateByQuery response
	updateResponse := `{
		"took": 10,
		"timed_out": false,
		"total": 1,
		"updated": 1,
		"deleted": 0,
		"batches": 1,
		"version_conflicts": 0,
		"noops": 0,
		"retries": {
			"bulk": 0,
			"search": 0
		},
		"throttled_millis": 0,
		"requests_per_second": -1.0,
		"throttled_until_millis": 0,
		"failures": []
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(updateResponse)),
	}, nil)

	err := store.DeleteSession(ctx, "session1")
	assert.NoError(t, err)
}

func addJsonResponse(transport *modmock.MockTransport, statusCode int, body string) {
	transport.AddResponse(&http.Response{
		StatusCode: statusCode,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}, nil)
}

func TestFindSessionsPendingMemoryScan(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	// Two pending sessions: one with counts recorded, one legacy session that
	// predates messageCount/lastMemoryScannedIndex entirely.
	sessionResponse := `{
		"hits": {
			"total": { "value": 2 },
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"userId": "user-a",
							"lastMemoryScannedIndex": 1,
							"messageCount": 2
						}
					}
				},
				{
					"_id": "session2",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session2",
							"userId": "user-b"
						}
					}
				}
			]
		}
	}`
	addJsonResponse(transport, 200, sessionResponse)

	chatResponse1 := `{
		"hits": {
			"total": { "value": 2 },
			"hits": [
				{
					"_id": "msg1",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session1",
							"message": { "role": "user", "contentStr": "Hello" }
						}
					}
				},
				{
					"_id": "msg2",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session1",
							"message": { "role": "assistant", "contentStr": "Hi there!" }
						}
					}
				}
			]
		}
	}`
	addJsonResponse(transport, 200, chatResponse1)

	chatResponse2 := `{
		"hits": {
			"total": { "value": 1 },
			"hits": [
				{
					"_id": "msg3",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session2",
							"message": { "role": "user", "contentStr": "Legacy message" }
						}
					}
				}
			]
		}
	}`
	addJsonResponse(transport, 200, chatResponse2)

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.NoError(t, err)
	assert.Len(t, details, 2)

	assert.Equal(t, "session1", details[0].Session.SessionId)
	assert.Equal(t, 1, details[0].Session.LastMemoryScannedIndex)
	assert.Equal(t, 2, details[0].Session.MessageCount)
	assert.Len(t, details[0].History, 2)
	assert.Equal(t, "Hello", details[0].History[0].Message.ContentStr)

	assert.Equal(t, "session2", details[1].Session.SessionId)
	assert.Equal(t, 0, details[1].Session.LastMemoryScannedIndex)
	assert.Len(t, details[1].History, 1)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 3)

	// The pending check is a single query on the session index: a script filter
	// comparing messageCount to lastMemoryScannedIndex, restricted to
	// non-deleted root sessions.
	body, err := io.ReadAll(reqs[0].Body)
	assert.NoError(t, err)
	assert.Contains(t, reqs[0].URL.Path, "session-index")
	assert.Contains(t, string(body), "script")
	assert.Contains(t, string(body), "so_session.messageCount")
	assert.Contains(t, string(body), "so_session.lastMemoryScannedIndex")
	// sessions past the retry threshold are excluded; a missing memoryErrors
	// counts as zero
	assert.Contains(t, string(body), `"so_session.memoryErrors":{"lte":2}`)
	assert.Contains(t, string(body), `"must_not":{"exists":{"field":"so_session.memoryErrors"}}`)
	assert.Contains(t, string(body), "so_session.deleteTime")
	assert.Contains(t, string(body), "so_session.parentSessionId")
	// memory-usage bookkeeping sessions are never scanned themselves
	assert.Contains(t, string(body), "so_session.tags")
	assert.Contains(t, string(body), `"memory"`)
	assert.Contains(t, string(body), `"embed"`)
	assert.Contains(t, string(body), `"reconcile"`)
	// nil dontScanBefore adds no range clause
	var pendingQuery map[string]any
	assert.NoError(t, json.Unmarshal(body, &pendingQuery))
	for _, clause := range pendingQuery["query"].(map[string]any)["bool"].(map[string]any)["must"].([]any) {
		_, hasRange := clause.(map[string]any)["range"]
		assert.False(t, hasRange)
	}

	body, err = io.ReadAll(reqs[1].Body)
	assert.NoError(t, err)
	assert.Contains(t, reqs[1].URL.Path, "chat-index")
	assert.Contains(t, string(body), "session1")

	body, err = io.ReadAll(reqs[2].Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "session2")
}

func TestFindSessionsPendingMemoryScan_EmptyHistorySkipped(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	// A legacy session with no messageCount matches the pending query even when
	// it has no messages at all; it must be skipped, not scanned.
	sessionResponse := `{
		"hits": {
			"total": { "value": 1 },
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"userId": "user-a"
						}
					}
				}
			]
		}
	}`
	addJsonResponse(transport, 200, sessionResponse)
	addJsonResponse(transport, 200, `{"hits": {"total": {"value": 0}, "hits": []}}`)

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.NoError(t, err)
	assert.Empty(t, details)
}

func TestFindSessionsPendingMemoryScan_HistoryErrorSkipsSession(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	sessionResponse := `{
		"hits": {
			"total": { "value": 2 },
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": { "sessionId": "session1", "userId": "user-a" }
					}
				},
				{
					"_id": "session2",
					"_source": {
						"so_kind": "session",
						"so_session": { "sessionId": "session2", "userId": "user-b" }
					}
				}
			]
		}
	}`
	addJsonResponse(transport, 200, sessionResponse)

	// session1's history fetch fails; the scan continues with session2.
	addJsonResponse(transport, 500, `{"error": "internal server error"}`)
	addJsonResponse(transport, 200, `{
		"hits": {
			"total": { "value": 1 },
			"hits": [
				{
					"_id": "msg1",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session2",
							"message": { "role": "user", "contentStr": "Hello" }
						}
					}
				}
			]
		}
	}`)

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.NoError(t, err)
	assert.Len(t, details, 1)
	assert.Equal(t, "session2", details[0].Session.SessionId)
}

func TestFindSessionsPendingMemoryScan_NoResults(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 200, `{"hits": {"total": {"value": 0}, "hits": []}}`)

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.NoError(t, err)
	assert.Empty(t, details)
	assert.Len(t, transport.GetRequests(), 1)
}

func TestFindSessionsPendingMemoryScan_DontScanBefore(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 200, `{"hits": {"total": {"value": 0}, "hits": []}}`)

	// The caller's instant is honored verbatim, offset included, so
	// Elasticsearch cannot reinterpret the day boundary as UTC.
	cutoff := time.Date(2026, 8, 15, 13, 45, 0, 0, time.FixedZone("MST", -7*3600))
	details, err := store.FindSessionsPendingMemoryScan(ctx, &cutoff, 2)
	assert.NoError(t, err)
	assert.Empty(t, details)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustQuery := boolQuery["must"].([]any)

	foundRange := false
	for _, clause := range mustQuery {
		if rangeClause, ok := clause.(map[string]any)["range"].(map[string]any); ok {
			if timestampRange, exists := rangeClause["@timestamp"].(map[string]any); exists {
				assert.Equal(t, "2026-08-15T13:45:00-07:00", timestampRange["gte"])
				foundRange = true
			}
		}
	}
	assert.True(t, foundRange, "dontScanBefore range filter should be in query")
}

func TestFindSessionsPendingMemoryScan_ElasticsearchError(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 500, `{"error": "internal server error"}`)

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.Error(t, err)
	assert.Nil(t, details)
}

func TestFindSessionsPendingMemoryScan_Unauthorized(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeUnauthorizedServer(), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	details, err := store.FindSessionsPendingMemoryScan(ctx, nil, 2)
	assert.Error(t, err)
	assert.Nil(t, details)
	assert.Empty(t, transport.GetRequests())
}

func TestUpdateSessionMemoryScanIndex(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 200, `{"took": 1, "updated": 1, "version_conflicts": 0, "failures": []}`)

	err := store.UpdateSessionMemoryScanIndex(ctx, "chat_123456", 7)
	assert.NoError(t, err)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)
	assert.Contains(t, reqs[0].URL.Path, "session-index")
	assert.Contains(t, reqs[0].URL.Path, "_update_by_query")
	assert.Contains(t, reqs[0].URL.RawQuery, "conflicts=proceed")
	assert.Contains(t, reqs[0].URL.RawQuery, "refresh=true")

	body, err := io.ReadAll(reqs[0].Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "chat_123456")
	assert.Contains(t, string(body), "lastMemoryScannedIndex")
	// The scanner also heals a missing or undercounted messageCount.
	assert.Contains(t, string(body), "messageCount")
	assert.Contains(t, string(body), `"scanned":7`)
	// A successful scan clears the failure counter.
	assert.Contains(t, string(body), "s.memoryErrors = 0;")
}

func TestIncrementSessionMemoryErrors(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 200, `{"took": 1, "updated": 1, "version_conflicts": 0, "failures": []}`)

	err := store.IncrementSessionMemoryErrors(ctx, "chat_123456")
	assert.NoError(t, err)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)
	assert.Contains(t, reqs[0].URL.Path, "session-index")
	assert.Contains(t, reqs[0].URL.Path, "_update_by_query")
	assert.Contains(t, reqs[0].URL.RawQuery, "conflicts=proceed")
	assert.Contains(t, reqs[0].URL.RawQuery, "refresh=true")

	body, err := io.ReadAll(reqs[0].Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "chat_123456")
	// A missing counter starts from zero.
	assert.Contains(t, string(body), "s.memoryErrors = (s.memoryErrors != null ? s.memoryErrors : 0) + 1;")
}

func TestIncrementSessionMemoryErrors_ElasticsearchError(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	transport.AddResponse(nil, errors.New("update by query failed"))

	err := store.IncrementSessionMemoryErrors(ctx, "chat_123456")
	assert.Error(t, err)
}

func TestIncrementSessionMemoryErrors_Unauthorized(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeUnauthorizedServer(), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	err := store.IncrementSessionMemoryErrors(ctx, "chat_123456")
	assert.Error(t, err)
	assert.Empty(t, transport.GetRequests())
}

func TestUpdateSessionMemoryScanIndex_ElasticsearchError(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	transport.AddResponse(nil, errors.New("update by query failed"))

	err := store.UpdateSessionMemoryScanIndex(ctx, "chat_123456", 7)
	assert.Error(t, err)
}

func TestUpdateSessionMemoryScanIndex_ElasticsearchErrorResponse(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 500, `{"error":{"type":"script_exception","reason":"runtime error"},"status":500}`)

	err := store.UpdateSessionMemoryScanIndex(ctx, "chat_123456", 7)
	assert.ErrorContains(t, err, "script_exception")
}

func TestIncrementSessionMemoryErrors_ElasticsearchErrorResponse(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)

	addJsonResponse(transport, 500, `{"error":{"type":"script_exception","reason":"runtime error"},"status":500}`)

	err := store.IncrementSessionMemoryErrors(ctx, "chat_123456")
	assert.ErrorContains(t, err, "script_exception")
}

func TestUpdateSessionMemoryScanIndex_Unauthorized(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeUnauthorizedServer(), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	err := store.UpdateSessionMemoryScanIndex(ctx, "chat_123456", 7)
	assert.Error(t, err)
	assert.Empty(t, transport.GetRequests())
}

func TestGetUsage(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.Background()

	// Mock search response with aggregations
	searchResponse := `{
		"aggregations": {
			"users": {
				"buckets": [
					{
						"key": "user1",
						"doc_count": 10,
						"total_input_tokens": {
							"value": 1500.0
						},
						"total_output_tokens": {
							"value": 3000.0
						},
						"total_credits": {
							"value": 5.0
						},
						"total_messages": {
							"value": 10.0
						},
						"total_sessions": {
							"value": 3.0
						},
						"model_usage": {
							"buckets": [
								{
									"key": "claude-sonnet-4.5@SOAI",
									"model_input_tokens": {
										"value": 1000.0
									},
									"model_output_tokens": {
										"value": 2000.0
									},
									"model_credits": {
										"value": 3.0
									},
									"model_messages": {
										"value": 6.0
									}
								},
								{
									"key": "gpt-4@OpenAI",
									"model_input_tokens": {
										"value": 500.0
									},
									"model_output_tokens": {
										"value": 1000.0
									},
									"model_credits": {
										"value": 2.0
									},
									"model_messages": {
										"value": 4.0
									}
								}
							]
						}
					},
					{
						"key": "user2",
						"doc_count": 15,
						"total_input_tokens": {
							"value": 2500.0
						},
						"total_output_tokens": {
							"value": 4500.0
						},
						"total_credits": {
							"value": 8.0
						},
						"total_messages": {
							"value": 15.0
						},
						"total_sessions": {
							"value": 5.0
						},
						"model_usage": {
							"buckets": [
								{
									"key": "claude-sonnet-4.5@SOAI",
									"model_input_tokens": {
										"value": 2500.0
									},
									"model_output_tokens": {
										"value": 4500.0
									},
									"model_credits": {
										"value": 8.0
									},
									"model_messages": {
										"value": 15.0
									}
								}
							]
						}
					}
				]
			}
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()
	usage, err := store.GetUsage(ctx, start, end)

	assert.NoError(t, err)
	assert.Len(t, usage, 2)

	// Verify user1 usage
	assert.Equal(t, "user1", usage[0].UserId)
	assert.Equal(t, 1500, usage[0].TotalInputTokens)
	assert.Equal(t, 3000, usage[0].TotalOutputTokens)
	assert.Equal(t, 5, usage[0].TotalCredits)
	assert.Equal(t, 10, usage[0].TotalMessages)
	assert.Equal(t, 3, usage[0].TotalSessions)

	// Verify user1 model usage
	assert.NotNil(t, usage[0].ModelUsage)
	assert.Len(t, usage[0].ModelUsage, 2)

	claudeStats := usage[0].ModelUsage["claude-sonnet-4.5@SOAI"]
	assert.NotNil(t, claudeStats)
	assert.Equal(t, 1000, claudeStats.ModelInputTokens)
	assert.Equal(t, 2000, claudeStats.ModelOutputTokens)
	assert.Equal(t, 3, claudeStats.ModelCredits)
	assert.Equal(t, 6, claudeStats.ModelMessages)

	gptStats := usage[0].ModelUsage["gpt-4@OpenAI"]
	assert.NotNil(t, gptStats)
	assert.Equal(t, 500, gptStats.ModelInputTokens)
	assert.Equal(t, 1000, gptStats.ModelOutputTokens)
	assert.Equal(t, 2, gptStats.ModelCredits)
	assert.Equal(t, 4, gptStats.ModelMessages)

	// Verify user2 usage
	assert.Equal(t, "user2", usage[1].UserId)
	assert.Equal(t, 2500, usage[1].TotalInputTokens)
	assert.Equal(t, 4500, usage[1].TotalOutputTokens)
	assert.Equal(t, 8, usage[1].TotalCredits)
	assert.Equal(t, 15, usage[1].TotalMessages)
	assert.Equal(t, 5, usage[1].TotalSessions)

	// Verify user2 model usage
	assert.NotNil(t, usage[1].ModelUsage)
	assert.Len(t, usage[1].ModelUsage, 1)

	claudeStats2 := usage[1].ModelUsage["claude-sonnet-4.5@SOAI"]
	assert.NotNil(t, claudeStats2)
	assert.Equal(t, 2500, claudeStats2.ModelInputTokens)
	assert.Equal(t, 4500, claudeStats2.ModelOutputTokens)
	assert.Equal(t, 8, claudeStats2.ModelCredits)
	assert.Equal(t, 15, claudeStats2.ModelMessages)
}

func TestGetChatHistory(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock session check
	sessionCheck := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(sessionCheck)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time) - called by GetSessions
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	// Mock search response for chat messages
	searchResponse := `{
		"hits": {
			"total": {
				"value": 2
			},
			"hits": [
				{
					"_id": "msg1",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session1",
							"userId": "test-user",
							"message": {
								"role": "user",
								"contentStr": "Hello"
							}
						}
					}
				},
				{
					"_id": "msg2",
					"_source": {
						"so_kind": "chat",
						"so_chat": {
							"sessionId": "session1",
							"userId": "test-user",
							"message": {
								"role": "assistant",
								"contentStr": "Hi there!"
							}
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	messages, err := store.GetChatHistory(ctx, "session1")
	assert.NoError(t, err)
	assert.Len(t, messages, 2)
	assert.Equal(t, "msg1", messages[0].Id)
	assert.Equal(t, "msg2", messages[1].Id)
	assert.Equal(t, "Hello", messages[0].Message.ContentStr)
	assert.Equal(t, "Hi there!", messages[1].Message.ContentStr)

	// ensure GetSession call does not filter out deleted or memory sessions
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 3) // One for GetSessions, one for session meta data, one for chat messages
	body, err := reqs[0].GetBody()
	assert.NoError(t, err)
	data, err := io.ReadAll(body)
	assert.NoError(t, err)
	assert.NotContains(t, string(data), "deleteTime")
	assert.NotContains(t, string(data), "so_session.tags")
}

func TestGetSessions_WithFilters(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock search response for sessions
	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Test Session",
							"userId": "specific-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(
		ctx,
		model.GetSessionsWithUserId("specific-user"),
		model.GetSessionsWithRange(start, end),
		model.GetSessionsWithIncludeDeleted(false),
	)

	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "session1", sessions[0].SessionId)
	assert.Equal(t, "specific-user", sessions[0].UserId)
}

func TestGetSessions_Authorization(t *testing.T) {
	tests := []struct {
		name     string
		server   *server.Server
		authored bool
		wantErr  bool
	}{
		{
			name:     "authorized read all",
			server:   server.NewFakeAuthorizedServer(nil),
			authored: false,
			wantErr:  false,
		},
		{
			name:     "authorized read authored",
			server:   server.NewFakeAuthorizedServer(nil),
			authored: true,
			wantErr:  false,
		},
		{
			name:     "unauthorized read all",
			server:   server.NewFakeUnauthorizedServer(),
			authored: false,
			wantErr:  true,
		},
		{
			name:     "unauthorized read authored",
			server:   server.NewFakeUnauthorizedServer(),
			authored: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEsClient, transport := modmock.NewMockClient(t)
			store := NewElasticAssistantstore(tt.server, mockEsClient, 1000)
			store.Init("chat-index", "session-index", "so_")

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			if !tt.wantErr {
				searchResponse := `{
					"hits": {
						"total": {
							"value": 0
						},
						"hits": []
					}
				}`

				transport.AddResponse(&http.Response{
					StatusCode: 200,
					Header: http.Header{
						"X-Elastic-Product": []string{"Elasticsearch"},
					},
					Body: io.NopCloser(strings.NewReader(searchResponse)),
				}, nil)
			}

			sessions, err := store.GetSessions(ctx)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, sessions)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, sessions)
			}
		})
	}
}

func TestGetSessions_EmptyResults(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 0
			},
			"hits": []
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx)
	assert.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestGetSessions_ElasticsearchError(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Simulate Elasticsearch error
	transport.AddResponse(&http.Response{
		StatusCode: 500,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"error": "internal server error"}`)),
	}, nil)

	sessions, err := store.GetSessions(ctx)
	assert.Error(t, err)
	assert.Nil(t, sessions)
}

func TestGetSessions_MalformedResponse(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Invalid JSON response
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{invalid json`)),
	}, nil)

	sessions, err := store.GetSessions(ctx)
	assert.Error(t, err)
	assert.Nil(t, sessions)
}

func TestGetSessions_UserIdFilter(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "User Session",
							"userId": "specific-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithUserId("specific-user"))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "specific-user", sessions[0].UserId)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 2) // One for sessions search, one for msearch (update time)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// Verify userId filter is in the query
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustQuery := boolQuery["must"].([]any)

	// Should have two must clauses: kind=session and userId=specific-user
	assert.Len(t, mustQuery, 2)

	// Find the userId term
	foundUserId := false
	for _, clause := range mustQuery {
		if term, ok := clause.(map[string]any)["term"].(map[string]any); ok {
			if userId, exists := term["so_session.userId"]; exists {
				assert.Equal(t, "specific-user", userId)
				foundUserId = true
			}
		}
	}
	assert.True(t, foundUserId, "userId filter should be in query")
}

func TestGetSessions_IncludeDeleted(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	now := time.Now()
	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Deleted Session",
							"userId": "test-user",
							"deleteTime": "` + now.Format(time.RFC3339) + `"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithIncludeDeleted(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.NotNil(t, sessions[0].DeleteTime)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 2) // One for sessions search, one for msearch (update time)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// includeDeleted=true drops the deleteTime exclusion; the default
	// memory-session exclusion remains as the only must_not member
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustNot, hasMustNot := boolQuery["must_not"].([]any)
	if assert.True(t, hasMustNot) && assert.Len(t, mustNot, 1) {
		terms := mustNot[0].(map[string]any)["terms"].(map[string]any)
		assert.ElementsMatch(t, []any{"memory", "embed", "reconcile"}, terms["so_session.tags"])
	}
}

func TestGetSessions_ExcludesMemorySessionsByDefault(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 0
			},
			"hits": []
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx)
	assert.NoError(t, err)
	assert.Empty(t, sessions)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// by default both the deleted and the memory-session exclusions apply
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustNot, hasMustNot := boolQuery["must_not"].([]any)
	if assert.True(t, hasMustNot) && assert.Len(t, mustNot, 2) {
		exists := mustNot[0].(map[string]any)["exists"].(map[string]any)
		assert.Equal(t, "so_session.deleteTime", exists["field"])

		terms := mustNot[1].(map[string]any)["terms"].(map[string]any)
		assert.ElementsMatch(t, []any{"memory", "embed", "reconcile"}, terms["so_session.tags"])
	}
}

func TestGetSessions_IncludeMemorySessions(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 0
			},
			"hits": []
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithIncludeDeleted(true), model.GetSessionsWithMemorySessions(true))
	assert.NoError(t, err)
	assert.Empty(t, sessions)

	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// with both include opts no exclusions remain
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	_, hasMustNot := boolQuery["must_not"]
	assert.False(t, hasMustNot, "must_not clause should not be present when both include opts are set")
}

func TestGetSessions_TimeRangeFilter(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Recent Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithRange(start, end))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 2) // One for sessions search, one for msearch (update time)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// Verify time range filter is in the query
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustQuery := boolQuery["must"].([]any)

	// Should have two must clauses: kind=session and range on @timestamp
	assert.Len(t, mustQuery, 2)

	// Find the range clause
	foundRange := false
	for _, clause := range mustQuery {
		if rangeClause, ok := clause.(map[string]any)["range"].(map[string]any); ok {
			if timestampRange, exists := rangeClause["@timestamp"].(map[string]any); exists {
				assert.Equal(t, start.Format(time.RFC3339), timestampRange["gte"])
				assert.Equal(t, end.Format(time.RFC3339), timestampRange["lte"])
				foundRange = true
			}
		}
	}
	assert.True(t, foundRange, "time range filter should be in query")
}

func TestGetSessions_UsagePopulationError(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Test Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// MSearch fails for usage
	transport.AddResponse(&http.Response{
		StatusCode: 500,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"error": "internal server error"}`)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithUsage(true))
	assert.Error(t, err)
	assert.Nil(t, sessions)
}

func TestGetSessions_PartiallyMalformedHits(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mix of valid and invalid session hits
	searchResponse := `{
		"hits": {
			"total": {
				"value": 3
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Valid Session",
							"userId": "test-user"
						}
					}
				},
				{
					"_id": "session2",
					"_source": {
						"so_kind": "session"
					}
				},
				{
					"_id": "session3",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session3",
							"title": "Another Valid Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			},
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx)
	assert.NoError(t, err)
	// Should only return the 2 valid sessions, skipping the malformed one
	assert.Len(t, sessions, 2)
	assert.Equal(t, "session1", sessions[0].SessionId)
	assert.Equal(t, "session3", sessions[1].SessionId)
}

func TestGetSessions_SessionIdFilter(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session123",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session123",
							"title": "Specific Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithSessionId("session123"))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "session123", sessions[0].SessionId)
	assert.Equal(t, "Specific Session", sessions[0].Title)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 2) // One for sessions search, one for msearch (update time)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// Verify sessionId filter is in the query
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustQuery := boolQuery["must"].([]any)

	// Should have two must clauses: kind=session and sessionId=session123
	assert.Len(t, mustQuery, 2)

	// Find the sessionId term
	foundSessionId := false
	for _, clause := range mustQuery {
		if term, ok := clause.(map[string]any)["term"].(map[string]any); ok {
			if sessionId, exists := term["so_session.sessionId"]; exists {
				assert.Equal(t, "session123", sessionId)
				foundSessionId = true
			}
		}
	}
	assert.True(t, foundSessionId, "sessionId filter should be in query")
}

func TestDoesUserOwnSession(t *testing.T) {
	ownerHitResponse := func(owner string) string {
		return `{
			"hits": {
				"total": {
					"value": 1
				},
				"hits": [
					{
						"_id": "session123",
						"_source": {
							"so_session": {
								"userId": "` + owner + `"
							}
						}
					}
				]
			}
		}`
	}

	testCases := []struct {
		name       string
		statusCode int
		response   string
		wantOwned  bool
		wantExists bool
		wantErr    bool
	}{
		{
			name:       "session owned by the user",
			statusCode: 200,
			response:   ownerHitResponse("test-user"),
			wantOwned:  true,
			wantExists: true,
		},
		{
			name:       "session owned by another user",
			statusCode: 200,
			response:   ownerHitResponse("someone-else"),
			wantOwned:  false,
			wantExists: true,
		},
		{
			name:       "nonexistent session",
			statusCode: 200,
			response:   `{"hits": {"total": {"value": 0}, "hits": []}}`,
			wantOwned:  false,
			wantExists: false,
		},
		{
			name:       "elasticsearch error propagates",
			statusCode: 500,
			response:   `{"error": "internal server error"}`,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockEsClient, transport := modmock.NewMockClient(t)

			store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
			store.Init("chat-index", "session-index", "so_")

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			addJsonResponse(transport, tc.statusCode, tc.response)

			ownedByUser, sessionExists, err := store.DoesUserOwnSession(ctx, "test-user", "session123")
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.wantOwned, ownedByUser)
			assert.Equal(t, tc.wantExists, sessionExists)

			// Verify the query fetches only the owner id: source-filtered to the
			// session userId field, capped to a single hit, filtered by kind and
			// sessionId.
			reqs := transport.GetRequests()
			assert.Len(t, reqs, 1)

			var query map[string]any
			assert.NoError(t, json.NewDecoder(reqs[0].Body).Decode(&query))
			assert.Equal(t, []any{"so_session.userId"}, query["_source"])
			assert.Equal(t, float64(1), query["size"])

			mustQuery := query["query"].(map[string]any)["bool"].(map[string]any)["must"].([]any)
			assert.Len(t, mustQuery, 2)
			foundSessionId := false
			for _, clause := range mustQuery {
				if term, ok := clause.(map[string]any)["term"].(map[string]any); ok {
					if sessionId, exists := term["so_session.sessionId"]; exists {
						assert.Equal(t, "session123", sessionId)
						foundSessionId = true
					}
				}
			}
			assert.True(t, foundSessionId, "sessionId filter should be in query")
		})
	}
}

func TestGetSessions_WithDescendants(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	sessionHit := func(id, parent, parentTool string) string {
		return `{"hits":{"hits":[{"_id":"` + id + `","_source":{"so_kind":"session","so_session":{"sessionId":"` + id + `","title":"` + id + `","userId":"test-user","parentSessionId":"` + parent + `","parentToolUseId":"` + parentTool + `"}}}]}}`
	}
	add := func(body string) {
		transport.AddResponse(&http.Response{
			StatusCode: 200,
			Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil)
	}

	// 1) root A, 2) children of A -> B, 3) children of B -> C, 4) children of C -> none
	add(sessionHit("A", "", ""))
	add(sessionHit("B", "A", "tu-A"))
	add(sessionHit("C", "B", "tu-B"))
	add(`{"hits":{"hits":[]}}`)
	// addMetaFromMessages msearch: one response per session (A, B, C)
	add(`{"responses":[{"aggregations":{"update_time":{"value":1234567890000}}},{"aggregations":{"update_time":{"value":1234567890000}}},{"aggregations":{"update_time":{"value":1234567890000}}}]}`)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithSessionId("A"), model.GetSessionsWithDescendants(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 3)

	ids := map[string]bool{}
	for _, s := range sessions {
		ids[s.SessionId] = true
	}
	assert.True(t, ids["A"] && ids["B"] && ids["C"], "should return the session and all descendants, any depth")

	// A descendant query must filter by parentSessionId via a terms clause.
	reqs := transport.GetRequests()
	var descendantQuery map[string]any
	assert.NoError(t, json.NewDecoder(reqs[1].Body).Decode(&descendantQuery))
	boolQuery := descendantQuery["query"].(map[string]any)["bool"].(map[string]any)
	foundTerms := false
	for _, clause := range boolQuery["must"].([]any) {
		if terms, ok := clause.(map[string]any)["terms"].(map[string]any); ok {
			if _, exists := terms["so_session.parentSessionId"]; exists {
				foundTerms = true
			}
		}
	}
	assert.True(t, foundTerms, "descendant query should filter by parentSessionId terms")
}

func TestGetSessions_WithDescendants_NoChildren(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	add := func(body string) {
		transport.AddResponse(&http.Response{
			StatusCode: 200,
			Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil)
	}

	add(`{"hits":{"hits":[{"_id":"solo","_source":{"so_kind":"session","so_session":{"sessionId":"solo","title":"Solo","userId":"test-user"}}}]}}`)
	add(`{"hits":{"hits":[]}}`) // no descendants
	add(`{"responses":[{"aggregations":{"update_time":{"value":1234567890000}}}]}`)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithSessionId("solo"), model.GetSessionsWithDescendants(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "solo", sessions[0].SessionId)
}

func TestGetSessions_MultipleSessionsWithUsage(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock search response for multiple sessions
	searchResponse := `{
		"hits": {
			"total": {
				"value": 3
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "First Session",
							"userId": "test-user"
						}
					}
				},
				{
					"_id": "session2",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session2",
							"title": "Second Session",
							"userId": "test-user"
						}
					}
				},
				{
					"_id": "session3",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session3",
							"title": "Third Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	// Mock MSearch response with usage data for all three sessions
	msearchResponse := `{
		"responses": [
			{
				"hits": {
					"total": {
						"value": 10
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 1000.0
					},
					"total_output_tokens": {
						"value": 2000.0
					},
					"total_credits": {
						"value": 3.0
					},
					"total_messages": {
						"value": 10.0
					}
				}
			},
			{
				"hits": {
					"total": {
						"value": 5
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 500.0
					},
					"total_output_tokens": {
						"value": 1000.0
					},
					"total_credits": {
						"value": 1.5
					},
					"total_messages": {
						"value": 5.0
					}
				}
			},
			{
				"hits": {
					"total": {
						"value": 20
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 3000.0
					},
					"total_output_tokens": {
						"value": 6000.0
					},
					"total_credits": {
						"value": 9.0
					},
					"total_messages": {
						"value": 20.0
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			},
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			},
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	sessions, err := store.GetSessions(ctx, model.GetSessionsWithUsage(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 3)

	// Verify first session usage
	assert.NotNil(t, sessions[0].Usage)
	assert.Equal(t, "session1", sessions[0].SessionId)
	assert.Equal(t, 1000, sessions[0].Usage.TotalInputTokens)
	assert.Equal(t, 2000, sessions[0].Usage.TotalOutputTokens)
	assert.Equal(t, 3, sessions[0].Usage.TotalCredits)
	assert.Equal(t, 10, sessions[0].Usage.TotalMessages)

	// Verify second session usage
	assert.NotNil(t, sessions[1].Usage)
	assert.Equal(t, "session2", sessions[1].SessionId)
	assert.Equal(t, 500, sessions[1].Usage.TotalInputTokens)
	assert.Equal(t, 1000, sessions[1].Usage.TotalOutputTokens)
	assert.Equal(t, 1, sessions[1].Usage.TotalCredits)
	assert.Equal(t, 5, sessions[1].Usage.TotalMessages)

	// Verify third session usage
	assert.NotNil(t, sessions[2].Usage)
	assert.Equal(t, "session3", sessions[2].SessionId)
	assert.Equal(t, 3000, sessions[2].Usage.TotalInputTokens)
	assert.Equal(t, 6000, sessions[2].Usage.TotalOutputTokens)
	assert.Equal(t, 9, sessions[2].Usage.TotalCredits)
	assert.Equal(t, 20, sessions[2].Usage.TotalMessages)
}

func TestGetSessions_CombinedFilters(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "Filtered Session",
							"userId": "specific-user"
						}
					}
				}
			]
		}
	}`

	msearchResponse := `{
		"responses": [
			{
				"hits": {
					"total": {
						"value": 8
					}
				},
				"aggregations": {
					"total_input_tokens": {
						"value": 800.0
					},
					"total_output_tokens": {
						"value": 1600.0
					},
					"total_credits": {
						"value": 2.4
					},
					"total_messages": {
						"value": 8.0
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchUpdateTimeResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchUpdateTimeResponse)),
	}, nil)

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(
		ctx,
		model.GetSessionsWithUserId("specific-user"),
		model.GetSessionsWithRange(start, end),
		model.GetSessionsWithUsage(true),
		model.GetSessionsWithIncludeDeleted(false),
	)

	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "session1", sessions[0].SessionId)
	assert.Equal(t, "specific-user", sessions[0].UserId)

	// Verify usage was populated
	assert.NotNil(t, sessions[0].Usage)
	assert.Equal(t, 800, sessions[0].Usage.TotalInputTokens)
	assert.Equal(t, 1600, sessions[0].Usage.TotalOutputTokens)
	assert.Equal(t, 2, sessions[0].Usage.TotalCredits)
	assert.Equal(t, 8, sessions[0].Usage.TotalMessages)

	// Verify the query sent to Elasticsearch includes all filters
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 3) // One for sessions search, one for msearch (usage), one for msearch (update time)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// Verify all filters are in the query
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	mustQuery := boolQuery["must"].([]any)
	mustNotQuery := boolQuery["must_not"]

	// Should have three must clauses: kind=session, userId=specific-user, and time range
	assert.Len(t, mustQuery, 3)

	// Verify userId filter
	foundUserId := false
	foundRange := false
	for _, clause := range mustQuery {
		if term, ok := clause.(map[string]any)["term"].(map[string]any); ok {
			if userId, exists := term["so_session.userId"]; exists {
				assert.Equal(t, "specific-user", userId)
				foundUserId = true
			}
		}
		if rangeClause, ok := clause.(map[string]any)["range"].(map[string]any); ok {
			if timestampRange, exists := rangeClause["@timestamp"].(map[string]any); exists {
				assert.Equal(t, start.Format(time.RFC3339), timestampRange["gte"])
				assert.Equal(t, end.Format(time.RFC3339), timestampRange["lte"])
				foundRange = true
			}
		}
	}
	assert.True(t, foundUserId, "userId filter should be in query")
	assert.True(t, foundRange, "time range filter should be in query")

	// Verify must_not clause is present (includeDeleted=false)
	assert.NotNil(t, mustNotQuery, "must_not clause should be present when includeDeleted=false")
}

func TestGetSessions_AuthoredWithUserId(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	searchResponse := `{
		"hits": {
			"total": {
				"value": 1
			},
			"hits": [
				{
					"_id": "session1",
					"_source": {
						"so_kind": "session",
						"so_session": {
							"sessionId": "session1",
							"title": "My Session",
							"userId": "test-user"
						}
					}
				}
			]
		}
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	// Mock MSearch response for addMetaFromMessages (update time)
	msearchResponse := `{
		"responses": [
			{
				"aggregations": {
					"update_time": {
						"value": 1234567890000,
						"value_as_string": "2009-02-13T23:31:30.000Z"
					}
				}
			}
		]
	}`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(msearchResponse)),
	}, nil)

	sessions, err := store.GetSessions(
		ctx,
		model.GetSessionsWithUserId("test-user"),
	)

	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "test-user", sessions[0].UserId)
}
