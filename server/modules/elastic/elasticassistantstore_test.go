// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
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

	// Valid IDs
	assert.NoError(t, store.validateId("12345", "test"))
	assert.NoError(t, store.validateId("chat_1757086398900_ykhmndscn", "test"))
	assert.NoError(t, store.validateId("a-b-c_d-e_f", "test"))
	assert.NoError(t, store.validateId("12345678901234567890123456789012345678901234567890", "test"))

	// Invalid IDs
	assert.Error(t, store.validateId("", "test"))
	assert.Error(t, store.validateId("1234", "test"))                                                // too short
	assert.Error(t, store.validateId("123456789012345678901234567890123456789012345678901", "test")) // too long
	assert.Error(t, store.validateId("invalid id", "test"))                                          // spaces
	assert.Error(t, store.validateId("invalid@id", "test"))                                          // special chars
}

func TestValidateChat(t *testing.T) {
	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), nil, 1000)
	store.Init("chat-index", "session-index", "so_")

	t.Run("valid chat with ContentStr", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message: &model.Message{
				ContentStr: "Hello, world!",
			},
		}
		err := store.validateChat(chat)
		assert.NoError(t, err)
	})

	t.Run("valid chat with ContentBlocks", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message: &model.Message{
				ContentBlocks: []model.ContentBlock{
					{Type: "text", Text: "Hello"},
				},
			},
		}
		err := store.validateChat(chat)
		assert.NoError(t, err)
	})

	t.Run("invalid session ID", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "bad",
			Message: &model.Message{
				ContentStr: "Hello",
			},
		}
		err := store.validateChat(chat)
		assert.Error(t, err)
	})

	t.Run("missing content", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message:   &model.Message{},
		}
		err := store.validateChat(chat)
		assert.Error(t, err)
	})

	t.Run("both content types", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message: &model.Message{
				ContentStr: "Hello",
				ContentBlocks: []model.ContentBlock{
					{Type: "text", Text: "World"},
				},
			},
		}
		err := store.validateChat(chat)
		assert.Error(t, err)
	})

	t.Run("empty text in content block", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message: &model.Message{
				ContentBlocks: []model.ContentBlock{
					{Type: "text", Text: ""},
				},
			},
		}
		err := store.validateChat(chat)
		assert.Error(t, err)
	})

	t.Run("missing type in content block", func(t *testing.T) {
		chat := &model.StoredMessage{
			SessionId: "chat_123456",
			Message: &model.Message{
				ContentBlocks: []model.ContentBlock{
					{Text: "Hello"},
				},
			},
		}
		err := store.validateChat(chat)
		assert.Error(t, err)
	})
}

func TestValidateSession(t *testing.T) {
	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), nil, 1000)
	store.Init("chat-index", "session-index", "so_")

	t.Run("valid session", func(t *testing.T) {
		session := &model.AssistantSession{
			SessionId: "chat_123456",
			Title:     "My Chat Session",
		}
		err := store.validateSession(session)
		assert.NoError(t, err)
	})

	t.Run("invalid session ID", func(t *testing.T) {
		session := &model.AssistantSession{
			SessionId: "bad",
			Title:     "My Chat Session",
		}
		err := store.validateSession(session)
		assert.Error(t, err)
	})

	t.Run("empty title", func(t *testing.T) {
		session := &model.AssistantSession{
			SessionId: "chat_123456",
			Title:     "",
		}
		err := store.validateSession(session)
		assert.Error(t, err)
	})
}

func TestPopulateSessionUsage_Empty(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)
	store.Init("chat-index", "session-index", "so_")
	ctx := context.Background()

	t.Run("empty sessions", func(t *testing.T) {
		sessions := []*model.AssistantSession{}
		err := store.populateSessionUsage(ctx, sessions)
		assert.NoError(t, err)
	})

	t.Run("nil sessions", func(t *testing.T) {
		err := store.populateSessionUsage(ctx, nil)
		assert.NoError(t, err)
	})
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

	// Verify second session usage
	assert.NotNil(t, sessions[1].Usage)
	assert.Equal(t, 2500, sessions[1].Usage.TotalInputTokens)
	assert.Equal(t, 4500, sessions[1].Usage.TotalOutputTokens)
	assert.Equal(t, 8, sessions[1].Usage.TotalCredits)
	assert.Equal(t, 15, sessions[1].Usage.TotalMessages)
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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithUsage(true))
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

	// No MSearch call should be made when usage is false
	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithUsage(false))
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

	t.Run("short string", func(t *testing.T) {
		input := "short"
		result := store.truncate(input)
		assert.Equal(t, "short", result)
	})

	t.Run("exact length", func(t *testing.T) {
		input := "1234567890"
		result := store.truncate(input)
		assert.Equal(t, "1234567890", result)
	})

	t.Run("long string", func(t *testing.T) {
		input := "12345678901234567890"
		result := store.truncate(input)
		assert.Equal(t, "1234567890...", result)
	})
}

func TestDisableCrossClusterIndex(t *testing.T) {
	store := NewElasticAssistantstore(nil, nil, 1000)

	t.Run("regular index", func(t *testing.T) {
		result := store.disableCrossClusterIndex("my-index")
		assert.Equal(t, "my-index", result)
	})

	t.Run("cross-cluster index", func(t *testing.T) {
		result := store.disableCrossClusterIndex("cluster1:my-index")
		assert.Equal(t, "my-index", result)
	})
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

	err := store.SaveChat(ctx, chat)
	assert.NoError(t, err)
	assert.NotNil(t, chat.CreateTime)
	assert.Equal(t, "test-user", chat.UserId)
}

func TestCreateSession(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	session := &model.AssistantSession{
		SessionId: "chat_123456",
		Title:     "My Chat Session",
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

	assert.Equal(t, "user1", usage[0].UserId)
	assert.Equal(t, 1500, usage[0].TotalInputTokens)
	assert.Equal(t, 3000, usage[0].TotalOutputTokens)
	assert.Equal(t, 5, usage[0].TotalCredits)
	assert.Equal(t, 10, usage[0].TotalMessages)

	assert.Equal(t, "user2", usage[1].UserId)
	assert.Equal(t, 2500, usage[1].TotalInputTokens)
	assert.Equal(t, 4500, usage[1].TotalOutputTokens)
	assert.Equal(t, 8, usage[1].TotalCredits)
	assert.Equal(t, 15, usage[1].TotalMessages)
}

func TestGetChatHistory(t *testing.T) {
	mockEsClient, transport := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeAuthorizedServer(nil), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock search response
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

	messages, err := store.GetChatHistory(ctx, "session1", true)
	assert.NoError(t, err)
	assert.Len(t, messages, 2)
	assert.Equal(t, "msg1", messages[0].Id)
	assert.Equal(t, "msg2", messages[1].Id)
	assert.Equal(t, "Hello", messages[0].Message.ContentStr)
	assert.Equal(t, "Hi there!", messages[1].Message.ContentStr)
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

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(
		ctx,
		false,
		model.GetSessionsWithUserId("specific-user"),
		model.GetSessionsWithRange(start, end),
		model.GetSessionsWithIncludeDeleted(false),
	)

	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "session1", sessions[0].SessionId)
	assert.Equal(t, "specific-user", sessions[0].UserId)
}

func TestGetSessions_AuthorizationReadAll(t *testing.T) {
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

	// Default behavior should require read_all permission
	sessions, err := store.GetSessions(ctx, false)
	assert.NoError(t, err)
	assert.NotNil(t, sessions)
}

func TestGetSessions_AuthorizationReadAuthored(t *testing.T) {
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

	// With authored=true, should require read_authored permission
	sessions, err := store.GetSessions(ctx, true)
	assert.NoError(t, err)
	assert.NotNil(t, sessions)
}

func TestGetSessions_Unauthorized(t *testing.T) {
	mockEsClient, _ := modmock.NewMockClient(t)

	store := NewElasticAssistantstore(server.NewFakeUnauthorizedServer(), mockEsClient, 1000)
	store.Init("chat-index", "session-index", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Should fail authorization check
	sessions, err := store.GetSessions(ctx, false)
	assert.Error(t, err)
	assert.Nil(t, sessions)

	sessions, err = store.GetSessions(ctx, true)
	assert.Error(t, err)
	assert.Nil(t, sessions)
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

	sessions, err := store.GetSessions(ctx, true)
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

	sessions, err := store.GetSessions(ctx, false)
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

	sessions, err := store.GetSessions(ctx, false)
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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithUserId("specific-user"))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "specific-user", sessions[0].UserId)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithIncludeDeleted(true))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.NotNil(t, sessions[0].DeleteTime)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

	var query map[string]any
	err = json.NewDecoder(reqs[0].Body).Decode(&query)
	assert.NoError(t, err)

	// Verify must_not clause is NOT present (includeDeleted=true)
	boolQuery := query["query"].(map[string]any)["bool"].(map[string]any)
	_, hasMustNot := boolQuery["must_not"]
	assert.False(t, hasMustNot, "must_not clause should not be present when includeDeleted=true")
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

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithRange(start, end))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithUsage(true))
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

	sessions, err := store.GetSessions(ctx, false)
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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithSessionId("session123"))
	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "session123", sessions[0].SessionId)
	assert.Equal(t, "Specific Session", sessions[0].Title)

	// Verify the query sent to Elasticsearch
	reqs := transport.GetRequests()
	assert.Len(t, reqs, 1)

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

	sessions, err := store.GetSessions(ctx, false, model.GetSessionsWithUsage(true))
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

	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	sessions, err := store.GetSessions(
		ctx,
		false,
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
	assert.Len(t, reqs, 2) // One for sessions search, one for msearch (usage)

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

	sessions, err := store.GetSessions(
		ctx,
		true,
		model.GetSessionsWithUserId("test-user"),
	)

	assert.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, "test-user", sessions[0].UserId)
}
