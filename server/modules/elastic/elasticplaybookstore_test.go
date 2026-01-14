// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
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

func TestNewElasticPlaybookstore(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)

	assert.NotNil(t, store)
	assert.Equal(t, srv, store.server)
	assert.Equal(t, PLAYBOOK_INDEX, store.index)
	assert.Equal(t, PLAYBOOK_AUDIT_INDEX, store.auditIndex)
	assert.Equal(t, PLAYBOOK_SCHEMA_PREFIX, store.schemaPrefix)
}

func TestPlaybookInit(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)

	err := store.Init("custom-index", "custom-audit-index", "custom_")
	assert.NoError(t, err)
	assert.Equal(t, "custom-index", store.index)
	assert.Equal(t, "custom-audit-index", store.auditIndex)
	assert.Equal(t, "custom_", store.schemaPrefix)
}

func TestPlaybookInit_EmptyValues(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)

	err := store.Init("", "", "")
	assert.NoError(t, err)
	assert.Equal(t, PLAYBOOK_INDEX, store.index)
	assert.Equal(t, PLAYBOOK_AUDIT_INDEX, store.auditIndex)
	assert.Equal(t, PLAYBOOK_SCHEMA_PREFIX, store.schemaPrefix)
}

func TestPlaybookConvertToDocument(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)
	store.Init("", "", "so_")

	now := time.Now()
	playbook := &model.Playbook{
		Name:              "Test Playbook",
		Description:       "Test Description",
		DetectionId:       "DET-123",
		DetectionCategory: "Process Creation",
		DetectionType:     "sigma",
		Contributors:      []string{"John Doe", "Jane Smith"},
		IsCommunity:       false,
		Ruleset:           model.PLAYBOOK_RULESET_CUSTOM,
		Questions: []*model.Question{
			{
				Question: "What is the source IP?",
				Context:  "Context for the question",
			},
		},
	}
	playbook.Id = "playbook-123"
	playbook.CreateTime = &now

	doc := store.convertToDocument(playbook)

	assert.Equal(t, PLAYBOOK_KIND, doc["so_kind"])

	pbData, ok := doc["so_playbook"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "playbook-123", pbData["id"])
	assert.Equal(t, "Test Playbook", pbData["name"])
	assert.Equal(t, "Test Description", pbData["description"])
	assert.Equal(t, "det-123", pbData["detection_id"]) // lowercase
	assert.Equal(t, "process creation", pbData["detection_category"]) // lowercase
	assert.Equal(t, "sigma", pbData["detection_type"])
	assert.Equal(t, []string{"John Doe", "Jane Smith"}, pbData["contributors"])
	assert.Equal(t, false, pbData["isCommunity"])
	assert.Equal(t, model.PLAYBOOK_RULESET_CUSTOM, pbData["ruleset"])
}

func TestPlaybookConvertFromDocument(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)
	store.Init("", "", "so_")

	doc := map[string]interface{}{
		"so_kind": PLAYBOOK_KIND,
		"so_playbook": map[string]interface{}{
			"id":                 "playbook-123",
			"name":               "Test Playbook",
			"description":        "Test Description",
			"detection_id":       "det-123",
			"detection_category": "process creation",
			"detection_type":     "sigma",
			"contributors":       []interface{}{"John Doe", "Jane Smith"},
			"isCommunity":        false,
			"ruleset":            model.PLAYBOOK_RULESET_CUSTOM,
			"createTime":         "2025-01-01T12:00:00Z",
			"updateTime":         "2025-01-02T12:00:00Z",
			"userId":             "user-123",
			"questions": []interface{}{
				map[string]interface{}{
					"question":       "What is the source IP?",
					"context":        "Context for the question",
					"range":          "+/-3d",
					"query":          "source.ip:*",
					"answer_sources": []interface{}{"alert", "events"},
				},
			},
		},
	}

	pb, err := store.convertFromDocument(doc)
	assert.NoError(t, err)
	assert.NotNil(t, pb)

	assert.Equal(t, "playbook-123", pb.Id)
	assert.Equal(t, "Test Playbook", pb.Name)
	assert.Equal(t, "Test Description", pb.Description)
	assert.Equal(t, "det-123", pb.DetectionId)
	assert.Equal(t, "process creation", pb.DetectionCategory)
	assert.Equal(t, "sigma", pb.DetectionType)
	assert.Equal(t, []string{"John Doe", "Jane Smith"}, pb.Contributors)
	assert.False(t, pb.IsCommunity)
	assert.Equal(t, model.PLAYBOOK_RULESET_CUSTOM, pb.Ruleset)
	assert.Equal(t, "user-123", pb.UserId)
	assert.NotNil(t, pb.CreateTime)
	assert.NotNil(t, pb.UpdateTime)

	assert.Len(t, pb.Questions, 1)
	assert.Equal(t, "What is the source IP?", pb.Questions[0].Question)
	assert.Equal(t, "Context for the question", pb.Questions[0].Context)
	assert.NotNil(t, pb.Questions[0].Range)
	assert.Equal(t, "+/-3d", *pb.Questions[0].Range)
	assert.Equal(t, "source.ip:*", pb.Questions[0].Query)
	assert.Equal(t, []string{"alert", "events"}, pb.Questions[0].AnswerSources)
}

func TestPlaybookConvertFromDocument_InvalidFormat(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)
	store.Init("", "", "so_")

	doc := map[string]interface{}{
		"so_kind": PLAYBOOK_KIND,
		// Missing so_playbook key
	}

	pb, err := store.convertFromDocument(doc)
	assert.Error(t, err)
	assert.Nil(t, pb)
	assert.Contains(t, err.Error(), "invalid playbook document format")
}

func TestCreatePlaybook_Success(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name:        "New Playbook",
		Description: "A new playbook",
		Questions: []*model.Question{
			{Question: "Test question?"},
		},
	}

	// Mock Index response (create)
	indexResponse := `{"_index": "so-playbook", "_id": "generated-id", "result": "created"}`
	transport.AddResponse(&http.Response{
		StatusCode: 201,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(indexResponse)),
	}, nil)

	// Mock Get response (after create)
	getResponse := `{
		"_index": "so-playbook",
		"_id": "generated-id",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "generated-id",
				"name": "New Playbook",
				"description": "A new playbook",
				"isCommunity": false,
				"ruleset": "__custom__",
				"questions": [{"question": "Test question?"}]
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "New Playbook", result.Name)
	assert.Equal(t, model.PLAYBOOK_RULESET_CUSTOM, result.Ruleset)
	assert.False(t, result.IsCommunity)
}

func TestCreatePlaybook_ValidationError(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Empty name should fail validation
	playbook := &model.Playbook{
		Name: "",
	}

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "name is required")
}

func TestCreatePlaybook_WithExistingId(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name: "Test Playbook",
	}
	playbook.Id = "existing-id"

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "unexpected ID found in new playbook")
}

func TestCreatePlaybook_CommunityPlaybook(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name:        "Community Playbook",
		IsCommunity: true,
	}

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot create community playbooks via API")
}

func TestCreatePlaybook_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	playbook := &model.Playbook{
		Name: "Test Playbook",
	}

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestUpdatePlaybook_Success(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name:        "Updated Playbook",
		Description: "Updated description",
	}
	playbook.Id = "playbook-123"

	// Mock Get response (to fetch existing)
	getResponse := `{
		"_index": "so-playbook",
		"_id": "playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "playbook-123",
				"name": "Original Playbook",
				"description": "Original description",
				"isCommunity": false,
				"ruleset": "__custom__",
				"createTime": "2025-01-01T12:00:00Z"
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	// Mock Index response (update)
	indexResponse := `{"_index": "so-playbook", "_id": "playbook-123", "result": "updated"}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(indexResponse)),
	}, nil)

	// Mock Get response (after update)
	getResponseAfter := `{
		"_index": "so-playbook",
		"_id": "playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "playbook-123",
				"name": "Updated Playbook",
				"description": "Updated description",
				"isCommunity": false,
				"ruleset": "__custom__"
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponseAfter)),
	}, nil)

	result, err := store.UpdatePlaybook(ctx, playbook)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Updated Playbook", result.Name)
}

func TestUpdatePlaybook_MissingId(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name: "Test Playbook",
	}
	// No ID set

	result, err := store.UpdatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "missing playbook ID")
}

func TestUpdatePlaybook_CommunityPlaybook(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name: "Test Playbook",
	}
	playbook.Id = "community-playbook-123"

	// Mock Get response - community playbook
	getResponse := `{
		"_index": "so-playbook",
		"_id": "community-playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "community-playbook-123",
				"name": "Community Playbook",
				"isCommunity": true,
				"ruleset": "community-rules"
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	result, err := store.UpdatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cannot update community playbooks")
}

func TestDeletePlaybook_Success(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Get response
	getResponse := `{
		"_index": "so-playbook",
		"_id": "playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "playbook-123",
				"name": "Test Playbook",
				"isCommunity": false,
				"ruleset": "__custom__"
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	// Mock Delete response
	deleteResponse := `{"_index": "so-playbook", "_id": "playbook-123", "result": "deleted"}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(deleteResponse)),
	}, nil)

	err := store.DeletePlaybook(ctx, "playbook-123")
	assert.NoError(t, err)
}

func TestDeletePlaybook_CommunityPlaybook(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Get response - community playbook
	getResponse := `{
		"_index": "so-playbook",
		"_id": "community-playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "community-playbook-123",
				"name": "Community Playbook",
				"isCommunity": true,
				"ruleset": "community-rules"
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	err := store.DeletePlaybook(ctx, "community-playbook-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete community playbooks")
}

func TestDeletePlaybook_NotFound(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Get response - not found
	transport.AddResponse(&http.Response{
		StatusCode: 404,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"found": false}`)),
	}, nil)

	err := store.DeletePlaybook(ctx, "nonexistent-playbook")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "playbook not found")
}

func TestGetPlaybook_Success(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Get response
	getResponse := `{
		"_index": "so-playbook",
		"_id": "playbook-123",
		"found": true,
		"_source": {
			"so_kind": "playbook",
			"so_playbook": {
				"id": "playbook-123",
				"name": "Test Playbook",
				"description": "A test playbook",
				"detection_type": "sigma",
				"isCommunity": false,
				"ruleset": "__custom__",
				"questions": [
					{"question": "What happened?", "context": "Some context"}
				]
			}
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(getResponse)),
	}, nil)

	result, err := store.GetPlaybook(ctx, "playbook-123")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "playbook-123", result.Id)
	assert.Equal(t, "Test Playbook", result.Name)
	assert.Equal(t, "A test playbook", result.Description)
	assert.Equal(t, "sigma", result.DetectionType)
	assert.Len(t, result.Questions, 1)
}

func TestGetPlaybook_NotFound(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock 404 response
	transport.AddResponse(&http.Response{
		StatusCode: 404,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"found": false}`)),
	}, nil)

	result, err := store.GetPlaybook(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "playbook not found")
}

func TestGetAllPlaybooks_Success(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Search response
	searchResponse := `{
		"hits": {
			"total": {"value": 2},
			"hits": [
				{
					"_id": "playbook-1",
					"_source": {
						"so_kind": "playbook",
						"so_playbook": {
							"id": "playbook-1",
							"name": "First Playbook",
							"isCommunity": false
						}
					}
				},
				{
					"_id": "playbook-2",
					"_source": {
						"so_kind": "playbook",
						"so_playbook": {
							"id": "playbook-2",
							"name": "Second Playbook",
							"isCommunity": true
						}
					}
				}
			]
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	results, err := store.GetAllPlaybooks(ctx)
	assert.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "First Playbook", results[0].Name)
	assert.False(t, results[0].IsCommunity)
	assert.Equal(t, "Second Playbook", results[1].Name)
	assert.True(t, results[1].IsCommunity)
}

func TestGetAllPlaybooks_Empty(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock empty Search response
	searchResponse := `{
		"hits": {
			"total": {"value": 0},
			"hits": []
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	results, err := store.GetAllPlaybooks(ctx)
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestGetCustomPlaybooksForDetection_ByDetectionId(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Search response
	searchResponse := `{
		"hits": {
			"total": {"value": 1},
			"hits": [
				{
					"_id": "playbook-1",
					"_source": {
						"so_kind": "playbook",
						"so_playbook": {
							"id": "playbook-1",
							"name": "Detection-specific Playbook",
							"detection_id": "det-123",
							"isCommunity": false
						}
					}
				}
			]
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	results, err := store.GetCustomPlaybooksForDetection(ctx, "DET-123", "", "")
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "Detection-specific Playbook", results[0].Name)
}

func TestGetCustomPlaybooksForDetection_ByCategory(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Mock Search response
	searchResponse := `{
		"hits": {
			"total": {"value": 1},
			"hits": [
				{
					"_id": "playbook-1",
					"_source": {
						"so_kind": "playbook",
						"so_playbook": {
							"id": "playbook-1",
							"name": "Category Playbook",
							"detection_category": "process_creation",
							"isCommunity": false
						}
					}
				}
			]
		}
	}`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(searchResponse)),
	}, nil)

	results, err := store.GetCustomPlaybooksForDetection(ctx, "", "Process_Creation", "")
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "Category Playbook", results[0].Name)
}

func TestGetCustomPlaybooksForDetection_ByEngine(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tests := []struct {
		name         string
		engine       model.EngineName
		expectedType string
	}{
		{"ElastAlert", model.EngineNameElastAlert, "sigma"},
		{"Suricata", model.EngineNameSuricata, "nids"},
		{"Strelka", model.EngineNameStrelka, "yara"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searchResponse := `{
				"hits": {
					"total": {"value": 1},
					"hits": [
						{
							"_id": "playbook-1",
							"_source": {
								"so_kind": "playbook",
								"so_playbook": {
									"id": "playbook-1",
									"name": "Engine Playbook",
									"detection_type": "` + tt.expectedType + `",
									"isCommunity": false
								}
							}
						}
					]
				}
			}`
			transport.AddResponse(&http.Response{
				StatusCode: 200,
				Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
				Body:       io.NopCloser(strings.NewReader(searchResponse)),
			}, nil)

			results, err := store.GetCustomPlaybooksForDetection(ctx, "", "", tt.engine)
			assert.NoError(t, err)
			assert.Len(t, results, 1)
		})
	}
}

func TestGetCustomPlaybooksForDetection_NoFilters(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Should return empty result when no filters provided
	results, err := store.GetCustomPlaybooksForDetection(ctx, "", "", "")
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestGetPlaybook_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	result, err := store.GetPlaybook(ctx, "playbook-123")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGetAllPlaybooks_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	results, err := store.GetAllPlaybooks(ctx)
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestDeletePlaybook_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	err := store.DeletePlaybook(ctx, "playbook-123")
	assert.Error(t, err)
}

func TestUpdatePlaybook_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	playbook := &model.Playbook{
		Name: "Test",
	}
	playbook.Id = "playbook-123"

	result, err := store.UpdatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGetCustomPlaybooksForDetection_Unauthorized(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeUnauthorizedServer()
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.Background()

	results, err := store.GetCustomPlaybooksForDetection(ctx, "det-123", "", "")
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestCreatePlaybook_ElasticsearchError(t *testing.T) {
	t.Parallel()

	mockEsClient, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, mockEsClient)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	playbook := &model.Playbook{
		Name: "Test Playbook",
	}

	// Mock error response from Elasticsearch
	transport.AddResponse(&http.Response{
		StatusCode: 500,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"error": {"type": "internal_server_error", "reason": "Something went wrong"}}`)),
	}, nil)

	result, err := store.CreatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to index playbook")
}

func TestUpdatePlaybook_ValidationError(t *testing.T) {
	t.Parallel()

	srv := server.NewFakeAuthorizedServer(nil)
	store := NewElasticPlaybookstore(srv, nil)
	store.Init("", "", "so_")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Name too long
	playbook := &model.Playbook{
		Name: strings.Repeat("a", 201),
	}
	playbook.Id = "playbook-123"

	result, err := store.UpdatePlaybook(ctx, playbook)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "200 characters or less")
}

func TestConvertFromDocument_WithInvalidTimestamp(t *testing.T) {
	t.Parallel()

	store := NewElasticPlaybookstore(nil, nil)
	store.Init("", "", "so_")

	doc := map[string]interface{}{
		"so_kind": PLAYBOOK_KIND,
		"so_playbook": map[string]interface{}{
			"id":         "playbook-123",
			"name":       "Test Playbook",
			"createTime": "invalid-timestamp",
			"updateTime": "also-invalid",
		},
	}

	pb, err := store.convertFromDocument(doc)
	assert.NoError(t, err)
	assert.NotNil(t, pb)
	assert.Equal(t, "playbook-123", pb.Id)
	// Invalid timestamps should be ignored, not cause errors
	assert.Nil(t, pb.CreateTime)
	assert.Nil(t, pb.UpdateTime)
}
