// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type ElasticAssistantstore struct {
	server       *server.Server
	esClient     *elasticsearch.Client
	chatIndex    string
	sessionIndex string
	schemaPrefix string
	maxLogLength int
}

func NewElasticAssistantstore(srv *server.Server, client *elasticsearch.Client, maxLogLength int) *ElasticAssistantstore {
	return &ElasticAssistantstore{
		server:       srv,
		esClient:     client,
		maxLogLength: maxLogLength,
	}
}

func (store *ElasticAssistantstore) Init(chatIndex string, sessionIndex string, schemaPrefix string) error {
	store.chatIndex = chatIndex
	store.sessionIndex = sessionIndex
	store.schemaPrefix = schemaPrefix

	return nil
}

func (store *ElasticAssistantstore) save(ctx context.Context, obj any, index string, kind string) (*model.EventIndexResults, error) {
	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err := store.indexDoc(ctx, index, document)

	return results, err
}

func (store *ElasticAssistantstore) indexDoc(ctx context.Context, index string, document map[string]any) (*model.EventIndexResults, error) {
	logger := log.FromContext(ctx)

	results := model.NewEventIndexResults()

	request, err := convertToElasticIndexRequest(document)
	if err == nil {
		var response string

		logger.Debug("Sending index request to primary Elasticsearch client")
		response, err = store.indexDocument(ctx, store.disableCrossClusterIndex(index), request)
		if err == nil {
			err = convertFromElasticIndexResults(response, results)
			if err != nil {
				logger.WithError(err).Error("Encountered error while converting document index results")
			}
		} else {
			logger.WithError(err).Error("Encountered error while indexing document into elasticsearch")
		}
	}

	return results, err
}

func (store *ElasticAssistantstore) indexDocument(ctx context.Context, index string, document string) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithFields(log.Fields{
		"documentIndex": index,
		"requestId":     ctx.Value(web.ContextKeyRequestId),
	}).Debug("Adding document to Elasticsearch")

	res, err := store.esClient.Index(index,
		strings.NewReader(document),
		store.esClient.Index.WithRefresh("true"),
		store.esClient.Index.WithContext(ctx),
	)

	if err != nil {
		logger.WithError(err).Error("Unable to index document into Elasticsearch")
		return "", err
	}
	defer res.Body.Close()

	json, err := readJsonFromResponse(res)

	logger.WithFields(log.Fields{
		"indexDocumentResponseLength": len(json),
		"requestId":                   ctx.Value(web.ContextKeyRequestId),
	}).Debug("Index new document finished")

	return json, err
}

func (store *ElasticAssistantstore) truncate(input string) string {
	if len(input) > store.maxLogLength {
		return input[:store.maxLogLength] + "..."
	}
	return input
}

func (store *ElasticAssistantstore) disableCrossClusterIndex(index string) string {
	pieces := strings.SplitN(index, ":", 2)
	if len(pieces) == 2 {
		index = pieces[1]
	}
	return index
}

func (store *ElasticAssistantstore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
	obj.UserId, _ = ctx.Value(web.ContextKeyRequestorId).(string)

	hasOpOverride := modcontext.ReadOverrideOperation(ctx) != nil

	// Don't waste space by saving the these values which are already part of ES documents
	id := obj.Id
	if !hasOpOverride {
		obj.Id = ""
	}
	obj.UpdateTime = nil

	return id
}

func (store *ElasticAssistantstore) validateId(id string, label string) error {
	var err error

	isValidId := regexp.MustCompile(`^[A-Za-z0-9-_]{5,50}$`).MatchString
	if !isValidId(id) {
		err = fmt.Errorf("invalid ID for %s", label)
	}

	return err
}

func (store *ElasticAssistantstore) validateChat(chat *model.StoredMessage) error {
	err := store.validateId(chat.SessionId, "SessionId")

	if err == nil {
		contentCount := 0
		if len(chat.Message.ContentBlocks) != 0 {
			contentCount++
			for _, cb := range chat.Message.ContentBlocks {
				if cb.Type == "text" && cb.Text == "" {
					err = fmt.Errorf("content block of type 'text' must have non-empty text")
				}
			}
		}

		if chat.Message.ContentStr != "" {
			contentCount++
		}

		if contentCount != 1 {
			err = fmt.Errorf("message must have exactly one content type: either ContentBlocks or ContentStr")
		}
	}

	return err
}

func (store *ElasticAssistantstore) validateSession(session *model.AssistantSession) error {
	err := store.validateId(session.SessionId, "SessionId")
	if err != nil {
		return err
	}

	if session.Title == "" {
		return fmt.Errorf("Title is too short")
	}

	return nil
}

func (store *ElasticAssistantstore) SaveChat(ctx context.Context, chat *model.StoredMessage) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	err := store.validateChat(chat)
	if err != nil {
		return err
	}

	chat.CreateTime = util.Ptr(time.Now())
	store.prepareForSave(ctx, &chat.Auditable)

	_, err = store.save(ctx, chat, store.chatIndex, "chat")

	return err
}

func (store *ElasticAssistantstore) GetChatHistory(ctx context.Context, sessionId string) ([]*model.StoredMessage, error) {
	if err := store.server.CheckAuthorized(ctx, "read_authored", "assistant"); err != nil {
		return nil, err
	}

	logger := log.FromContext(ctx)

	// Build Elasticsearch query to get all messages for the session
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "chat.sessionId": sessionId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "chat",
						},
					},
				},
			},
		},
		"sort": []any{
			map[string]any{
				"@timestamp": map[string]any{
					"order": "asc",
				},
			},
		},
		"size": 10000, // Get all messages for the session
	}

	// Convert query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Elasticsearch query")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"assistantEsQuery": store.truncate(string(queryJSON)),
		"sessionId":        sessionId,
		"requestId":        ctx.Value(web.ContextKeyRequestId),
	}).Debug("Searching for chat history")

	// Execute search
	res, err := store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(store.chatIndex),
		store.esClient.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute Elasticsearch search")
		return nil, err
	}
	defer res.Body.Close()

	// Read response
	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read Elasticsearch response")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"queryChatHistoryResponseLength": len(responseJSON),
		"sessionId":                      sessionId,
		"requestId":                      ctx.Value(web.ContextKeyRequestId),
	}).Debug("Received Elasticsearch response")

	// Parse response
	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal Elasticsearch response")
		return nil, err
	}

	// Extract messages from hits
	messages := []*model.StoredMessage{}
	if hits, ok := response["hits"].(map[string]any); ok {
		if hitsArray, ok := hits["hits"].([]any); ok {
			for _, hitObj := range hitsArray {
				if hit, ok := hitObj.(map[string]any); ok {
					if source, ok := hit["_source"].(map[string]any); ok {
						if chat, ok := source[store.schemaPrefix+"chat"].(map[string]any); ok {
							// Convert the source to a StoredMessage
							sourceJSON, err := json.Marshal(chat)
							if err != nil {
								logger.WithError(err).Error("Failed to marshal message source")
								continue
							}

							var message model.StoredMessage
							if err := json.Unmarshal(sourceJSON, &message); err != nil {
								logger.WithError(err).Error("Failed to unmarshal StoredMessage")
								continue
							}

							message.Auditable.Kind = source[store.schemaPrefix+"kind"].(string)
							message.Auditable.Id = hit["_id"].(string)

							messages = append(messages, &message)
						}
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"messageCount": len(messages),
		"sessionId":    sessionId,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found chat history messages")

	return messages, nil
}

func (store *ElasticAssistantstore) GetSessions(ctx context.Context, userId string) ([]*model.AssistantSession, error) {
	if err := store.server.CheckAuthorized(ctx, "read_authored", "assistant"); err != nil {
		return nil, err
	}

	logger := log.FromContext(ctx)

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.userId": userId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
				},
				"must_not": []any{
					map[string]any{
						"exists": map[string]any{
							"field": store.schemaPrefix + "session.deleteTime",
						},
					},
				},
			},
		},
		"sort": []any{
			map[string]any{
				"@timestamp": map[string]any{
					"order": "asc",
				},
			},
		},
		"size": 10000,
	}

	// Convert query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Elasticsearch query")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"query":     store.truncate(string(queryJSON)),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Searching for first messages of each session")

	// Execute search
	res, err := store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(store.sessionIndex),
		store.esClient.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute Elasticsearch search")
		return nil, err
	}
	defer res.Body.Close()

	// Read response
	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read Elasticsearch response")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"response":  store.truncate(responseJSON),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Received Elasticsearch response")

	// Parse response
	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal Elasticsearch response")
		return nil, err
	}

	sessions := []*model.AssistantSession{}
	if hits, ok := response["hits"].(map[string]any); ok {
		if hitsArray, ok := hits["hits"].([]any); ok {
			for _, hitObj := range hitsArray {
				if hit, ok := hitObj.(map[string]any); ok {
					if source, ok := hit["_source"].(map[string]any); ok {
						if sess, ok := source[store.schemaPrefix+"session"].(map[string]any); ok {
							// Convert the source to an AssistantSession
							sourceJSON, err := json.Marshal(sess)
							if err != nil {
								logger.WithError(err).Error("Failed to marshal session source")
								continue
							}

							var session model.AssistantSession
							if err := json.Unmarshal(sourceJSON, &session); err != nil {
								logger.WithError(err).Error("Failed to unmarshal AssistantSession")
								continue
							}

							session.Auditable.Kind = source[store.schemaPrefix+"kind"].(string)
							session.Auditable.Id = hit["_id"].(string)

							sessions = append(sessions, &session)
						}
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"userId":       userId,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found first messages for sessions")

	return sessions, nil
}

func (store *ElasticAssistantstore) CreateSession(ctx context.Context, session *model.AssistantSession) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	err := store.validateSession(session)
	if err != nil {
		return err
	}

	session.CreateTime = util.Ptr(time.Now())
	store.prepareForSave(ctx, &session.Auditable)

	_, err = store.save(ctx, session, store.sessionIndex, "session")

	return err
}

func (store *ElasticAssistantstore) DeleteSession(ctx context.Context, sessionId string) error {
	if err := store.server.CheckAuthorized(ctx, "delete_authored", "assistant"); err != nil {
		return err
	}

	logger := log.FromContext(ctx)

	now := time.Now()
	nowStr := now.Format(time.RFC3339)

	// Build UpdateByQuery request to mark session as deleted
	query := map[string]any{
		"query": map[string]any{
			"term": map[string]any{
				store.schemaPrefix + "session.sessionId": sessionId,
			},
		},
		"script": map[string]any{
			"source": "ctx._source." + store.schemaPrefix + "session.deleteTime = params.deleteTime;",
			"lang":   "painless",
			"params": map[string]any{
				"deleteTime": nowStr,
			},
		},
	}

	// Convert query to JSON
	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal UpdateByQuery request")
		return err
	}

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Marking session as deleted using UpdateByQuery")

	// Execute UpdateByQuery to mark the session as deleted
	res, err := store.esClient.UpdateByQuery(
		[]string{store.disableCrossClusterIndex(store.sessionIndex)},
		store.esClient.UpdateByQuery.WithContext(ctx),
		store.esClient.UpdateByQuery.WithBody(strings.NewReader(string(queryJSON))),
		store.esClient.UpdateByQuery.WithRefresh(true),
		store.esClient.UpdateByQuery.WithWaitForCompletion(true),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to mark session as deleted")
		return err
	}
	defer res.Body.Close()

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("successfully deleted session")

	return nil
}
