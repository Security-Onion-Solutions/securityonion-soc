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

func (store *ElasticAssistantstore) save(ctx context.Context, obj any, index string, kind string, id string) (*model.EventIndexResults, error) {
	// if err := store.server.CheckAuthorized(ctx, "write", "detections"); err != nil {
	// 	return nil, err
	// }

	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err := store.indexDoc(ctx, index, document, id)

	return results, err
}

func (store *ElasticAssistantstore) indexDoc(ctx context.Context, index string, document map[string]any, id string) (*model.EventIndexResults, error) {
	logger := log.FromContext(ctx)

	results := model.NewEventIndexResults()

	request, err := convertToElasticIndexRequest(document)
	if err == nil {
		var response string

		logger.Debug("Sending index request to primary Elasticsearch client")
		response, err = store.indexDocument(ctx, store.disableCrossClusterIndex(index), request, id)
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

func (store *ElasticAssistantstore) indexDocument(ctx context.Context, index string, document string, id string) (string, error) {
	logger := log.FromContext(ctx)

	// err := store.server.CheckAuthorized(ctx, "write", "detections")
	// if err != nil {
	// 	return "", err
	// }

	logger.WithFields(log.Fields{
		"documentIndex": index,
		"documentId":    id,
		"document":      store.truncate(document),
		"requestId":     ctx.Value(web.ContextKeyRequestId),
	}).Debug("Adding document to Elasticsearch")

	res, err := store.esClient.Index(index,
		strings.NewReader(document),
		store.esClient.Index.WithRefresh("true"),
		store.esClient.Index.WithDocumentID(id),
		store.esClient.Index.WithContext(ctx),
	)

	if err != nil {
		logger.WithError(err).Error("Unable to index document into Elasticsearch")
		return "", err
	}
	defer res.Body.Close()

	json, err := readJsonFromResponse(res)

	logger.WithFields(log.Fields{
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
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

func (store *ElasticAssistantstore) ConvertObjectToDocument(ctx context.Context, kind string, obj any, auditable *model.Auditable, isEdit bool, auditDocId *string, op *string) (doc []byte, index string, err error) {
	if auditDocId == nil {
		index = "so-detection"
	} else {
		index = "so-detectionhistory"
	}

	id := auditable.Id
	updateTime := auditable.UpdateTime

	defer func() {
		auditable.Id = id
		auditable.UpdateTime = updateTime
	}()

	store.prepareForSave(ctx, auditable)
	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)

	document[store.schemaPrefix+"kind"] = kind
	if auditDocId != nil {
		document[store.schemaPrefix+AUDIT_DOC_ID] = *auditDocId
		if op != nil {
			document[store.schemaPrefix+"operation"] = *op
		}
	}

	if isEdit {
		document = map[string]any{
			"doc": document,
		}
	}

	rawDoc, err := json.Marshal(document)

	return rawDoc, index, err
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
	err := store.validateId(session.Id, "SessionId")
	if err != nil {
		return err
	}

	if session.Title == "" {
		return fmt.Errorf("Title is too short")
	}

	return nil
}

func (store *ElasticAssistantstore) SaveChat(ctx context.Context, chat *model.StoredMessage) error {
	err := store.validateChat(chat)
	if err != nil {
		return err
	}

	chat.CreateTime = util.Ptr(time.Now())

	_, err = store.save(ctx, chat, store.chatIndex, "chat", store.prepareForSave(ctx, &chat.Auditable))

	return err
}

func (store *ElasticAssistantstore) GetChatHistory(ctx context.Context, sessionId string) ([]*model.StoredMessage, error) {
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
		"query":     store.truncate(string(queryJSON)),
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
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
		"response":  store.truncate(responseJSON),
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
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

func (store *ElasticAssistantstore) getSessionById(ctx context.Context, sessionId string) (*model.AssistantSession, error) {
	logger := log.FromContext(ctx)

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.id": sessionId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
				},
			},
		},
		"size": 1,
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

	// Extract first messages from aggregation
	result := &model.AssistantSession{}
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

							if err := json.Unmarshal(sourceJSON, &result); err != nil {
								logger.WithError(err).Error("Failed to unmarshal AssistantSession")
								continue
							}

							result.Auditable.Kind = source[store.schemaPrefix+"kind"].(string)
							result.Auditable.Id = hit["_id"].(string)
						}
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("found session")

	return result, nil
}

func (store *ElasticAssistantstore) CreateSession(ctx context.Context, session *model.AssistantSession) error {
	err := store.validateSession(session)
	if err != nil {
		return err
	}

	session.CreateTime = util.Ptr(time.Now())

	keepIdCtx := modcontext.WriteOverrideOperation(ctx, "create")

	_, err = store.save(ctx, session, store.sessionIndex, "session", store.prepareForSave(keepIdCtx, &session.Auditable))

	return err
}

func (store *ElasticAssistantstore) DeleteSession(ctx context.Context, sessionId string) error {
	logger := log.FromContext(ctx)

	session, err := store.getSessionById(ctx, sessionId)
	if err != nil {
		return err
	}

	// Set DeletedAt timestamp on the message
	now := time.Now()
	session.DeleteTime = &now

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Setting deletedAt timestamp and saving message")

	// Use save() method to reindex the document (same pattern as UpdateDetection)
	_, err = store.save(ctx, session, store.sessionIndex, "session", session.Auditable.Id)
	if err != nil {
		logger.WithError(err).Error("Failed to save updated message for session deletion")
		return err
	}

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("successfully deleted session")

	return nil
}
