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
	index        string
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

func (store *ElasticAssistantstore) Init(index string, schemaPrefix string) error {
	store.index = index
	store.schemaPrefix = schemaPrefix

	return nil
}

func (store *ElasticAssistantstore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
	// if err := store.server.CheckAuthorized(ctx, "write", "detections"); err != nil {
	// 	return nil, err
	// }

	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err := store.indexDoc(ctx, store.index, document, id)

	return results, err
}

func (store *ElasticAssistantstore) indexDoc(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error) {
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
		document = map[string]interface{}{
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
				if cb.Type == "tool_result" && (cb.ToolUseID == "" || cb.ToolResult == nil) {
					err = fmt.Errorf("content block of type 'tool_result' must have non-empty tool use ID and tool result")
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

func (store *ElasticAssistantstore) SaveChat(ctx context.Context, chat *model.StoredMessage) error {
	err := store.validateChat(chat)
	if err != nil {
		return err
	}

	chat.CreateTime = util.Ptr(time.Now())

	_, err = store.save(ctx, chat, "chat", store.prepareForSave(ctx, &chat.Auditable))

	return err
}

func (store *ElasticAssistantstore) GetChatHistory(ctx context.Context, conversationId string) ([]*model.StoredMessage, error) {
	return nil, nil
}

func (store *ElasticAssistantstore) GetPreviousConversations(ctx context.Context, userId string) ([]*model.StoredMessage, error) {
	logger := log.FromContext(ctx)

	// Build Elasticsearch query to get the first message of each session for the user
	query := map[string]any{
		"size": 0, // Only want aggregation results, not documents
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "chat.userId.keyword": userId,
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
		"aggs": map[string]any{
			"sessions": map[string]any{
				"terms": map[string]any{
					"field": store.schemaPrefix + "chat.sessionId.keyword",
					"size":  10000,
				},
				"aggs": map[string]any{
					"first_message": map[string]any{
						"top_hits": map[string]any{
							"sort": []any{
								map[string]any{
									"@timestamp": map[string]any{
										"order": "asc",
									},
								},
							},
							"size": 1,
						},
					},
				},
			},
		},
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
		store.esClient.Search.WithIndex(store.index),
		store.esClient.Search.WithBody(strings.NewReader(string(queryJSON))),
		store.esClient.Search.WithTrackTotalHits(true),
		store.esClient.Search.WithPretty(),
		store.esClient.Search.WithIgnoreUnavailable(true),
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
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal Elasticsearch response")
		return nil, err
	}

	// Extract first messages from aggregation
	messages := []*model.StoredMessage{}
	if aggregations, ok := response["aggregations"].(map[string]interface{}); ok {
		if sessions, ok := aggregations["sessions"].(map[string]interface{}); ok {
			if buckets, ok := sessions["buckets"].([]interface{}); ok {
				for _, bucketObj := range buckets {
					if bucket, ok := bucketObj.(map[string]interface{}); ok {
						if firstMessage, ok := bucket["first_message"].(map[string]interface{}); ok {
							if hits, ok := firstMessage["hits"].(map[string]interface{}); ok {
								if hitsArray, ok := hits["hits"].([]interface{}); ok && len(hitsArray) > 0 {
									if hit, ok := hitsArray[0].(map[string]interface{}); ok {
										if source, ok := hit["_source"].(map[string]interface{}); ok {
											if chat, ok := source[store.schemaPrefix+"chat"].(map[string]interface{}); ok {
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
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"messageCount": len(messages),
		"userId":       userId,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found first messages for sessions")

	return messages, nil
}
