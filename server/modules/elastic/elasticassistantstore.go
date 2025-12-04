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
	"slices"
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
			keepers := make([]model.ContentBlock, 0, len(chat.Message.ContentBlocks))
			filtered := false

			for _, cb := range chat.Message.ContentBlocks {
				if cb.Type == "" {
					err = fmt.Errorf("every content block must have a type")
					break
				}

				if !(cb.Type == "text" && cb.Text == "") {
					keepers = append(keepers, cb)
				} else {
					filtered = true
				}
			}

			if filtered {
				chat.Message.ContentBlocks = keepers
			}
		}

		if chat.Message.ContentStr != "" {
			contentCount++
		}

		if contentCount != 1 && err == nil {
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
	logger := log.FromContext(ctx)

	existing, err := store.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId))
	if err != nil {
		return nil, err
	}

	if len(existing) == 0 {
		return nil, fmt.Errorf("Object not found")
	}

	session := existing[0]

	userId := ctx.Value(web.ContextKeyRequestorId).(string)
	if session.UserId == userId {
		// they own it, can the user read_authored?
		err := store.server.CheckAuthorized(ctx, "read_authored", "assistant")
		if err != nil {
			return nil, err
		}
	} else if slices.Contains(session.Tags, "shared") {
		// they don't own it but it's shared, can the user read_shared?
		err := store.server.CheckAuthorized(ctx, "read_shared", "assistant")
		if err != nil {
			return nil, err
		}
	} else {
		// they don't own it and it isn't shared, can the user read_all?
		err := store.server.CheckAuthorized(ctx, "read_all", "assistant")
		if err != nil {
			return nil, err
		}
	}

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

func (store *ElasticAssistantstore) GetSessions(ctx context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
	opt := &model.GetSessionsOpts{}
	for _, o := range opts {
		o(opt)
	}

	logger := log.FromContext(ctx)

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []map[string]any{
					{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
				},
			},
		},
		"sort": []map[string]any{
			{
				"@timestamp": map[string]any{
					"order": "asc",
				},
			},
		},
		"size": 10000,
	}

	if opt.UserId() != "" {
		boolQuery, _ := query["query"].(map[string]any)["bool"].(map[string]any)
		mustQuery, _ := boolQuery["must"].([]map[string]any)

		mustQuery = append(mustQuery, map[string]any{
			"term": map[string]any{
				store.schemaPrefix + "session.userId": opt.UserId(),
			},
		})

		boolQuery["must"] = mustQuery
	}

	if opt.SessionId() != "" {
		boolQuery, _ := query["query"].(map[string]any)["bool"].(map[string]any)
		mustQuery, _ := boolQuery["must"].([]map[string]any)

		mustQuery = append(mustQuery, map[string]any{
			"term": map[string]any{
				store.schemaPrefix + "session.sessionId": opt.SessionId(),
			},
		})

		boolQuery["must"] = mustQuery
	}

	if !opt.IncludeDeleted() {
		boolQuery, _ := query["query"].(map[string]any)["bool"].(map[string]any)
		boolQuery["must_not"] = []any{
			map[string]any{
				"exists": map[string]any{
					"field": store.schemaPrefix + "session.deleteTime",
				},
			},
		}
	}

	start, end := opt.Range()
	if !start.IsZero() && !end.IsZero() {
		boolQuery, _ := query["query"].(map[string]any)["bool"].(map[string]any)
		mustQuery, _ := boolQuery["must"].([]map[string]any)

		mustQuery = append(mustQuery, map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		})

		boolQuery["must"] = mustQuery
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
		"getSessionsResponseLength": len(responseJSON),
		"requestId":                 ctx.Value(web.ContextKeyRequestId),
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
		"userId":       opt.UserId(),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found first messages for sessions")

	sessions = store.filterSharedSessions(ctx, sessions)

	if opt.Usage() {
		if err := store.populateSessionUsage(ctx, sessions); err != nil {
			logger.WithError(err).Error("Failed to populate session usage")
			return nil, err
		}
	}

	if err := store.addMetaFromMessages(ctx, sessions); err != nil {
		logger.WithError(err).Error("Failed to populate session update time")
		return nil, err
	}

	return sessions, nil
}

func (store *ElasticAssistantstore) filterSharedSessions(ctx context.Context, sessions []*model.AssistantSession) []*model.AssistantSession {
	logger := log.FromContext(ctx)
	userId := ctx.Value(web.ContextKeyRequestorId).(string)
	filteredOut := 0

	var canReadAll, canReadShared, canReadAuthored *bool

	filtered := make([]*model.AssistantSession, 0, len(sessions))
	for _, s := range sessions {
		if s.UserId == userId {
			// they own it, can they read it?
			if canReadAuthored == nil {
				err := store.server.CheckAuthorized(ctx, "read_authored", "assistant")
				canReadAuthored = util.Ptr(err == nil)
			}
			if *canReadAuthored {
				filtered = append(filtered, s)
			} else {
				filteredOut++
			}
		} else {
			// they don't own it, is it shared?
			if slices.Contains(s.Tags, "shared") {
				// its shared, can they read shared?
				if canReadShared == nil {
					err := store.server.CheckAuthorized(ctx, "read_shared", "assistant")
					canReadShared = util.Ptr(err == nil)
				}
				if *canReadShared {
					filtered = append(filtered, s)
				} else {
					filteredOut++
				}
			} else {
				// they don't own it and it's not shared, can they read all?
				if canReadAll == nil {
					err := store.server.CheckAuthorized(ctx, "read_all", "assistant")
					canReadAll = util.Ptr(err == nil)
				}
				if *canReadAll {
					filtered = append(filtered, s)
				} else {
					filteredOut++
				}
			}
		}
	}

	if filteredOut != 0 {
		logger.WithField("filteredSessions", filteredOut).Info("filtering out shared sessions")
	}

	return filtered
}

func (store *ElasticAssistantstore) populateSessionUsage(ctx context.Context, sessions []*model.AssistantSession) error {
	if len(sessions) == 0 {
		return nil
	}

	logger := log.FromContext(ctx)

	// Build MSearch request body - one search per session
	var msearchBody strings.Builder
	for _, session := range sessions {
		// Header line (empty object means use default index)
		msearchBody.WriteString("{}\n")

		// Query to aggregate usage for this session
		query := map[string]any{
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						map[string]any{
							"term": map[string]any{
								store.schemaPrefix + "chat.sessionId": session.SessionId,
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
				"total_input_tokens": map[string]any{
					"sum": map[string]any{
						"field": store.schemaPrefix + "chat.message.usage.input_tokens",
					},
				},
				"total_output_tokens": map[string]any{
					"sum": map[string]any{
						"field": store.schemaPrefix + "chat.message.usage.output_tokens",
					},
				},
				"total_credits": map[string]any{
					"sum": map[string]any{
						"field": store.schemaPrefix + "chat.message.usage.credits",
					},
				},
				"total_messages": map[string]any{
					"value_count": map[string]any{
						"field": store.schemaPrefix + "chat.sessionId",
					},
				},
			},
			"size": 0,
		}

		queryJSON, err := json.Marshal(query)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal session usage query")
			return err
		}
		msearchBody.WriteString(string(queryJSON))
		msearchBody.WriteString("\n")
	}

	logger.WithFields(log.Fields{
		"sessionCount":  len(sessions),
		"msearchLength": msearchBody.Len(),
		"requestId":     ctx.Value(web.ContextKeyRequestId),
	}).Debug("Executing MSearch for session usage")

	// Execute MSearch
	res, err := store.esClient.Msearch(
		strings.NewReader(msearchBody.String()),
		store.esClient.Msearch.WithContext(ctx),
		store.esClient.Msearch.WithIndex(store.chatIndex),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute MSearch for session usage")
		return err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read MSearch response")
		return err
	}

	logger.WithFields(log.Fields{
		"msearchResponseLength": len(responseJSON),
		"requestId":             ctx.Value(web.ContextKeyRequestId),
	}).Debug("Received MSearch response")

	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal MSearch response")
		return err
	}

	// Parse responses and populate session usage
	if responses, ok := response["responses"].([]any); ok {
		for i, respObj := range responses {
			if i >= len(sessions) {
				break
			}

			session := sessions[i]
			if resp, ok := respObj.(map[string]any); ok {
				// Check for error
				if errObj, hasErr := resp["error"]; hasErr {
					logger.WithFields(log.Fields{
						"sessionId": session.SessionId,
						"error":     errObj,
					}).Warn("Error in MSearch response for session")
					continue
				}

				// Extract aggregations
				if aggs, ok := resp["aggregations"].(map[string]any); ok {
					usage := &model.SessionUsage{}

					if inputTokensAgg, ok := aggs["total_input_tokens"].(map[string]any); ok {
						if value, ok := inputTokensAgg["value"].(float64); ok {
							usage.TotalInputTokens = int(value)
						}
					}

					if outputTokensAgg, ok := aggs["total_output_tokens"].(map[string]any); ok {
						if value, ok := outputTokensAgg["value"].(float64); ok {
							usage.TotalOutputTokens = int(value)
						}
					}

					if creditsAgg, ok := aggs["total_credits"].(map[string]any); ok {
						if value, ok := creditsAgg["value"].(float64); ok {
							usage.TotalCredits = int(value)
						}
					}

					if messagesAgg, ok := aggs["total_messages"].(map[string]any); ok {
						if value, ok := messagesAgg["value"].(float64); ok {
							usage.TotalMessages = int(value)
						}
					}

					session.Usage = usage
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Populated session usage")

	return nil
}

func (store *ElasticAssistantstore) addMetaFromMessages(ctx context.Context, sessions []*model.AssistantSession) error {
	if len(sessions) == 0 {
		return nil
	}

	logger := log.FromContext(ctx)

	// Build MSearch request body - one search per session
	var msearchBody strings.Builder
	for _, session := range sessions {
		// Header line (empty object means use default index)
		msearchBody.WriteString("{}\n")

		// Query to aggregate usage for this session
		query := map[string]any{
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						map[string]any{
							"term": map[string]any{
								store.schemaPrefix + "chat.sessionId": session.SessionId,
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
				"update_time": map[string]any{
					"max": map[string]any{
						"field":  store.schemaPrefix + "chat.createTime",
						"format": "strict_date_optional_time",
					},
				},
			},
			"size": 0,
		}

		queryJSON, err := json.Marshal(query)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal session usage query")
			return err
		}
		msearchBody.WriteString(string(queryJSON))
		msearchBody.WriteString("\n")
	}

	logger.WithFields(log.Fields{
		"sessionCount":  len(sessions),
		"msearchLength": msearchBody.Len(),
		"requestId":     ctx.Value(web.ContextKeyRequestId),
	}).Debug("Executing MSearch for session usage")

	// Execute MSearch
	res, err := store.esClient.Msearch(
		strings.NewReader(msearchBody.String()),
		store.esClient.Msearch.WithContext(ctx),
		store.esClient.Msearch.WithIndex(store.chatIndex),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute MSearch for session usage")
		return err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read MSearch response")
		return err
	}

	logger.WithFields(log.Fields{
		"msearchResponseLength": len(responseJSON),
		"requestId":             ctx.Value(web.ContextKeyRequestId),
	}).Debug("Received MSearch response")

	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal MSearch response")
		return err
	}

	// Parse responses and populate session usage
	if responses, ok := response["responses"].([]any); ok {
		for i, respObj := range responses {
			if i >= len(sessions) {
				break
			}

			session := sessions[i]
			if resp, ok := respObj.(map[string]any); ok {
				// Check for error
				if errObj, hasErr := resp["error"]; hasErr {
					logger.WithFields(log.Fields{
						"sessionId": session.SessionId,
						"error":     errObj,
					}).Warn("Error in MSearch response for session")
					continue
				}

				// Extract aggregations
				if aggs, ok := resp["aggregations"].(map[string]any); ok {
					if updateTimeAgg, ok := aggs["update_time"].(map[string]any); ok {
						if value, ok := updateTimeAgg["value_as_string"].(string); ok {
							updateTimeConverted, err := time.Parse(time.RFC3339, value)
							if err != nil {
								return fmt.Errorf("failed to parse updateTime string: %w", err)
							}
							session.UpdateTime = &updateTimeConverted
						}
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Populated session usage")

	return nil
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

func (store *ElasticAssistantstore) UpdateSessionTags(ctx context.Context, sessionId string, tags []string) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)
	logger := log.FromContext(ctx)

	// Build UpdateByQuery request to update session tags
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.userId": userId,
						},
					},
				},
			},
		},
		"script": map[string]any{
			"source": "ctx._source." + store.schemaPrefix + "session.tags = params.tags;",
			"lang":   "painless",
			"params": map[string]any{
				"tags": tags,
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
		"tags":      tags,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Updating session tags using UpdateByQuery")

	// Execute UpdateByQuery to update the session tags
	res, err := store.esClient.UpdateByQuery(
		[]string{store.disableCrossClusterIndex(store.sessionIndex)},
		store.esClient.UpdateByQuery.WithContext(ctx),
		store.esClient.UpdateByQuery.WithBody(strings.NewReader(string(queryJSON))),
		store.esClient.UpdateByQuery.WithRefresh(true),
		store.esClient.UpdateByQuery.WithWaitForCompletion(true),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to update session tags")
		return err
	}
	defer res.Body.Close()

	logger.WithFields(log.Fields{
		"sessionId": sessionId,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("successfully updated session tags")

	return nil
}

func (store *ElasticAssistantstore) DeleteSession(ctx context.Context, sessionId string) error {
	if err := store.server.CheckAuthorized(ctx, "delete_authored", "assistant"); err != nil {
		return err
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)
	logger := log.FromContext(ctx)

	now := time.Now()
	nowStr := now.Format(time.RFC3339)

	// Build UpdateByQuery request to mark session as deleted
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.userId": userId,
						},
					},
				},
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

func (store *ElasticAssistantstore) GetUsage(ctx context.Context, start time.Time, end time.Time) ([]*model.UserUsage, error) {
	if err := store.server.CheckAuthorized(ctx, "read_all", "assistant"); err != nil {
		return nil, err
	}

	logger := log.FromContext(ctx)

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "chat",
						},
					},
					map[string]any{
						"range": map[string]any{
							"@timestamp": map[string]any{
								"gte": start.Format(time.RFC3339),
								"lte": end.Format(time.RFC3339),
							},
						},
					},
				},
			},
		},
		"aggs": map[string]any{
			"users": map[string]any{
				"terms": map[string]any{
					"field": store.schemaPrefix + "chat.userId",
					"size":  10000,
				},
				"aggs": map[string]any{
					"total_input_tokens": map[string]any{
						"sum": map[string]any{
							"field": store.schemaPrefix + "chat.message.usage.input_tokens",
						},
					},
					"total_output_tokens": map[string]any{
						"sum": map[string]any{
							"field": store.schemaPrefix + "chat.message.usage.output_tokens",
						},
					},
					"total_credits": map[string]any{
						"sum": map[string]any{
							"field": store.schemaPrefix + "chat.message.usage.credits",
						},
					},
					"total_messages": map[string]any{
						"value_count": map[string]any{
							"field": store.schemaPrefix + "chat.userId",
						},
					},
					"total_sessions": map[string]any{
						"cardinality": map[string]any{
							"field": store.schemaPrefix + "chat.sessionId",
						},
					},
				},
			},
		},
		"size": 0,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Elasticsearch aggregation query")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"usageQuery":     store.truncate(string(queryJSON)),
		"startDateRange": start.Format(time.RFC3339),
		"endDateRange":   end.Format(time.RFC3339),
		"requestId":      ctx.Value(web.ContextKeyRequestId),
	}).Debug("Executing usage aggregation query")

	res, err := store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(store.chatIndex),
		store.esClient.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute usage aggregation query")
		return nil, err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read usage aggregation response")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"usageResponseLength": len(responseJSON),
		"requestId":           ctx.Value(web.ContextKeyRequestId),
	}).Debug("Received usage aggregation response")

	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal usage aggregation response")
		return nil, err
	}

	userUsages := []*model.UserUsage{}
	if aggs, ok := response["aggregations"].(map[string]any); ok {
		if users, ok := aggs["users"].(map[string]any); ok {
			if buckets, ok := users["buckets"].([]any); ok {
				for _, bucketObj := range buckets {
					if bucket, ok := bucketObj.(map[string]any); ok {
						userId, _ := bucket["key"].(string)

						totalInputTokens := 0
						if inputTokensAgg, ok := bucket["total_input_tokens"].(map[string]any); ok {
							if value, ok := inputTokensAgg["value"].(float64); ok {
								totalInputTokens = int(value)
							}
						}

						totalOutputTokens := 0
						if outputTokensAgg, ok := bucket["total_output_tokens"].(map[string]any); ok {
							if value, ok := outputTokensAgg["value"].(float64); ok {
								totalOutputTokens = int(value)
							}
						}

						totalCredits := 0
						if creditsAgg, ok := bucket["total_credits"].(map[string]any); ok {
							if value, ok := creditsAgg["value"].(float64); ok {
								totalCredits = int(value)
							}
						}

						totalMessages := 0
						if messagesAgg, ok := bucket["total_messages"].(map[string]any); ok {
							if value, ok := messagesAgg["value"].(float64); ok {
								totalMessages = int(value)
							}
						}

						totalSessions := 0
						if sessionsAgg, ok := bucket["total_sessions"].(map[string]any); ok {
							if value, ok := sessionsAgg["value"].(float64); ok {
								totalSessions = int(value)
							}
						}

						userUsage := &model.UserUsage{
							UserId:            userId,
							TotalInputTokens:  totalInputTokens,
							TotalOutputTokens: totalOutputTokens,
							TotalCredits:      totalCredits,
							TotalMessages:     totalMessages,
							TotalSessions:     totalSessions,
						}
						userUsages = append(userUsages, userUsage)
					}
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"userCount": len(userUsages),
		"start":     start.Format(time.RFC3339),
		"end":       end.Format(time.RFC3339),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Processed usage aggregation results")

	return userUsages, nil
}
