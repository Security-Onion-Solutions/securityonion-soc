// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/google/uuid"

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

	// The assistant indices are data streams, which accept only op_type=create,
	// so this never carries a document id. Rewrites go through updateChatByMessageId.
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
				if cb.Type == "" && cb.ToolResult == nil {
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
	if err != nil {
		return err
	}

	// Non-fatal: the message is already durably saved, and an undercount only
	// delays the memory scanner until the next message; the scanner's index
	// update rewrites the true count.
	if err := store.incrementSessionMessageCount(ctx, chat.SessionId); err != nil {
		log.FromContext(ctx).WithError(err).WithField("sessionId", chat.SessionId).Warn("Failed to increment session message count")
	}

	return nil
}

// SavePartialChat stores a still-generating message, tagged partial. It
// validates like SaveChat, so a stream with no content yet is not flushable.
func (store *ElasticAssistantstore) SavePartialChat(ctx context.Context, chat *model.StoredMessage) error {
	return store.upsertChat(ctx, chat, true)
}

// FinishPartialChat stores the final content of a streaming turn and clears the
// partial tag.
func (store *ElasticAssistantstore) FinishPartialChat(ctx context.Context, chat *model.StoredMessage) error {
	return store.upsertChat(ctx, chat, false)
}

// upsertChat rewrites the document carrying chat.Message.Id, or appends one if
// none exists yet. The caller keeps one chat across a turn's flushes, so
// CreateTime and the tags persist, and replaces chat.Message with each freshly
// parsed version of the stream.
func (store *ElasticAssistantstore) upsertChat(ctx context.Context, chat *model.StoredMessage, partial bool) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	if err := store.validateChat(chat); err != nil {
		return err
	}

	// An empty id would match every message that never set one.
	if chat.Message.Id == "" {
		return fmt.Errorf("a streaming chat message requires a Message.Id")
	}

	if partial {
		if !slices.Contains(chat.Tags, model.MessageTagPartial) {
			chat.Tags = append(chat.Tags, model.MessageTagPartial)
		}
	} else {
		chat.Tags = slices.DeleteFunc(chat.Tags, func(tag string) bool {
			return tag == model.MessageTagPartial
		})
	}

	if chat.CreateTime == nil {
		chat.CreateTime = util.Ptr(time.Now())
	}

	store.prepareForSave(ctx, &chat.Auditable)

	found, err := store.updateChatByMessageId(ctx, chat)
	if err != nil || found {
		return err
	}

	if _, err := store.save(ctx, chat, store.chatIndex, "chat"); err != nil {
		return err
	}

	if err := store.incrementSessionMessageCount(ctx, chat.SessionId); err != nil {
		log.FromContext(ctx).WithError(err).WithField("sessionId", chat.SessionId).Warn("Failed to increment session message count")
	}

	return nil
}

// updateChatByMessageId replaces the so_chat object of the document carrying
// chat.Message.Id, reporting whether one exists.
func (store *ElasticAssistantstore) updateChatByMessageId(ctx context.Context, chat *model.StoredMessage) (bool, error) {
	body := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "chat",
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "chat.sessionId": chat.SessionId,
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "chat.message.id": chat.Message.Id,
						},
					},
				},
			},
		},
		"script": map[string]any{
			"source": "ctx._source." + store.schemaPrefix + "chat = params.chat;",
			"lang":   "painless",
			"params": map[string]any{
				"chat": chat,
			},
		},
	}

	total, updated, err := store.updateByQuery(ctx, store.chatIndex, body)
	if err != nil {
		return false, err
	}

	if total > 0 && updated == 0 {
		log.FromContext(ctx).WithFields(log.Fields{
			"sessionId": chat.SessionId,
			"messageId": chat.Message.Id,
		}).Warn("Chat message rewrite lost a version conflict")
	}

	return total > 0, nil
}

// updateByQuery runs body against index with conflicts=proceed and reports how
// many documents matched and how many were written.
func (store *ElasticAssistantstore) updateByQuery(ctx context.Context, index string, body map[string]any) (total int, updated int, err error) {
	logger := log.FromContext(ctx)

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal UpdateByQuery request")
		return 0, 0, err
	}

	res, err := store.esClient.UpdateByQuery(
		[]string{store.disableCrossClusterIndex(index)},
		store.esClient.UpdateByQuery.WithContext(ctx),
		store.esClient.UpdateByQuery.WithBody(strings.NewReader(string(bodyJSON))),
		store.esClient.UpdateByQuery.WithRefresh(true),
		store.esClient.UpdateByQuery.WithWaitForCompletion(true),
		store.esClient.UpdateByQuery.WithConflicts("proceed"),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute UpdateByQuery")
		return 0, 0, err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to execute UpdateByQuery")
		return 0, 0, err
	}

	var response struct {
		Total   int `json:"total"`
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal UpdateByQuery response")
		return 0, 0, err
	}

	logger.WithFields(log.Fields{
		"index":     index,
		"total":     response.Total,
		"updated":   response.Updated,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("UpdateByQuery finished")

	return response.Total, response.Updated, nil
}

// incrementSessionMessageCount bumps the denormalized messageCount on the
// session document so the memory scanner can find sessions with unscanned
// messages in a single query. It also clears memoryErrors so new activity gives
// a session excluded for repeated scan failures another chance.
func (store *ElasticAssistantstore) incrementSessionMessageCount(ctx context.Context, sessionId string) error {
	body := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
				},
			},
		},
		"script": map[string]any{
			"source": "def s = ctx._source." + store.schemaPrefix + "session; s.messageCount = (s.messageCount != null ? s.messageCount : 0) + 1; s.memoryErrors = 0;",
			"lang":   "painless",
		},
	}

	// A conflicting concurrent update loses this increment; that self-heals
	// when the memory scanner records the true count.
	_, _, err := store.updateByQuery(ctx, store.sessionIndex, body)

	return err
}

// Use only with sessions pulled from ES.
func (store *ElasticAssistantstore) GetChatHistory(ctx context.Context, session *model.AssistantSession) ([]*model.StoredMessage, error) {
	if session == nil {
		return nil, fmt.Errorf("session is required")
	}

	// A missing requestor id (only possible on a non-HTTP call path) leaves
	// userId empty: never the owner, so access falls through to the read_shared
	// or read_all authorization checks below.
	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	if session.UserId == userId {
		// they own it, can the user read_authored?
		err := store.server.CheckAuthorized(ctx, "read_authored", "assistant")
		if err != nil {
			return nil, err
		}
	} else if slices.Contains(session.Tags, model.SessionTagShared) {
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

	return store.searchChatHistory(ctx, session.SessionId)
}

func (store *ElasticAssistantstore) chatHistoryQuery(sessionId string) map[string]any {
	return map[string]any{
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
		// createTime is set once per message and survives rewrites and clones;
		// @timestamp only breaks same-millisecond ties.
		"sort": []any{
			map[string]any{
				store.schemaPrefix + "chat.createTime": map[string]any{
					"order": "asc",
				},
			},
			map[string]any{
				"@timestamp": map[string]any{
					"order": "asc",
				},
			},
		},
		"size": 10000,
	}
}

func (store *ElasticAssistantstore) searchChatHistory(ctx context.Context, sessionId string) ([]*model.StoredMessage, error) {
	logger := log.FromContext(ctx)

	queryJSON, err := json.Marshal(store.chatHistoryQuery(sessionId))
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

	messages := store.parseChatHits(ctx, response)

	logger.WithFields(log.Fields{
		"messageCount": len(messages),
		"sessionId":    sessionId,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found chat history messages")

	return messages, nil
}

func (store *ElasticAssistantstore) parseChatHits(ctx context.Context, response map[string]any) []*model.StoredMessage {
	logger := log.FromContext(ctx)

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

	return messages
}

// msearch runs one search per query against the chat index and returns the
// responses in order. Callers decide what a response's own error entry means.
func (store *ElasticAssistantstore) msearch(ctx context.Context, queries []map[string]any) ([]map[string]any, error) {
	var body strings.Builder
	for _, query := range queries {
		line, err := json.Marshal(query)
		if err != nil {
			return nil, err
		}
		body.WriteString("{}\n")
		body.Write(line)
		body.WriteString("\n")
	}

	res, err := store.esClient.Msearch(strings.NewReader(body.String()),
		store.esClient.Msearch.WithContext(ctx),
		store.esClient.Msearch.WithIndex(store.chatIndex))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		return nil, err
	}

	var response struct {
		Responses []map[string]any `json:"responses"`
	}
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		return nil, err
	}
	if len(response.Responses) != len(queries) {
		return nil, fmt.Errorf("msearch returned %d responses for %d queries", len(response.Responses), len(queries))
	}

	return response.Responses, nil
}

// searchChatHistories fetches every session's history in one msearch, in the order given.
func (store *ElasticAssistantstore) searchChatHistories(ctx context.Context, sessionIds []string) ([][]*model.StoredMessage, error) {
	queries := make([]map[string]any, len(sessionIds))
	for i, id := range sessionIds {
		queries[i] = store.chatHistoryQuery(id)
	}

	responses, err := store.msearch(ctx, queries)
	if err != nil {
		return nil, err
	}

	histories := make([][]*model.StoredMessage, len(sessionIds))
	for i, resp := range responses {
		if errObj, ok := resp["error"]; ok {
			return nil, fmt.Errorf("chat history search failed for session %s: %v", sessionIds[i], errObj)
		}
		histories[i] = store.parseChatHits(ctx, resp)
	}

	return histories, nil
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

	mustNot := []any{}

	if !opt.IncludeDeleted() {
		mustNot = append(mustNot, map[string]any{
			"exists": map[string]any{
				"field": store.schemaPrefix + "session.deleteTime",
			},
		})
	}

	if !opt.IncludeMemorySessions() {
		mustNot = append(mustNot, map[string]any{
			"terms": map[string]any{
				store.schemaPrefix + "session.tags": model.MemorySessionTags,
			},
		})
	}

	if !opt.IncludeAutomationSessions() {
		mustNot = append(mustNot, map[string]any{
			"term": map[string]any{
				store.schemaPrefix + "session.tags": model.SessionTagAutomation,
			},
		})
	}

	if len(mustNot) != 0 {
		boolQuery, _ := query["query"].(map[string]any)["bool"].(map[string]any)
		boolQuery["must_not"] = mustNot
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

	sessions, err := store.searchSessions(ctx, query)
	if err != nil {
		return nil, err
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"userId":       opt.UserId(),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Found first messages for sessions")

	sessions = store.filterSharedSessions(ctx, sessions)

	if opt.Descendants() && len(sessions) > 0 {
		descendants, err := store.fetchDescendantSessions(ctx, sessions, opt.IncludeDeleted())
		if err != nil {
			logger.WithError(err).Error("Failed to fetch descendant sessions")
			return nil, err
		}
		sessions = append(sessions, store.filterSharedSessions(ctx, descendants)...)
	}

	if opt.Usage() {
		if err := store.populateSessionUsage(ctx, sessions); err != nil {
			logger.WithError(err).Error("Failed to populate session usage")
			return nil, err
		}
	}

	if opt.MessageMeta() {
		if err := store.addMetaFromMessages(ctx, sessions); err != nil {
			logger.WithError(err).Error("Failed to populate session update time")
			return nil, err
		}
	}

	return sessions, nil
}

// DoesUserOwnSession reports whether the session identified by sessionId is
// recorded (soft-deleted included) as owned by userId, whether it exists at all,
// and whether it is an automation run's transcript. Only the owner id and tags are
// fetched from the index — the session document is never transferred or
// deserialized. A session that doesn't exist returns (false, false, false, nil).
func (store *ElasticAssistantstore) DoesUserOwnSession(ctx context.Context, userId, sessionId string) (ownedByUser bool, sessionExists bool, isAutomation bool, err error) {
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
					{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
				},
			},
		},
		"_source": []string{
			store.schemaPrefix + "session.userId",
			store.schemaPrefix + "session.tags",
		},
		"size": 1,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Elasticsearch query")
		return false, false, false, err
	}

	res, err := store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(store.sessionIndex),
		store.esClient.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to execute Elasticsearch search")
		return false, false, false, err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read Elasticsearch response")
		return false, false, false, err
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		logger.WithError(err).Error("Failed to unmarshal Elasticsearch response")
		return false, false, false, err
	}

	hits, _ := response["hits"].(map[string]any)
	hitsArray, _ := hits["hits"].([]any)
	if len(hitsArray) == 0 {
		return false, false, false, nil
	}

	hit, _ := hitsArray[0].(map[string]any)
	source, _ := hit["_source"].(map[string]any)
	sess, _ := source[store.schemaPrefix+"session"].(map[string]any)
	owner, _ := sess["userId"].(string)

	// Sessions predating the tags field, and those saved with none, decode to a nil
	// slice here rather than an error.
	tags, _ := sess["tags"].([]any)
	for _, tag := range tags {
		if s, ok := tag.(string); ok && s == model.SessionTagAutomation {
			isAutomation = true
			break
		}
	}

	return owner == userId, true, isAutomation, nil
}

// searchSessions executes a session-index query and deserializes the hits into
// AssistantSession values.
func (store *ElasticAssistantstore) searchSessions(ctx context.Context, query map[string]any) ([]*model.AssistantSession, error) {
	logger := log.FromContext(ctx)

	queryJSON, err := json.Marshal(query)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Elasticsearch query")
		return nil, err
	}

	logger.WithFields(log.Fields{
		"query":     store.truncate(string(queryJSON)),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Searching sessions")

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

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		logger.WithError(err).Error("Failed to read Elasticsearch response")
		return nil, err
	}

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

	return sessions, nil
}

// fetchDescendantSessions breadth-first walks the delegation tree rooted at the
// given sessions, returning every descendant session linked by parentSessionId, to
// any depth. A seen set guards against cycles.
func (store *ElasticAssistantstore) fetchDescendantSessions(ctx context.Context, roots []*model.AssistantSession, includeDeleted bool) ([]*model.AssistantSession, error) {
	seen := map[string]bool{}
	frontier := []string{}
	for _, s := range roots {
		if s.SessionId == "" || seen[s.SessionId] {
			continue
		}
		seen[s.SessionId] = true
		frontier = append(frontier, s.SessionId)
	}

	descendants := []*model.AssistantSession{}
	for len(frontier) > 0 {
		ids := make([]any, 0, len(frontier))
		for _, id := range frontier {
			ids = append(ids, id)
		}

		boolQuery := map[string]any{
			"must": []map[string]any{
				{"term": map[string]any{store.schemaPrefix + "kind": "session"}},
				{"terms": map[string]any{store.schemaPrefix + "session.parentSessionId": ids}},
			},
		}
		if !includeDeleted {
			boolQuery["must_not"] = []any{
				map[string]any{"exists": map[string]any{"field": store.schemaPrefix + "session.deleteTime"}},
			}
		}

		query := map[string]any{
			"query": map[string]any{"bool": boolQuery},
			"sort":  []map[string]any{{"@timestamp": map[string]any{"order": "asc"}}},
		}

		children, err := store.searchSessions(ctx, query)
		if err != nil {
			return nil, err
		}

		nextFrontier := []string{}
		for _, c := range children {
			if c.SessionId == "" || seen[c.SessionId] {
				continue
			}
			seen[c.SessionId] = true
			descendants = append(descendants, c)
			nextFrontier = append(nextFrontier, c.SessionId)
		}
		frontier = nextFrontier
	}

	return descendants, nil
}

func (store *ElasticAssistantstore) filterSharedSessions(ctx context.Context, sessions []*model.AssistantSession) []*model.AssistantSession {
	logger := log.FromContext(ctx)
	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
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
			if slices.Contains(s.Tags, model.SessionTagShared) {
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

	queries := make([]map[string]any, len(sessions))
	for i, session := range sessions {
		queries[i] = map[string]any{
			"query": store.sessionChatsQuery(session.SessionId),
			"aggs":  store.usageAggs(store.schemaPrefix + "chat.sessionId"),
			"size":  0,
		}
	}

	responses, err := store.msearch(ctx, queries)
	if err != nil {
		logger.WithError(err).Error("Failed to execute MSearch for session usage")
		return err
	}

	for i, resp := range responses {
		session := sessions[i]
		if errObj, hasErr := resp["error"]; hasErr {
			logger.WithFields(log.Fields{
				"sessionId": session.SessionId,
				"error":     errObj,
			}).Warn("Error in MSearch response for session")
			continue
		}
		if aggs, ok := resp["aggregations"].(map[string]any); ok {
			session.Usage = parseUsageAggs(aggs)
		}
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Populated session usage")

	return nil
}

func (store *ElasticAssistantstore) sessionChatsQuery(sessionId string) map[string]any {
	return map[string]any{
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
	}
}

// usageBillableAgg filters the token and credit sums to messages not cloned from another session.
const usageBillableAgg = "billable"

func (store *ElasticAssistantstore) usageAggs(countField string) map[string]any {
	sum := func(field string) map[string]any {
		return map[string]any{"sum": map[string]any{"field": store.schemaPrefix + "chat.message.usage." + field}}
	}
	billable := func(prefix string) map[string]any {
		return map[string]any{
			"filter": map[string]any{
				"bool": map[string]any{
					"must_not": []any{
						map[string]any{"term": map[string]any{store.schemaPrefix + "chat.tags": model.MessageTagClone}},
					},
				},
			},
			"aggs": map[string]any{
				prefix + "input_tokens":  sum("input_tokens"),
				prefix + "output_tokens": sum("output_tokens"),
				prefix + "credits":       sum("credits"),
			},
		}
	}

	return map[string]any{
		usageBillableAgg: billable("total_"),
		"total_messages": map[string]any{"value_count": map[string]any{"field": countField}},
		"model_usage": map[string]any{
			"terms": map[string]any{
				"field": store.schemaPrefix + "chat.model",
				"size":  100,
			},
			"aggs": map[string]any{
				usageBillableAgg: billable("model_"),
				"model_messages": map[string]any{"value_count": map[string]any{"field": countField}},
			},
		},
	}
}

func aggValue(aggs map[string]any, name string) int {
	if agg, ok := aggs[name].(map[string]any); ok {
		if value, ok := agg["value"].(float64); ok {
			return int(value)
		}
	}
	return 0
}

func parseUsageAggs(aggs map[string]any) *model.SessionUsage {
	billable, _ := aggs[usageBillableAgg].(map[string]any)
	usage := &model.SessionUsage{
		TotalInputTokens:  aggValue(billable, "total_input_tokens"),
		TotalOutputTokens: aggValue(billable, "total_output_tokens"),
		TotalCredits:      aggValue(billable, "total_credits"),
		TotalMessages:     aggValue(aggs, "total_messages"),
	}

	byModelAgg, _ := aggs["model_usage"].(map[string]any)
	buckets, _ := byModelAgg["buckets"].([]any)
	if len(buckets) == 0 {
		return usage
	}

	usage.ModelUsage = make(map[string]*model.ModelUsageStats)
	for _, bucketObj := range buckets {
		bucket, ok := bucketObj.(map[string]any)
		if !ok {
			continue
		}
		modelKey, _ := bucket["key"].(string)
		if modelKey == "" {
			continue
		}
		modelBillable, _ := bucket[usageBillableAgg].(map[string]any)
		usage.ModelUsage[modelKey] = &model.ModelUsageStats{
			ModelInputTokens:  aggValue(modelBillable, "model_input_tokens"),
			ModelOutputTokens: aggValue(modelBillable, "model_output_tokens"),
			ModelCredits:      aggValue(modelBillable, "model_credits"),
			ModelMessages:     aggValue(bucket, "model_messages"),
		}
	}

	return usage
}

func (store *ElasticAssistantstore) addMetaFromMessages(ctx context.Context, sessions []*model.AssistantSession) error {
	if len(sessions) == 0 {
		return nil
	}

	logger := log.FromContext(ctx)

	queries := make([]map[string]any, len(sessions))
	for i, session := range sessions {
		queries[i] = map[string]any{
			"query": store.sessionChatsQuery(session.SessionId),
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
	}

	responses, err := store.msearch(ctx, queries)
	if err != nil {
		logger.WithError(err).Error("Failed to execute MSearch for session meta")
		return err
	}

	for i, resp := range responses {
		session := sessions[i]
		if errObj, hasErr := resp["error"]; hasErr {
			logger.WithFields(log.Fields{
				"sessionId": session.SessionId,
				"error":     errObj,
			}).Warn("Error in MSearch response for session")
			continue
		}
		aggs, ok := resp["aggregations"].(map[string]any)
		if !ok {
			continue
		}
		updateTimeAgg, ok := aggs["update_time"].(map[string]any)
		if !ok {
			continue
		}
		if value, ok := updateTimeAgg["value_as_string"].(string); ok {
			updateTime, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return fmt.Errorf("failed to parse updateTime string: %w", err)
			}
			session.UpdateTime = &updateTime
		}
	}

	logger.WithFields(log.Fields{
		"sessionCount": len(sessions),
		"requestId":    ctx.Value(web.ContextKeyRequestId),
	}).Debug("Populated session meta")

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

// ToggleSessionsTag adds or removes one tag on every listed session the caller
// owns in a single write, so a shared-tag cascade cannot half-apply.
func (store *ElasticAssistantstore) ToggleSessionsTag(ctx context.Context, sessionIds []string, tag string, present bool) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)
	logger := log.FromContext(ctx)

	tags := "ctx._source." + store.schemaPrefix + "session.tags"
	source := "if (" + tags + " != null) { " + tags + ".removeIf(t -> t == params.tag); }"
	if present {
		source = "if (" + tags + " == null) { " + tags + " = []; } if (!" + tags + ".contains(params.tag)) { " + tags + ".add(params.tag); }"
	}

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"terms": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionIds,
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
			"source": source,
			"lang":   "painless",
			"params": map[string]any{
				"tag": tag,
			},
		},
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return err
	}

	logger.WithFields(log.Fields{
		"sessionIds": sessionIds,
		"tag":        tag,
		"present":    present,
		"requestId":  ctx.Value(web.ContextKeyRequestId),
	}).Debug("Toggling session tag using UpdateByQuery")

	res, err := store.esClient.UpdateByQuery(
		[]string{store.disableCrossClusterIndex(store.sessionIndex)},
		store.esClient.UpdateByQuery.WithContext(ctx),
		store.esClient.UpdateByQuery.WithBody(strings.NewReader(string(queryJSON))),
		store.esClient.UpdateByQuery.WithRefresh(true),
		store.esClient.UpdateByQuery.WithWaitForCompletion(true),
	)
	if err != nil {
		logger.WithError(err).Error("Failed to toggle session tag")
		return err
	}
	defer res.Body.Close()

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

// FindSessionsPendingMemoryScan returns non-deleted root sessions whose
// messageCount is ahead of lastMemoryScannedIndex (or whose count is not yet
// recorded) and whose memoryErrors is at most maxMemoryRetries, with full
// History populated, for the memory scanner.
func (store *ElasticAssistantstore) FindSessionsPendingMemoryScan(ctx context.Context, dontScanBefore *time.Time, maxMemoryRetries int) ([]*model.AssistantSessionDetails, error) {
	if err := store.server.CheckAuthorized(ctx, "read_all", "assistant"); err != nil {
		return nil, err
	}

	logger := log.FromContext(ctx)

	countField := store.schemaPrefix + "session.messageCount"
	scannedField := store.schemaPrefix + "session.lastMemoryScannedIndex"
	errorsField := store.schemaPrefix + "session.memoryErrors"

	must := []map[string]any{
		{
			"term": map[string]any{
				store.schemaPrefix + "kind": "session",
			},
		},
		{
			// A session is pending when more messages have been saved than
			// scanned. A missing lastMemoryScannedIndex means never scanned
			// (0); a missing messageCount means the session predates the
			// field, so its count is unknown and it is treated as pending
			// until the scanner records the true count.
			"script": map[string]any{
				"script": map[string]any{
					"source": "long c = doc.containsKey(params.cf) && doc[params.cf].size() > 0 ? doc[params.cf].value : -1L; long s = doc.containsKey(params.sf) && doc[params.sf].size() > 0 ? doc[params.sf].value : 0L; return c == -1L || c > s;",
					"lang":   "painless",
					"params": map[string]any{
						"cf": countField,
						"sf": scannedField,
					},
				},
			},
		},
		{
			// A missing memoryErrors means no failures yet (0).
			"bool": map[string]any{
				"should": []any{
					map[string]any{
						"range": map[string]any{
							errorsField: map[string]any{
								"lte": maxMemoryRetries,
							},
						},
					},
					map[string]any{
						"bool": map[string]any{
							"must_not": map[string]any{
								"exists": map[string]any{
									"field": errorsField,
								},
							},
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
	}

	if dontScanBefore != nil {
		must = append(must, map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{
					// The explicit offset keeps Elasticsearch from reinterpreting
					// the instant as UTC and shifting the day boundary.
					"gte": dontScanBefore.Format("2006-01-02T15:04:05-07:00"),
				},
			},
		})
	}

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": must,
				"must_not": []any{
					map[string]any{
						"exists": map[string]any{
							"field": store.schemaPrefix + "session.deleteTime",
						},
					},
					// Root sessions only; delegated sub-session transcripts are not
					// scanned for memories.
					map[string]any{
						"exists": map[string]any{
							"field": store.schemaPrefix + "session.parentSessionId",
						},
					},
					// Memory-pipeline bookkeeping sessions record agent token usage
					// and must never be scanned themselves.
					map[string]any{
						"terms": map[string]any{
							store.schemaPrefix + "session.tags": model.MemorySessionTags,
						},
					},
					// Incognito sessions opted out of memory extraction at creation.
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.tags": model.SessionTagIncognito,
						},
					},
					// An automation transcript is the machine talking to itself;
					// scanning it would feed a run's own output back as the owner's
					// memories, and the scanner can otherwise read a partial mid-run.
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.tags": model.SessionTagAutomation,
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
	}

	sessions, err := store.searchSessions(ctx, query)
	if err != nil {
		return nil, err
	}

	details := []*model.AssistantSessionDetails{}
	for _, session := range sessions {
		history, err := store.GetChatHistory(ctx, session)
		if err != nil {
			// One bad session shouldn't starve the scan; it is retried next tick.
			logger.WithError(err).WithField("sessionId", session.SessionId).Error("failed to fetch history for session pending memory scan")
			continue
		}

		// Sessions that predate messageCount match the query even when empty;
		// nothing to scan until a message arrives.
		if len(history) == 0 {
			continue
		}

		details = append(details, &model.AssistantSessionDetails{
			Session: session,
			History: history,
		})
	}

	logger.WithFields(log.Fields{
		"pendingCount": len(details),
	}).Debug("Found sessions pending memory scan")

	return details, nil
}

// UpdateSessionMemoryScanIndex records that the memory scanner has processed the
// session's messages up to scannedIndex. It also raises messageCount to
// scannedIndex when the stored count is missing or lower, healing legacy
// sessions and lost increments; a higher stored count is left alone so messages
// that arrived mid-scan stay pending. A successful scan also clears memoryErrors.
// Not scoped to the requestor's userId: the scanner runs as SYSTEM over sessions
// owned by real users.
func (store *ElasticAssistantstore) UpdateSessionMemoryScanIndex(ctx context.Context, sessionId string, scannedIndex int) error {
	if err := store.server.CheckAuthorized(ctx, "write_all", "assistant"); err != nil {
		return err
	}

	body := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
				},
			},
		},
		"script": map[string]any{
			"source": "def s = ctx._source." + store.schemaPrefix + "session; s.lastMemoryScannedIndex = params.scanned; s.memoryErrors = 0; if (s.messageCount == null || s.messageCount < params.scanned) { s.messageCount = params.scanned; }",
			"lang":   "painless",
			"params": map[string]any{
				"scanned": scannedIndex,
			},
		},
	}

	// A conflicting concurrent update loses this write; the session is then
	// rescanned next tick and reconciliation dedupes any repeated facts.
	_, _, err := store.updateByQuery(ctx, store.sessionIndex, body)

	return err
}

// IncrementSessionMemoryErrors bumps the session's memoryErrors after a failed
// memory scan so a session that keeps failing is eventually excluded from the
// scan. Not scoped to the requestor's userId, for the same reason as
// UpdateSessionMemoryScanIndex.
func (store *ElasticAssistantstore) IncrementSessionMemoryErrors(ctx context.Context, sessionId string) error {
	if err := store.server.CheckAuthorized(ctx, "write_all", "assistant"); err != nil {
		return err
	}

	body := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "kind": "session",
						},
					},
					map[string]any{
						"term": map[string]any{
							store.schemaPrefix + "session.sessionId": sessionId,
						},
					},
				},
			},
		},
		"script": map[string]any{
			"source": "def s = ctx._source." + store.schemaPrefix + "session; s.memoryErrors = (s.memoryErrors != null ? s.memoryErrors : 0) + 1;",
			"lang":   "painless",
		},
	}

	// A lost increment only delays exclusion by one more failed scan.
	_, _, err := store.updateByQuery(ctx, store.sessionIndex, body)

	return err
}

func (store *ElasticAssistantstore) GetUsage(ctx context.Context, start time.Time, end time.Time) ([]*model.UserUsage, error) {
	if err := store.server.CheckAuthorized(ctx, "read_all", "assistant"); err != nil {
		return nil, err
	}

	logger := log.FromContext(ctx)

	userAggs := store.usageAggs(store.schemaPrefix + "chat.userId")
	userAggs["total_sessions"] = map[string]any{
		"cardinality": map[string]any{
			"field": store.schemaPrefix + "chat.sessionId",
		},
	}

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
				"aggs": userAggs,
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
					bucket, ok := bucketObj.(map[string]any)
					if !ok {
						continue
					}
					userId, _ := bucket["key"].(string)
					usage := parseUsageAggs(bucket)
					userUsages = append(userUsages, &model.UserUsage{
						UserId:            userId,
						TotalInputTokens:  usage.TotalInputTokens,
						TotalOutputTokens: usage.TotalOutputTokens,
						TotalCredits:      usage.TotalCredits,
						TotalMessages:     usage.TotalMessages,
						TotalSessions:     aggValue(bucket, "total_sessions"),
						ModelUsage:        usage.ModelUsage,
					})
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

// CloneSession copies a readable session and its delegated descendants into new sessions owned by the caller.
func (store *ElasticAssistantstore) CloneSession(ctx context.Context, sessionId string) (*model.AssistantSession, error) {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return nil, err
	}
	// A failed clone is rolled back through DeleteSession.
	if err := store.server.CheckAuthorized(ctx, "delete_authored", "assistant"); err != nil {
		return nil, err
	}

	sessions, err := store.GetSessions(ctx,
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithAutomationSessions(true),
		model.GetSessionsWithMessageMeta(false))
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 {
		return nil, server.ErrSessionNotFound
	}
	root := sessions[0]
	if root.ParentSessionId != "" {
		return nil, server.ErrSessionNotRoot
	}

	// Readable root implies readable tree; level order means parents are created first.
	descendants, err := store.fetchDescendantSessions(ctx, sessions, false)
	if err != nil {
		return nil, err
	}
	sessions = append(sessions, descendants...)

	sessionIds := make([]string, len(sessions))
	for i, src := range sessions {
		sessionIds[i] = src.SessionId
	}
	histories, err := store.searchChatHistories(ctx, sessionIds)
	if err != nil {
		return nil, err
	}

	ids := make(map[string]string, len(sessions))
	cloneIds := make([]string, 0, len(sessions))
	for _, src := range sessions {
		ids[src.SessionId] = uuid.NewString()
		cloneIds = append(cloneIds, ids[src.SessionId])
	}

	var cloneRoot *model.AssistantSession
	var sessionBody strings.Builder
	var chats []*model.StoredMessage

	for i, src := range sessions {
		clone := cloneSessionRecord(src, ids)
		messages := cloneMessages(histories[i], clone.SessionId)
		clone.MessageCount = len(messages)
		clone.LastMemoryScannedIndex = len(messages)

		if err := store.validateSession(clone); err != nil {
			return nil, err
		}

		clone.CreateTime = util.Ptr(time.Now())
		store.prepareForSave(ctx, &clone.Auditable)

		line, err := store.bulkCreateLine("session", clone)
		if err != nil {
			return nil, err
		}

		sessionBody.WriteString(line)
		chats = append(chats, messages...)

		if cloneRoot == nil {
			cloneRoot = clone
		}
	}

	// A bulk write is not atomic, so either failure rolls back every clone id.
	if err := store.bulkCreate(ctx, store.sessionIndex, sessionBody.String()); err != nil {
		return nil, store.abandonClone(ctx, cloneIds, err)
	}
	if err := store.saveClonedChats(ctx, chats); err != nil {
		return nil, store.abandonClone(ctx, cloneIds, err)
	}

	return cloneRoot, nil
}

func cloneSessionRecord(src *model.AssistantSession, ids map[string]string) *model.AssistantSession {
	clone := &model.AssistantSession{
		SessionId: ids[src.SessionId],
		Title:     src.Title,
		Type:      src.Type,
		EntityId:  src.EntityId,
		Model:     src.Model,
		Depth:     src.Depth,
		Tags: slices.DeleteFunc(slices.Clone(src.Tags), func(tag string) bool {
			return tag == model.SessionTagAutomation || tag == model.SessionTagShared
		}),
	}
	if src.ParentSessionId != "" {
		clone.ParentSessionId = ids[src.ParentSessionId]
		clone.ParentToolUseId = src.ParentToolUseId
		clone.ParentModel = src.ParentModel
		clone.DelegateAgent = src.DelegateAgent
	}
	return clone
}

// Partial messages are skipped: an unfinished turn has nothing to resume from.
func cloneMessages(history []*model.StoredMessage, sessionId string) []*model.StoredMessage {
	clones := make([]*model.StoredMessage, 0, len(history))
	for _, msg := range history {
		if msg.Message == nil || msg.IsPartial() {
			continue
		}
		tags := slices.Clone(msg.Tags)
		if !slices.Contains(tags, model.MessageTagClone) {
			tags = append(tags, model.MessageTagClone)
		}
		clones = append(clones, &model.StoredMessage{
			Auditable: model.Auditable{CreateTime: msg.CreateTime},
			Tags:      tags,
			SessionId: sessionId,
			Model:     msg.Model,
			Message:   msg.Message,
		})
	}
	return clones
}

// The clone session's messageCount was set when it was created.
func (store *ElasticAssistantstore) saveClonedChats(ctx context.Context, chats []*model.StoredMessage) error {
	if len(chats) == 0 {
		return nil
	}

	var body strings.Builder
	for _, chat := range chats {
		if err := store.validateChat(chat); err != nil {
			return err
		}
		if chat.CreateTime == nil {
			chat.CreateTime = util.Ptr(time.Now())
		}

		store.prepareForSave(ctx, &chat.Auditable)

		line, err := store.bulkCreateLine("chat", chat)
		if err != nil {
			return err
		}

		body.WriteString(line)
	}

	return store.bulkCreate(ctx, store.chatIndex, body.String())
}

func (store *ElasticAssistantstore) bulkCreateLine(kind string, obj any) (string, error) {
	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	line, err := convertToElasticIndexRequest(document)
	if err != nil {
		return "", err
	}

	return `{"create":{}}` + "\n" + line + "\n", nil
}

// bulkCreate appends documents to a data stream in one request, refreshing
// once. Any rejected item fails the call.
func (store *ElasticAssistantstore) bulkCreate(ctx context.Context, index string, body string) error {
	res, err := store.esClient.Bulk(strings.NewReader(body),
		store.esClient.Bulk.WithIndex(store.disableCrossClusterIndex(index)),
		store.esClient.Bulk.WithRefresh("true"),
		store.esClient.Bulk.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	responseJSON, err := readJsonFromResponse(res)
	if err != nil {
		return err
	}

	var response struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Error any `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		return err
	}
	if !response.Errors {
		return nil
	}
	for _, item := range response.Items {
		for _, result := range item {
			if result.Error != nil {
				return fmt.Errorf("bulk create rejected: %v", result.Error)
			}
		}
	}
	return fmt.Errorf("bulk create rejected")
}

// Rollback runs on a detached context so a cancelled request still cleans up.
func (store *ElasticAssistantstore) abandonClone(ctx context.Context, cloneIds []string, cause error) error {
	ctx = web.DetachContext(ctx)

	for _, id := range cloneIds {
		if err := store.DeleteSession(ctx, id); err != nil {
			log.FromContext(ctx).WithError(err).WithField("sessionId", id).Warn("Failed to delete abandoned clone")
		}
	}

	return cause
}
