// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

const (
	PLAYBOOK_INDEX         = "so-playbook"
	PLAYBOOK_AUDIT_INDEX   = "so-playbookhistory"
	PLAYBOOK_KIND          = "playbook"
	PLAYBOOK_SCHEMA_PREFIX = "so_"
)

type ElasticPlaybookstore struct {
	server       *server.Server
	esClient     *elasticsearch.Client
	index        string
	auditIndex   string
	schemaPrefix string
}

func NewElasticPlaybookstore(srv *server.Server, client *elasticsearch.Client) *ElasticPlaybookstore {
	return &ElasticPlaybookstore{
		server:       srv,
		esClient:     client,
		index:        PLAYBOOK_INDEX,
		auditIndex:   PLAYBOOK_AUDIT_INDEX,
		schemaPrefix: PLAYBOOK_SCHEMA_PREFIX,
	}
}

func (store *ElasticPlaybookstore) Init(index string, auditIndex string, schemaPrefix string) error {
	if index != "" {
		store.index = index
	}
	if auditIndex != "" {
		store.auditIndex = auditIndex
	}
	if schemaPrefix != "" {
		store.schemaPrefix = schemaPrefix
	}
	return nil
}

func (store *ElasticPlaybookstore) CreatePlaybook(ctx context.Context, playbook *model.Playbook) (*model.Playbook, error) {
	logger := log.FromContext(ctx)

	if err := store.server.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return nil, err
	}

	// Validate playbook
	if err := playbook.Validate(); err != nil {
		return nil, err
	}

	// Ensure no ID is set for new playbooks
	if playbook.Id != "" {
		return nil, errors.New("unexpected ID found in new playbook")
	}

	// Cannot create community playbooks via API
	if playbook.IsCommunity {
		return nil, errors.New("cannot create community playbooks via API")
	}

	// Set custom ruleset
	playbook.Ruleset = model.PLAYBOOK_RULESET_CUSTOM
	playbook.IsCommunity = false

	// Set timestamps
	now := time.Now()
	playbook.CreateTime = &now

	// Generate ID from name
	playbook.Id = util.ToUUID(playbook.Name + "-" + now.Format(time.RFC3339Nano))

	// Set kind and operation
	playbook.Kind = PLAYBOOK_KIND
	playbook.Operation = "create"

	// Get user ID from context
	if userID, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		playbook.UserId = userID
	}

	// Save to Elasticsearch
	document := store.convertToDocument(playbook)
	docBytes, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal playbook: %w", err)
	}

	req := esapi.IndexRequest{
		Index:      store.index,
		DocumentID: playbook.Id,
		Body:       bytes.NewReader(docBytes),
		Refresh:    "wait_for",
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return nil, fmt.Errorf("failed to index playbook: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to index playbook: %s - %s", res.Status(), string(body))
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbook.Id,
		"playbookName": playbook.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       playbook.UserId,
	}).Info("Playbook created")

	// Return the created playbook
	return store.GetPlaybook(ctx, playbook.Id)
}

func (store *ElasticPlaybookstore) UpdatePlaybook(ctx context.Context, playbook *model.Playbook) (*model.Playbook, error) {
	logger := log.FromContext(ctx)

	if err := store.server.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return nil, err
	}

	// Validate playbook
	if err := playbook.Validate(); err != nil {
		return nil, err
	}

	// Require ID for updates
	if playbook.Id == "" {
		return nil, errors.New("missing playbook ID")
	}

	// Get existing playbook
	existing, err := store.GetPlaybook(ctx, playbook.Id)
	if err != nil {
		return nil, err
	}

	// Cannot update community playbooks
	if existing.IsCommunity {
		return nil, errors.New("cannot update community playbooks")
	}

	// Preserve read-only fields
	playbook.CreateTime = existing.CreateTime
	playbook.IsCommunity = existing.IsCommunity
	playbook.Ruleset = existing.Ruleset

	// Update timestamp
	now := time.Now()
	playbook.UpdateTime = &now

	// Set kind and operation
	playbook.Kind = PLAYBOOK_KIND
	playbook.Operation = "update"

	// Get user ID from context
	if userID, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		playbook.UserId = userID
	}

	// Save to Elasticsearch
	document := store.convertToDocument(playbook)
	docBytes, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal playbook: %w", err)
	}

	req := esapi.IndexRequest{
		Index:      store.index,
		DocumentID: playbook.Id,
		Body:       bytes.NewReader(docBytes),
		Refresh:    "wait_for",
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return nil, fmt.Errorf("failed to update playbook: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to update playbook: %s - %s", res.Status(), string(body))
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbook.Id,
		"playbookName": playbook.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       playbook.UserId,
	}).Info("Playbook updated")

	// Return the updated playbook
	return store.GetPlaybook(ctx, playbook.Id)
}

func (store *ElasticPlaybookstore) DeletePlaybook(ctx context.Context, playbookId string) error {
	logger := log.FromContext(ctx)

	if err := store.server.CheckAuthorized(ctx, "write", "playbooks"); err != nil {
		return err
	}

	// Get existing playbook
	existing, err := store.GetPlaybook(ctx, playbookId)
	if err != nil {
		return err
	}

	// Cannot delete community playbooks
	if existing.IsCommunity {
		return errors.New("cannot delete community playbooks")
	}

	// Delete from Elasticsearch
	req := esapi.DeleteRequest{
		Index:      store.index,
		DocumentID: playbookId,
		Refresh:    "wait_for",
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return fmt.Errorf("failed to delete playbook: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("failed to delete playbook: %s - %s", res.Status(), string(body))
	}

	logger.WithFields(log.Fields{
		"playbookId":   playbookId,
		"playbookName": existing.Name,
		"requestId":    ctx.Value(web.ContextKeyRequestId),
		"userId":       ctx.Value(web.ContextKeyRequestorId),
	}).Info("Playbook deleted")

	return nil
}

func (store *ElasticPlaybookstore) GetPlaybook(ctx context.Context, playbookId string) (*model.Playbook, error) {
	if err := store.server.CheckAuthorized(ctx, "read", "playbooks"); err != nil {
		return nil, err
	}

	req := esapi.GetRequest{
		Index:      store.index,
		DocumentID: playbookId,
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		return nil, fmt.Errorf("playbook not found: %s", playbookId)
	}

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to get playbook: %s - %s", res.Status(), string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	source, ok := result["_source"].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid response format")
	}

	return store.convertFromDocument(source)
}

func (store *ElasticPlaybookstore) GetAllPlaybooks(ctx context.Context) ([]*model.Playbook, error) {
	if err := store.server.CheckAuthorized(ctx, "read", "playbooks"); err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"term": map[string]interface{}{
							store.schemaPrefix + "kind": PLAYBOOK_KIND,
						},
					},
				},
			},
		},
		"size": 10000,
		"sort": []map[string]interface{}{
			{
				store.schemaPrefix + "playbook.name": map[string]interface{}{
					"order": "asc",
				},
			},
		},
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req := esapi.SearchRequest{
		Index: []string{store.index},
		Body:  bytes.NewReader(queryBytes),
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return nil, fmt.Errorf("failed to search playbooks: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to search playbooks: %s - %s", res.Status(), string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	playbooks := []*model.Playbook{}

	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return playbooks, nil
	}

	hitsList, ok := hits["hits"].([]interface{})
	if !ok {
		return playbooks, nil
	}

	for _, hit := range hitsList {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}

		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		pb, err := store.convertFromDocument(source)
		if err != nil {
			log.WithError(err).Warn("failed to convert playbook from document")
			continue
		}

		playbooks = append(playbooks, pb)
	}

	return playbooks, nil
}

func (store *ElasticPlaybookstore) GetCustomPlaybooksForDetection(ctx context.Context, detectionId string, detectCategory string, detectEngine model.EngineName) ([]*model.Playbook, error) {
	if err := store.server.CheckAuthorized(ctx, "read", "playbooks"); err != nil {
		return nil, err
	}

	// Build query to match by detection ID, category, or engine type
	shouldClauses := []map[string]interface{}{}

	if detectionId != "" {
		shouldClauses = append(shouldClauses, map[string]interface{}{
			"term": map[string]interface{}{
				store.schemaPrefix + "playbook.detection_id": strings.ToLower(detectionId),
			},
		})
	}

	if detectCategory != "" {
		shouldClauses = append(shouldClauses, map[string]interface{}{
			"term": map[string]interface{}{
				store.schemaPrefix + "playbook.detection_category": strings.ToLower(detectCategory),
			},
		})
	}

	// Map engine to detection type
	var detectType string
	switch detectEngine {
	case model.EngineNameElastAlert:
		detectType = "sigma"
	case model.EngineNameStrelka:
		detectType = "yara"
	case model.EngineNameSuricata:
		detectType = "nids"
	}

	if detectType != "" {
		shouldClauses = append(shouldClauses, map[string]interface{}{
			"term": map[string]interface{}{
				store.schemaPrefix + "playbook.detection_type": detectType,
			},
		})
	}

	if len(shouldClauses) == 0 {
		return []*model.Playbook{}, nil
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"term": map[string]interface{}{
							store.schemaPrefix + "kind": PLAYBOOK_KIND,
						},
					},
				},
				"should":               shouldClauses,
				"minimum_should_match": 1,
			},
		},
		"size": 100,
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req := esapi.SearchRequest{
		Index: []string{store.index},
		Body:  bytes.NewReader(queryBytes),
	}

	res, err := req.Do(ctx, store.esClient)
	if err != nil {
		return nil, fmt.Errorf("failed to search playbooks: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("failed to search playbooks: %s - %s", res.Status(), string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	playbooks := []*model.Playbook{}

	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return playbooks, nil
	}

	hitsList, ok := hits["hits"].([]interface{})
	if !ok {
		return playbooks, nil
	}

	for _, hit := range hitsList {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}

		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		pb, err := store.convertFromDocument(source)
		if err != nil {
			log.WithError(err).Warn("failed to convert playbook from document")
			continue
		}

		playbooks = append(playbooks, pb)
	}

	return playbooks, nil
}

func (store *ElasticPlaybookstore) convertToDocument(pb *model.Playbook) map[string]interface{} {
	doc := map[string]interface{}{
		store.schemaPrefix + "kind": PLAYBOOK_KIND,
		store.schemaPrefix + "playbook": map[string]interface{}{
			"id":                 pb.Id,
			"name":               pb.Name,
			"description":        pb.Description,
			"detection_id":       strings.ToLower(pb.DetectionId),
			"detection_category": strings.ToLower(pb.DetectionCategory),
			"detection_type":     strings.ToLower(pb.DetectionType),
			"contributors":       pb.Contributors,
			"questions":          pb.Questions,
			"isCommunity":        pb.IsCommunity,
			"ruleset":            pb.Ruleset,
			"createTime":         pb.CreateTime,
			"updateTime":         pb.UpdateTime,
			"userId":             pb.UserId,
		},
	}
	return doc
}

func (store *ElasticPlaybookstore) convertFromDocument(source map[string]interface{}) (*model.Playbook, error) {
	pbData, ok := source[store.schemaPrefix+"playbook"].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid playbook document format")
	}

	pb := &model.Playbook{}

	if id, ok := pbData["id"].(string); ok {
		pb.Id = id
	}
	if name, ok := pbData["name"].(string); ok {
		pb.Name = name
	}
	if desc, ok := pbData["description"].(string); ok {
		pb.Description = desc
	}
	if detId, ok := pbData["detection_id"].(string); ok {
		pb.DetectionId = detId
	}
	if detCat, ok := pbData["detection_category"].(string); ok {
		pb.DetectionCategory = detCat
	}
	if detType, ok := pbData["detection_type"].(string); ok {
		pb.DetectionType = detType
	}
	if isCommunity, ok := pbData["isCommunity"].(bool); ok {
		pb.IsCommunity = isCommunity
	}
	if ruleset, ok := pbData["ruleset"].(string); ok {
		pb.Ruleset = ruleset
	}
	if userId, ok := pbData["userId"].(string); ok {
		pb.UserId = userId
	}

	// Parse contributors
	if contribs, ok := pbData["contributors"].([]interface{}); ok {
		for _, c := range contribs {
			if s, ok := c.(string); ok {
				pb.Contributors = append(pb.Contributors, s)
			}
		}
	}

	// Parse timestamps
	if createTime, ok := pbData["createTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, createTime); err == nil {
			pb.CreateTime = &t
		}
	}
	if updateTime, ok := pbData["updateTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, updateTime); err == nil {
			pb.UpdateTime = &t
		}
	}

	// Parse questions
	if questions, ok := pbData["questions"].([]interface{}); ok {
		for _, q := range questions {
			qMap, ok := q.(map[string]interface{})
			if !ok {
				continue
			}

			question := &model.Question{}
			if qText, ok := qMap["question"].(string); ok {
				question.Question = qText
			}
			if context, ok := qMap["context"].(string); ok {
				question.Context = context
			}
			if rangeVal, ok := qMap["range"].(string); ok {
				question.Range = &rangeVal
			}
			if query, ok := qMap["query"].(string); ok {
				question.Query = query
			}

			// Parse answer sources
			if sources, ok := qMap["answer_sources"].([]interface{}); ok {
				for _, s := range sources {
					if str, ok := s.(string); ok {
						question.AnswerSources = append(question.AnswerSources, str)
					}
				}
			}

			pb.Questions = append(pb.Questions, question)
		}
	}

	return pb, nil
}
