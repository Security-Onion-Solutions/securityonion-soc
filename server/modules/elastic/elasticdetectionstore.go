// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/tidwall/gjson"
)

type ElasticDetectionstore struct {
	server          *server.Server
	esClient        *elasticsearch.Client
	index           string
	auditIndex      string
	maxAssociations int
	schemaPrefix    string
	maxLogLength    int
}

func NewElasticDetectionstore(srv *server.Server, client *elasticsearch.Client, maxLogLength int) *ElasticDetectionstore {
	return &ElasticDetectionstore{
		server:       srv,
		esClient:     client,
		maxLogLength: maxLogLength,
	}
}

func (store *ElasticDetectionstore) Init(index string, auditIndex string, maxAssociations int, schemaPrefix string) error {
	store.index = index
	store.auditIndex = auditIndex
	store.maxAssociations = maxAssociations
	store.schemaPrefix = schemaPrefix

	return nil
}

func (store *ElasticDetectionstore) validateId(id string, label string) error {
	var err error

	isValidId := regexp.MustCompile(`^[A-Za-z0-9-_]{5,50}$`).MatchString
	if !isValidId(id) {
		err = fmt.Errorf("invalid ID for %s", label)
	}

	return err
}

func (store *ElasticDetectionstore) validateString(str string, max int, label string) error {
	return store.validateStringRequired(str, 0, max, label)
}

func (store *ElasticDetectionstore) validateStringRequired(str string, min int, max int, label string) error {
	var err error

	length := len(str)
	if length > max {
		err = errors.New(fmt.Sprintf("%s is too long (%d/%d)", label, length, max))
	} else if length < min {
		err = errors.New(fmt.Sprintf("%s is too short (%d/%d)", label, length, min))
	}

	return err
}

func (store *ElasticDetectionstore) validateDetection(detect *model.Detection) error {
	var err error

	if err == nil && detect.Id != "" {
		err = store.validateId(detect.Id, "Id")
	}

	if err == nil && detect.PublicID != "" {
		err = store.validateId(detect.PublicID, "publicId")
	}

	if err == nil && detect.Title != "" {
		err = store.validateString(detect.Title, LONG_STRING_MAX, "title")
	}

	if err == nil && detect.Severity != "" {
		err = store.validateString(string(detect.Severity), SHORT_STRING_MAX, "severity")
	}

	if err == nil && detect.Author != "" {
		err = store.validateString(detect.Author, SHORT_STRING_MAX, "author")
	}

	if err == nil && detect.Description != "" {
		err = store.validateString(detect.Description, LONG_STRING_MAX, "description")
	}

	if err == nil && detect.Content != "" {
		err = store.validateString(detect.Content, LONG_STRING_MAX, "content")
	}

	if err == nil && detect.IsCommunity && detect.Ruleset == nil {
		err = store.validateStringRequired(*detect.Ruleset, 0, SHORT_STRING_MAX, "ruleset")
	}

	if err == nil && len(detect.Tags) > 0 {
		for _, tag := range detect.Tags {
			err = store.validateString(tag, SHORT_STRING_MAX, "tag")
			if err != nil {
				break
			}
		}
	}

	if err == nil {
		_, okEngine := model.EnginesByName[detect.Engine]
		if !okEngine {
			err = errors.New("invalid engine")
		}
	}

	if err == nil {
		_, okLang := model.SupportedLanguages[model.SigLanguage(detect.Language)]
		if !okLang {
			err = errors.New("invalid language")
		}
	}

	return err
}

func (store *ElasticDetectionstore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
	var results *model.EventIndexResults
	var err error

	// if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
	document := convertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err = store.server.Eventstore.Index(ctx, store.index, document, id)
	if err == nil {
		document[store.schemaPrefix+AUDIT_DOC_ID] = results.DocumentId

		if id == "" {
			document[store.schemaPrefix+"operation"] = "create"
		} else {
			document[store.schemaPrefix+"operation"] = "update"
		}

		_, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
		if err != nil {
			log.WithFields(log.Fields{
				"documentId": results.DocumentId,
				"kind":       kind,
			}).WithError(err).Error("Object indexed successfully however audit record failed to index")
		}
	}
	// }

	return results, err
}

func (store *ElasticDetectionstore) delete(ctx context.Context, obj interface{}, kind string, id string) error {
	var err error

	// if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
	err = store.server.Eventstore.Delete(ctx, store.index, id)
	if err == nil {
		document := convertObjectToDocumentMap(kind, obj, store.schemaPrefix)
		document[store.schemaPrefix+AUDIT_DOC_ID] = id
		document[store.schemaPrefix+"kind"] = kind
		document[store.schemaPrefix+"operation"] = "delete"

		_, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
		if err != nil {
			log.WithFields(log.Fields{
				"documentId": id,
				"kind":       kind,
			}).WithError(err).Error("Object deleted successfully however audit record failed to index")
		}
	}
	// }

	return err
}

func (store *ElasticDetectionstore) get(ctx context.Context, id string, kind string) (interface{}, error) {
	query := fmt.Sprintf(`_index:"%s" AND %skind:"%s" AND _id:"%s"`, store.index, store.schemaPrefix, kind, id)

	objects, err := store.Query(ctx, query, 1)
	if err == nil {
		if len(objects) > 0 {
			return objects[0], err
		}

		err = errors.New("Object not found")
	}

	return nil, err
}

func (store *ElasticDetectionstore) Query(ctx context.Context, query string, max int) ([]interface{}, error) {
	var err error
	var objects []interface{}

	// if err = store.server.CheckAuthorized(ctx, "read", "cases"); err == nil {
	criteria := model.NewEventSearchCriteria()
	format := "2006-01-02 3:04:05 PM"

	var zeroTime time.Time

	zeroTimeStr := zeroTime.Format(format)
	now := time.Now()
	endTime := now.Format(format)
	zone := now.Location().String()

	unlimited := false
	if max == -1 {
		max = 10000
		unlimited = true
	}

	sort := []interface{}{}

	for {
		err = criteria.Populate(query,
			zeroTimeStr+" - "+endTime, // timeframe range
			format,                    // timeframe format
			zone,                      // timezone
			"0",                       // no metrics
			strconv.Itoa(max))

		if err != nil {
			return nil, err
		}

		if unlimited {
			// need a deterministic sort order for paging
			criteria.SortFields = []*model.SortCriteria{
				{
					Field: "@timestamp",
					Order: "desc",
				},
			}

			if len(sort) != 0 {
				criteria.SearchAfter = sort
			}
		}

		var results *model.EventSearchResults

		results, err = store.server.Eventstore.Search(ctx, criteria)
		if err != nil {
			return nil, err
		}

		for _, event := range results.Events {
			var obj interface{}

			obj, err = convertElasticEventToObject(event, store.schemaPrefix)
			if err == nil {
				objects = append(objects, obj)
			} else {
				log.WithField("event", event).WithError(err).Error("Unable to convert case object")
			}
		}

		if !unlimited || len(results.Events) == 0 {
			break
		}

		sort = results.Events[len(results.Events)-1].Sort
	}

	// }

	return objects, err
}

func (store *ElasticDetectionstore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
	obj.UserId = ctx.Value(web.ContextKeyRequestorId).(string)

	// Don't waste space by saving the these values which are already part of ES documents
	id := obj.Id
	obj.Id = ""
	obj.UpdateTime = nil

	return id
}

func (store *ElasticDetectionstore) CreateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	var err error

	err = store.validateDetection(detect)
	if err != nil {
		return nil, err
	}

	if detect.Id != "" {
		return nil, errors.New("Unexpected ID found in new comment")
	}

	now := time.Now()
	detect.CreateTime = &now

	var results *model.EventIndexResults

	results, err = store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
	if err == nil {
		// Read object back to get new modify date, etc
		detect, err = store.GetDetection(ctx, results.DocumentId)
	}

	return detect, err
}

func (store *ElasticDetectionstore) GetDetection(ctx context.Context, detectId string) (detect *model.Detection, err error) {
	err = store.validateId(detectId, "detectId")
	if err != nil {
		return nil, err
	}

	obj, err := store.get(ctx, detectId, "detection")
	if err == nil && obj != nil {
		detect = obj.(*model.Detection)
	}

	return detect, err
}

func (store *ElasticDetectionstore) UpdateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	err := store.validateDetection(detect)
	if err != nil {
		return nil, err
	}

	if detect.Id == "" {
		err = errors.New("Missing detection onion ID")
		return nil, err
	}

	var old *model.Detection

	old, err = store.GetDetection(ctx, detect.Id)
	if err != nil {
		return nil, err
	}

	var results *model.EventIndexResults

	// Preserve read-only fields
	detect.CreateTime = old.CreateTime

	results, err = store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
	if err != nil {
		return nil, err
	}

	// Read object back to get new modify date, etc
	return store.GetDetection(ctx, results.DocumentId)
}

func (store *ElasticDetectionstore) UpdateDetectionField(ctx context.Context, id string, fields map[string]interface{}) (*model.Detection, error) {
	if len(fields) == 0 {
		return nil, errors.New("no fields to update")
	}

	unQtemplate := `ctx._source.%s=%v`
	Qtemplate := `ctx._source.%s='%v'`

	lines := make([]string, 0, len(fields)+1)

	for field, value := range fields {
		switch strings.ToLower(field) {
		case "isenabled":
			newField := store.schemaPrefix + "detection.isEnabled"
			lines = append(lines, fmt.Sprintf(unQtemplate, newField, value))
		default:
			return nil, fmt.Errorf("unsupported field: %s", field)
		}
	}

	lines = append(lines, fmt.Sprintf(Qtemplate, store.schemaPrefix+"detection.userId", ctx.Value(web.ContextKeyRequestorId).(string)))

	opts := []func(*esapi.UpdateRequest){
		store.esClient.Update.WithContext(ctx),
		store.esClient.Update.WithSource("true"),
	}

	script := strings.Join(lines, "; ")

	res, err := store.esClient.Update("so-detection", id, strings.NewReader(fmt.Sprintf(`{"script": "%s"}`, script)), opts...)
	if err != nil {
		return nil, err
	}

	if res.IsError() {
		return nil, fmt.Errorf("update error: %s", res.String())
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	det := &model.Detection{}

	rawDet := gjson.Get(string(raw), "get._source.so_detection").Raw

	err = json.Unmarshal([]byte(rawDet), det)
	if err != nil {
		return nil, err
	}

	document := convertObjectToDocumentMap("detection", json.RawMessage(rawDet), store.schemaPrefix)
	document[store.schemaPrefix+AUDIT_DOC_ID] = id
	document[store.schemaPrefix+"kind"] = "detection"
	document[store.schemaPrefix+"operation"] = "update"

	err = store.audit(ctx, document, id)
	if err != nil {
		log.WithFields(log.Fields{
			"documentId": id,
			"kind":       "detection",
		}).WithError(err).Error("Detection updated successfully however audit record failed to index")
	}

	return det, nil
}

func (store *ElasticDetectionstore) DeleteDetection(ctx context.Context, onionID string) (*model.Detection, error) {
	detect, err := store.GetDetection(ctx, onionID)
	if err != nil {
		return nil, err
	}

	err = store.delete(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))

	return detect, err
}

func (store *ElasticDetectionstore) GetAllCommunitySIDs(ctx context.Context, engine *model.EngineName) (map[string]*model.Detection, error) {
	query := fmt.Sprintf(`_index:"%s" AND %skind:"%s"`, store.index, store.schemaPrefix, "detection")
	if engine != nil {
		query += fmt.Sprintf(` AND %sdetection.engine:"%s"`, store.schemaPrefix, *engine)
	}

	all, err := store.Query(ctx, query, -1)
	if err != nil {
		return nil, err
	}

	sids := map[string]*model.Detection{}
	for _, det := range all {
		detection := det.(*model.Detection)
		sids[detection.PublicID] = detection
	}

	return sids, nil
}

func (store *ElasticDetectionstore) GetDetectionHistory(ctx context.Context, detectID string) ([]interface{}, error) {
	query := fmt.Sprintf(`_index:"%s" AND %s%s:"%s" | sortby @timestamp^`, store.auditIndex, store.schemaPrefix, AUDIT_DOC_ID, detectID)
	history, err := store.Query(ctx, query, store.maxAssociations)

	return history, err
}

func (store *ElasticDetectionstore) audit(ctx context.Context, document map[string]interface{}, id string) error {
	var err error

	// TODO: Rethink permissions here
	// if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
	// store.refreshCache(ctx)

	var request string
	request, err = convertToElasticIndexRequest(nil, document)
	if err == nil {
		log.Debug("Sending index request to primary Elasticsearch client")
		_, err = store.indexDocument(ctx, store.disableCrossClusterIndex(store.auditIndex), request, id)
		if err != nil {
			log.WithError(err).Error("Encountered error while indexing document into elasticsearch")
		}
	}
	// }
	return err
}

func (store *ElasticDetectionstore) indexDocument(ctx context.Context, index string, document string, id string) (string, error) {
	log.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"document":  store.truncate(document),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Adding document to Elasticsearch")

	res, err := store.esClient.Index(index,
		strings.NewReader(document),
		store.esClient.Index.WithRefresh("true"),
		store.esClient.Index.WithDocumentID(id),
		store.esClient.Index.WithContext(ctx),
	)

	if err != nil {
		log.WithError(err).Error("Unable to index document into Elasticsearch")
		return "", err
	}
	defer res.Body.Close()
	json, err := store.readJsonFromResponse(res)

	log.WithFields(log.Fields{
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Index new document finished")
	return json, err
}

func (store *ElasticDetectionstore) truncate(input string) string {
	if len(input) > store.maxLogLength {
		return input[:store.maxLogLength] + "..."
	}
	return input
}

func (store *ElasticDetectionstore) disableCrossClusterIndex(index string) string {
	pieces := strings.SplitN(index, ":", 2)
	if len(pieces) == 2 {
		index = pieces[1]
	}
	return index
}

func (store *ElasticDetectionstore) readErrorFromJson(json string) error {
	errorType := gjson.Get(json, "error.type").String()
	errorReason := gjson.Get(json, "error.reason").String()
	errorDetails := json
	if len(json) > MAX_ERROR_LENGTH {
		errorDetails = json[0:MAX_ERROR_LENGTH]
	}
	err := errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
	return err
}

func (store *ElasticDetectionstore) readJsonFromResponse(res *esapi.Response) (string, error) {
	var err error
	var b bytes.Buffer
	b.ReadFrom(res.Body)
	json := b.String()
	if res.IsError() {
		err = store.readErrorFromJson(json)
	}
	return json, err
}
