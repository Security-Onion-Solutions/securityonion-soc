// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
)

type ElasticDetectionstore struct {
	server                 *server.Server
	esClient               *elasticsearch.Client
	index                  string
	auditIndex             string
	maxAssociations        int
	schemaPrefix           string
	maxLogLength           int
	bulkIndexerWorkerCount int
}

func NewElasticDetectionstore(srv *server.Server, client *elasticsearch.Client, maxLogLength int) *ElasticDetectionstore {
	return &ElasticDetectionstore{
		server:       srv,
		esClient:     client,
		maxLogLength: maxLogLength,
	}
}

func (store *ElasticDetectionstore) Init(index string, auditIndex string, maxAssociations int, schemaPrefix string, bulkIndexerWorkerCount int) error {
	store.index = index
	store.auditIndex = auditIndex
	store.maxAssociations = maxAssociations
	store.schemaPrefix = schemaPrefix
	if bulkIndexerWorkerCount > 0 {
		store.bulkIndexerWorkerCount = bulkIndexerWorkerCount
	} else {
		store.bulkIndexerWorkerCount = runtime.NumCPU()
	}

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

func (store *ElasticDetectionstore) validatePublicId(id string, label string) error {
	var err error

	isValidId := regexp.MustCompile(`^[A-Za-z0-9-_]{3,128}$`).MatchString
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

func (store *ElasticDetectionstore) validateStringArray(array []string, maxLen int, maxElements int, label string) error {
	var err error
	length := len(array)
	if length > maxElements {
		err = errors.New(fmt.Sprintf("Field '%s' contains excessive elements (%d/%d)", label, length, maxElements))
	} else {
		for idx, tag := range array {
			err = store.validateString(tag, maxLen, fmt.Sprintf("Tag[%d]", idx))
			if err != nil {
				break
			}
		}
	}
	return err
}

func (store *ElasticDetectionstore) validateDetection(detect *model.Detection) error {
	var err error

	if detect.Id != "" {
		err = store.validateId(detect.Id, "Id")
	}

	if err == nil && detect.PublicID != "" {
		err = store.validatePublicId(detect.PublicID, "publicId")
	}

	if err == nil && detect.Title != "" {
		err = store.validateString(detect.Title, LONG_STRING_MAX, "title")
	}

	if err == nil && detect.Severity != "" {
		err = store.validateString(string(detect.Severity), SHORT_STRING_MAX, "severity")
	}

	if err == nil && detect.Author != "" {
		err = store.validateString(detect.Author, MAX_AUTHOR_LENGTH, "author")
	}

	if err == nil && detect.Description != "" {
		err = store.validateString(detect.Description, LONG_STRING_MAX, "description")
	}

	if err == nil && detect.Content != "" {
		err = store.validateString(detect.Content, LONG_STRING_MAX, "content")
	}

	if err == nil && detect.Ruleset != "" {
		err = store.validateStringRequired(detect.Ruleset, 0, SHORT_STRING_MAX, "ruleset")
	}

	if err == nil && len(detect.Tags) != 0 {
		err = store.validateStringArray(detect.Tags, SHORT_STRING_MAX, MAX_ARRAY_ELEMENTS, "Tags")
	}

	if err == nil {
		engine, okEngine := model.EnginesByName[detect.Engine]
		if !okEngine {
			err = errors.New("invalid engine")
		}

		if err == nil {
			_, okLang := model.SupportedLanguages[model.SigLanguage(detect.Language)]
			if !okLang {
				err = errors.New("invalid language")
			} else {
				if engine.SigLanguage != model.SigLanguage(detect.Language) {
					err = errors.New("engine and language mismatch")
				}
			}
		}
	}

	if err == nil && len(detect.Kind) > 0 {
		err = errors.New("Field 'Kind' must not be specified")
	}

	if err == nil && len(detect.Operation) > 0 {
		err = errors.New("Field 'Operation' must not be specified")
	}

	return err
}

func (store *ElasticDetectionstore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
	if err := store.server.CheckAuthorized(ctx, "write", "detections"); err != nil {
		return nil, err
	}

	skipAudit := modcontext.ReadSkipAudit(ctx)

	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+"kind"] = kind

	results, err := store.Index(ctx, store.index, document, id)
	if err == nil && !skipAudit {
		document[store.schemaPrefix+AUDIT_DOC_ID] = results.DocumentId

		if id == "" {
			document[store.schemaPrefix+"operation"] = "create"
		} else {
			document[store.schemaPrefix+"operation"] = "update"
		}

		_, err = store.Index(ctx, store.auditIndex, document, "")
		if err != nil {
			log.WithFields(log.Fields{
				"documentId":   results.DocumentId,
				"documentKind": kind,
			}).WithError(err).Error("Object indexed successfully however audit record failed to index")
		}
	}

	return results, err
}

func (store *ElasticDetectionstore) Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error) {
	results := model.NewEventIndexResults()

	request, err := convertToElasticIndexRequest(document)
	if err == nil {
		var response string

		log.Debug("Sending index request to primary Elasticsearch client")
		response, err = store.indexDocument(ctx, store.disableCrossClusterIndex(index), request, id)
		if err == nil {
			err = convertFromElasticIndexResults(response, results)
			if err != nil {
				log.WithError(err).Error("Encountered error while converting document index results")
			}
		} else {
			log.WithError(err).Error("Encountered error while indexing document into elasticsearch")
		}
	}

	return results, err
}

func (store *ElasticDetectionstore) deleteDocument(ctx context.Context, index string, obj interface{}, kind string, id string) (string, error) {
	err := store.server.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return "", err
	}

	log.WithFields(log.Fields{
		"deleteIndex": index,
		"documentId":  id,
		"requestId":   ctx.Value(web.ContextKeyRequestId),
	}).Debug("Deleting document from Elasticsearch")

	res, err := store.esClient.Delete(transformIndex(index), id, store.esClient.Delete.WithContext(ctx))

	if err != nil {
		log.WithFields(log.Fields{
			"deleteIndex": index,
			"documentId":  id,
			"requestId":   ctx.Value(web.ContextKeyRequestId),
		}).WithError(err).Error("Unable to delete document from Elasticsearch")
		return "", err
	}
	defer res.Body.Close()

	document := ConvertObjectToDocumentMap(kind, obj, store.schemaPrefix)
	document[store.schemaPrefix+AUDIT_DOC_ID] = id
	document[store.schemaPrefix+"kind"] = kind
	document[store.schemaPrefix+"operation"] = "delete"
	err = store.audit(ctx, document, id)
	if err != nil {
		log.WithFields(log.Fields{
			"documentId":    id,
			"detectionKind": kind,
		}).WithError(err).Error("Object deleted successfully however audit record failed to index")
	}

	json, err := readJsonFromResponse(res)

	log.WithFields(log.Fields{
		"deleteIndex": index,
		"documentId":  id,
		"response":    store.truncate(json),
		"requestId":   ctx.Value(web.ContextKeyRequestId),
	}).Debug("Delete document finished")
	return json, err
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

func (store *ElasticDetectionstore) getAll(ctx context.Context, query string, max int) ([]interface{}, error) {
	criteria := model.NewEventSearchCriteria()
	format := "2006-01-02 3:04:05 PM"

	var zeroTime time.Time
	zeroTimeStr := zeroTime.Format(format)
	now := time.Now()
	endTime := now.Format(format)
	zone := now.Location().String()

	err := criteria.Populate(query,
		zeroTimeStr+" - "+endTime, // timeframe range
		format,                    // timeframe format
		zone,                      // timezone
		"0",                       // no metrics
		strconv.Itoa(max))
	if err != nil {
		return nil, err
	}

	results, err := store.DetectionSearch(ctx, criteria)
	if err != nil {
		return nil, err
	}

	objects := make([]interface{}, 0, len(results.Events))

	for _, event := range results.Events {
		obj, err := convertElasticEventToObject(event, store.schemaPrefix)
		if err != nil {
			log.WithField("returnedEvent", event).WithError(err).Error("Unable to convert detection object")
			continue
		}

		objects = append(objects, obj)
	}

	return objects, err
}

func (store *ElasticDetectionstore) Query(ctx context.Context, query string, max int) ([]interface{}, error) {
	var objects []interface{}

	err := store.server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		return nil, err
	}

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

	var results *model.EventSearchResults

	if unlimited {
		criteria := model.NewEventScrollCriteria()
		criteria.RawQuery = query
		criteria.ParsedQuery.Parse(query)

		scrollResults, err := store.DetectionScroll(ctx, criteria)
		if err != nil {
			return nil, err
		}

		results = &model.EventSearchResults{
			Events: scrollResults.Events,
		}
	} else {
		criteria := model.NewEventSearchCriteria()
		err = criteria.Populate(query,
			zeroTimeStr+" - "+endTime, // timeframe range
			format,                    // timeframe format
			zone,                      // timezone
			"0",                       // no metrics
			strconv.Itoa(max))

		if err != nil {
			return nil, err
		}

		results, err = store.DetectionSearch(ctx, criteria)
		if err != nil {
			return nil, err
		}
	}

	for _, event := range results.Events {
		var obj interface{}

		obj, err = convertElasticEventToObject(event, store.schemaPrefix)
		if err == nil {
			objects = append(objects, obj)
		} else {
			log.WithField("returnedEvent", event).WithError(err).Error("Unable to convert case object")
		}
	}

	return objects, err
}

func (store *ElasticDetectionstore) DetectionSearch(ctx context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	err := store.server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		return nil, err
	}

	return store.server.Eventstore.Search(ctx, criteria)
}

func (store *ElasticDetectionstore) DetectionScroll(ctx context.Context, criteria *model.EventScrollCriteria) (*model.EventScrollResults, error) {
	err := store.server.CheckAuthorized(ctx, "read", "detections")
	if err != nil {
		return nil, err
	}

	return store.server.Eventstore.Scroll(ctx, criteria, []string{store.index})
}

func (store *ElasticDetectionstore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
	obj.UserId, _ = ctx.Value(web.ContextKeyRequestorId).(string)

	// Don't waste space by saving the these values which are already part of ES documents
	id := obj.Id
	obj.Id = ""
	obj.UpdateTime = nil

	return id
}

func (store *ElasticDetectionstore) DoesTemplateExist(ctx context.Context, tmpl string) (bool, error) {
	response, err := store.esClient.Indices.GetIndexTemplate(
		store.esClient.Indices.GetIndexTemplate.WithName(tmpl),
	)
	if err != nil {
		return false, err
	}

	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

func (store *ElasticDetectionstore) CreateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	err := store.validateDetection(detect)
	if err != nil {
		return nil, err
	}

	if detect.Id != "" {
		return nil, errors.New("Unexpected ID found in new comment")
	}

	if detect.PublicID != "" {
		duplicates, err := store.getAll(ctx, fmt.Sprintf(`_index:"%s" AND %skind:"%s" AND %sdetection.publicId:"%s" AND %sdetection.engine:"%s"`, store.index, store.schemaPrefix, "detection", store.schemaPrefix, detect.PublicID, store.schemaPrefix, detect.Engine), 1)
		if err != nil {
			return nil, err
		}

		if len(duplicates) > 0 {
			return nil, errors.New("publicId already exists for this engine")
		}
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

func (store *ElasticDetectionstore) GetDetectionByPublicId(ctx context.Context, publicId string) (detect *model.Detection, err error) {
	err = store.validatePublicId(publicId, "publicId")
	if err != nil {
		return nil, err
	}

	obj, err := store.Query(ctx, fmt.Sprintf(`_index:"%s" AND %skind:"detection" AND %sdetection.publicId:"%s"`, store.index, store.schemaPrefix, store.schemaPrefix, publicId), 1)
	if err == nil && len(obj) > 0 {
		detect = obj[0].(*model.Detection)
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

	// prepareForSave clears Id creating a side effect for the caller
	id := detect.Id
	defer func() {
		detect.Id = id
	}()

	results, err := store.save(ctx, detect, "detection", store.prepareForSave(ctx, &detect.Auditable))
	if err != nil {
		return nil, err
	}

	// Read object back to get new modify date, etc
	return store.GetDetection(ctx, results.DocumentId)
}

func (store *ElasticDetectionstore) DeleteDetection(ctx context.Context, id string) (*model.Detection, error) {
	detect, err := store.GetDetection(ctx, id)
	if err != nil {
		return nil, err
	}

	_, err = store.deleteDocument(ctx, store.disableCrossClusterIndex(store.index), detect, "detection", id)

	if err == nil {
		log.WithFields(log.Fields{
			"ruleId":       id,
			"rulePublicId": detect.PublicID,
			"ruleName":     detect.Title,
			"requestId":    ctx.Value(web.ContextKeyRequestId),
			"userId":       ctx.Value(web.ContextKeyRequestorId).(string),
		}).Info("Detection deleted")
	}

	return detect, err
}

func (store *ElasticDetectionstore) GetAllDetections(ctx context.Context, opts ...model.GetAllOption) (map[string]*model.Detection, error) {
	query := fmt.Sprintf(`_index:"%s" AND %skind:"%s"`, store.index, store.schemaPrefix, "detection")

	for _, opt := range opts {
		query = opt(query, store.schemaPrefix)
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
	query := fmt.Sprintf(`_index:"%s" AND (%s%s:"%s" OR %sdetectioncomment.detectionId:"%s") | sortby @timestamp^`, store.auditIndex, store.schemaPrefix, AUDIT_DOC_ID, detectID, store.schemaPrefix, detectID)
	history, err := store.Query(ctx, query, store.maxAssociations)

	return history, err
}

func (store *ElasticDetectionstore) audit(ctx context.Context, document map[string]interface{}, id string) error {
	request, err := convertToElasticIndexRequest(document)
	if err == nil {
		log.Debug("Sending index request to primary Elasticsearch client")
		_, err = store.indexDocument(ctx, store.disableCrossClusterIndex(store.auditIndex), request, id)
		if err != nil {
			log.WithError(err).Error("Encountered error while indexing document into elasticsearch")
		}
	}

	return err
}

func (store *ElasticDetectionstore) indexDocument(ctx context.Context, index string, document string, id string) (string, error) {
	err := store.server.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return "", err
	}

	log.WithFields(log.Fields{
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
		log.WithError(err).Error("Unable to index document into Elasticsearch")
		return "", err
	}
	defer res.Body.Close()
	json, err := readJsonFromResponse(res)

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

func (store *ElasticDetectionstore) validateComment(comment *model.DetectionComment) error {
	var err error

	if comment.Id != "" {
		err = store.validateId(comment.Id, "commentId")
	}
	if err == nil && comment.DetectionId != "" {
		err = store.validateId(comment.DetectionId, "detectionId")
	}
	if err == nil && comment.UserId != "" {
		err = store.validateId(comment.UserId, "userId")
	}
	if err == nil && len(comment.Kind) > 0 {
		err = errors.New("Field 'Kind' must not be specified")
	}
	if err == nil && len(comment.Operation) > 0 {
		err = errors.New("Field 'Operation' must not be specified")
	}
	if err == nil {
		err = store.validateStringRequired(comment.Value, 1, LONG_STRING_MAX, "value")
	}

	return err
}

func (store *ElasticDetectionstore) CreateComment(ctx context.Context, comment *model.DetectionComment) (*model.DetectionComment, error) {
	err := store.validateComment(comment)
	if err != nil {
		return nil, err
	}

	if comment.Id != "" {
		return nil, errors.New("Unexpected ID found in new comment")
	}

	if comment.DetectionId == "" {
		return nil, errors.New("Missing Detection ID in new comment")
	}

	_, err = store.GetDetection(ctx, comment.DetectionId)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	comment.CreateTime = util.Ptr(now)

	results, err := store.save(ctx, comment, "detectioncomment", store.prepareForSave(ctx, &comment.Auditable))
	if err != nil {
		return nil, err
	}

	// Read object back to get new modify date, etc
	return store.GetComment(ctx, results.DocumentId)
}

func (store *ElasticDetectionstore) GetComment(ctx context.Context, commentId string) (*model.DetectionComment, error) {
	var comment *model.DetectionComment

	err := store.validateId(commentId, "commentId")
	if err != nil {
		return nil, err
	}

	obj, err := store.get(ctx, commentId, "detectioncomment")
	if err == nil {
		comment = obj.(*model.DetectionComment)
	}

	return comment, err
}

func (store *ElasticDetectionstore) GetComments(ctx context.Context, detectionId string) ([]*model.DetectionComment, error) {
	err := store.validateId(detectionId, "detectionId")
	if err != nil {
		return nil, err
	}

	comments := []*model.DetectionComment{}
	query := fmt.Sprintf(`_index:"%s" AND %skind:"detectioncomment" AND %sdetectioncomment.detectionId:"%s" | sortby %sdetectioncomment.createTime^`, store.index, store.schemaPrefix, store.schemaPrefix, detectionId, store.schemaPrefix)

	objects, err := store.getAll(ctx, query, store.maxAssociations)
	if err != nil {
		return nil, err
	}

	for _, obj := range objects {
		comments = append(comments, obj.(*model.DetectionComment))
	}

	return comments, err
}

func (store *ElasticDetectionstore) UpdateComment(ctx context.Context, comment *model.DetectionComment) (*model.DetectionComment, error) {
	err := store.validateComment(comment)
	if err != nil {
		return nil, err
	}

	if comment.Id == "" {
		return nil, errors.New("Missing comment ID")
	}

	old, err := store.GetComment(ctx, comment.Id)
	if err != nil {
		return nil, err
	}

	// Preserve read-only fields
	comment.CreateTime = old.CreateTime

	results, err := store.save(ctx, comment, "detectioncomment", store.prepareForSave(ctx, &comment.Auditable))
	if err != nil {
		return nil, err
	}

	// Read object back to get new modify date, etc
	return store.GetComment(ctx, results.DocumentId)
}

func (store *ElasticDetectionstore) DeleteComment(ctx context.Context, id string) error {
	dc, err := store.GetComment(ctx, id)
	if err != nil {
		return err
	}

	_, err = store.deleteDocument(ctx, store.disableCrossClusterIndex(store.index), dc, "detectioncomment", id)
	return err
}

func (store *ElasticDetectionstore) BuildBulkIndexer(ctx context.Context, logger *log.Entry) (esutil.BulkIndexer, error) {
	bulk, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:     store.esClient,
		Refresh:    "wait_for",
		NumWorkers: store.bulkIndexerWorkerCount,
		OnError: func(ctx context.Context, err error) {
			logger.WithError(err).Error("error during bulk import")
		},
	})

	return bulk, err
}

func (store *ElasticDetectionstore) ConvertObjectToDocument(ctx context.Context, kind string, obj any, auditable *model.Auditable, isEdit bool, auditDocId *string, op *string) (doc []byte, index string, err error) {
	if auditDocId == nil {
		index = "so-detection"
	} else {
		index = "so-detectionhistory"
	}

	id := auditable.Id

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

	auditable.Id = id

	return rawDoc, index, err
}
