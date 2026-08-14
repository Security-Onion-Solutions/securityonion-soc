// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/tidwall/gjson"
)

const (
	MAX_ERROR_LENGTH = 4096
	// ASYNC_UPDATE_MAX_WAIT bounds how long a single async update task will be watched before giving up.
	ASYNC_UPDATE_MAX_WAIT = 30 * time.Minute
	// ASYNC_UPDATE_POLL_TIMEOUT is how long each Tasks.Get call blocks server-side waiting for completion.
	ASYNC_UPDATE_POLL_TIMEOUT = 30 * time.Second
	ASYNC_UPDATE_PAUSE        = time.Second
	// ASYNC_UPDATE_MAX_ERRORS caps how many individual errors are broadcast to the client
	ASYNC_UPDATE_MAX_ERRORS = 5
)

type FieldDefinition struct {
	name         string
	fieldType    string
	aggregatable bool
	searchable   bool
}

type ElasticEventstore struct {
	server             *server.Server
	hostUrls           []string
	esClient           *elasticsearch.Client
	esRemoteClients    []*elasticsearch.Client
	esAllClients       []*elasticsearch.Client
	timeShiftMs        int
	defaultDurationMs  int
	esSearchOffsetMs   int
	timeoutMs          time.Duration
	index              string
	cacheMs            time.Duration
	cacheTime          time.Time
	cacheLock          sync.Mutex
	fieldDefs          map[string]*FieldDefinition
	intervals          int
	asyncThreshold     int
	maxLogLength       int
	lookupTunnelParent bool
	maxScrollSize      int
}

func NewElasticEventstore(srv *server.Server) *ElasticEventstore {
	return &ElasticEventstore{
		server:          srv,
		hostUrls:        make([]string, 0),
		esRemoteClients: make([]*elasticsearch.Client, 0),
		esAllClients:    make([]*elasticsearch.Client, 0),
	}
}

func (store *ElasticEventstore) Init(hostUrl string,
	remoteHosts []string,
	user string,
	pass string,
	verifyCert bool,
	timeShiftMs int,
	defaultDurationMs int,
	esSearchOffsetMs int,
	timeoutMs int,
	cacheMs int,
	index string,
	asyncThreshold int,
	intervals int,
	maxLogLength int,
	lookupTunnelParent bool,
	maxScrollSize int) error {
	store.timeShiftMs = timeShiftMs
	store.defaultDurationMs = defaultDurationMs
	store.esSearchOffsetMs = esSearchOffsetMs
	store.index = index
	store.asyncThreshold = asyncThreshold
	store.timeoutMs = time.Duration(timeoutMs) * time.Millisecond
	store.cacheMs = time.Duration(cacheMs) * time.Millisecond
	store.intervals = intervals
	store.maxLogLength = maxLogLength
	store.lookupTunnelParent = lookupTunnelParent
	store.maxScrollSize = maxScrollSize

	var err error
	store.esClient, err = store.makeEsClient(hostUrl, user, pass, verifyCert)
	if err == nil {
		store.hostUrls = append(store.hostUrls, hostUrl)
		store.esAllClients = append(store.esAllClients, store.esClient)
		for _, remoteHostUrl := range remoteHosts {
			client, err := store.makeEsClient(remoteHostUrl, user, pass, verifyCert)
			if err == nil {
				store.hostUrls = append(store.hostUrls, remoteHostUrl)
				store.esRemoteClients = append(store.esRemoteClients, client)
				store.esAllClients = append(store.esAllClients, client)
			} else {
				break
			}
		}
	}
	return err
}

func (store *ElasticEventstore) validateId(id string, label string) error {
	var err error
	isValidId := regexp.MustCompile(`^[A-Za-z0-9\-_]{3,128}$`).MatchString
	if !isValidId(id) {
		err = fmt.Errorf("invalid ID for %s", label)
	}
	return err
}

func (store *ElasticEventstore) truncate(input string) string {
	if len(input) > store.maxLogLength {
		return input[:store.maxLogLength] + "..."
	}
	return input
}

func (store *ElasticEventstore) makeEsClient(host string, user string, pass string, verifyCert bool) (*elasticsearch.Client, error) {
	var esClient *elasticsearch.Client

	hosts := make([]string, 1)
	hosts[0] = host
	esConfig := elasticsearch.Config{
		Addresses: hosts,
		Username:  user,
		Password:  pass,
		Transport: NewElasticTransport(user, pass, store.timeoutMs, verifyCert),
	}
	maskedPassword := "*****"
	if len(esConfig.Password) == 0 {
		maskedPassword = ""
	}

	esClient, err := elasticsearch.NewClient(esConfig)
	fields := log.Fields{
		"InsecureSkipVerify": !verifyCert,
		"HostUrl":            host,
		"Username":           esConfig.Username,
		"Password":           maskedPassword,
		"Index":              store.index,
		"TimeoutMs":          store.timeoutMs,
	}
	if err == nil {
		log.WithFields(fields).Info("Initialized Elasticsearch Client")
	} else {
		log.WithFields(fields).Error("Failed to initialize Elasticsearch Client")
		esClient = nil
	}
	return esClient, err
}

func mapElasticField(fieldDefs map[string]*FieldDefinition, field string) string {
	mappedField := fieldDefs[field]
	if mappedField != nil && !mappedField.aggregatable {
		keyword := field + ".keyword"
		mappedField = fieldDefs[keyword]
		if mappedField != nil && mappedField.aggregatable {
			field = keyword
		}
	}
	return field
}

func unmapElasticField(fieldDefs map[string]*FieldDefinition, field string) string {
	suffix := ".keyword"
	if strings.HasSuffix(field, suffix) {
		newField := strings.TrimSuffix(field, suffix)
		mappedField := fieldDefs[newField]
		if mappedField != nil && !mappedField.aggregatable {
			field = newField
		}
	}
	return field
}

func (store *ElasticEventstore) Search(ctx context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	err := store.server.CheckAuthorized(ctx, "read", "events")
	if err != nil {
		return nil, err
	}

	results := model.NewEventSearchResults()

	store.refreshCache(ctx)

	var query string
	query, err = convertToElasticRequest(store.fieldDefs, store.intervals, criteria)
	if err == nil {
		var response string
		response, err = store.luceneSearch(ctx, query)
		if err == nil {
			err = convertFromElasticResults(store.fieldDefs, response, results, criteria.AllowTimeout)
			results.Criteria = criteria
		}
	}

	results.Complete()

	return results, err
}

func (store *ElasticEventstore) MSearch(ctx context.Context, criteria []*model.EventMSearchCriteria) (results *model.EventMSearchResults, err error) {
	err = store.server.CheckAuthorized(ctx, "read", "events")
	if err != nil {
		return nil, err
	}

	results = model.NewEventMSearchResults()

	buf := bytes.Buffer{}
	for _, c := range criteria {
		indexes := c.Index
		if indexes == "" {
			indexes = store.index
		}

		header := map[string][]string{"index": strings.Split(indexes, ",")}
		headerJSON, _ := json.Marshal(header)
		buf.Write(headerJSON)
		buf.WriteString("\r\n")

		query, err := convertToElasticRequest(store.fieldDefs, store.intervals, &c.EventSearchCriteria)
		if err != nil {
			return results, err
		}

		buf.WriteString(query)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\n")

	response, err := store.esClient.Msearch(strings.NewReader(buf.String()), store.esClient.Msearch.WithContext(ctx))
	if err != nil {
		return results, err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return results, err
	}

	err = convertFromElasticMSearchResults(store.fieldDefs, string(body), criteria, results)

	return results, err
}

func (store *ElasticEventstore) Scroll(ctx context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error) {
	var err error
	var query, scrollId, jsonStr string
	finalResults := model.NewEventScrollResults()
	finalResults.Criteria = criteria

	store.refreshCache(ctx)

	logger := log.WithField("requestId", ctx.Value(web.ContextKeyRequestId))

	query, err = convertToElasticScrollRequest(store.fieldDefs, criteria, store.maxScrollSize)
	if err != nil {
		return nil, err
	}

	logger.WithFields(log.Fields{
		"scrollQuery": store.truncate(query),
	}).Info("scrolling Elasticsearch")

	if len(indexes) == 0 {
		indexes = strings.Split(store.index, ",")
	}

	var res *esapi.Response

	ops := []func(*esapi.SearchRequest){
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(indexes...),
		store.esClient.Search.WithBody(strings.NewReader(query)),
		store.esClient.Search.WithTrackTotalHits(true),
		store.esClient.Search.WithPretty(),
		store.esClient.Search.WithScroll(time.Minute),
		store.esClient.Search.WithIgnoreUnavailable(true),
	}

	if len(criteria.SortFields) != 0 {
		sorts := make([]string, 0, len(criteria.SortFields))
		for _, sortField := range criteria.SortFields {
			field := mapElasticField(store.fieldDefs, sortField.Field)
			if field != "" {
				sort := field + ":" + sortField.Order
				sorts = append(sorts, sort)
			}
		}

		if len(sorts) > 0 {
			ops = append(ops, store.esClient.Search.WithSort(sorts...))
		}
	}

	res, err = store.esClient.Search(ops...)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	jsonStr, err = readJsonFromResponse(res)
	if err == nil {
		batchNum := 0

		err = convertFromElasticScrollResults(store.fieldDefs, jsonStr, finalResults)
		if err != nil {
			finalResults.Complete()

			return finalResults, err
		}

		if len(finalResults.Events) == 0 && strings.Contains(query, "so_detection.engine") {
			// only 2 actions call this Scroll function: GetAllDetections used in
			// DetectionEngine Syncs, and Bulk Updates of Detections. If the query
			// contains a condition for the engine, then it's a GetAllDetections call
			logger.WithFields(log.Fields{
				"scrollQuery":      query,
				"fullJsonResponse": jsonStr,
			}).Info("scrolled for 0 results")
		}

		logger.WithFields(log.Fields{
			"batchNum": batchNum,
			"hitCount": len(finalResults.Events),
		}).Debug("scroll progress")

		scrollId = gjson.Get(jsonStr, "_scroll_id").String()

		lastPageCount := len(finalResults.Events)

		for {
			// Break out of the loop when there are no results or we have all the results
			if lastPageCount == 0 || len(finalResults.Events) >= finalResults.TotalEvents {
				logger.Debug("finished scrolling")
				break
			}

			batchNum++

			scrollBody := map[string]string{"scroll_id": scrollId}
			scrollJSON, _ := json.Marshal(scrollBody)
			res, err = store.esClient.Scroll(
				store.esClient.Scroll.WithContext(ctx),
				store.esClient.Scroll.WithScroll(time.Minute),
				store.esClient.Scroll.WithBody(bytes.NewReader(scrollJSON)),
			)
			if err != nil {
				break
			}

			defer res.Body.Close()

			jsonStr, err = readJsonFromResponse(res)
			if err != nil {
				break
			}

			results := model.NewEventScrollResults()

			err = convertFromElasticScrollResults(store.fieldDefs, jsonStr, results)
			if err != nil {
				break
			}

			finalResults.ElapsedMs += results.ElapsedMs
			finalResults.Events = append(finalResults.Events, results.Events...)

			scrollId = gjson.Get(jsonStr, "_scroll_id").String()
			lastPageCount = len(results.Events)

			logger.WithFields(log.Fields{
				"batchNum": batchNum,
				"hitCount": lastPageCount,
			}).Debug("scroll progress")
		}
	}

	finalResults.Complete()

	if scrollId != "" {
		scrollBody := map[string]string{"scroll_id": scrollId}
		scrollJSON, _ := json.Marshal(scrollBody)
		res, scrollErr := store.esClient.ClearScroll(
			store.esClient.ClearScroll.WithContext(ctx),
			store.esClient.ClearScroll.WithBody(bytes.NewReader(scrollJSON)),
		)
		if scrollErr != nil {
			logger.WithError(scrollErr).Warn("call to close scroll failed, scroll should self-close shortly")
		}

		if res != nil && res.IsError() && res.StatusCode != 404 {
			defer res.Body.Close()

			_, respErr := readJsonFromResponse(res)
			if respErr != nil {
				logger.WithError(respErr).Warn("error closing scroll, scroll should self-close shortly")
			}
		}
	}

	return finalResults, err
}

func (store *ElasticEventstore) disableCrossClusterIndex(index string) string {
	pieces := strings.SplitN(index, ":", 2)
	if len(pieces) == 2 {
		index = pieces[1]
	}
	return index
}

func (store *ElasticEventstore) disableCrossClusterIndexing(indexes []string) []string {
	for idx, index := range indexes {
		indexes[idx] = store.disableCrossClusterIndex(index)
	}
	return indexes
}

func (store *ElasticEventstore) Update(ctx context.Context, criteria *model.EventUpdateCriteria) (results *model.EventUpdateResults, err error) {
	logger := log.FromContext(ctx)

	results = model.NewEventUpdateResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		store.refreshCache(ctx)

		results.Criteria = criteria
		var query string
		query, err = convertToElasticUpdateRequest(store, criteria)
		if err == nil {
			var response string
			var asyncTasks []asyncTaskRef

			for idx, client := range store.esAllClients {
				logger.WithField("clientHost", store.hostUrls[idx]).Debug("Sending request to client")
				response, err = store.updateDocuments(ctx, client, query, store.disableCrossClusterIndexing(strings.Split(store.index, ",")), !criteria.Asynchronous)
				if err == nil {
					if !criteria.Asynchronous {
						currentResults := model.NewEventUpdateResults()
						err = convertFromElasticUpdateResults(store, response, currentResults)
						if err == nil {
							results.AddEventUpdateResults(currentResults)
						} else {
							logger.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
							results.Errors = append(results.Errors, err.Error())
						}
					} else {
						// The update is running asynchronously; capture the node-specific task id
						// so a background goroutine can watch it to completion and report the outcome.
						taskId, taskErr := convertFromElasticAsyncUpdateResults(response)
						if taskErr == nil {
							asyncTasks = append(asyncTasks, asyncTaskRef{client: client, hostUrl: store.hostUrls[idx], taskId: taskId})
						} else {
							logger.WithError(taskErr).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while parsing asynchronous elasticsearch update response")
							results.Errors = append(results.Errors, taskErr.Error())
						}
					}
				} else {
					logger.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
					results.Errors = append(results.Errors, err.Error())
				}
			}

			if criteria.Asynchronous && len(asyncTasks) > 0 {
				// The returned task ids are the correlation tokens the client tracks (one per
				// host); the watcher polls every node's task and broadcasts a single aggregated
				// result carrying all of them.
				taskIds := make([]string, len(asyncTasks))
				for i, task := range asyncTasks {
					taskIds[i] = task.taskId
				}
				results.TaskIds = taskIds

				noTimeOutCtx := context.Background()
				val := ctx.Value(web.ContextKeyRunAsUsername)
				if val != nil {
					if username, ok := val.(string); ok {
						noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRunAsUsername, username)
					}
				}
				noTimeOutCtx = context.WithValue(noTimeOutCtx, web.ContextKeyRequestorId, ctx.Value(web.ContextKeyRequestorId).(string))
				noTimeOutCtx = log.NewContext(noTimeOutCtx, log.FromContext(ctx))

				go store.watchAsyncUpdate(noTimeOutCtx, asyncTasks, taskIds)
			}
		}

		if len(results.Errors) < len(store.esAllClients) {
			// Do not fail this request completely since some hosts succeeded.
			// The results.Errors property contains the list of errors.
			err = nil
		}
	}

	results.Complete()
	return results, err
}

func (store *ElasticEventstore) Index(ctx context.Context, index string, document map[string]interface{}, id string) (results *model.EventIndexResults, err error) {
	logger := log.FromContext(ctx)

	if id != "" {
		if err = store.validateId(id, "id"); err != nil {
			return nil, err
		}
	}

	results = model.NewEventIndexResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		store.refreshCache(ctx)

		var request string
		request, err = convertToElasticIndexRequest(document)
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
	}
	return results, err
}

func (store *ElasticEventstore) Delete(ctx context.Context, index string, id string) (err error) {
	logger := log.FromContext(ctx)

	if err = store.validateId(id, "id"); err != nil {
		return err
	}

	results := model.NewEventIndexResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		var response string
		logger.Debug("Sending delete request to primary Elasticsearch client")
		response, err = store.deleteDocument(ctx, store.disableCrossClusterIndex(index), id)
		if err == nil {
			err = convertFromElasticIndexResults(response, results)
			if err != nil {
				logger.WithError(err).Error("Encountered error while converting document index results")
			}
		} else {
			logger.WithError(err).Error("Encountered error while deleting document from elasticsearch")
		}
	}
	return err
}

func (store *ElasticEventstore) luceneSearch(ctx context.Context, query string) (string, error) {
	return store.indexSearch(ctx, query, strings.Split(store.index, ","))
}

func transformIndex(index string) string {
	today := time.Now().Format("2006.01.02")
	index = strings.ReplaceAll(index, "{today}", today)
	return index
}

func readErrorFromJson(json string) error {
	errorType := gjson.Get(json, "error.type").String()
	errorReason := gjson.Get(json, "error.reason").String()
	errorDetails := json
	if len(json) > MAX_ERROR_LENGTH {
		errorDetails = json[0:MAX_ERROR_LENGTH]
	}
	err := errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
	return err
}

func readJsonFromResponse(res *esapi.Response) (string, error) {
	var err error
	var b bytes.Buffer
	b.ReadFrom(res.Body)
	jsonStr := b.String()
	if res.IsError() {
		err = readErrorFromJson(jsonStr)
	}
	return jsonStr, err
}

func (store *ElasticEventstore) indexSearch(ctx context.Context, query string, indexes []string) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithFields(log.Fields{
		"query":     store.truncate(query),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Info("Searching Elasticsearch")

	var jsonStr string

	res, err := store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(indexes...),
		store.esClient.Search.WithBody(strings.NewReader(query)),
		store.esClient.Search.WithTrackTotalHits(true),
		store.esClient.Search.WithPretty(),
		store.esClient.Search.WithIgnoreUnavailable(true),
	)
	if err == nil {
		defer res.Body.Close()
		jsonStr, err = readJsonFromResponse(res)
	}

	logger.WithFields(log.Fields{
		"response":  store.truncate(jsonStr),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Search finished")

	return jsonStr, err
}

func (store *ElasticEventstore) indexDocument(ctx context.Context, index string, document string, id string) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"document":  store.truncate(document),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Adding document to Elasticsearch")

	res, err := store.esClient.Index(transformIndex(index),
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

	jsonStr, err := readJsonFromResponse(res)

	logger.WithFields(log.Fields{
		"response":  store.truncate(jsonStr),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Index new document finished")

	return jsonStr, err
}

func (store *ElasticEventstore) deleteDocument(ctx context.Context, index string, id string) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Deleting document from Elasticsearch")

	res, err := store.esClient.Delete(transformIndex(index), id, store.esClient.Delete.WithContext(ctx))

	if err != nil {
		logger.WithFields(log.Fields{
			"index":     index,
			"id":        id,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).WithError(err).Error("Unable to delete document from Elasticsearch")
		return "", err
	}
	defer res.Body.Close()

	jsonStr, err := readJsonFromResponse(res)

	logger.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"response":  store.truncate(jsonStr),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Delete document finished")

	return jsonStr, err
}

func (store *ElasticEventstore) updateDocuments(ctx context.Context, client *elasticsearch.Client, query string, indexes []string, waitForCompletion bool) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithFields(log.Fields{
		"query":     store.truncate(query),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Updating documents in Elasticsearch")
	var jsonStr string
	res, err := client.UpdateByQuery(
		indexes,
		client.UpdateByQuery.WithContext(ctx),
		client.UpdateByQuery.WithPretty(),
		client.UpdateByQuery.WithConflicts("proceed"),
		client.UpdateByQuery.WithBody(strings.NewReader(query)),
		client.UpdateByQuery.WithRefresh(true),
		client.UpdateByQuery.WithWaitForCompletion(waitForCompletion),
	)
	if err == nil {
		defer res.Body.Close()
		jsonStr, err = readJsonFromResponse(res)
	}

	logger.WithFields(log.Fields{
		"response":  store.truncate(jsonStr),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Update finished")

	return jsonStr, err
}

// asyncTaskRef pairs an Elasticsearch task id with the client that submitted it. Task ids are
// node-specific, so the task must be polled on the same client that created it.
type asyncTaskRef struct {
	client  *elasticsearch.Client
	hostUrl string
	taskId  string
}

// watchAsyncUpdate watches all of the supplied asynchronous update tasks to completion, then
// broadcasts a single aggregated result so the initiating client can report success or failure.
func (store *ElasticEventstore) watchAsyncUpdate(ctx context.Context, tasks []asyncTaskRef, taskIds []string) {
	logger := log.FromContext(ctx).WithField("taskIds", taskIds)

	status := store.aggregateAsyncUpdate(ctx, tasks, taskIds)

	logger.WithFields(log.Fields{
		"success": status.Success,
		"updated": status.Updated,
		"errors":  status.Errors,
	}).Info("Asynchronous event update task finished; broadcasting result")

	store.server.Host.Broadcast("events:ack", "events", status)
}

// aggregateAsyncUpdate watches every supplied task to completion and combines their results into a
// single status carrying the total updated count and any errors across all hosts.
func (store *ElasticEventstore) aggregateAsyncUpdate(ctx context.Context, tasks []asyncTaskRef, taskIds []string) model.EventAckStatus {
	status := model.EventAckStatus{
		TaskIds: taskIds,
		Success: true,
		Errors:  make([]string, 0),
	}

	for _, task := range tasks {
		updated, errs := store.waitForUpdateTask(ctx, task)
		status.Updated += updated
		if len(errs) > 0 {
			status.Success = false
			status.Errors = append(status.Errors, errs...)
		}
	}

	// Avoid broadcasting an unbounded error string; the full set is preserved in the server logs.
	if len(status.Errors) > ASYNC_UPDATE_MAX_ERRORS {
		remaining := len(status.Errors) - ASYNC_UPDATE_MAX_ERRORS
		status.Errors = append(status.Errors[:ASYNC_UPDATE_MAX_ERRORS:ASYNC_UPDATE_MAX_ERRORS],
			fmt.Sprintf("...and %d more error(s)", remaining))
	}

	return status
}

// waitForUpdateTask polls a single update task until it completes (or times out) and returns the
// number of updated documents along with any errors encountered.
func (store *ElasticEventstore) waitForUpdateTask(ctx context.Context, task asyncTaskRef) (int, []string) {
	deadline := time.Now().Add(ASYNC_UPDATE_MAX_WAIT)
	for {
		time.Sleep(ASYNC_UPDATE_PAUSE)

		res, err := task.client.Tasks.Get(
			task.taskId,
			task.client.Tasks.Get.WithContext(ctx),
			task.client.Tasks.Get.WithWaitForCompletion(true),
			task.client.Tasks.Get.WithTimeout(ASYNC_UPDATE_POLL_TIMEOUT),
		)
		if err != nil {
			return 0, []string{err.Error()}
		}

		body, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil {
			return 0, []string{readErr.Error()}
		}

		if res.IsError() {
			return 0, []string{fmt.Sprintf("error retrieving task %s: %s", task.taskId, store.truncate(string(body)))}
		}

		parsed := gjson.ParseBytes(body)
		if !parsed.Get("completed").Bool() {
			if time.Now().After(deadline) {
				return 0, []string{fmt.Sprintf("timed out waiting for task %s to complete", task.taskId)}
			}
			// Tasks.Get returned before the task finished (server-side poll timeout); keep waiting.
			continue
		}

		updated, errs, rawErrs := parseAsyncUpdateOutcome(parsed)
		if len(rawErrs) > 0 {
			// Preserve the verbatim Elasticsearch error/failure JSON in the server logs while the
			// client only receives the human-readable reasons in errs.
			log.FromContext(ctx).WithFields(log.Fields{
				"taskId": task.taskId,
				"errors": rawErrs,
			}).Error("Asynchronous Elasticsearch update reported errors")
		}
		return updated, errs
	}
}

// parseAsyncUpdateOutcome extracts the updated count and any errors from a completed Tasks.Get
// response (shape: {"completed":true,"task":{...},"response":{...},"error":{...}}). The returned
// errs are human-readable messages safe to surface to clients; rawErrs carries the verbatim
// Elasticsearch error/failure JSON for server-side logging.
func parseAsyncUpdateOutcome(parsed gjson.Result) (updated int, errs []string, rawErrs []string) {
	errs = make([]string, 0)
	rawErrs = make([]string, 0)

	if topErr := parsed.Get("error"); topErr.Exists() {
		rawErrs = append(rawErrs, topErr.Raw)
		errs = append(errs, asyncErrorReason(topErr))
	}

	resp := parsed.Get("response")
	updated = int(resp.Get("updated").Int())

	if resp.Get("timed_out").Bool() {
		errs = append(errs, "timeout while updating documents in Elasticsearch")
	}
	for _, f := range resp.Get("failures").Array() {
		rawErrs = append(rawErrs, f.Raw)
		errs = append(errs, asyncErrorReason(f))
	}

	return updated, errs, rawErrs
}

// asyncErrorReason returns a concise, human-readable message from an Elasticsearch error object.
// Bulk failures nest the detail under "cause"; top-level task errors are flat. It falls back to a
// generic message when neither a reason nor a type is present.
func asyncErrorReason(errObj gjson.Result) string {
	if cause := errObj.Get("cause"); cause.Exists() {
		errObj = cause
	}
	if reason := errObj.Get("reason").String(); reason != "" {
		return reason
	}
	if errType := errObj.Get("type").String(); errType != "" {
		return errType
	}
	return "an unexpected error occurred while updating events in Elasticsearch"
}

func (store *ElasticEventstore) refreshCache(ctx context.Context) {
	store.cacheLock.Lock()
	defer store.cacheLock.Unlock()
	if store.cacheTime.IsZero() || time.Since(store.cacheTime) > store.cacheMs {
		err := store.refreshCacheFromFieldCaps(ctx)
		if err == nil {
			store.cacheTime = time.Now()
		}
	}
}

func (store *ElasticEventstore) refreshCacheFromFieldCaps(ctx context.Context) error {
	logger := log.FromContext(ctx)

	logger.Info("Fetching Field Capabilities from Elasticsearch")
	indexes := strings.Split(store.index, ",")
	var jsonStr string
	res, err := store.esClient.FieldCaps(
		store.esClient.FieldCaps.WithContext(ctx),
		store.esClient.FieldCaps.WithIndex(indexes...),
		store.esClient.FieldCaps.WithFields("*"),
		store.esClient.FieldCaps.WithPretty(),
	)
	if err == nil {
		defer res.Body.Close()
		jsonStr, err = readJsonFromResponse(res)
		logger.WithFields(log.Fields{
			"response": store.truncate(jsonStr),
		}).Debug("Fetch finished")
		store.cacheFieldsFromJson(jsonStr)
	} else {
		logger.WithError(err).Error("Failed to refresh cache from index patterns")
	}

	return err
}

func (store *ElasticEventstore) cacheFieldsFromJson(jsonStr string) {
	store.fieldDefs = make(map[string]*FieldDefinition)
	gjson.Get(jsonStr, "fields").ForEach(func(key, value gjson.Result) bool {
		return cacheFields(store.fieldDefs, key, value)
	})
}

func cacheFields(fieldDefs map[string]*FieldDefinition, name gjson.Result, details gjson.Result) bool {
	fieldName := name.String()
	detailsMap := make(map[string]map[string]interface{})
	json.NewDecoder(strings.NewReader(details.String())).Decode(&detailsMap)
	for _, field := range detailsMap {
		fieldType := field["type"].(string)

		fieldDef := &FieldDefinition{
			name:         fieldName,
			fieldType:    fieldType,
			aggregatable: field["aggregatable"].(bool),
			searchable:   field["searchable"].(bool),
		}

		// If there are multiple types for this field prefer the non-aggregatable since
		// we cannot reliably aggregate across all indices. In most, or maybe all cases,
		// there will be a .keyword subfield across both indices which will be used
		// for aggregation purposes until all ingested data is fully ECS data type
		// compliant.
		if fieldDefs[fieldName] == nil || !fieldDef.aggregatable {
			fieldDefs[fieldName] = fieldDef
		}
	}
	return true
}

func (store *ElasticEventstore) clusterState(ctx context.Context) (string, error) {
	logger := log.FromContext(ctx)

	logger.WithField("cacheMs", store.cacheMs).Debug("Refreshing field definitions")
	indexes := strings.Split(store.index, ",")
	var jsonStr string
	res, err := store.esClient.Cluster.State(
		store.esClient.Cluster.State.WithContext(ctx),
		store.esClient.Cluster.State.WithIndex(indexes...),
	)
	if err == nil {
		defer res.Body.Close()

		var b bytes.Buffer
		b.ReadFrom(res.Body)
		jsonStr = b.String()

		if res.IsError() {
			errorType := gjson.Get(jsonStr, "error.type").String()
			errorReason := gjson.Get(jsonStr, "error.reason").String()
			errorDetails := jsonStr
			if len(jsonStr) > 255 {
				errorDetails = jsonStr[0:512]
			}
			err = errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
		}
	}

	logger.WithFields(log.Fields{"response": store.truncate(jsonStr)}).Debug("Refresh Finished")

	return jsonStr, err
}

func (store *ElasticEventstore) parseFirst(jsonStr string, name string) string {
	result := gjson.Get(jsonStr, "hits.hits.0._source."+name).String()
	// Select first uid if multiple were provided
	if len(result) > 0 && result[0] == '[' {
		result = gjson.Get(jsonStr, "hits.hits.0._source."+name+".0").String()
	}
	return result
}

func (store *ElasticEventstore) buildRangeFilter(timestampStr string) (map[string]any, time.Time) {
	if len(timestampStr) > 0 {
		timestamp, err := time.Parse(time.RFC3339, timestampStr)
		if err != nil {
			log.WithFields(log.Fields{
				"timestampStr": timestampStr,
			}).WithError(err).Error("Unable to parse document timestamp")
		}
		startTime := timestamp.Add(time.Duration(-store.esSearchOffsetMs)*time.Millisecond).Unix() * 1000
		endTime := timestamp.Add(time.Duration(store.esSearchOffsetMs)*time.Millisecond).Unix() * 1000
		filter := map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{
					"gte":    startTime,
					"lte":    endTime,
					"format": "epoch_millis",
				},
			},
		}
		return filter, timestamp
	}
	return nil, time.Time{}
}

/*
  - Fetch record via provided Elasticsearch document query.
  - If the record has a tunnel_parent, search for a UID=tunnel_parent[0]
  - - If found, discard original record and replace with the new record
  - If the record has source IP/port and destination IP/port, or protocol is icmp, use it as the filter.
  - Else if the record has a Zeek x509 "ID" search for the first Zeek record with this ID.
  - Else if the record has a Zeek file "FUID" search for the first Zeek record with this FUID.
  - Search for the Zeek record with a matching log.id.uid equal to the UID from the previously found record
  - - If multiple UIDs exist in the record, use the first UID in the list.
  - Review the results from the Zeek search and find the record with the timestamp nearest
    to the original ES ID record and use the IP/port details as the filter.
*/
func (store *ElasticEventstore) PopulateJobFromDocQuery(ctx context.Context, idField string, idValue string, timestampStr string, job *model.Job) error {
	logger := log.FromContext(ctx)

	if err := store.validateId(idValue, "idValue"); err != nil {
		return err
	}

	rangeFilter, timestamp := store.buildRangeFilter(timestampStr)

	must := []any{
		map[string]any{
			"match": map[string]any{
				idField: idValue,
			},
		},
	}
	if rangeFilter != nil {
		must = append(must, rangeFilter)
	}

	queryMap := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": must,
			},
		},
	}

	queryJSON, _ := json.Marshal(queryMap)
	query := string(queryJSON)

	var outputSensorId string
	filter := model.NewFilter()
	jsonStr, err := store.luceneSearch(ctx, query)
	logger.WithFields(log.Fields{
		"query":     store.truncate(query),
		"response":  store.truncate(jsonStr),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Elasticsearch primary search finished")
	if err != nil {
		logger.WithField("query", store.truncate(query)).WithError(err).Error("Unable to lookup initial document record")
		return err
	}

	hits := gjson.Get(jsonStr, "hits.total.value").Int()
	if hits == 0 {
		logger.WithField("query", store.truncate(query)).Error("Pivoted document record was not found")
		return errors.New("Unable to locate document record")
	}

	// Try to grab the timestamp from this new record, if the time wasn't provided to this function
	if rangeFilter == nil {
		timestampStr = gjson.Get(jsonStr, "hits.hits.0._source.\\@timestamp").String()
		rangeFilter, timestamp = store.buildRangeFilter(timestampStr)
	}

	if store.lookupTunnelParent {
		// Check if user has pivoted to a PCAP that is encapsulated in a tunnel. The best we
		// can do in this situation is respond with the tunnel PCAP data, which could be excessive.
		tunnelParent := gjson.Get(jsonStr, "hits.hits.0._source.log.id.tunnel_parents").String()
		if len(tunnelParent) > 0 {
			logger.Info("Document is inside of a tunnel; attempting to lookup tunnel connection log")
			if tunnelParent[0] == '[' {
				tunnelParent = gjson.Get(jsonStr, "hits.hits.0._source.log.id.tunnel_parents.0").String()
			}
			must := []any{
				map[string]any{
					"match": map[string]any{
						"log.id.uid": tunnelParent,
					},
				},
			}
			if rangeFilter != nil {
				must = append(must, rangeFilter)
			}

			queryMap := map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": must,
					},
				},
			}

			queryJSON, _ := json.Marshal(queryMap)
			query := string(queryJSON)

			jsonStr, err = store.luceneSearch(ctx, query)
			logger.WithFields(log.Fields{
				"query":    store.truncate(query),
				"response": store.truncate(jsonStr),
			}).Debug("Elasticsearch tunnel search finished")
			if err != nil {
				logger.WithField("query", store.truncate(query)).WithError(err).Error("Unable to lookup tunnel record")
				return err
			}
			hits := gjson.Get(jsonStr, "hits.total.value").Int()
			if hits == 0 {
				logger.WithField("query", store.truncate(query)).Error("Tunnel record was not found")
				return errors.New("Unable to locate encapsulating tunnel record")
			}
		}
	}

	filter.ImportId = gjson.Get(jsonStr, "hits.hits.0._source.import.id").String()
	filter.Protocol = strings.ToLower(gjson.Get(jsonStr, "hits.hits.0._source.network.transport").String())
	filter.SrcIp = gjson.Get(jsonStr, "hits.hits.0._source.source.ip").String()
	filter.SrcPort = int(gjson.Get(jsonStr, "hits.hits.0._source.source.port").Int())
	filter.DstIp = gjson.Get(jsonStr, "hits.hits.0._source.destination.ip").String()
	filter.DstPort = int(gjson.Get(jsonStr, "hits.hits.0._source.destination.port").Int())
	uid := store.parseFirst(jsonStr, "log.id.uid")
	x509id := store.parseFirst(jsonStr, "log.id.id")
	fuid := store.parseFirst(jsonStr, "log.id.fuid")
	store.addParameterToFilter(jsonStr, "suricata.capture_file", filter)
	outputSensorId = gjson.Get(jsonStr, "hits.hits.0._source.observer.name").String()
	duration := int64(store.defaultDurationMs)

	// If source and destination IP/port details aren't available search ES again for a correlating Zeek record
	if (len(filter.SrcIp) == 0 || len(filter.DstIp) == 0 || filter.SrcPort == 0 || filter.DstPort == 0) && filter.Protocol != model.PROTOCOL_ICMP {
		if len(uid) == 0 || uid[0] != 'C' {
			zeekFileQuery := ""
			if len(x509id) > 0 && x509id[0] == 'F' {
				zeekFileQuery = x509id
			} else if len(fuid) > 0 && fuid[0] == 'F' {
				zeekFileQuery = fuid
			}

			if len(zeekFileQuery) > 0 {
				must := []any{
					map[string]any{
						"query_string": map[string]any{
							"query":            fmt.Sprintf("event.dataset:zeek.file AND %s", util.EscapeLucene(zeekFileQuery)),
							"analyze_wildcard": true,
						},
					},
				}
				if rangeFilter != nil {
					must = append(must, rangeFilter)
				}

				queryMap := map[string]any{
					"query": map[string]any{
						"bool": map[string]any{
							"must": must,
						},
					},
				}

				queryJSON, _ := json.Marshal(queryMap)
				query = string(queryJSON)
				jsonStr, err = store.luceneSearch(ctx, query)
				logger.WithFields(log.Fields{
					"query":     store.truncate(query),
					"response":  store.truncate(jsonStr),
					"requestId": ctx.Value(web.ContextKeyRequestId),
				}).Debug("Elasticsearch Zeek File search finished")

				if err != nil {
					logger.WithFields(log.Fields{
						"query":         store.truncate(query),
						"zeekFileQuery": store.truncate(zeekFileQuery),
						"requestId":     ctx.Value(web.ContextKeyRequestId),
					}).WithError(err).Error("Unable to lookup Zeek File record")
					return err
				}

				hits = gjson.Get(jsonStr, "hits.total.value").Int()
				if hits == 0 {
					logger.WithFields(log.Fields{
						"query":         store.truncate(query),
						"zeekFileQuery": store.truncate(zeekFileQuery),
						"requestId":     ctx.Value(web.ContextKeyRequestId),
					}).Error("Zeek File record was not found")
					return errors.New("Unable to locate Zeek File record")
				}

				uid = store.parseFirst(jsonStr, "log.id.uid")
				store.addParameterToFilter(jsonStr, "suricata.capture_file", filter)
			}

			if len(uid) == 0 {
				logger.WithFields(log.Fields{
					"query":         store.truncate(query),
					"zeekFileQuery": store.truncate(zeekFileQuery),
					"requestId":     ctx.Value(web.ContextKeyRequestId),
				}).Warn("Zeek File record is missing a UID")
				return errors.New("No valid Zeek connection ID found")
			}
		}

		// Search for the Zeek connection ID
		must := []any{
			map[string]any{
				"query_string": map[string]any{
					"query":            fmt.Sprintf("event.module:zeek AND %s", util.EscapeLucene(uid)),
					"analyze_wildcard": true,
				},
			},
		}
		if rangeFilter != nil {
			must = append(must, rangeFilter)
		}

		queryMap := map[string]any{
			"query": map[string]any{
				"bool": map[string]any{
					"must": must,
				},
			},
		}

		queryJSON, _ := json.Marshal(queryMap)
		query = string(queryJSON)
		jsonStr, err = store.luceneSearch(ctx, query)
		logger.WithFields(log.Fields{
			"query":     store.truncate(query),
			"response":  store.truncate(jsonStr),
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Debug("Elasticsearch Zeek search finished")

		if err != nil {
			logger.WithFields(log.Fields{
				"query":     store.truncate(query),
				"uid":       uid,
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).WithError(err).Error("Unable to lookup Zeek record")
			return err
		}

		hits = gjson.Get(jsonStr, "hits.total.value").Int()
		if hits == 0 {
			logger.WithFields(log.Fields{
				"query":     store.truncate(query),
				"uid":       uid,
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).Error("Zeek record was not found")
			return errors.New("Unable to locate Zeek record")
		}

		store.addParameterToFilter(jsonStr, "suricata.capture_file", filter)
		results := gjson.Get(jsonStr, "hits.hits.#._source.\\@timestamp").Array()
		var closestDeltaNs int64
		closestDeltaNs = 0
		for idx, ts := range results {
			var matchTs time.Time
			matchTs, err = time.Parse(time.RFC3339, ts.String())
			if err == nil {
				idxStr := strconv.Itoa(idx)
				protocol := strings.ToLower(gjson.Get(jsonStr, "hits.hits.0._source.network.transport").String())
				srcIp := gjson.Get(jsonStr, "hits.hits."+idxStr+"._source.source.ip").String()
				srcPort := int(gjson.Get(jsonStr, "hits.hits."+idxStr+"._source.source.port").Int())
				dstIp := gjson.Get(jsonStr, "hits.hits."+idxStr+"._source.destination.ip").String()
				dstPort := int(gjson.Get(jsonStr, "hits.hits."+idxStr+"._source.destination.port").Int())

				if (len(srcIp) > 0 && len(dstIp) > 0 && srcPort > 0 && dstPort > 0) || (protocol == model.PROTOCOL_ICMP) {
					delta := timestamp.Sub(matchTs)
					deltaNs := delta.Nanoseconds()
					if deltaNs < 0 {
						deltaNs = -deltaNs
					}
					if closestDeltaNs == 0 || deltaNs < closestDeltaNs {
						closestDeltaNs = deltaNs

						timestamp = matchTs
						filter.Protocol = protocol
						filter.SrcIp = srcIp
						filter.SrcPort = srcPort
						filter.DstIp = dstIp
						filter.DstPort = dstPort
						durationFloat := gjson.Get(jsonStr, "hits.hits."+idxStr+"._source.event.duration").Float()
						if durationFloat > 0 {
							duration = int64(math.Round(durationFloat * 1000.0))
						}
					}
				}
			}
		}

		logger.WithFields(log.Fields{
			"sensorId":  outputSensorId,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Info("Obtained output parameters")
	}

	if len(filter.SrcIp) == 0 || len(filter.DstIp) == 0 || ((filter.SrcPort == 0 || filter.DstPort == 0) && filter.Protocol != model.PROTOCOL_ICMP) {
		logger.WithFields(log.Fields{
			"query":     store.truncate(query),
			"uid":       uid,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Warn("Unable to lookup PCAP due to missing TCP/UDP/ICMP parameters")
		return errors.New("No TCP/UDP/ICMP record was found for retrieving PCAP")
	}

	filter.BeginTime = timestamp.Add(time.Duration(-duration-int64(store.timeShiftMs)) * time.Millisecond)
	filter.EndTime = timestamp.Add(time.Duration(duration+int64(store.timeShiftMs)) * time.Millisecond)
	job.SetNodeId(outputSensorId)
	job.Filter = filter

	return nil
}

func (store *ElasticEventstore) addParameterToFilter(jsonStr string, key string, filter *model.Filter) {
	value := store.parseFirst(jsonStr, key)

	// If the key was provided, add it to the filter parameters.
	// Overwrite if the key already exists
	if len(value) > 0 {
		filter.Parameters[key] = value
	}
}

func (store *ElasticEventstore) addAcknowledgeScript(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, esc bool, userId string) {
	trackTiming := licensing.IsEnabled(licensing.FEAT_RPT)
	nowMillis := timeNow.UnixMilli()

	updateCriteria.Params["trackTiming"] = trackTiming
	updateCriteria.Params["escBool"] = esc
	updateCriteria.Params["nowMillis"] = nowMillis
	updateCriteria.Params["userId"] = userId

	updateCriteria.AddUpdateScript(`
			boolean track_timing = params.trackTiming;
			boolean esc_bool = params.escBool;
			Instant now_instant = Instant.ofEpochMilli(params.nowMillis);
			ZonedDateTime now_date = ZonedDateTime.ofInstant(now_instant, ZoneId.of('Z'));
			long elapsed_seconds = 0;
			if (ctx._source.containsKey('@timestamp')) {
				ZonedDateTime event_date = ZonedDateTime.parse(ctx._source['@timestamp']);
				elapsed_seconds = ChronoUnit.SECONDS.between(event_date, now_date)
			}

			if (ctx._source.event.acknowledged != true) {
				ctx._source.event.acknowledged = true;
				ctx._source.event.acknowledged_by = params.userId;
				if (track_timing) {
					ctx._source.event.acknowledged_timestamp = now_date;
					ctx._source.event.acknowledged_elapsed_seconds = elapsed_seconds;
				}
			}

			if (ctx._source.event.escalated != true && esc_bool) {
				ctx._source.event.escalated = esc_bool;
				ctx._source.event.escalated_by = params.userId;
				if (track_timing) {
					ctx._source.event.escalated_timestamp = now_date;
					ctx._source.event.escalated_elapsed_seconds = elapsed_seconds;
				}
			}
			`)
}

func (store *ElasticEventstore) addInvestigateScript(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, userId string, sessionId ...string) {
	trackTiming := licensing.IsEnabled(licensing.FEAT_RPT)
	nowMillis := timeNow.UnixMilli()

	// Get sessionId if provided
	sessionIdStr := ""
	if len(sessionId) > 0 && sessionId[0] != "" {
		sessionIdStr = sessionId[0]
	}

	updateCriteria.Params["trackTiming"] = trackTiming
	updateCriteria.Params["nowMillis"] = nowMillis
	updateCriteria.Params["userId"] = userId

	script := `
			boolean track_timing = params.trackTiming;
			Instant now_instant = Instant.ofEpochMilli(params.nowMillis);
			ZonedDateTime now_date = ZonedDateTime.ofInstant(now_instant, ZoneId.of('Z'));
			
			ctx._source.event.investigated = true;
			ctx._source.event.investigated_by = params.userId;`

	if sessionIdStr != "" {
		updateCriteria.Params["sessionId"] = sessionIdStr
		script += `
			ctx._source.event.investigation_session_id = params.sessionId;`
	}

	script += `
			if (track_timing) {
				ctx._source.event.investigated_timestamp = now_date;
			}
			`
	updateCriteria.AddUpdateScript(script)
}

func (store *ElasticEventstore) addUnacknowledgeScript(updateCriteria *model.EventUpdateCriteria) {
	updateCriteria.AddUpdateScript(`ctx._source.event.acknowledged = false;`)
}

func (store *ElasticEventstore) addInvestigateDeleteScript(updateCriteria *model.EventUpdateCriteria) {
	updateCriteria.AddUpdateScript(`
		if (ctx._source.event.containsKey('investigation_session_id')) {
			ctx._source.event.remove('investigation_session_id');
		}
	`)
}

func (store *ElasticEventstore) AddAckEscalateUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, ack bool, esc bool, userId string) {
	if ack {
		store.addAcknowledgeScript(updateCriteria, timeNow, esc, userId)
	} else {
		store.addUnacknowledgeScript(updateCriteria)
	}
}

func (store *ElasticEventstore) AddInvestigationUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, userId string, isDelete bool, sessionId ...string) {
	if isDelete {
		store.addInvestigateDeleteScript(updateCriteria)
	} else {
		store.addInvestigateScript(updateCriteria, timeNow, userId, sessionId...)
	}
}

func (store *ElasticEventstore) Acknowledge(ctx context.Context, ackCriteria *model.EventAckCriteria) (results *model.EventUpdateResults, err error) {
	logger := log.FromContext(ctx)

	if len(ackCriteria.EventFilter) > 0 {
		if err = store.server.CheckAuthorized(ctx, "ack", "events"); err == nil {
			logger.WithFields(log.Fields{
				"searchFilter": ackCriteria.SearchFilter,
				"eventFilter":  ackCriteria.EventFilter,
				"escalate":     ackCriteria.Escalate,
				"acknowledge":  ackCriteria.Acknowledge,
				"requestId":    ctx.Value(web.ContextKeyRequestId),
			}).Info("Acknowledging event")

			updateCriteria := model.NewEventUpdateCriteria()
			userId := ctx.Value(web.ContextKeyRequestorId).(string)
			store.AddAckEscalateUpdateScripts(updateCriteria, time.Now(), ackCriteria.Acknowledge, ackCriteria.Escalate, userId)
			updateCriteria.Populate(ackCriteria.SearchFilter,
				ackCriteria.DateRange,
				ackCriteria.DateRangeFormat,
				ackCriteria.Timezone,
				"0",
				"0")

			// Add the event filters to the search query
			var searchSegment *model.SearchSegment
			segment := updateCriteria.ParsedQuery.NamedSegment("search")
			if segment == nil {
				searchSegment = model.NewSearchSegmentEmpty()
			} else {
				searchSegment = segment.(*model.SearchSegment)
			}

			updateCriteria.Asynchronous = false
			for key, value := range ackCriteria.EventFilter {
				if strings.ToLower(key) != "count" {
					valueStr := fmt.Sprintf("%v", value)
					searchSegment.AddFilter(mapElasticField(store.fieldDefs, key), valueStr, model.IsScalar(value), true, false)
				} else if int(value.(float64)) > store.asyncThreshold {
					logger.WithFields(log.Fields{
						key:         value,
						"threshold": store.asyncThreshold,
						"requestId": ctx.Value(web.ContextKeyRequestId),
					}).Info("Acknowledging events asynchronously due to large quantity")
					updateCriteria.Asynchronous = true
				}
			}

			// Baseline the query to be based only on the search component
			updateCriteria.ParsedQuery = model.NewQuery()
			updateCriteria.ParsedQuery.AddSegment(searchSegment)

			results, err = store.Update(ctx, updateCriteria)
			if err == nil && !updateCriteria.Asynchronous {
				if results.UpdatedCount == 0 {
					if results.UnchangedCount == 0 {
						err = errors.New("No eligible events available to acknowledge")
					} else {
						err = errors.New("All events have already been acknowledged")
					}
				}
			}
		}
	} else {
		err = errors.New("EventFilter must be specified to ack an event")
	}
	return results, err
}
