// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/tidwall/gjson"
)

const MAX_ERROR_LENGTH = 4096

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

func (store *ElasticEventstore) EventSearch(ctx context.Context, critera *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	err := store.server.CheckAuthorized(ctx, "read", "events")
	if err != nil {
		return nil, err
	}

	return store.Search(ctx, critera)
}

func (store *ElasticEventstore) Search(ctx context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	var err error
	results := model.NewEventSearchResults()

	store.refreshCache(ctx)

	var query string
	query, err = convertToElasticRequest(store.fieldDefs, store.intervals, criteria)
	if err == nil {
		var response string
		response, err = store.luceneSearch(ctx, query)
		if err == nil {
			err = convertFromElasticResults(store.fieldDefs, response, results)
			results.Criteria = criteria
		}
	}

	results.Complete()

	return results, err
}

func (store *ElasticEventstore) MSearch(ctx context.Context, criteria []*model.EventMSearchCriteria) (results *model.EventMSearchResults, err error) {
	results = model.NewEventMSearchResults()

	buf := bytes.Buffer{}
	for _, criteria := range criteria {
		buf.WriteString(fmt.Sprintf(`{"index":"%s"}`, criteria.Index))
		buf.WriteString("\r\n")

		query, err := convertToElasticMSearchRequest(store.fieldDefs, criteria)
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

	err = convertFromElasticMSearchResults(store.fieldDefs, string(body), results)

	return results, err
}

func (store *ElasticEventstore) Scroll(ctx context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error) {
	var err error
	var query, scrollId, json string
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

	res, err = store.esClient.Search(
		store.esClient.Search.WithContext(ctx),
		store.esClient.Search.WithIndex(indexes...),
		store.esClient.Search.WithBody(strings.NewReader(query)),
		store.esClient.Search.WithTrackTotalHits(true),
		store.esClient.Search.WithPretty(),
		store.esClient.Search.WithScroll(time.Minute),
		store.esClient.Search.WithIgnoreUnavailable(true),
	)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	json, err = readJsonFromResponse(res)
	if err == nil {
		batchNum := 0

		err = convertFromElasticScrollResults(store.fieldDefs, json, finalResults)
		if err != nil {
			finalResults.Complete()

			return finalResults, err
		}

		logger.WithFields(log.Fields{
			"batchNum": batchNum,
			"hitCount": len(finalResults.Events),
		}).Debug("scroll progress")

		scrollId = gjson.Get(json, "_scroll_id").String()

		lastPageCount := len(finalResults.Events)

		for {
			// Break out of the loop when there are no results or we have all the results
			if lastPageCount == 0 || len(finalResults.Events) >= finalResults.TotalEvents {
				logger.Debug("finished scrolling")
				break
			}

			batchNum++

			res, err = store.esClient.Scroll(
				store.esClient.Scroll.WithContext(ctx),
				store.esClient.Scroll.WithScroll(time.Minute),
				store.esClient.Scroll.WithBody(strings.NewReader(fmt.Sprintf(`{"scroll_id":"%s"}`, scrollId))),
			)
			if err != nil {
				break
			}

			defer res.Body.Close()

			json, err = readJsonFromResponse(res)
			if err != nil {
				break
			}

			results := model.NewEventScrollResults()

			err = convertFromElasticScrollResults(store.fieldDefs, json, results)
			if err != nil {
				break
			}

			finalResults.ElapsedMs += results.ElapsedMs
			finalResults.Events = append(finalResults.Events, results.Events...)

			scrollId = gjson.Get(json, "_scroll_id").String()
			lastPageCount = len(results.Events)

			logger.WithFields(log.Fields{
				"batchNum": batchNum,
				"hitCount": lastPageCount,
			}).Debug("scroll progress")
		}
	}

	finalResults.Complete()

	if scrollId != "" {
		res, scrollErr := store.esClient.ClearScroll(
			store.esClient.ClearScroll.WithContext(ctx),
			store.esClient.ClearScroll.WithBody(strings.NewReader(fmt.Sprintf(`{"scroll_id":"%s"}`, scrollId))),
		)
		if scrollErr != nil {
			logger.WithError(scrollErr).Warn("call to close scroll failed, scroll should self-close shortly")
		}

		if res != nil {
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

func (store *ElasticEventstore) Update(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
	var err error
	results := model.NewEventUpdateResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		store.refreshCache(ctx)

		results.Criteria = criteria
		var query string
		query, err = convertToElasticUpdateRequest(store, criteria)
		if err == nil {
			var response string

			for idx, client := range store.esAllClients {
				log.WithField("clientHost", store.hostUrls[idx]).Debug("Sending request to client")
				response, err = store.updateDocuments(ctx, client, query, store.disableCrossClusterIndexing(strings.Split(store.index, ",")), !criteria.Asynchronous)
				if err == nil {
					if !criteria.Asynchronous {
						currentResults := model.NewEventUpdateResults()
						err = convertFromElasticUpdateResults(store, response, currentResults)
						if err == nil {
							results.AddEventUpdateResults(currentResults)
						} else {
							log.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
							results.Errors = append(results.Errors, err.Error())
						}
					}
				} else {
					log.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
					results.Errors = append(results.Errors, err.Error())
				}
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

func (store *ElasticEventstore) Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error) {
	var err error
	results := model.NewEventIndexResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		store.refreshCache(ctx)

		var request string
		request, err = convertToElasticIndexRequest(document)
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
	}
	return results, err
}

func (store *ElasticEventstore) Delete(ctx context.Context, index string, id string) error {
	var err error
	results := model.NewEventIndexResults()
	if err = store.server.CheckAuthorized(ctx, "write", "events"); err == nil {
		var response string
		log.Debug("Sending delete request to primary Elasticsearch client")
		response, err = store.deleteDocument(ctx, store.disableCrossClusterIndex(index), id)
		if err == nil {
			err = convertFromElasticIndexResults(response, results)
			if err != nil {
				log.WithError(err).Error("Encountered error while converting document index results")
			}
		} else {
			log.WithError(err).Error("Encountered error while deleting document from elasticsearch")
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
	json := b.String()
	if res.IsError() {
		err = readErrorFromJson(json)
	}
	return json, err
}

func (store *ElasticEventstore) indexSearch(ctx context.Context, query string, indexes []string) (string, error) {
	log.WithFields(log.Fields{
		"query":     store.truncate(query),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Info("Searching Elasticsearch")

	var json string

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
		json, err = readJsonFromResponse(res)
	}
	log.WithFields(log.Fields{
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Search finished")
	return json, err
}

func (store *ElasticEventstore) indexDocument(ctx context.Context, index string, document string, id string) (string, error) {
	log.WithFields(log.Fields{
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

func (store *ElasticEventstore) deleteDocument(ctx context.Context, index string, id string) (string, error) {
	log.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Deleting document from Elasticsearch")

	res, err := store.esClient.Delete(transformIndex(index), id, store.esClient.Delete.WithContext(ctx))

	if err != nil {
		log.WithFields(log.Fields{
			"index":     index,
			"id":        id,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).WithError(err).Error("Unable to delete document from Elasticsearch")
		return "", err
	}
	defer res.Body.Close()
	json, err := readJsonFromResponse(res)

	log.WithFields(log.Fields{
		"index":     index,
		"id":        id,
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Delete document finished")
	return json, err
}

func (store *ElasticEventstore) updateDocuments(ctx context.Context, client *elasticsearch.Client, query string, indexes []string, waitForCompletion bool) (string, error) {
	log.WithFields(log.Fields{
		"query":     store.truncate(query),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Updating documents in Elasticsearch")
	var json string
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
		json, err = readJsonFromResponse(res)
	}
	log.WithFields(log.Fields{
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Update finished")
	return json, err
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
	log.Info("Fetching Field Capabilities from Elasticsearch")
	indexes := strings.Split(store.index, ",")
	var json string
	res, err := store.esClient.FieldCaps(
		store.esClient.FieldCaps.WithContext(ctx),
		store.esClient.FieldCaps.WithIndex(indexes...),
		store.esClient.FieldCaps.WithFields("*"),
		store.esClient.FieldCaps.WithPretty(),
	)
	if err == nil {
		defer res.Body.Close()
		json, err = readJsonFromResponse(res)
		log.WithFields(log.Fields{"response": store.truncate(json)}).Debug("Fetch finished")
		store.cacheFieldsFromJson(json)
	} else {
		log.WithError(err).Error("Failed to refresh cache from index patterns")
	}
	return err
}

func (store *ElasticEventstore) cacheFieldsFromJson(json string) {
	store.fieldDefs = make(map[string]*FieldDefinition)
	gjson.Get(json, "fields").ForEach(func(key, value gjson.Result) bool {
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

		log.WithFields(log.Fields{
			"fieldName":    name,
			"fieldType":    fieldType,
			"aggregatable": fieldDef.aggregatable,
			"searchable":   fieldDef.searchable,
		}).Debug("Added field definition")
	}
	return true
}

func (store *ElasticEventstore) clusterState(ctx context.Context) (string, error) {
	log.WithField("cacheMs", store.cacheMs).Debug("Refreshing field definitions")
	indexes := strings.Split(store.index, ",")
	var json string
	res, err := store.esClient.Cluster.State(
		store.esClient.Cluster.State.WithContext(ctx),
		store.esClient.Cluster.State.WithIndex(indexes...),
	)
	if err == nil {
		defer res.Body.Close()

		var b bytes.Buffer
		b.ReadFrom(res.Body)
		json = b.String()

		if res.IsError() {
			errorType := gjson.Get(json, "error.type").String()
			errorReason := gjson.Get(json, "error.reason").String()
			errorDetails := json
			if len(json) > 255 {
				errorDetails = json[0:512]
			}
			err = errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
		}
	}
	log.WithFields(log.Fields{"response": store.truncate(json)}).Debug("Refresh Finished")
	return json, err
}

func (store *ElasticEventstore) parseFirst(json string, name string) string {
	result := gjson.Get(json, "hits.hits.0._source."+name).String()
	// Select first uid if multiple were provided
	if len(result) > 0 && result[0] == '[' {
		result = gjson.Get(json, "hits.hits.0._source."+name+".0").String()
	}
	return result
}

func (store *ElasticEventstore) buildRangeFilter(timestampStr string) (string, time.Time) {
	if len(timestampStr) > 0 {
		timestamp, err := time.Parse(time.RFC3339, timestampStr)
		if err != nil {
			log.WithFields(log.Fields{
				"timestampStr": timestampStr,
			}).WithError(err).Error("Unable to parse document timestamp")
		}
		startTime := timestamp.Add(time.Duration(-store.esSearchOffsetMs)*time.Millisecond).Unix() * 1000
		endTime := timestamp.Add(time.Duration(store.esSearchOffsetMs)*time.Millisecond).Unix() * 1000
		filter := fmt.Sprintf(`,{"range":{"@timestamp":{"gte":"%d","lte":"%d","format":"epoch_millis"}}}`, startTime, endTime)
		return filter, timestamp
	}
	return "", time.Time{}
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
	rangeFilter, timestamp := store.buildRangeFilter(timestampStr)

	query := fmt.Sprintf(`
    {
      "query" : {
        "bool": {
          "must": [
            { "match" : { "%s" : "%s" }}%s
          ]
        }
      }
    }`, idField, idValue, rangeFilter)

	var outputSensorId string
	filter := model.NewFilter()
	json, err := store.luceneSearch(ctx, query)
	log.WithFields(log.Fields{
		"query":     store.truncate(query),
		"response":  store.truncate(json),
		"requestId": ctx.Value(web.ContextKeyRequestId),
	}).Debug("Elasticsearch primary search finished")
	if err != nil {
		log.WithField("query", store.truncate(query)).WithError(err).Error("Unable to lookup initial document record")
		return err
	}

	hits := gjson.Get(json, "hits.total.value").Int()
	if hits == 0 {
		log.WithField("query", store.truncate(query)).Error("Pivoted document record was not found")
		return errors.New("Unable to locate document record")
	}

	// Try to grab the timestamp from this new record, if the time wasn't provided to this function
	if len(rangeFilter) == 0 {
		timestampStr = gjson.Get(json, "hits.hits.0._source.\\@timestamp").String()
		rangeFilter, timestamp = store.buildRangeFilter(timestampStr)
	}

	if store.lookupTunnelParent {
		// Check if user has pivoted to a PCAP that is encapsulated in a tunnel. The best we
		// can do in this situation is respond with the tunnel PCAP data, which could be excessive.
		tunnelParent := gjson.Get(json, "hits.hits.0._source.log.id.tunnel_parents").String()
		if len(tunnelParent) > 0 {
			log.Info("Document is inside of a tunnel; attempting to lookup tunnel connection log")
			if tunnelParent[0] == '[' {
				tunnelParent = gjson.Get(json, "hits.hits.0._source.log.id.tunnel_parents.0").String()
			}
			query := fmt.Sprintf(`
		{
			"query" : {
			"bool": {
				"must": [
				{ "match" : { "log.id.uid" : "%s" }}%s
				]
			}
			}
		}`, tunnelParent, rangeFilter)

			json, err = store.luceneSearch(ctx, query)
			log.WithFields(log.Fields{
				"query":    store.truncate(query),
				"response": store.truncate(json),
			}).Debug("Elasticsearch tunnel search finished")
			if err != nil {
				log.WithField("query", store.truncate(query)).WithError(err).Error("Unable to lookup tunnel record")
				return err
			}
			hits := gjson.Get(json, "hits.total.value").Int()
			if hits == 0 {
				log.WithField("query", store.truncate(query)).Error("Tunnel record was not found")
				return errors.New("Unable to locate encapsulating tunnel record")
			}
		}
	}

	filter.ImportId = gjson.Get(json, "hits.hits.0._source.import.id").String()
	filter.Protocol = strings.ToLower(gjson.Get(json, "hits.hits.0._source.network.transport").String())
	filter.SrcIp = gjson.Get(json, "hits.hits.0._source.source.ip").String()
	filter.SrcPort = int(gjson.Get(json, "hits.hits.0._source.source.port").Int())
	filter.DstIp = gjson.Get(json, "hits.hits.0._source.destination.ip").String()
	filter.DstPort = int(gjson.Get(json, "hits.hits.0._source.destination.port").Int())
	uid := store.parseFirst(json, "log.id.uid")
	x509id := store.parseFirst(json, "log.id.id")
	fuid := store.parseFirst(json, "log.id.fuid")
	outputSensorId = gjson.Get(json, "hits.hits.0._source.observer.name").String()
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
				query = fmt.Sprintf(`{"query":{"bool":{"must":[{"query_string":{"query":"event.dataset:zeek.file AND %s","analyze_wildcard":true}}%s]}}}`,
					zeekFileQuery, rangeFilter)
				json, err = store.luceneSearch(ctx, query)
				log.WithFields(log.Fields{
					"query":     store.truncate(query),
					"response":  store.truncate(json),
					"requestId": ctx.Value(web.ContextKeyRequestId),
				}).Debug("Elasticsearch Zeek File search finished")

				if err != nil {
					log.WithFields(log.Fields{
						"query":         store.truncate(query),
						"zeekFileQuery": store.truncate(zeekFileQuery),
						"requestId":     ctx.Value(web.ContextKeyRequestId),
					}).WithError(err).Error("Unable to lookup Zeek File record")
					return err
				}

				hits = gjson.Get(json, "hits.total.value").Int()
				if hits == 0 {
					log.WithFields(log.Fields{
						"query":         store.truncate(query),
						"zeekFileQuery": store.truncate(zeekFileQuery),
						"requestId":     ctx.Value(web.ContextKeyRequestId),
					}).Error("Zeek File record was not found")
					return errors.New("Unable to locate Zeek File record")
				}

				uid = store.parseFirst(json, "log.id.uid")
			}

			if len(uid) == 0 {
				log.WithFields(log.Fields{
					"query":         store.truncate(query),
					"zeekFileQuery": store.truncate(zeekFileQuery),
					"requestId":     ctx.Value(web.ContextKeyRequestId),
				}).Warn("Zeek File record is missing a UID")
				return errors.New("No valid Zeek connection ID found")
			}
		}

		// Search for the Zeek connection ID
		query = fmt.Sprintf(`{"query":{"bool":{"must":[{"query_string":{"query":"event.module:zeek AND %s","analyze_wildcard":true}}%s]}}}`,
			uid, rangeFilter)
		json, err = store.luceneSearch(ctx, query)
		log.WithFields(log.Fields{
			"query":     store.truncate(query),
			"response":  store.truncate(json),
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Debug("Elasticsearch Zeek search finished")

		if err != nil {
			log.WithFields(log.Fields{
				"query":     store.truncate(query),
				"uid":       uid,
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).WithError(err).Error("Unable to lookup Zeek record")
			return err
		}

		hits = gjson.Get(json, "hits.total.value").Int()
		if hits == 0 {
			log.WithFields(log.Fields{
				"query":     store.truncate(query),
				"uid":       uid,
				"requestId": ctx.Value(web.ContextKeyRequestId),
			}).Error("Zeek record was not found")
			return errors.New("Unable to locate Zeek record")
		}

		results := gjson.Get(json, "hits.hits.#._source.\\@timestamp").Array()
		var closestDeltaNs int64
		closestDeltaNs = 0
		for idx, ts := range results {
			var matchTs time.Time
			matchTs, err = time.Parse(time.RFC3339, ts.String())
			if err == nil {
				idxStr := strconv.Itoa(idx)
				protocol := strings.ToLower(gjson.Get(json, "hits.hits.0._source.network.transport").String())
				srcIp := gjson.Get(json, "hits.hits."+idxStr+"._source.source.ip").String()
				srcPort := int(gjson.Get(json, "hits.hits."+idxStr+"._source.source.port").Int())
				dstIp := gjson.Get(json, "hits.hits."+idxStr+"._source.destination.ip").String()
				dstPort := int(gjson.Get(json, "hits.hits."+idxStr+"._source.destination.port").Int())

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
						durationFloat := gjson.Get(json, "hits.hits."+idxStr+"._source.event.duration").Float()
						if durationFloat > 0 {
							duration = int64(math.Round(durationFloat * 1000.0))
						}
					}
				}
			}
		}

		log.WithFields(log.Fields{
			"sensorId":  outputSensorId,
			"requestId": ctx.Value(web.ContextKeyRequestId),
		}).Info("Obtained output parameters")
	}

	if len(filter.SrcIp) == 0 || len(filter.DstIp) == 0 || ((filter.SrcPort == 0 || filter.DstPort == 0) && filter.Protocol != model.PROTOCOL_ICMP) {
		log.WithFields(log.Fields{
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

func (store *ElasticEventstore) addUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, ack bool, esc bool) {
	if ack {
		trackTiming := strconv.FormatBool(licensing.IsEnabled(licensing.FEAT_RPT))
		escBool := strconv.FormatBool(esc)
		nowMillis := timeNow.UnixMilli()
		nowMillisStr := strconv.FormatInt(nowMillis, 10)
		updateCriteria.AddUpdateScript(`
			boolean track_timing = ` + trackTiming + `;
			boolean esc_bool = ` + escBool + `;
			Instant now_instant = Instant.ofEpochMilli(` + nowMillisStr + `L);
			ZonedDateTime now_date = ZonedDateTime.ofInstant(now_instant, ZoneId.of('Z'));
			long elapsed_seconds = 0;
			if (ctx._source.containsKey('@timestamp')) {
				ZonedDateTime event_date = ZonedDateTime.parse(ctx._source['@timestamp']);
				elapsed_seconds = ChronoUnit.SECONDS.between(event_date, now_date)
			}

			if (ctx._source.event.acknowledged != true) {
				ctx._source.event.acknowledged = true;
				if (track_timing) {
					ctx._source.event.acknowledged_timestamp = now_date;
					ctx._source.event.acknowledged_elapsed_seconds = elapsed_seconds;
				}
			}

			if (ctx._source.event.escalated != true && esc_bool) {
				ctx._source.event.escalated = esc_bool;
				if (track_timing) {
					ctx._source.event.escalated_timestamp = now_date;
					ctx._source.event.escalated_elapsed_seconds = elapsed_seconds;
				}
			}
			`)
	} else {
		updateCriteria.AddUpdateScript(`ctx._source.event.acknowledged = false;`)
	}
}

func (store *ElasticEventstore) Acknowledge(ctx context.Context, ackCriteria *model.EventAckCriteria) (*model.EventUpdateResults, error) {
	var results *model.EventUpdateResults
	var err error
	if len(ackCriteria.EventFilter) > 0 {
		if err = store.server.CheckAuthorized(ctx, "ack", "events"); err == nil {
			log.WithFields(log.Fields{
				"searchFilter": ackCriteria.SearchFilter,
				"eventFilter":  ackCriteria.EventFilter,
				"escalate":     ackCriteria.Escalate,
				"acknowledge":  ackCriteria.Acknowledge,
				"requestId":    ctx.Value(web.ContextKeyRequestId),
			}).Info("Acknowledging event")

			updateCriteria := model.NewEventUpdateCriteria()
			store.addUpdateScripts(updateCriteria, time.Now(), ackCriteria.Acknowledge, ackCriteria.Escalate)
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
					log.WithFields(log.Fields{
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
