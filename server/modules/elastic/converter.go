// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

func stripSegmentOptions(keys []string) []string {
	tmp := make([]string, 0, 0)
	for _, k := range keys {
		if !strings.HasPrefix(k, "-") {
			tmp = append(tmp, k)
		}
	}
	return tmp
}

func makeAggregation(fieldDefs map[string]*FieldDefinition, prefix string, keys []string, count int, ascending bool) (map[string]interface{}, string) {
	agg := make(map[string]interface{})
	orderFields := make(map[string]interface{})
	orderFields["_count"] = "desc"
	if ascending {
		orderFields["_count"] = "asc"
	}
	aggFields := make(map[string]interface{})
	if strings.HasSuffix(keys[0], "*") {
		keys[0] = strings.TrimSuffix(keys[0], "*")
		aggFields["missing"] = "__missing__"
	}

	aggFields["field"] = mapElasticField(fieldDefs, keys[0])
	aggFields["size"] = count
	aggFields["order"] = orderFields
	agg["terms"] = aggFields

	name := prefix + "|" + keys[0]
	if len(keys) > 1 {
		inner := make(map[string]interface{})
		innerAgg, innerName := makeAggregation(fieldDefs, name, keys[1:], count, ascending)
		inner[innerName] = innerAgg
		agg["aggs"] = inner
	}
	return agg, name
}

func makeTimeline(interval string) map[string]interface{} {
	timeline := make(map[string]interface{})
	timelineFields := make(map[string]interface{})
	timelineFields["field"] = "@timestamp"
	timelineFields["fixed_interval"] = interval
	timelineFields["min_doc_count"] = 1
	timeline["date_histogram"] = timelineFields
	return timeline
}

func formatSearch(input string) string {
	input = strings.Trim(input, " ")
	if len(input) == 0 {
		input = "*"
	}
	return input
}

func mapSearch(fieldDefs map[string]*FieldDefinition, searchSegment *model.SearchSegment) *model.SearchSegment {
	const delim = ":"
	for _, term := range searchSegment.Terms() {
		if strings.HasSuffix(term.Raw, delim) && !term.Grouped && !term.Quoted {
			field := strings.Trim(term.Raw, delim)
			newField := mapElasticField(fieldDefs, field)
			if newField != field {
				term.Raw = newField + delim
			}
		}
	}
	return searchSegment
}

func makeQuery(fieldDefs map[string]*FieldDefinition, parsedQuery *model.Query, beginTime time.Time, endTime time.Time) map[string]interface{} {
	searchString := ""
	segment := parsedQuery.NamedSegment(model.SegmentKind_Search)
	if segment != nil {
		searchSegment := segment.(*model.SearchSegment)
		searchString = mapSearch(fieldDefs, searchSegment).String()
	}

	queryDetails := make(map[string]interface{})
	queryDetails["query"] = formatSearch(searchString)
	queryDetails["analyze_wildcard"] = true
	queryDetails["default_field"] = "*"

	query := make(map[string]interface{})
	query["query_string"] = queryDetails
	must := make([]interface{}, 0)
	must = append(must, query)

	if !endTime.IsZero() {
		timestampDetails := make(map[string]interface{})
		timestampDetails["gte"] = beginTime.Format(time.RFC3339)
		timestampDetails["lte"] = endTime.Format(time.RFC3339)
		timestampDetails["format"] = "strict_date_optional_time"

		timerangeDetails := make(map[string]interface{})
		timerangeDetails["@timestamp"] = timestampDetails

		timerange := make(map[string]interface{})
		timerange["range"] = timerangeDetails
		must = append(must, timerange)
	}

	terms := make(map[string]interface{})
	terms["must"] = must
	terms["filter"] = []interface{}{}
	terms["should"] = []interface{}{}
	terms["must_not"] = []interface{}{}

	clause := make(map[string]interface{})
	clause["bool"] = terms

	return clause
}

func calcTimelineInterval(intervals int, beginTime time.Time, endTime time.Time) string {
	difference := endTime.Sub(beginTime)
	intervalSeconds := difference.Seconds() / float64(intervals)

	// Find a common interval nearest the calculated interval
	if intervalSeconds <= 3 {
		return "1s"
	}
	if intervalSeconds <= 7 {
		return "5s"
	}
	if intervalSeconds <= 13 {
		return "10s"
	}
	if intervalSeconds <= 23 {
		return "15s"
	}
	if intervalSeconds <= 45 {
		return "30s"
	}
	if intervalSeconds <= 180 {
		return "1m"
	}
	if intervalSeconds <= 420 {
		return "5m"
	}
	if intervalSeconds <= 780 {
		return "10m"
	}
	if intervalSeconds <= 1380 {
		return "15m"
	}
	if intervalSeconds <= 2700 {
		return "30m"
	}
	if intervalSeconds <= 5400 {
		return "1h"
	}
	if intervalSeconds <= 25200 {
		return "5h"
	}
	if intervalSeconds <= 54000 {
		return "10h"
	}
	if intervalSeconds <= 259200 {
		return "1d"
	}
	if intervalSeconds <= 604800 {
		return "5d"
	}
	if intervalSeconds <= 1296000 {
		return "10d"
	}
	return "30d"
}

func convertToElasticRequest(fieldDefs map[string]*FieldDefinition, intervals int, criteria *model.EventSearchCriteria) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["size"] = criteria.EventLimit
	esMap["query"] = makeQuery(fieldDefs, criteria.ParsedQuery, criteria.BeginTime, criteria.EndTime)

	if len(criteria.SearchAfter) != 0 {
		esMap["search_after"] = criteria.SearchAfter
	}

	aggregations := make(map[string]interface{})

	if criteria.MetricLimit > 0 {
		if !criteria.EndTime.IsZero() {
			aggregations["timeline"] = makeTimeline(calcTimelineInterval(intervals, criteria.BeginTime, criteria.EndTime))
		}
		segments := criteria.ParsedQuery.NamedSegments(model.SegmentKind_GroupBy)
		for idx, segment := range segments {
			groupBySegment := segment.(*model.GroupBySegment)
			fields := groupBySegment.RawFields()
			fields = stripSegmentOptions(fields)
			if len(fields) > 0 {
				prefix := fmt.Sprintf("groupby_%d", idx)
				agg, name := makeAggregation(fieldDefs, prefix, fields, criteria.MetricLimit, false)
				aggregations[name] = agg
				if aggregations["bottom"] == nil {
					aggregations["bottom"], _ = makeAggregation(fieldDefs, "", fields[0:1], criteria.MetricLimit, true)
				}
			}
		}
	}

	if len(aggregations) > 0 {
		esMap["aggs"] = aggregations
	}

	segment := criteria.ParsedQuery.NamedSegment(model.SegmentKind_SortBy)
	if segment != nil {
		sortBySegment := segment.(*model.SortBySegment)
		fields := sortBySegment.RawFields()
		if len(fields) > 0 {
			sorting := []map[string]map[string]string{}
			for _, field := range fields {
				newSort := make(map[string]map[string]string)
				order := "desc"
				if strings.HasSuffix(field, "^") {
					field = strings.TrimSuffix(field, "^")
					order = "asc"
				}
				sortParams := make(map[string]string)
				sortParams["order"] = order
				sortParams["missing"] = "_last"
				sortParams["unmapped_type"] = "date"
				newSort[field] = sortParams
				sorting = append(sorting, newSort)
			}

			if len(sorting) != 0 {
				esMap["sort"] = sorting
			}
		}
	} else {
		sort := map[string]string{}
		for _, field := range criteria.SortFields {
			sort[field.Field] = field.Order
		}

		if len(sort) != 0 {
			esMap["sort"] = sort
		}
	}

	bytes, err := json.WriteJson(esMap)
	if err == nil {
		esJson = string(bytes)
	}

	return esJson, err
}

func convertToElasticScrollRequest(fieldDefs map[string]*FieldDefinition, criteria *model.EventScrollCriteria, maxScrollSize int) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["size"] = maxScrollSize
	esMap["query"] = makeQuery(fieldDefs, criteria.ParsedQuery, criteria.BeginTime, criteria.EndTime)

	bytes, err := json.WriteJson(esMap)
	if err == nil {
		esJson = string(bytes)
	}

	return esJson, err
}

func parseAggregation(name string, aggObj interface{}, keys []interface{}, results *model.EventSearchResults) {
	agg := aggObj.(map[string]interface{})
	buckets := agg["buckets"]
	if buckets != nil {
		metrics := results.Metrics[name]
		if metrics == nil {
			metrics = []*model.EventMetric{}
		}
		for _, bucketObj := range buckets.([]interface{}) {
			bucket := bucketObj.(map[string]interface{})
			metric := &model.EventMetric{}
			count := bucket["doc_count"]
			if count != nil {
				metric.Value = int(count.(float64))
				key := bucket["key_as_string"]
				if key == nil {
					key = bucket["key"]
				}
				if key != nil {
					tmpKeys := make([]interface{}, len(keys), len(keys)+1)
					copy(tmpKeys, keys)
					tmpKeys = append(tmpKeys, key)
					metric.Keys = tmpKeys
					metrics = append(metrics, metric)
					for innerName, innerAgg := range bucket {
						if strings.HasPrefix(innerName, "groupby_") {
							parseAggregation(innerName, innerAgg, tmpKeys, results)
						}
					}
				}
			}
		}
		results.Metrics[name] = metrics
	}
}

func flattenKeyValue(fieldDefs map[string]*FieldDefinition, fieldMap map[string]interface{}, prefix string, value map[string]interface{}) {
	for key, value := range value {
		flattenedKey := prefix + key
		switch v := value.(type) {
		case map[string]interface{}:
			flattenKeyValue(fieldDefs, fieldMap, flattenedKey+".", v)
		default:
			fieldMap[unmapElasticField(fieldDefs, flattenedKey)] = value
		}
	}
}

func flatten(fieldDefs map[string]*FieldDefinition, data map[string]interface{}) map[string]interface{} {
	fieldMap := make(map[string]interface{})
	flattenKeyValue(fieldDefs, fieldMap, "", data)
	return fieldMap
}

func convertFromElasticResults(fieldDefs map[string]*FieldDefinition, esJson string, results *model.EventSearchResults) error {
	esResults := make(map[string]interface{})
	err := json.LoadJson([]byte(esJson), &esResults)
	if esResults["took"] == nil || esResults["timed_out"] == nil || esResults["hits"] == nil {
		return errors.New("Elasticsearch response is not a valid JSON search result")
	}
	results.ElapsedMs = int(esResults["took"].(float64))
	timedOut := esResults["timed_out"].(bool)
	if timedOut {
		return errors.New("Timeout while fetching results from Elasticsearch")
	}

	hits := esResults["hits"].(map[string]interface{})
	switch hits["total"].(type) {
	case float64:
		results.TotalEvents = int(hits["total"].(float64))
	default:
		total := hits["total"].(map[string]interface{})
		results.TotalEvents = int(total["value"].(float64))
	}

	records := hits["hits"].([]interface{})
	for _, record := range records {
		event := &model.EventRecord{}
		esRecord := record.(map[string]interface{})
		event.Source = esRecord["_index"].(string)
		event.Id = esRecord["_id"].(string)
		if esRecord["_type"] != nil {
			event.Type = esRecord["_type"].(string)
		}
		if esRecord["_score"] != nil {
			event.Score = esRecord["_score"].(float64)
		}
		event.Payload = flatten(fieldDefs, esRecord["_source"].(map[string]interface{}))
		if esRecord["sort"] != nil {
			event.Sort = esRecord["sort"].([]interface{})
		}

		if event.Payload["@timestamp"] != nil {
			event.Time, _ = time.Parse(time.RFC3339, event.Payload["@timestamp"].(string))
		} else if event.Payload["timestamp"] != nil {
			event.Time, _ = time.Parse(time.RFC3339, event.Payload["timestamp"].(string))
		}
		event.Timestamp = event.Time.Format("2006-01-02T15:04:05.000Z")
		results.Events = append(results.Events, event)
	}

	aggs := esResults["aggregations"]
	if aggs != nil {
		for name, aggObj := range aggs.(map[string]interface{}) {
			keys := make([]interface{}, 0)
			parseAggregation(name, aggObj, keys, results)
		}
	}

	shards := esResults["_shards"].(map[string]interface{})
	failed := shards["failed"].(float64)
	if failed > 0 {
		failures := shards["failures"].([]interface{})
		for _, failureGeneric := range failures {
			failure := failureGeneric.(map[string]interface{})
			reason := failure["reason"].(map[string]interface{})
			reasonType := ""
			if reason["type"] != nil {
				reasonType = reason["type"].(string)
			}
			reasonDetails := "N/A"
			if reason["reason"] != nil {
				reasonDetails = reason["reason"].(string)
			}
			log.WithFields(log.Fields{
				"reasonType": reasonType,
				"reason":     reasonDetails,
			}).Warn("Shard failure")
			err = errors.New("ERROR_QUERY_FAILED_ELASTICSEARCH")
		}
	}

	return err
}

func convertFromElasticScrollResults(fieldDefs map[string]*FieldDefinition, esJson string, results *model.EventScrollResults) error {
	esResults := make(map[string]interface{})
	err := json.LoadJson([]byte(esJson), &esResults)
	if esResults["took"] == nil || esResults["timed_out"] == nil || esResults["hits"] == nil {
		return errors.New("Elasticsearch response is not a valid JSON search result")
	}
	results.ElapsedMs = int(esResults["took"].(float64))
	timedOut := esResults["timed_out"].(bool)
	if timedOut {
		return errors.New("Timeout while fetching results from Elasticsearch")
	}

	hits := esResults["hits"].(map[string]interface{})
	switch hits["total"].(type) {
	case float64:
		results.TotalEvents = int(hits["total"].(float64))
	default:
		total := hits["total"].(map[string]interface{})
		results.TotalEvents = int(total["value"].(float64))
	}

	records := hits["hits"].([]interface{})
	for _, record := range records {
		event := &model.EventRecord{}
		esRecord := record.(map[string]interface{})
		event.Source = esRecord["_index"].(string)
		event.Id = esRecord["_id"].(string)
		if esRecord["_type"] != nil {
			event.Type = esRecord["_type"].(string)
		}
		if esRecord["_score"] != nil {
			event.Score = esRecord["_score"].(float64)
		}
		event.Payload = flatten(fieldDefs, esRecord["_source"].(map[string]interface{}))
		if esRecord["sort"] != nil {
			event.Sort = esRecord["sort"].([]interface{})
		}

		if event.Payload["@timestamp"] != nil {
			event.Time, _ = time.Parse(time.RFC3339, event.Payload["@timestamp"].(string))
		} else if event.Payload["timestamp"] != nil {
			event.Time, _ = time.Parse(time.RFC3339, event.Payload["timestamp"].(string))
		}
		event.Timestamp = event.Time.Format("2006-01-02T15:04:05.000Z")
		results.Events = append(results.Events, event)
	}

	shards := esResults["_shards"].(map[string]interface{})
	failed := shards["failed"].(float64)
	if failed > 0 {
		failures := shards["failures"].([]interface{})
		for _, failureGeneric := range failures {
			failure := failureGeneric.(map[string]interface{})
			reason := failure["reason"].(map[string]interface{})
			reasonType := ""
			if reason["type"] != nil {
				reasonType = reason["type"].(string)
			}
			reasonDetails := "N/A"
			if reason["reason"] != nil {
				reasonDetails = reason["reason"].(string)
			}
			log.WithFields(log.Fields{
				"shardFailureReasonType": reasonType,
				"shardFailureReason":     reasonDetails,
			}).Warn("Shard failure")
			err = errors.New("ERROR_QUERY_FAILED_ELASTICSEARCH")
		}
	}

	return err
}

func parseTime(fieldmap map[string]interface{}, key string) *time.Time {
	var t time.Time

	if value, ok := fieldmap[key]; ok {
		switch v := value.(type) {
		case time.Time:
			t = v
		case *time.Time:
			t = *v
		case string:
			t, _ = time.Parse(time.RFC3339, v)
		}
	}

	return &t
}

func convertElasticEventToAuditable(event *model.EventRecord, auditable *model.Auditable, schemaPrefix string) error {
	auditable.Id = event.Id
	auditable.UpdateTime = &event.Time
	if value, ok := event.Payload[schemaPrefix+"kind"]; ok {
		auditable.Kind = value.(string)
	}
	if value, ok := event.Payload[schemaPrefix+"operation"]; ok {
		auditable.Operation = value.(string)
	}
	return nil
}

func convertSeverity(sev string) string {
	sev = strings.ToLower(sev)
	if len(sev) != 0 {
		switch sev {
		case "1":
			sev = "low"
		case "2":
			sev = "medium"
		case "3":
			sev = "high"
		case "4":
			sev = "critical"
		}
	} else {
		sev = "high"
	}
	return sev
}

func convertElasticEventToCase(event *model.EventRecord, schemaPrefix string) (*model.Case, error) {
	var err error
	var obj *model.Case

	if event != nil {
		obj = model.NewCase()
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"case.title"]; ok {
				obj.Title = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.description"]; ok {
				obj.Description = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.priority"]; ok {
				obj.Priority = int(value.(float64))
			}
			if value, ok := event.Payload[schemaPrefix+"case.severity"]; ok {
				obj.Severity = convertSeverity(value.(string))
			}
			if value, ok := event.Payload[schemaPrefix+"case.status"]; ok {
				obj.Status = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.template"]; ok {
				obj.Template = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.assigneeId"]; ok {
				obj.AssigneeId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.tlp"]; ok {
				obj.Tlp = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.category"]; ok {
				obj.Category = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.pap"]; ok {
				obj.Pap = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"case.tags"]; ok && value != nil {
				obj.Tags = convertToStringArray(value.([]interface{}))
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"case.createTime")
			obj.StartTime = parseTime(event.Payload, schemaPrefix+"case.startTime")
			obj.CompleteTime = parseTime(event.Payload, schemaPrefix+"case.completeTime")
		}
	}
	return obj, err
}

func convertToStringArray(input []interface{}) []string {
	out := make([]string, len(input))
	for idx, value := range input {
		out[idx] = value.(string)
	}
	return out
}

func convertElasticEventToComment(event *model.EventRecord, schemaPrefix string) (*model.Comment, error) {
	var err error
	var obj *model.Comment

	if event != nil {
		obj = model.NewComment()
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"comment.description"]; ok {
				obj.Description = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"comment.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"comment.caseId"]; ok {
				obj.CaseId = value.(string)
			}
			if licensing.IsEnabled(licensing.FEAT_TTR) {
				if value, ok := event.Payload[schemaPrefix+"comment.hours"]; ok {
					obj.Hours = value.(float64)
				}
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"comment.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToDetectionComment(event *model.EventRecord, schemaPrefix string) (*model.DetectionComment, error) {
	var err error
	var obj *model.DetectionComment

	if event != nil {
		obj = &model.DetectionComment{}
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"detectioncomment.value"]; ok {
				obj.Value = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detectioncomment.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detectioncomment.detectionId"]; ok {
				obj.DetectionId = value.(string)
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"detectioncomment.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToRelatedEvent(event *model.EventRecord, schemaPrefix string) (*model.RelatedEvent, error) {
	var err error
	var obj *model.RelatedEvent

	if event != nil {
		obj = model.NewRelatedEvent()
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			obj.Fields = make(map[string]interface{})
			for key, value := range event.Payload {
				if strings.HasPrefix(key, schemaPrefix+"related.fields.") {
					key = strings.TrimPrefix(key, schemaPrefix+"related.fields.")
					obj.Fields[key] = value
				}
			}

			if value, ok := event.Payload[schemaPrefix+"related.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"related.caseId"]; ok {
				obj.CaseId = value.(string)
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"related.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToArtifact(event *model.EventRecord, schemaPrefix string) (*model.Artifact, error) {
	var err error
	var obj *model.Artifact

	if event != nil {
		obj = model.NewArtifact()
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"artifact.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.caseId"]; ok {
				obj.CaseId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.groupType"]; ok {
				obj.GroupType = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.groupId"]; ok {
				obj.GroupId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.description"]; ok {
				obj.Description = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.artifactType"]; ok {
				obj.ArtifactType = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.streamLength"]; ok {
				obj.StreamLen = int(value.(float64))
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.streamId"]; ok {
				obj.StreamId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.mimeType"]; ok {
				obj.MimeType = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.value"]; ok {
				obj.Value = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.tlp"]; ok {
				obj.Tlp = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.tags"]; ok && value != nil {
				obj.Tags = convertToStringArray(value.([]interface{}))
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.ioc"]; ok {
				obj.Ioc = value.(bool)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.md5"]; ok {
				obj.Md5 = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.sha1"]; ok {
				obj.Sha1 = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.sha256"]; ok {
				obj.Sha256 = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifact.protected"]; ok {
				obj.Protected = value.(bool)
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"artifact.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToArtifactStream(event *model.EventRecord, schemaPrefix string) (*model.ArtifactStream, error) {
	var err error
	var obj *model.ArtifactStream

	if event != nil {
		obj = model.NewArtifactStream()
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"artifactstream.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"artifactstream.content"]; ok {
				obj.Content = value.(string)
			}
			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"artifactstream.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToDetection(event *model.EventRecord, schemaPrefix string) (*model.Detection, error) {
	var err error
	var obj *model.Detection

	if event != nil {
		obj = &model.Detection{}
		err = convertElasticEventToAuditable(event, &obj.Auditable, schemaPrefix)
		if err == nil {
			if value, ok := event.Payload[schemaPrefix+"detection.userId"]; ok {
				obj.UserId = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.publicId"]; ok {
				obj.PublicID = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.title"]; ok {
				obj.Title = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.severity"]; ok {
				obj.Severity = model.Severity(value.(string))
			}
			if value, ok := event.Payload[schemaPrefix+"detection.author"]; ok {
				obj.Author = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.description"]; ok {
				obj.Description = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.content"]; ok {
				obj.Content = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.isEnabled"]; ok {
				obj.IsEnabled = value.(bool)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.isReporting"]; ok {
				obj.IsReporting = value.(bool)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.isCommunity"]; ok {
				obj.IsCommunity = value.(bool)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.ruleset"]; ok {
				if value != nil {
					obj.Ruleset = value.(string)
				}
			}
			if value, ok := event.Payload[schemaPrefix+"detection.engine"]; ok {
				obj.Engine = model.EngineName(value.(string))
			}
			if value, ok := event.Payload[schemaPrefix+"detection.language"]; ok {
				obj.Language = model.SigLanguage(value.(string))
			}
			if value, ok := event.Payload[schemaPrefix+"detection.license"]; ok {
				obj.License = value.(string)
			}
			if value, ok := event.Payload[schemaPrefix+"detection.tags"]; ok && value != nil {
				arr := value.([]interface{})
				obj.Tags = make([]string, 0, len(arr))

				for _, tag := range arr {
					obj.Tags = append(obj.Tags, tag.(string))
				}
			}
			if value, ok := event.Payload[schemaPrefix+"detection.overrides"]; ok && value != nil {
				obj.Overrides = convertElasticEventToOverride(value.([]interface{}))
			}

			obj.CreateTime = parseTime(event.Payload, schemaPrefix+"detection.createTime")
		}
	}

	return obj, err
}

func convertElasticEventToOverride(overrides []interface{}) []*model.Override {
	overs := make([]*model.Override, 0, len(overrides))
	for _, inter := range overrides {
		override := inter.(map[string]interface{})
		over := &model.Override{}

		if value, ok := override["type"]; ok {
			over.Type = model.OverrideType(value.(string))
		}
		if value, ok := override["isEnabled"]; ok {
			over.IsEnabled = value.(bool)
		}
		if value, ok := override["note"]; ok {
			over.Note = value.(string)
		}
		if value, ok := override["createdAt"]; ok {
			over.CreatedAt, _ = time.Parse(time.RFC3339, value.(string))
		}
		if value, ok := override["updatedAt"]; ok {
			over.UpdatedAt, _ = time.Parse(time.RFC3339, value.(string))
		}
		if value, ok := override["thresholdType"]; ok && value != nil {
			over.ThresholdType = util.Ptr(value.(string))
		}
		if value, ok := override["regex"]; ok && value != nil {
			over.Regex = util.Ptr(value.(string))
		}
		if value, ok := override["value"]; ok && value != nil {
			over.Value = util.Ptr(value.(string))
		}
		if value, ok := override["ip"]; ok && value != nil {
			over.IP = util.Ptr(value.(string))
		}
		if value, ok := override["track"]; ok && value != nil {
			over.Track = util.Ptr(value.(string))
		}
		if value, ok := override["count"]; ok && value != nil {
			over.Count = util.Ptr(int(value.(float64)))
		}
		if value, ok := override["seconds"]; ok && value != nil {
			over.Seconds = util.Ptr(int(value.(float64)))
		}
		if value, ok := override["customFilter"]; ok && value != nil {
			over.CustomFilter = util.Ptr(value.(string))
		}

		overs = append(overs, over)
	}

	return overs
}

func convertElasticEventToObject(event *model.EventRecord, schemaPrefix string) (interface{}, error) {
	var obj interface{}
	var err error

	if value, ok := event.Payload[schemaPrefix+"kind"]; ok {
		switch value.(string) {
		case "case":
			obj, err = convertElasticEventToCase(event, schemaPrefix)
		case "comment":
			obj, err = convertElasticEventToComment(event, schemaPrefix)
		case "detectioncomment":
			obj, err = convertElasticEventToDetectionComment(event, schemaPrefix)
		case "related":
			obj, err = convertElasticEventToRelatedEvent(event, schemaPrefix)
		case "artifact":
			obj, err = convertElasticEventToArtifact(event, schemaPrefix)
		case "artifactstream":
			obj, err = convertElasticEventToArtifactStream(event, schemaPrefix)
		case "detection":
			obj, err = convertElasticEventToDetection(event, schemaPrefix)
		}
	} else {
		err = errors.New("Unknown object kind; id=" + event.Id)
	}
	return obj, err
}

func convertToElasticUpdateRequest(store *ElasticEventstore, criteria *model.EventUpdateCriteria) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["query"] = makeQuery(store.fieldDefs, criteria.ParsedQuery, criteria.BeginTime, criteria.EndTime)

	script := make(map[string]string)
	script["inline"] = strings.Join(criteria.UpdateScripts, "; ")
	script["lang"] = "painless"
	esMap["script"] = script

	bytes, err := json.WriteJson(esMap)
	if err == nil {
		esJson = string(bytes)
	}

	return esJson, err
}

func convertFromElasticUpdateResults(store *ElasticEventstore, esJson string, results *model.EventUpdateResults) error {
	esResults := make(map[string]interface{})
	err := json.LoadJson([]byte(esJson), &esResults)
	if esResults["took"] == nil || esResults["timed_out"] == nil || esResults["updated"] == nil || esResults["noops"] == nil {
		return errors.New("Elasticsearch response is not a valid JSON updated result")
	}
	results.ElapsedMs = int(esResults["took"].(float64))
	timedOut := esResults["timed_out"].(bool)
	if timedOut {
		return errors.New("Timeout while updating documents in Elasticsearch")
	}

	results.UpdatedCount = int(esResults["updated"].(float64))
	results.UnchangedCount = int(esResults["noops"].(float64))

	return err
}

func ConvertObjectToDocumentMap(name string, obj interface{}, schemaPrefix string) map[string]interface{} {
	doc := make(map[string]interface{})
	doc[schemaPrefix+name] = obj
	doc["@timestamp"] = time.Now()
	return doc
}

func convertToElasticIndexRequest(event map[string]interface{}) (string, error) {
	var err error
	var esJson string

	bytes, err := json.WriteJson(event)
	if err == nil {
		esJson = string(bytes)
	}

	return esJson, err
}

func convertFromElasticIndexResults(esJson string, results *model.EventIndexResults) error {
	esResults := make(map[string]interface{})
	err := json.LoadJson([]byte(esJson), &esResults)

	results.DocumentId = esResults["_id"].(string)
	result := esResults["result"].(string)
	results.Success = result == "created" || result == "updated"

	return err
}
