// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func NewTestStore() *ElasticEventstore {
	return &ElasticEventstore{
		fieldDefs: make(map[string]*FieldDefinition),
		intervals: DEFAULT_INTERVALS,
	}
}

func TestMakeAggregation(t *testing.T) {
	keys := []string{"one*", "two", "three*"}
	agg, name := makeAggregation(NewTestStore().fieldDefs, "groupby_0", keys, 10, false)
	assert.Equal(t, "groupby_0|one", name)

	assert.NotNil(t, agg["terms"])
	terms := agg["terms"].(map[string]interface{})
	assert.Equal(t, "one", terms["field"])
	assert.Equal(t, "__missing__", terms["missing"])
	assert.Equal(t, 10, terms["size"])

	assert.NotNil(t, terms["order"])
	order := terms["order"].(map[string]interface{})
	assert.Equal(t, "desc", order["_count"])

	assert.NotNil(t, agg["aggs"])
	secondAggs := agg["aggs"].(map[string]interface{})
	assert.NotNil(t, secondAggs["groupby_0|one|two"])
	secondAgg := secondAggs["groupby_0|one|two"].(map[string]interface{})
	assert.NotNil(t, secondAgg["aggs"])
	terms = secondAgg["terms"].(map[string]interface{})
	assert.Nil(t, terms["missing"])

	thirdAggs := secondAgg["aggs"].(map[string]interface{})
	assert.NotNil(t, thirdAggs["groupby_0|one|two|three"])
	thirdAgg := thirdAggs["groupby_0|one|two|three"].(map[string]interface{})
	assert.Nil(t, thirdAgg["aggs"])
	terms = thirdAgg["terms"].(map[string]interface{})
	assert.Equal(t, "__missing__", terms["missing"])
}

func TestMakeTimeline(t *testing.T) {
	timeline := makeTimeline("30m")
	assert.NotNil(t, timeline["date_histogram"])
	terms := timeline["date_histogram"].(map[string]interface{})
	assert.Equal(t, "@timestamp", terms["field"])
	assert.Equal(t, "30m", terms["fixed_interval"])
	assert.Equal(t, 1, terms["min_doc_count"])
}

func TestCalcTimelineInterval(t *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2021-01-02T05:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	interval := calcTimelineInterval(25, start, end)
	assert.Equal(t, "15m", interval)

	// Boundaries
	start, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	end, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:01Z")
	interval = calcTimelineInterval(25, start, end)
	assert.Equal(t, "1s", interval)

	start, _ = time.Parse(time.RFC3339, "1990-01-02T05:00:00Z")
	end, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	interval = calcTimelineInterval(25, start, end)
	assert.Equal(t, "30d", interval)
}

func TestConvertToElasticRequestEmptyCriteria(t *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.MetricLimit = 0
	teststore := NewTestStore()
	actualJson, err := convertToElasticRequest(teststore.fieldDefs, teststore.intervals, criteria)
	assert.Nil(t, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}}],"must_not":[],"should":[]}},"size":25}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertToElasticRequestGroupByCriteria(t *testing.T) {
	criteria := model.NewEventSearchCriteria()

	err := criteria.Populate(`abc AND def AND q:"\\\\file\\path" | groupby -something "ghi" jkl*`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	assert.NoError(t, err)

	teststore := NewTestStore()
	actualJson, err := convertToElasticRequest(teststore.fieldDefs, teststore.intervals, criteria)
	assert.Nil(t, err)

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby_0|ghi":{"aggs":{"groupby_0|ghi|jkl":{"terms":{"field":"jkl","missing":"__missing__","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertToElasticRequestSortByCriteria(t *testing.T) {
	criteria := model.NewEventSearchCriteria()

	err := criteria.Populate(`abc AND def AND q:"\\\\file\\path" | sortby "ghi" jkl^`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	assert.NoError(t, err)

	criteria.SortFields = []*model.SortCriteria{
		{Field: "ignored", Order: "ignored"},
	}

	teststore := NewTestStore()

	actualJson, err := convertToElasticRequest(teststore.fieldDefs, teststore.intervals, criteria)
	assert.Nil(t, err)

	expectedJson := `{"aggs":{"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25,"sort":[{"ghi":{"missing":"_last","order":"desc","unmapped_type":"date"}},{"jkl":{"missing":"_last","order":"asc","unmapped_type":"date"}}]}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertToElasticRequestGroupBySortByCriteria(t *testing.T) {
	criteria := model.NewEventSearchCriteria()
	err := criteria.Populate(`abc AND def AND q:"\\\\file\\path" | groupby ghi jkl* | groupby mno | sortby ghi jkl^`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	assert.NoError(t, err)
	teststore := NewTestStore()
	actualJson, err := convertToElasticRequest(teststore.fieldDefs, teststore.intervals, criteria)
	assert.Nil(t, err)

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby_0|ghi":{"aggs":{"groupby_0|ghi|jkl":{"terms":{"field":"jkl","missing":"__missing__","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"groupby_1|mno":{"terms":{"field":"mno","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25,"sort":[{"ghi":{"missing":"_last","order":"desc","unmapped_type":"date"}},{"jkl":{"missing":"_last","order":"asc","unmapped_type":"date"}}]}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertToElasticRequestProgrammaticSortBy(t *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.MetricLimit = 0
	criteria.SortFields = []*model.SortCriteria{
		{Field: "name", Order: "asc"},
	}
	teststore := NewTestStore()
	actualJson, err := convertToElasticRequest(teststore.fieldDefs, teststore.intervals, criteria)
	assert.Nil(t, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}}],"must_not":[],"should":[]}},"size":25,"sort":{"name":"asc"}}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertFromElasticResultsSuccess(t *testing.T) {
	esData, err := os.ReadFile("converter_response.json")
	assert.Nil(t, err)

	results := model.NewEventSearchResults()
	err = convertFromElasticResults(NewTestStore().fieldDefs, string(esData), results)
	if assert.Nil(t, err) {
		assert.Equal(t, 9534, results.ElapsedMs)
		assert.Equal(t, 23689430, results.TotalEvents)
		assert.Len(t, results.Events, 25)
		assert.Equal(t, "2020-04-24T03:00:55.300Z", results.Events[0].Timestamp)
		assert.Equal(t, "2020-04-24T03:00:55.038Z", results.Events[1].Timestamp) // Check for alternate timestamp field
		assert.Equal(t, "so16:logstash-bro-2020.04.24", results.Events[0].Source)
		assert.NotNil(t, results.Metrics["groupby_0|source_ip"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip|protocol"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip|protocol|destination_port"])
	}
}

func TestConvertFromElasticResultsFailure(t *testing.T) {
	esData, err := os.ReadFile("converter_response_failure.json")
	assert.Nil(t, err)

	results := model.NewEventSearchResults()
	err = convertFromElasticResults(NewTestStore().fieldDefs, string(esData), results)
	if assert.NotNil(t, err) {
		assert.Error(t, err, "ERROR_QUERY_FAILED_ELASTICSEARCH")
		assert.Equal(t, 9534, results.ElapsedMs)
		assert.Equal(t, 23689430, results.TotalEvents)
		assert.Len(t, results.Events, 25)
		assert.Equal(t, "2020-04-24T03:00:55.300Z", results.Events[0].Timestamp)
		assert.Equal(t, "2020-04-24T03:00:55.038Z", results.Events[1].Timestamp) // Check for alternate timestamp field
		assert.Equal(t, "so16:logstash-bro-2020.04.24", results.Events[0].Source)
		assert.NotNil(t, results.Metrics["groupby_0|source_ip"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip|protocol"])
		assert.NotNil(t, results.Metrics["groupby_0|source_ip|destination_ip|protocol|destination_port"])
	}
}

func TestConvertFromElasticResultsTimedOut(t *testing.T) {
	results := model.NewEventSearchResults()
	err := convertFromElasticResults(NewTestStore().fieldDefs, `{ "took": 123, "timed_out": true, "hits": {} }`, results)
	assert.Error(t, err)

	assert.Equal(t, 123, results.ElapsedMs, "ElapsedMs should exist even on timeout.")
}

func TestConvertFromElasticResultsInvalid(t *testing.T) {
	results := model.NewEventSearchResults()
	err := convertFromElasticResults(NewTestStore().fieldDefs, `{ }`, results)
	assert.Error(t, err)
}

func TestConvertToElasticUpdateRequest(t *testing.T) {
	criteria := model.NewEventUpdateCriteria()
	criteria.AddUpdateScript("ctx._source.event.acknowledged=true")
	criteria.AddUpdateScript("ctx._source.event.escalated=true")

	err := criteria.Populate("event.dataset:alerts", "2020/09/24 10:11:12 AM - 2020/09/24 12:14:15 PM", "2006/01/02 3:04:05 PM", "America/New_York", "0", "0")
	assert.NoError(t, err)

	actualJson, err := convertToElasticUpdateRequest(NewTestStore(), criteria)
	assert.Nil(t, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"event.dataset:alerts"}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-09-24T10:11:12-04:00","lte":"2020-09-24T12:14:15-04:00"}}}],"must_not":[],"should":[]}},"script":{"inline":"ctx._source.event.acknowledged=true; ctx._source.event.escalated=true","lang":"painless"}}`
	assert.Equal(t, expectedJson, actualJson)
}

const updateResponse = `{
  "took" : 202,
  "timed_out" : false,
  "total" : 1,
  "updated" : 3,
  "deleted" : 0,
  "batches" : 1,
  "version_conflicts" : 0,
  "noops" : 2,
  "retries" : {
    "bulk" : 0,
    "search" : 0
  },
  "throttled_millis" : 0,
  "requests_per_second" : -1.0,
  "throttled_until_millis" : 0,
  "failures" : [ ]
}`

func TestConvertFromElasticUpdateResultsSuccess(t *testing.T) {
	results := model.NewEventUpdateResults()
	err := convertFromElasticUpdateResults(NewTestStore(), updateResponse, results)
	if assert.Nil(t, err) {
		assert.Equal(t, 202, results.ElapsedMs)
		assert.Equal(t, 3, results.UpdatedCount)
		assert.Equal(t, 2, results.UnchangedCount)
	}
}

func TestAddEventUpdateResults(t *testing.T) {
	results1 := model.NewEventUpdateResults()
	results1.ElapsedMs = 100
	results1.UpdatedCount = 200
	results1.UnchangedCount = 400
	results2 := model.NewEventUpdateResults()
	results2.ElapsedMs = 12
	results2.UpdatedCount = 2
	results2.UnchangedCount = 4

	results1.AddEventUpdateResults(results2)
	assert.Equal(t, 112, results1.ElapsedMs)
	assert.Equal(t, 202, results1.UpdatedCount)
	assert.Equal(t, 404, results1.UnchangedCount)
}

func validateFormatSearch(t *testing.T, original string, expected string) {
	output := formatSearch(original)
	assert.Equal(t, expected, output)
}

func TestFormatSearch(t *testing.T) {
	validateFormatSearch(t, "", "*")
	validateFormatSearch(t, " ", "*")
	validateFormatSearch(t, "\\foo\\bar", "\\foo\\bar")
}

func validateMappedQuery(t *testing.T, original string, expected string) {
	store := NewTestStore()
	store.fieldDefs["foo"] = &FieldDefinition{aggregatable: false}
	store.fieldDefs["foo.keyword"] = &FieldDefinition{aggregatable: true}
	query := model.NewQuery()
	query.Parse(original)
	search := query.NamedSegment(model.SegmentKind_Search)
	mapSearch(store.fieldDefs, search.(*model.SearchSegment))
	output := search.String()
	assert.Equal(t, expected, output)
}

func TestMapSearch(t *testing.T) {
	validateMappedQuery(t, "foo: \"bar\"", "foo.keyword: \"bar\"")
	validateMappedQuery(t, "foo: \"bar\" AND barfoo: \"blue\"", "foo.keyword: \"bar\" AND barfoo: \"blue\"")
	validateMappedQuery(t, "foo: 123", "foo.keyword: 123")
	validateMappedQuery(t, "(foo: \"123\")", "(foo: \"123\")")
	validateMappedQuery(t, "foo2: \"bar\"", "foo2: \"bar\"")
	validateMappedQuery(t, "barfoo: \"bar\"", "barfoo: \"bar\"")
	validateMappedQuery(t, "barfoo: \"foo: bar\"", "barfoo: \"foo: bar\"")
}

func TestConvertObjectToDocumentMap(t *testing.T) {
	caseObj := model.NewCase()
	actual := ConvertObjectToDocumentMap("test", caseObj, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NotNil(t, actual)
	assert.Equal(t, caseObj, actual["so_test"])
	assert.NotNil(t, actual["@timestamp"])
}

func TestConvertToElasticIndexRequest(t *testing.T) {
	event := make(map[string]interface{})
	event["foo"] = "bar"
	expected := `{"foo":"bar"}`

	actual, err := convertToElasticIndexRequest(event)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestConvertFromElasticIndexResults(t *testing.T) {
	results := model.NewEventIndexResults()
	json := `{"_version":1, "_id":"123abc", "result": "successful"}`

	err := convertFromElasticIndexResults(json, results)
	assert.NoError(t, err)
}

func TestConvertFromElasticResults_Failure(t *testing.T) {
	store := NewTestStore()
	results := model.NewEventSearchResults()
	json := `{"took" : 11,"timed_out" : false,"_shards" : {"total" : 28,"successful" : 16,"skipped" : 0,"failed" : 12,"failures" : [{"shard" : 0,"index" : "manager:.ds-logs-elastic_agent-default-2023.09.29-000002","node" : null,"reason" : {"type" : "no_shard_available_action_exception","reason" : "no"}},{"shard" : 0,"index" : "manager:.ds-logs-elastic_agent.filebeat-default-2023.09.29-000002","node" : null,"reason" : {"type" : null,"reason" : null}},{"shard" : 0,"index" : "manager:.ds-logs-elastic_agent.fleet_server-default-2023.09.29-000002","node" : null,"reason" : {"type" : "no_shard_available_action_exception","reason" : null}}]}, "hits":{"hits":[],"total":{"value": 0}}}`

	err := convertFromElasticResults(store.fieldDefs, json, results)
	assert.Error(t, err, "ERROR_QUERY_FAILED_ELASTICSEARCH")
}

func TestConvertElasticEventToCaseNil(t *testing.T) {
	caseObj, err := convertElasticEventToCase(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	assert.Nil(t, caseObj)
}

func TestConvertElasticEventToCaseWithoutTags(t *testing.T) {
	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["kind"] = "case"
	event.Payload["operation"] = "create"
	event.Payload["case.tags"] = nil

	_, err := convertElasticEventToCase(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
}

func TestConvertElasticEventToCase(t *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)
	myCompleteTime := myTime.Add(time.Hour * -2)
	myStartTime := myTime.Add(time.Hour * -3)

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "case"
	event.Payload["so_operation"] = "update"
	event.Payload["so_case.title"] = "myTitle"
	event.Payload["so_case.description"] = "myDesc"
	event.Payload["so_case.priority"] = float64(123)
	event.Payload["so_case.severity"] = "medium"
	event.Payload["so_case.status"] = "myStatus"
	event.Payload["so_case.template"] = "myTemplate"
	event.Payload["so_case.userId"] = "myUserId"
	event.Payload["so_case.assigneeId"] = "myAssigneeId"
	event.Payload["so_case.tlp"] = "myTlp"
	event.Payload["so_case.pap"] = "myPap"
	event.Payload["so_case.category"] = "myCategory"
	tags := make([]interface{}, 2)
	tags[0] = "tag1"
	tags[1] = "tag2"
	event.Payload["so_case.tags"] = tags
	event.Time = myTime
	event.Payload["so_case.createTime"] = myCreateTime
	event.Payload["so_case.completeTime"] = myCompleteTime
	event.Payload["so_case.startTime"] = myStartTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	caseObj := interf.(*model.Case)
	assert.Equal(t, "case", caseObj.Kind)
	assert.Equal(t, "update", caseObj.Operation)
	assert.Equal(t, "myTitle", caseObj.Title)
	assert.Equal(t, "myDesc", caseObj.Description)
	assert.Equal(t, 123, caseObj.Priority)
	assert.Equal(t, "medium", caseObj.Severity)
	assert.Equal(t, "myStatus", caseObj.Status)
	assert.Equal(t, "myTemplate", caseObj.Template)
	assert.Equal(t, "myUserId", caseObj.UserId)
	assert.Equal(t, "myAssigneeId", caseObj.AssigneeId)
	assert.Equal(t, "myPap", caseObj.Pap)
	assert.Equal(t, "myTlp", caseObj.Tlp)
	assert.Equal(t, "myCategory", caseObj.Category)
	assert.Equal(t, tags[0], "tag1")
	assert.Equal(t, tags[1], "tag2")
	assert.Equal(t, &myTime, caseObj.UpdateTime)
	assert.Equal(t, &myCreateTime, caseObj.CreateTime)
	assert.Equal(t, &myCompleteTime, caseObj.CompleteTime)
	assert.Equal(t, &myStartTime, caseObj.StartTime)
}

func TestConvertElasticEventToArtifactNil(t *testing.T) {
	artifactObj, err := convertElasticEventToArtifact(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	assert.Nil(t, artifactObj)
}

func TestConvertElasticEventToArtifactWithoutTags(t *testing.T) {
	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "artifact"
	event.Payload["so_operation"] = "create"
	event.Payload["so_case.tags"] = nil

	_, err := convertElasticEventToCase(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
}

func TestConvertElasticEventToArtifact(t *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "artifact"
	event.Payload["so_operation"] = "update"
	event.Payload["so_artifact.value"] = "myValue"
	event.Payload["so_artifact.description"] = "myDesc"
	event.Payload["so_artifact.streamLength"] = float64(123)
	event.Payload["so_artifact.streamId"] = "myStreamId"
	event.Payload["so_artifact.groupType"] = "myGroupType"
	event.Payload["so_artifact.groupId"] = "myGroupId"
	event.Payload["so_artifact.userId"] = "myUserId"
	event.Payload["so_artifact.artifactType"] = "myArtifactType"
	event.Payload["so_artifact.tlp"] = "myTlp"
	event.Payload["so_artifact.mimeType"] = "myMimeType"
	event.Payload["so_artifact.ioc"] = true
	event.Payload["so_artifact.md5"] = "myMd5"
	event.Payload["so_artifact.sha1"] = "mySha1"
	event.Payload["so_artifact.sha256"] = "mySha256"
	tags := make([]interface{}, 2)
	tags[0] = "tag1"
	tags[1] = "tag2"
	event.Payload["so_artifact.tags"] = tags
	event.Time = myTime
	event.Payload["so_artifact.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	artifactObj := interf.(*model.Artifact)
	assert.Equal(t, "artifact", artifactObj.Kind)
	assert.Equal(t, "update", artifactObj.Operation)
	assert.Equal(t, "myValue", artifactObj.Value)
	assert.Equal(t, "myDesc", artifactObj.Description)
	assert.Equal(t, 123, artifactObj.StreamLen)
	assert.Equal(t, "myStreamId", artifactObj.StreamId)
	assert.Equal(t, "myGroupType", artifactObj.GroupType)
	assert.Equal(t, "myGroupId", artifactObj.GroupId)
	assert.Equal(t, "myUserId", artifactObj.UserId)
	assert.Equal(t, "myArtifactType", artifactObj.ArtifactType)
	assert.Equal(t, "myTlp", artifactObj.Tlp)
	assert.Equal(t, "myMimeType", artifactObj.MimeType)
	assert.Equal(t, true, artifactObj.Ioc)
	assert.Equal(t, tags[0], "tag1")
	assert.Equal(t, tags[1], "tag2")
	assert.Equal(t, "myMd5", artifactObj.Md5)
	assert.Equal(t, "mySha1", artifactObj.Sha1)
	assert.Equal(t, "mySha256", artifactObj.Sha256)
	assert.Equal(t, &myTime, artifactObj.UpdateTime)
	assert.Equal(t, &myCreateTime, artifactObj.CreateTime)
}

func TestConvertElasticEventToArtifactStreamNil(t *testing.T) {
	artifactObj, err := convertElasticEventToArtifactStream(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	assert.Nil(t, artifactObj)
}

func TestConvertElasticEventToArtifactStream(t *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "artifactstream"
	event.Payload["so_operation"] = "create"
	event.Payload["so_artifactstream.content"] = "myValue"
	event.Payload["so_artifactstream.userId"] = "myUserId"
	event.Time = myTime
	event.Payload["so_artifactstream.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	obj := interf.(*model.ArtifactStream)
	assert.Equal(t, "artifactstream", obj.Kind)
	assert.Equal(t, "create", obj.Operation)
	assert.Equal(t, "myUserId", obj.UserId)
	assert.Equal(t, &myTime, obj.UpdateTime)
	assert.Equal(t, &myCreateTime, obj.CreateTime)
	assert.Equal(t, "myValue", obj.Content)
}

func TestParseTime(t *testing.T) {
	m := make(map[string]interface{})

	format := "2006-01-02 03:04pm"
	tm, _ := time.Parse(format, "2021-12-20 12:43pm")
	m["obj"] = tm
	m["ptr"] = &tm
	m["str"] = "2021-12-20T12:43:00Z"
	m["bad"] = 12

	expected := "2021-12-20 12:43pm"

	actual := parseTime(m, "obj").Format(format)
	assert.Equal(t, expected, actual)

	actual = parseTime(m, "ptr").Format(format)
	assert.Equal(t, expected, actual)

	actual = parseTime(m, "str").Format(format)
	assert.Equal(t, expected, actual)

	actualObj := parseTime(m, "bad")
	assert.True(t, actualObj.IsZero())
}

func TestConvertElasticEventToCommentNil(t *testing.T) {
	obj, err := convertElasticEventToComment(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	assert.Nil(t, obj)
}

func TestConvertElasticEventToComment(t *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)

	licensing.Test(licensing.FEAT_TTR, 0, 0, "", "")

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "comment"
	event.Payload["so_operation"] = "create"
	event.Payload["so_comment.description"] = "myDesc"
	event.Payload["so_comment.hours"] = 1.52
	event.Payload["so_comment.userId"] = "myUserId"
	event.Payload["so_comment.caseId"] = "myCaseId"
	event.Time = myTime
	event.Payload["so_comment.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	obj := interf.(*model.Comment)
	assert.Equal(t, "comment", obj.Kind)
	assert.Equal(t, "create", obj.Operation)
	assert.Equal(t, "myDesc", obj.Description)
	assert.Equal(t, 1.52, obj.Hours)
	assert.Equal(t, "myUserId", obj.UserId)
	assert.Equal(t, "myCaseId", obj.CaseId)
	assert.Equal(t, &myTime, obj.UpdateTime)
	assert.Equal(t, &myCreateTime, obj.CreateTime)
}

func TestConvertElasticEventToRelatedEvent(t *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "related"
	event.Payload["so_operation"] = "create"
	event.Payload["so_related.fields.foo"] = "bar"
	event.Payload["so_related.userId"] = "myUserId"
	event.Payload["so_related.caseId"] = "myCaseId"
	event.Time = myTime
	event.Payload["so_related.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(t, err)
	obj := interf.(*model.RelatedEvent)
	assert.Equal(t, "related", obj.Kind)
	assert.Equal(t, "create", obj.Operation)
	assert.Equal(t, "myUserId", obj.UserId)
	assert.Equal(t, "myCaseId", obj.CaseId)
	assert.Equal(t, &myTime, obj.UpdateTime)
	assert.Equal(t, &myCreateTime, obj.CreateTime)
	assert.Len(t, obj.Fields, 1)
	assert.Equal(t, "bar", obj.Fields["foo"])
}

func TestConvertSeverity(t *testing.T) {
	assert.Equal(t, "high", convertSeverity(""))
	assert.Equal(t, "unknown", convertSeverity("unknown"))
	assert.Equal(t, "low", convertSeverity("low"))
	assert.Equal(t, "low", convertSeverity("Low"))
	assert.Equal(t, "low", convertSeverity("1"))
	assert.Equal(t, "medium", convertSeverity("medium"))
	assert.Equal(t, "medium", convertSeverity("Medium"))
	assert.Equal(t, "medium", convertSeverity("2"))
	assert.Equal(t, "high", convertSeverity("high"))
	assert.Equal(t, "high", convertSeverity("High"))
	assert.Equal(t, "high", convertSeverity("3"))
	assert.Equal(t, "critical", convertSeverity("critical"))
	assert.Equal(t, "critical", convertSeverity("4"))
	assert.Equal(t, "critical", convertSeverity("Critical"))
}

func TestConvertToElasticScrollRequestEmpty(t *testing.T) {
	criteria := model.NewEventScrollCriteria()
	teststore := NewTestStore()
	actualJson, err := convertToElasticScrollRequest(teststore.fieldDefs, criteria, 10000)
	assert.Nil(t, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}}],"must_not":[],"should":[]}},"size":10000}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertToElasticScrollRequestWithQuery(t *testing.T) {
	criteria := model.NewEventScrollCriteria()
	query := `_index:"*:so-detection" AND so_kind:"detection" AND so_detection.engine:"strelka" AND so_detection.isEnabled:"true"`
	criteria.RawQuery = query
	err := criteria.ParsedQuery.Parse(query)
	assert.NoError(t, err)

	teststore := NewTestStore()
	actualJson, err := convertToElasticScrollRequest(teststore.fieldDefs, criteria, 5000)
	assert.Nil(t, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"_index: \"*:so-detection\" AND so_kind: \"detection\" AND so_detection.engine: \"strelka\" AND so_detection.isEnabled: \"true\""}}],"must_not":[],"should":[]}},"size":5000}`
	assert.Equal(t, expectedJson, actualJson)
}

func TestConvertFromElasticMSearchResults(t *testing.T) {
	esData, err := os.ReadFile("converter_response.json")
	assert.Nil(t, err)

	buf := bytes.Buffer{}
	buf.WriteString(`{ "took": 10, "responses": [`)
	buf.Write(esData)
	buf.WriteString(`]}`)

	results := model.NewEventMSearchResults()
	err = convertFromElasticMSearchResults(NewTestStore().fieldDefs, buf.String(), results)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, results.ElapsedMs)
		assert.Equal(t, 1, len(results.Responses))

		response := results.Responses[0]
		assert.Equal(t, 9534, response.ElapsedMs)
		assert.Equal(t, 23689430, response.TotalEvents)
		assert.Len(t, response.Events, 25)
		assert.Equal(t, "2020-04-24T03:00:55.300Z", response.Events[0].Timestamp)
		assert.Equal(t, "2020-04-24T03:00:55.038Z", response.Events[1].Timestamp) // Check for alternate timestamp field
		assert.Equal(t, "so16:logstash-bro-2020.04.24", response.Events[0].Source)
		assert.NotNil(t, response.Metrics["groupby_0|source_ip"])
		assert.NotNil(t, response.Metrics["groupby_0|source_ip|destination_ip"])
		assert.NotNil(t, response.Metrics["groupby_0|source_ip|destination_ip|protocol"])
		assert.NotNil(t, response.Metrics["groupby_0|source_ip|destination_ip|protocol|destination_port"])
	}
}
