// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func NewTestStore() *ElasticEventstore {
	return &ElasticEventstore{
		fieldDefs: make(map[string]*FieldDefinition),
		intervals: DEFAULT_INTERVALS,
	}
}

func TestMakeAggregation(tester *testing.T) {
	keys := []string{"one*", "two", "three*"}
	agg, name := makeAggregation(NewTestStore(), "groupby_0", keys, 10, false)
	assert.Equal(tester, "groupby_0|one", name)

	assert.NotNil(tester, agg["terms"])
	terms := agg["terms"].(map[string]interface{})
	assert.Equal(tester, "one", terms["field"])
	assert.Equal(tester, "__missing__", terms["missing"])
	assert.Equal(tester, 10, terms["size"])

	assert.NotNil(tester, terms["order"])
	order := terms["order"].(map[string]interface{})
	assert.Equal(tester, "desc", order["_count"])

	assert.NotNil(tester, agg["aggs"])
	secondAggs := agg["aggs"].(map[string]interface{})
	assert.NotNil(tester, secondAggs["groupby_0|one|two"])
	secondAgg := secondAggs["groupby_0|one|two"].(map[string]interface{})
	assert.NotNil(tester, secondAgg["aggs"])
	terms = secondAgg["terms"].(map[string]interface{})
	assert.Nil(tester, terms["missing"])

	thirdAggs := secondAgg["aggs"].(map[string]interface{})
	assert.NotNil(tester, thirdAggs["groupby_0|one|two|three"])
	thirdAgg := thirdAggs["groupby_0|one|two|three"].(map[string]interface{})
	assert.Nil(tester, thirdAgg["aggs"])
	terms = thirdAgg["terms"].(map[string]interface{})
	assert.Equal(tester, "__missing__", terms["missing"])
}

func TestMakeTimeline(tester *testing.T) {
	timeline := makeTimeline("30m")
	assert.NotNil(tester, timeline["date_histogram"])
	terms := timeline["date_histogram"].(map[string]interface{})
	assert.Equal(tester, "@timestamp", terms["field"])
	assert.Equal(tester, "30m", terms["fixed_interval"])
	assert.Equal(tester, 1, terms["min_doc_count"])
}

func TestCalcTimelineInterval(tester *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2021-01-02T05:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	interval := calcTimelineInterval(25, start, end)
	assert.Equal(tester, "15m", interval)

	// Boundaries
	start, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	end, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:01Z")
	interval = calcTimelineInterval(25, start, end)
	assert.Equal(tester, "1s", interval)

	start, _ = time.Parse(time.RFC3339, "1990-01-02T05:00:00Z")
	end, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
	interval = calcTimelineInterval(25, start, end)
	assert.Equal(tester, "30d", interval)
}

func TestConvertToElasticRequestEmptyCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.MetricLimit = 0
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}}],"must_not":[],"should":[]}},"size":25}`
	assert.Equal(tester, expectedJson, actualJson)
}

func TestConvertToElasticRequestGroupByCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.Populate(`abc AND def AND q:"\\\\file\\path" | groupby -something "ghi" jkl*`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby_0|ghi":{"aggs":{"groupby_0|ghi|jkl":{"terms":{"field":"jkl","missing":"__missing__","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25}`
	assert.Equal(tester, expectedJson, actualJson)
}

func TestConvertToElasticRequestSortByCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.Populate(`abc AND def AND q:"\\\\file\\path" | sortby "ghi" jkl^`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"aggs":{"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25,"sort":[{"ghi":{"missing":"_last","order":"desc","unmapped_type":"date"}},{"jkl":{"missing":"_last","order":"asc","unmapped_type":"date"}}]}`
	assert.Equal(tester, expectedJson, actualJson)
}

func TestConvertToElasticRequestGroupBySortByCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.Populate(`abc AND def AND q:"\\\\file\\path" | groupby ghi jkl* | groupby mno | sortby ghi jkl^`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby_0|ghi":{"aggs":{"groupby_0|ghi|jkl":{"terms":{"field":"jkl","missing":"__missing__","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"groupby_1|mno":{"terms":{"field":"mno","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25,"sort":[{"ghi":{"missing":"_last","order":"desc","unmapped_type":"date"}},{"jkl":{"missing":"_last","order":"asc","unmapped_type":"date"}}]}`
	assert.Equal(tester, expectedJson, actualJson)
}

func TestConvertFromElasticResultsSuccess(tester *testing.T) {
	esData, err := ioutil.ReadFile("converter_response.json")
	assert.Nil(tester, err)

	results := model.NewEventSearchResults()
	err = convertFromElasticResults(NewTestStore(), string(esData), results)
	if assert.Nil(tester, err) {
		assert.Equal(tester, 9534, results.ElapsedMs)
		assert.Equal(tester, 23689430, results.TotalEvents)
		assert.Len(tester, results.Events, 25)
		assert.Equal(tester, "2020-04-24T03:00:55.300Z", results.Events[0].Timestamp)
		assert.Equal(tester, "2020-04-24T03:00:55.038Z", results.Events[1].Timestamp) // Check for alternate timestamp field
		assert.Equal(tester, "so16:logstash-bro-2020.04.24", results.Events[0].Source)
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip|protocol"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip|protocol|destination_port"])
	}
}

func TestConvertFromElasticResultsFailure(tester *testing.T) {
	esData, err := ioutil.ReadFile("converter_response_failure.json")
	assert.Nil(tester, err)

	results := model.NewEventSearchResults()
	err = convertFromElasticResults(NewTestStore(), string(esData), results)
	if assert.NotNil(tester, err) {
		assert.Error(tester, err, "ERROR_QUERY_FAILED_ELASTICSEARCH")
		assert.Equal(tester, 9534, results.ElapsedMs)
		assert.Equal(tester, 23689430, results.TotalEvents)
		assert.Len(tester, results.Events, 25)
		assert.Equal(tester, "2020-04-24T03:00:55.300Z", results.Events[0].Timestamp)
		assert.Equal(tester, "2020-04-24T03:00:55.038Z", results.Events[1].Timestamp) // Check for alternate timestamp field
		assert.Equal(tester, "so16:logstash-bro-2020.04.24", results.Events[0].Source)
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip|protocol"])
		assert.NotNil(tester, results.Metrics["groupby_0|source_ip|destination_ip|protocol|destination_port"])
	}
}

func TestConvertFromElasticResultsTimedOut(tester *testing.T) {
	results := model.NewEventSearchResults()
	err := convertFromElasticResults(NewTestStore(), `{ "took": 123, "timed_out": true, "hits": {} }`, results)
	assert.Error(tester, err)

	assert.Equal(tester, 123, results.ElapsedMs, "ElapsedMs should exist even on timeout.")
}

func TestConvertFromElasticResultsInvalid(tester *testing.T) {
	results := model.NewEventSearchResults()
	err := convertFromElasticResults(NewTestStore(), `{ }`, results)
	assert.Error(tester, err)
}

func TestConvertToElasticUpdateRequest(tester *testing.T) {
	criteria := model.NewEventUpdateCriteria()
	criteria.AddUpdateScript("ctx._source.event.acknowledged=true")
	criteria.AddUpdateScript("ctx._source.event.escalated=true")
	criteria.Populate("event.dataset:alerts", "2020/09/24 10:11:12 AM - 2020/09/24 12:14:15 PM", "2006/01/02 3:04:05 PM", "America/New_York", "0", "0")

	actualJson, err := convertToElasticUpdateRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"event.dataset:alerts"}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-09-24T10:11:12-04:00","lte":"2020-09-24T12:14:15-04:00"}}}],"must_not":[],"should":[]}},"script":{"inline":"ctx._source.event.acknowledged=true; ctx._source.event.escalated=true","lang":"painless"}}`
	assert.Equal(tester, expectedJson, actualJson)
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

func TestConvertFromElasticUpdateResultsSuccess(tester *testing.T) {
	results := model.NewEventUpdateResults()
	err := convertFromElasticUpdateResults(NewTestStore(), updateResponse, results)
	if assert.Nil(tester, err) {
		assert.Equal(tester, 202, results.ElapsedMs)
		assert.Equal(tester, 3, results.UpdatedCount)
		assert.Equal(tester, 2, results.UnchangedCount)
	}
}

func TestAddEventUpdateResults(tester *testing.T) {
	results1 := model.NewEventUpdateResults()
	results1.ElapsedMs = 100
	results1.UpdatedCount = 200
	results1.UnchangedCount = 400
	results2 := model.NewEventUpdateResults()
	results2.ElapsedMs = 12
	results2.UpdatedCount = 2
	results2.UnchangedCount = 4

	results1.AddEventUpdateResults(results2)
	assert.Equal(tester, 112, results1.ElapsedMs)
	assert.Equal(tester, 202, results1.UpdatedCount)
	assert.Equal(tester, 404, results1.UnchangedCount)
}

func validateFormatSearch(tester *testing.T, original string, expected string) {
	output := formatSearch(original)
	assert.Equal(tester, expected, output)
}

func TestFormatSearch(tester *testing.T) {
	validateFormatSearch(tester, "", "*")
	validateFormatSearch(tester, " ", "*")
	validateFormatSearch(tester, "\\foo\\bar", "\\foo\\bar")
}

func validateMappedQuery(tester *testing.T, original string, expected string) {
	store := NewTestStore()
	store.fieldDefs["foo"] = &FieldDefinition{aggregatable: false}
	store.fieldDefs["foo.keyword"] = &FieldDefinition{aggregatable: true}
	query := model.NewQuery()
	query.Parse(original)
	search := query.NamedSegment(model.SegmentKind_Search)
	mapSearch(store, search.(*model.SearchSegment))
	output := search.String()
	assert.Equal(tester, expected, output)
}

func TestMapSearch(tester *testing.T) {
	validateMappedQuery(tester, "foo: \"bar\"", "foo.keyword: \"bar\"")
	validateMappedQuery(tester, "foo: \"bar\" AND barfoo: \"blue\"", "foo.keyword: \"bar\" AND barfoo: \"blue\"")
	validateMappedQuery(tester, "foo: 123", "foo.keyword: 123")
	validateMappedQuery(tester, "(foo: \"123\")", "(foo: \"123\")")
	validateMappedQuery(tester, "foo2: \"bar\"", "foo2: \"bar\"")
	validateMappedQuery(tester, "barfoo: \"bar\"", "barfoo: \"bar\"")
	validateMappedQuery(tester, "barfoo: \"foo: bar\"", "barfoo: \"foo: bar\"")
}

func TestConvertObjectToDocumentMap(tester *testing.T) {
	caseObj := model.NewCase()
	actual := convertObjectToDocumentMap("test", caseObj, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NotNil(tester, actual)
	assert.Equal(tester, caseObj, actual["so_test"])
	assert.NotNil(tester, actual["@timestamp"])
}

func TestConvertToElasticIndexRequest(tester *testing.T) {
	store := NewTestStore()
	event := make(map[string]interface{})
	event["foo"] = "bar"
	expected := `{"foo":"bar"}`

	actual, err := convertToElasticIndexRequest(store, event)
	assert.NoError(tester, err)
	assert.Equal(tester, expected, actual)
}

func TestConvertFromElasticIndexResults(tester *testing.T) {
	store := NewTestStore()
	results := model.NewEventIndexResults()
	json := `{"_version":1, "_id":"123abc", "result": "successful"}`

	err := convertFromElasticIndexResults(store, json, results)
	assert.NoError(tester, err)
}

func TestConvertElasticEventToCaseNil(tester *testing.T) {
	caseObj, err := convertElasticEventToCase(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	assert.Nil(tester, caseObj)
}

func TestConvertElasticEventToCaseWithoutTags(tester *testing.T) {
	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["kind"] = "case"
	event.Payload["operation"] = "create"
	event.Payload["case.tags"] = nil

	_, err := convertElasticEventToCase(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
}

func TestConvertElasticEventToCase(tester *testing.T) {
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
	tags := make([]interface{}, 2, 2)
	tags[0] = "tag1"
	tags[1] = "tag2"
	event.Payload["so_case.tags"] = tags
	event.Time = myTime
	event.Payload["so_case.createTime"] = myCreateTime
	event.Payload["so_case.completeTime"] = myCompleteTime
	event.Payload["so_case.startTime"] = myStartTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	caseObj := interf.(*model.Case)
	assert.Equal(tester, "case", caseObj.Kind)
	assert.Equal(tester, "update", caseObj.Operation)
	assert.Equal(tester, "myTitle", caseObj.Title)
	assert.Equal(tester, "myDesc", caseObj.Description)
	assert.Equal(tester, 123, caseObj.Priority)
	assert.Equal(tester, "medium", caseObj.Severity)
	assert.Equal(tester, "myStatus", caseObj.Status)
	assert.Equal(tester, "myTemplate", caseObj.Template)
	assert.Equal(tester, "myUserId", caseObj.UserId)
	assert.Equal(tester, "myAssigneeId", caseObj.AssigneeId)
	assert.Equal(tester, "myPap", caseObj.Pap)
	assert.Equal(tester, "myTlp", caseObj.Tlp)
	assert.Equal(tester, "myCategory", caseObj.Category)
	assert.Equal(tester, tags[0], "tag1")
	assert.Equal(tester, tags[1], "tag2")
	assert.Equal(tester, &myTime, caseObj.UpdateTime)
	assert.Equal(tester, &myCreateTime, caseObj.CreateTime)
	assert.Equal(tester, &myCompleteTime, caseObj.CompleteTime)
	assert.Equal(tester, &myStartTime, caseObj.StartTime)
}

func TestConvertElasticEventToArtifactNil(tester *testing.T) {
	artifactObj, err := convertElasticEventToArtifact(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	assert.Nil(tester, artifactObj)
}

func TestConvertElasticEventToArtifactWithoutTags(tester *testing.T) {
	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "artifact"
	event.Payload["so_operation"] = "create"
	event.Payload["so_case.tags"] = nil

	_, err := convertElasticEventToCase(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
}

func TestConvertElasticEventToArtifact(tester *testing.T) {
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
	tags := make([]interface{}, 2, 2)
	tags[0] = "tag1"
	tags[1] = "tag2"
	event.Payload["so_artifact.tags"] = tags
	event.Time = myTime
	event.Payload["so_artifact.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	artifactObj := interf.(*model.Artifact)
	assert.Equal(tester, "artifact", artifactObj.Kind)
	assert.Equal(tester, "update", artifactObj.Operation)
	assert.Equal(tester, "myValue", artifactObj.Value)
	assert.Equal(tester, "myDesc", artifactObj.Description)
	assert.Equal(tester, 123, artifactObj.StreamLen)
	assert.Equal(tester, "myStreamId", artifactObj.StreamId)
	assert.Equal(tester, "myGroupType", artifactObj.GroupType)
	assert.Equal(tester, "myGroupId", artifactObj.GroupId)
	assert.Equal(tester, "myUserId", artifactObj.UserId)
	assert.Equal(tester, "myArtifactType", artifactObj.ArtifactType)
	assert.Equal(tester, "myTlp", artifactObj.Tlp)
	assert.Equal(tester, "myMimeType", artifactObj.MimeType)
	assert.Equal(tester, true, artifactObj.Ioc)
	assert.Equal(tester, tags[0], "tag1")
	assert.Equal(tester, tags[1], "tag2")
	assert.Equal(tester, "myMd5", artifactObj.Md5)
	assert.Equal(tester, "mySha1", artifactObj.Sha1)
	assert.Equal(tester, "mySha256", artifactObj.Sha256)
	assert.Equal(tester, &myTime, artifactObj.UpdateTime)
	assert.Equal(tester, &myCreateTime, artifactObj.CreateTime)
}

func TestConvertElasticEventToArtifactStreamNil(tester *testing.T) {
	artifactObj, err := convertElasticEventToArtifactStream(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	assert.Nil(tester, artifactObj)
}

func TestConvertElasticEventToArtifactStream(tester *testing.T) {
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
	assert.NoError(tester, err)
	obj := interf.(*model.ArtifactStream)
	assert.Equal(tester, "artifactstream", obj.Kind)
	assert.Equal(tester, "create", obj.Operation)
	assert.Equal(tester, "myUserId", obj.UserId)
	assert.Equal(tester, &myTime, obj.UpdateTime)
	assert.Equal(tester, &myCreateTime, obj.CreateTime)
	assert.Equal(tester, "myValue", obj.Content)
}

func TestParseTime(tester *testing.T) {
	m := make(map[string]interface{})

	format := "2006-01-02 03:04pm"
	t, _ := time.Parse(format, "2021-12-20 12:43pm")
	m["obj"] = t
	m["ptr"] = &t
	m["str"] = "2021-12-20T12:43:00Z"
	m["bad"] = 12

	expected := "2021-12-20 12:43pm"

	actual := parseTime(m, "obj").Format(format)
	assert.Equal(tester, expected, actual)

	actual = parseTime(m, "ptr").Format(format)
	assert.Equal(tester, expected, actual)

	actual = parseTime(m, "str").Format(format)
	assert.Equal(tester, expected, actual)

	actualObj := parseTime(m, "bad")
	assert.True(tester, actualObj.IsZero())
}

func TestConvertElasticEventToCommentNil(tester *testing.T) {
	obj, err := convertElasticEventToComment(nil, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	assert.Nil(tester, obj)
}

func TestConvertElasticEventToComment(tester *testing.T) {
	myTime := time.Now()
	myCreateTime := myTime.Add(time.Hour * -1)

	event := &model.EventRecord{}
	event.Payload = make(map[string]interface{})
	event.Payload["so_kind"] = "comment"
	event.Payload["so_operation"] = "create"
	event.Payload["so_comment.description"] = "myDesc"
	event.Payload["so_comment.userId"] = "myUserId"
	event.Payload["so_comment.caseId"] = "myCaseId"
	event.Time = myTime
	event.Payload["so_comment.createTime"] = myCreateTime
	interf, err := convertElasticEventToObject(event, DEFAULT_CASE_SCHEMA_PREFIX)
	assert.NoError(tester, err)
	obj := interf.(*model.Comment)
	assert.Equal(tester, "comment", obj.Kind)
	assert.Equal(tester, "create", obj.Operation)
	assert.Equal(tester, "myDesc", obj.Description)
	assert.Equal(tester, "myUserId", obj.UserId)
	assert.Equal(tester, "myCaseId", obj.CaseId)
	assert.Equal(tester, &myTime, obj.UpdateTime)
	assert.Equal(tester, &myCreateTime, obj.CreateTime)
}

func TestConvertElasticEventToRelatedEvent(tester *testing.T) {
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
	assert.NoError(tester, err)
	obj := interf.(*model.RelatedEvent)
	assert.Equal(tester, "related", obj.Kind)
	assert.Equal(tester, "create", obj.Operation)
	assert.Equal(tester, "myUserId", obj.UserId)
	assert.Equal(tester, "myCaseId", obj.CaseId)
	assert.Equal(tester, &myTime, obj.UpdateTime)
	assert.Equal(tester, &myCreateTime, obj.CreateTime)
	assert.Len(tester, obj.Fields, 1)
	assert.Equal(tester, "bar", obj.Fields["foo"])
}

func TestConvertSeverity(tester *testing.T) {
	assert.Equal(tester, "high", convertSeverity(""))
	assert.Equal(tester, "unknown", convertSeverity("unknown"))
	assert.Equal(tester, "low", convertSeverity("low"))
	assert.Equal(tester, "low", convertSeverity("Low"))
	assert.Equal(tester, "low", convertSeverity("1"))
	assert.Equal(tester, "medium", convertSeverity("medium"))
	assert.Equal(tester, "medium", convertSeverity("Medium"))
	assert.Equal(tester, "medium", convertSeverity("2"))
	assert.Equal(tester, "high", convertSeverity("high"))
	assert.Equal(tester, "high", convertSeverity("High"))
	assert.Equal(tester, "high", convertSeverity("3"))
	assert.Equal(tester, "critical", convertSeverity("critical"))
	assert.Equal(tester, "critical", convertSeverity("4"))
	assert.Equal(tester, "critical", convertSeverity("Critical"))
}
