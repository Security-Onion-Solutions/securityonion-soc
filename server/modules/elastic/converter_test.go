// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
	agg, name := makeAggregation(NewTestStore(), "groupby", keys, 10, false)
	assert.Equal(tester, "groupby|one", name)

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
	assert.NotNil(tester, secondAggs["groupby|one|two"])
	secondAgg := secondAggs["groupby|one|two"].(map[string]interface{})
	assert.NotNil(tester, secondAgg["aggs"])
	terms = secondAgg["terms"].(map[string]interface{})
	assert.Nil(tester, terms["missing"])

	thirdAggs := secondAgg["aggs"].(map[string]interface{})
	assert.NotNil(tester, thirdAggs["groupby|one|two|three"])
	thirdAgg := thirdAggs["groupby|one|two|three"].(map[string]interface{})
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
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"aggs":{"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1s","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"0001-01-01T00:00:00Z","lte":"0001-01-01T00:00:00Z"}}}],"must_not":[],"should":[]}},"size":25}`
	assert.Equal(tester, expectedJson, actualJson)
}

func TestConvertToElasticRequestGroupByCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	criteria.Populate(`abc AND def AND q:"\\\\file\\path" | groupby ghi jkl*`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
	assert.Nil(tester, err)

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby|ghi":{"aggs":{"groupby|ghi|jkl":{"terms":{"field":"jkl","missing":"__missing__","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25}`
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
		assert.Equal(tester, "so16:logstash-bro-2020.04.24", results.Events[0].Source)
		assert.NotNil(tester, results.Metrics["groupby|source_ip"])
		assert.NotNil(tester, results.Metrics["groupby|source_ip|destination_ip"])
		assert.NotNil(tester, results.Metrics["groupby|source_ip|destination_ip|protocol"])
		assert.NotNil(tester, results.Metrics["groupby|source_ip|destination_ip|protocol|destination_port"])
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
