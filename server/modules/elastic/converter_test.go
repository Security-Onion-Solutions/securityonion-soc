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
)

func NewTestStore() *ElasticEventstore {
  return &ElasticEventstore{
    fieldDefs: make(map[string]*FieldDefinition),
    intervals: DEFAULT_INTERVALS,
  }
}

func TestMakeAggregation(tester *testing.T) {
  keys := []string{"one","two","three"}
  agg := makeAggregation(NewTestStore(), "groupby|one", keys, 10, false)
  if agg["terms"] == nil {
    tester.Errorf("aggregation missing terms")
  }
  terms := agg["terms"].(map[string]interface{})
  if terms["field"] != "one" {
    tester.Errorf("Expected %s, Actual %s", "one", terms["field"])
  }
  if terms["size"] != 10 {
    tester.Errorf("Expected %d, Actual %d", 10, terms["size"])
  }
  if terms["order"] == nil {
    tester.Errorf("aggregation missing order")
  }
  order := terms["order"].(map[string]interface{})
  if order["_count"] != "desc" {
    tester.Errorf("Expected %s, Actual %s", "desc", terms["order"])
  }
  if agg["aggs"] == nil {
    tester.Errorf("aggregation missing nested aggregations")
  }
  secondAggs := agg["aggs"].(map[string]interface{})
  if secondAggs["groupby|one|two"] == nil {
    tester.Errorf("Nested aggregation missing 'groupby|one|two' key")
  }
  secondAgg := secondAggs["groupby|one|two"].(map[string]interface{})
  if secondAgg["aggs"] == nil {
    tester.Errorf("aggregation missing second level aggregations")
  }
  thirdAggs := secondAgg["aggs"].(map[string]interface{})
  if thirdAggs["groupby|one|two|three"] == nil {
    tester.Errorf("Nested aggregation missing 'groupby|one|two|three' key")
  }
}

func TestMakeTimeline(tester *testing.T) {
  timeline := makeTimeline("30m")
  if timeline["date_histogram"] == nil {
    tester.Errorf("timeline missing date_histogram")
  }
  terms := timeline["date_histogram"].(map[string]interface{})
  if terms["field"] != "@timestamp" {
    tester.Errorf("Expected %s, Actual %s", "@timestamp", terms["field"])
  }
  if terms["fixed_interval"] != "30m" {
    tester.Errorf("Expected %s, Actual %s", "30m", terms["fixed_interval"])
  }
  if terms["min_doc_count"] != 1 {
    tester.Errorf("Expected %d, Actual %d", 1, terms["min_doc_count"])
  }
}

func TestCalcTimelineInterval(tester *testing.T) {
  start, _ := time.Parse(time.RFC3339, "2021-01-02T05:00:00Z")
  end, _   := time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
  interval := calcTimelineInterval(25, start, end)
  if interval != "15m" {
    tester.Errorf("Expected 15m interval but got %s", interval)
  }

  // Boundaries
  start, _ = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
  end, _   = time.Parse(time.RFC3339, "2021-01-02T13:00:01Z")
  interval = calcTimelineInterval(25, start, end)
  if interval != "1s" {
    tester.Errorf("Expected 1s interval but got %s", interval)
  }

  start, _ = time.Parse(time.RFC3339, "1990-01-02T05:00:00Z")
  end, _   = time.Parse(time.RFC3339, "2021-01-02T13:00:00Z")
  interval = calcTimelineInterval(25, start, end)
  if interval != "30d" {
    tester.Errorf("Expected 30d interval but got %s", interval)
  }
}

func TestConvertToElasticRequestEmptyCriteria(tester *testing.T) {
  criteria := model.NewEventSearchCriteria()
  actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
  }

  expectedJson := `{"aggs":{"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1s","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"*"}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"0001-01-01T00:00:00Z","lte":"0001-01-01T00:00:00Z"}}}],"must_not":[],"should":[]}},"size":25}`
  if actualJson != expectedJson {
    tester.Errorf("Mismatched ES request conversion; actual='%s' vs expected='%s'", actualJson, expectedJson)
  }
}

func TestConvertToElasticRequestGroupByCriteria(tester *testing.T) {
  criteria := model.NewEventSearchCriteria()
  criteria.Populate(`abc AND def AND q:"\\file\path" | groupby ghi jkl`, "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "10", "25")
  actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
  }

  expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby|ghi":{"aggs":{"groupby|ghi|jkl":{"terms":{"field":"jkl","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","fixed_interval":"1m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-01-02T12:13:14Z","lte":"2020-01-02T13:13:14Z"}}}],"must_not":[],"should":[]}},"size":25}`
  if actualJson != expectedJson {
    tester.Errorf("Mismatched ES request conversion; actual='%s' vs expected='%s'", actualJson, expectedJson)
  }
}

func TestConvertFromElasticResultsSuccess(tester *testing.T) {
  esData, err := ioutil.ReadFile("converter_response.json")
  if err != nil {
    tester.Errorf("unexpected test setup error: %s", err)
  }
  
  results := model.NewEventSearchResults()
  err = convertFromElasticResults(NewTestStore(), string(esData), results)
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
  }

  if results.ElapsedMs != 9534 {
    tester.Errorf("Failed to parse ElapsedMs (%d): %s", results.ElapsedMs, err)
  }

  if results.TotalEvents != 23689430 {
    tester.Errorf("Unexpected total events: %d", results.TotalEvents)
  }

  if len(results.Events) != 25 {
    tester.Errorf("Unexpected returned event count: %d", len(results.Events))
  }

  if results.Events[0].Timestamp != "2020-04-24T03:00:55.300Z" {
    tester.Errorf("Unexpected timestamp: %-v", results.Events[0].Timestamp)
  }

  if results.Events[0].Source != "so16:logstash-bro-2020.04.24" {
    tester.Errorf("Unexpected source: %s", results.Events[0].Source)
  }

  if results.Metrics["groupby|source_ip"] == nil {
    tester.Errorf("Missing outer groupby metric")
  }

  if results.Metrics["groupby|source_ip|destination_ip"] == nil {
    tester.Errorf("Missing outer groupby metric")
  }

  if results.Metrics["groupby|source_ip|destination_ip|protocol"] == nil {
    tester.Errorf("Missing outer groupby metric")
  }

  if results.Metrics["groupby|source_ip|destination_ip|protocol|destination_port"] == nil {
    tester.Errorf("Missing outer groupby metric")
  }
}

func TestConvertFromElasticResultsTimedOut(tester *testing.T) {
  results := model.NewEventSearchResults()
  err := convertFromElasticResults(NewTestStore(), `{ "took": 123, "timed_out": true, "hits": {} }`, results)
  if err == nil {
    tester.Errorf("Expected timed out results")
  }

  if results.ElapsedMs != 123 {
    tester.Errorf("Failed to parse ElapsedMs (%d) regardless of timed_out flag: %s", results.ElapsedMs, err)
  }
}

func TestConvertFromElasticResultsInvalid(tester *testing.T) {
  results := model.NewEventSearchResults()
 err := convertFromElasticResults(NewTestStore(), `{ }`, results)
 if err == nil {
   tester.Errorf("Expected invalid results error")
 }
}

func TestConvertToElasticUpdateRequest(tester *testing.T) {
  criteria := model.NewEventUpdateCriteria()
  criteria.AddUpdateScript("ctx._source.event.acknowledged=true")
  criteria.AddUpdateScript("ctx._source.event.escalated=true")
  criteria.Populate("event.dataset:alerts", "2020/09/24 10:11:12 AM - 2020/09/24 12:14:15 PM", "2006/01/02 3:04:05 PM", "America/New_York", "0", "0");

  actualJson, err := convertToElasticUpdateRequest(NewTestStore(), criteria)
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
  }

  expectedJson := `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"event.dataset:alerts"}},{"range":{"@timestamp":{"format":"strict_date_optional_time","gte":"2020-09-24T10:11:12-04:00","lte":"2020-09-24T12:14:15-04:00"}}}],"must_not":[],"should":[]}},"script":{"inline":"ctx._source.event.acknowledged=true; ctx._source.event.escalated=true","lang":"painless"}}`
  if actualJson != expectedJson {
    tester.Errorf("Mismatched ES request conversion; actual='%s' vs expected='%s'", actualJson, expectedJson)
  }
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
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
  }

  if results.ElapsedMs != 202 {
    tester.Errorf("Failed to parse ElapsedMs (%d): %s", results.ElapsedMs, err)
  }

  if results.UpdatedCount != 3 {
    tester.Errorf("Unexpected updated count: %d", results.UpdatedCount)
  }

  if results.UnchangedCount != 2 {
    tester.Errorf("Unexpected updated count: %d", results.UnchangedCount)
  }
}

func TestMergeElasticUpdateResults(tester *testing.T) {
  results1 := model.NewEventUpdateResults()
  results1.ElapsedMs = 100
  results1.UpdatedCount = 200
  results1.UnchangedCount = 400
  results2 := model.NewEventUpdateResults()
  results2.ElapsedMs = 12
  results2.UpdatedCount = 2
  results2.UnchangedCount = 4
  mergeElasticUpdateResults(results1, results2)
  if results1.ElapsedMs != 112 {
    tester.Errorf("Unexpected ElapsedMs: %d", results1.ElapsedMs)
  }

  if results1.UpdatedCount != 202 {
    tester.Errorf("Unexpected updated count: %d", results1.UpdatedCount)
  }

  if results1.UnchangedCount != 404 {
    tester.Errorf("Unexpected updated count: %d", results1.UnchangedCount)
  }
}

func validateFormatSearch(tester *testing.T, original string, expected string) {
  output := formatSearch(original)
  if output != expected {
    tester.Errorf("Expected mapped query '%s' but got '%s'", expected, output)
  }
}

func TestFormatSearch(tester *testing.T) {
  validateFormatSearch(tester, "", "*")
  validateFormatSearch(tester, " ", "*")
  validateFormatSearch(tester, "\\foo\\bar", "\\\\foo\\\\bar")
}


func validateMappedQuery(tester *testing.T, original string, expected string) {
  store := NewTestStore()
  store.fieldDefs["foo"] = &FieldDefinition { aggregatable: false, }
  store.fieldDefs["foo.keyword"] = &FieldDefinition { aggregatable: true, }
  query := model.NewQuery()
  query.Parse(original)
  search := query.NamedSegment(model.SegmentKind_Search)
  mapSearch(store, search.(*model.SearchSegment))
  output := search.String()
  if output != expected {
    tester.Errorf("Expected mapped query '%s' but got '%s'", expected, output)
  }
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
