// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
	if terms["interval"] != "30m" {
		tester.Errorf("Expected %s, Actual %s", "30m", terms["interval"])
	}
	if terms["min_doc_count"] != 1 {
		tester.Errorf("Expected %d, Actual %d", 1, terms["min_doc_count"])
	}
}

func TestConvertToElasticRequestEmptyCriteria(tester *testing.T) {
	criteria := model.NewEventSearchCriteria()
	actualJson, err := convertToElasticRequest(NewTestStore(), criteria)
  if err != nil {
    tester.Errorf("unexpected conversion error: %s", err)
	}

	expectedJson := `{"aggs":{"timeline":{"date_histogram":{"field":"@timestamp","interval":"30m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":""}},{"range":{"@timestamp":{"format":"epoch_millis","gte":-62135596800000,"lte":-62135596800000}}}],"must_not":[],"should":[]}},"size":25}`
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

	expectedJson := `{"aggs":{"bottom":{"terms":{"field":"ghi","order":{"_count":"asc"},"size":10}},"groupby|ghi":{"aggs":{"groupby|ghi|jkl":{"terms":{"field":"jkl","order":{"_count":"desc"},"size":10}}},"terms":{"field":"ghi","order":{"_count":"desc"},"size":10}},"timeline":{"date_histogram":{"field":"@timestamp","interval":"30m","min_doc_count":1}}},"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"abc AND def AND q: \"\\\\\\\\file\\\\path\""}},{"range":{"@timestamp":{"format":"epoch_millis","gte":1577967194000,"lte":1577970794000}}}],"must_not":[],"should":[]}},"size":25}`
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

	if results.FetchElapsedMs != 9534 {
		tester.Errorf("Failed to parse FetchElapsedMs (%d): %s", results.FetchElapsedMs, err)
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

	if results.FetchElapsedMs != 123 {
		tester.Errorf("Failed to parse FetchElapsedMs (%d) regardless of timed_out flag: %s", results.FetchElapsedMs, err)
	}
}

func TestConvertFromElasticResultsInvalid(tester *testing.T) {
	results := model.NewEventSearchResults()
 err := convertFromElasticResults(NewTestStore(), `{ }`, results)
 if err == nil {
	 tester.Errorf("Expected invalid results error")
 }
}