// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
	"errors"
	"strings"
	"time"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func makeAggregation(store *ElasticEventstore, name string, keys []string, count int, ascending bool) map[string]interface{} {
	agg := make(map[string]interface{})
	orderFields := make(map[string]interface{})
	orderFields["_count"] = "desc"
	if ascending {
		orderFields["_count"] = "asc"
	}
	aggFields := make(map[string]interface{})
	aggFields["field"] = store.mapElasticField(keys[0])
	aggFields["size"] = count
	aggFields["order"] = orderFields
	agg["terms"] = aggFields
	if len(keys) > 1 {
		inner := make(map[string]interface{})
		name = name + "|" + keys[1]
		inner[name] = makeAggregation(store, name, keys[1:], count, ascending)
		agg["aggs"] = inner
	}
	return agg
}

func makeTimeline(interval string) map[string]interface{} {
	timeline := make(map[string]interface{})
	timelineFields := make(map[string]interface{})
	timelineFields["field"] = "@timestamp"
	timelineFields["interval"] = interval
	timelineFields["min_doc_count"] = 1
	timeline["date_histogram"] = timelineFields
	return timeline
}

func makeQuery(store *ElasticEventstore, criteria *model.EventSearchCriteria) map[string]interface{} {
	searchString := ""
	segment := criteria.ParsedQuery.NamedSegment(model.SegmentKind_Search)
	if segment != nil {
		searchSegment := segment.(*model.SearchSegment)
		searchString = searchSegment.String()
	}

	queryDetails := make(map[string]interface{})
	queryDetails["query"] = searchString
	queryDetails["analyze_wildcard"] = true
	queryDetails["default_field"] = "*"

	query := make(map[string]interface{})
	query["query_string"] = queryDetails

	timestampDetails := make(map[string]interface{})
	timestampDetails["gte"] = criteria.BeginTime.Unix() * 1000
	timestampDetails["lte"] = criteria.EndTime.Unix() * 1000
	timestampDetails["format"] = "epoch_millis"

	timerangeDetails := make(map[string]interface{})
	timerangeDetails["@timestamp"] = timestampDetails

	timerange := make(map[string]interface{})
	timerange["range"] = timerangeDetails

	must := make([]interface{}, 0, 0)
	must = append(must, query)
	must = append(must, timerange)

	terms := make(map[string]interface{})
	terms["must"] = must
	terms["filter"] = []interface{}{}
	terms["should"] = []interface{}{}
	terms["must_not"] = []interface{}{}

	clause := make(map[string]interface{})
	clause["bool"] = terms

	return clause
}

func convertToElasticRequest(store *ElasticEventstore, criteria *model.EventSearchCriteria) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["size"] = criteria.EventLimit
	esMap["query"] = makeQuery(store, criteria)

	aggregations := make(map[string]interface{})
	esMap["aggs"] = aggregations
	aggregations["timeline"] = makeTimeline("30m")

	segment := criteria.ParsedQuery.NamedSegment(model.SegmentKind_GroupBy)
	if segment != nil {
		groupBySegment := segment.(*model.GroupBySegment)
		fields := groupBySegment.Fields()
		if len(fields) > 0 {
			name := "groupby|" + fields[0]
			aggregations[name] = makeAggregation(store, name, fields, criteria.MetricLimit, false)
			aggregations["bottom"] = makeAggregation(store, "", fields[0:1], criteria.MetricLimit, true)
		}
	}

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
			metrics = make([]*model.EventMetric,0,0)
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
					tmpKeys := append(keys, key)
					metric.Keys = tmpKeys
					metrics = append(metrics, metric)
					for innerName, innerAgg := range bucket {
						if strings.HasPrefix(innerName, "groupby|") {
							parseAggregation(innerName, innerAgg, tmpKeys, results)
						}
					}
				}
			}
		}
		results.Metrics[name] = metrics
	}
}

func flattenKeyValue(store *ElasticEventstore, fieldMap map[string]interface{}, prefix string, value map[string]interface{}) {
	for key, value := range value {
		flattenedKey := prefix + key
		switch value.(type) {
		case map[string]interface{}:
			flattenKeyValue(store, fieldMap, flattenedKey + ".", value.(map[string]interface{}))
		default:
			fieldMap[store.unmapElasticField(flattenedKey)] = value
		}
	}
}

func flatten(store *ElasticEventstore, data map[string]interface{}) map[string]interface{} {
	fieldMap := make(map[string]interface{})
	flattenKeyValue(store, fieldMap, "", data)
	return fieldMap
}

func convertFromElasticResults(store *ElasticEventstore, esJson string, results *model.EventSearchResults) error {
	esResults := make(map[string]interface{})
	err := json.LoadJson([]byte(esJson), &esResults)
	if esResults["took"] == nil || esResults["timed_out"] == nil || esResults["hits"] == nil {
		return errors.New("Elasticsearch response is not a valid JSON search result")
	}
	results.FetchElapsedMs = int(esResults["took"].(float64))
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
		event.Type = esRecord["_type"].(string)
		event.Score = esRecord["_score"].(float64)
		event.Payload = flatten(store, esRecord["_source"].(map[string]interface{}))
		event.Timestamp, _ = time.Parse(time.RFC3339, event.Payload["@timestamp"].(string))
		results.Events = append(results.Events, event)
	}

	aggs := esResults["aggregations"]
	if aggs != nil {
		for name, aggObj := range aggs.(map[string]interface{}) {
			keys := make([]interface{}, 0, 0)
			parseAggregation(name, aggObj, keys, results)
		}
	}

	return err
}
