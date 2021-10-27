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
	"errors"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func makeAggregation(store *ElasticEventstore, prefix string, keys []string, count int, ascending bool) (map[string]interface{}, string) {
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

	aggFields["field"] = store.mapElasticField(keys[0])
	aggFields["size"] = count
	aggFields["order"] = orderFields
	agg["terms"] = aggFields

	name := prefix + "|" + keys[0]
	if len(keys) > 1 {
		inner := make(map[string]interface{})
		innerAgg, innerName := makeAggregation(store, name, keys[1:], count, ascending)
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

func mapSearch(store *ElasticEventstore, searchSegment *model.SearchSegment) *model.SearchSegment {
	const delim = ":"
	for _, term := range searchSegment.Terms() {
		if strings.HasSuffix(term.Raw, delim) && !term.Grouped && !term.Quoted {
			field := strings.Trim(term.Raw, delim)
			newField := store.mapElasticField(field)
			if newField != field {
				term.Raw = newField + delim
			}
		}
	}
	return searchSegment
}

func makeQuery(store *ElasticEventstore, parsedQuery *model.Query, beginTime time.Time, endTime time.Time) map[string]interface{} {
	searchString := ""
	segment := parsedQuery.NamedSegment(model.SegmentKind_Search)
	if segment != nil {
		searchSegment := segment.(*model.SearchSegment)
		searchString = mapSearch(store, searchSegment).String()
	}

	queryDetails := make(map[string]interface{})
	queryDetails["query"] = formatSearch(searchString)
	queryDetails["analyze_wildcard"] = true
	queryDetails["default_field"] = "*"

	query := make(map[string]interface{})
	query["query_string"] = queryDetails

	timestampDetails := make(map[string]interface{})
	timestampDetails["gte"] = beginTime.Format(time.RFC3339)
	timestampDetails["lte"] = endTime.Format(time.RFC3339)
	timestampDetails["format"] = "strict_date_optional_time"

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

func convertToElasticRequest(store *ElasticEventstore, criteria *model.EventSearchCriteria) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["size"] = criteria.EventLimit
	esMap["query"] = makeQuery(store, criteria.ParsedQuery, criteria.BeginTime, criteria.EndTime)

	aggregations := make(map[string]interface{})
	esMap["aggs"] = aggregations
	aggregations["timeline"] = makeTimeline(calcTimelineInterval(store.intervals, criteria.BeginTime, criteria.EndTime))

	segment := criteria.ParsedQuery.NamedSegment(model.SegmentKind_GroupBy)
	if segment != nil {
		groupBySegment := segment.(*model.GroupBySegment)
		fields := groupBySegment.Fields()
		if len(fields) > 0 {
			agg, name := makeAggregation(store, "groupby", fields, criteria.MetricLimit, false)
			aggregations[name] = agg
			aggregations["bottom"], _ = makeAggregation(store, "", fields[0:1], criteria.MetricLimit, true)
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
			metrics = make([]*model.EventMetric, 0, 0)
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
			flattenKeyValue(store, fieldMap, flattenedKey+".", value.(map[string]interface{}))
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
		event.Type = esRecord["_type"].(string)
		event.Score = esRecord["_score"].(float64)
		event.Payload = flatten(store, esRecord["_source"].(map[string]interface{}))
		var ts time.Time
		if event.Payload["@timestamp"] != nil {
			ts, _ = time.Parse(time.RFC3339, event.Payload["@timestamp"].(string))
		} else if event.Payload["timestamp"] != nil {
			ts, _ = time.Parse(time.RFC3339, event.Payload["timestamp"].(string))
		}
		event.Timestamp = ts.Format("2006-01-02T15:04:05.000Z")
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

func convertToElasticUpdateRequest(store *ElasticEventstore, criteria *model.EventUpdateCriteria) (string, error) {
	var err error
	var esJson string

	esMap := make(map[string]interface{})
	esMap["query"] = makeQuery(store, criteria.ParsedQuery, criteria.BeginTime, criteria.EndTime)

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
