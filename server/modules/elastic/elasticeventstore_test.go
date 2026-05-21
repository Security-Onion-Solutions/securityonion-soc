// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modmock "github.com/security-onion-solutions/securityonion-soc/server/modules/mock"

	"github.com/stretchr/testify/assert"
)

func TestFieldMapping(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := os.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	// Exists as keyword and not already aggregatable
	actual := mapElasticField(store.fieldDefs, "smb.service")
	assert.Equal(tester, "smb.service.keyword", actual)

	// Exists as keyword but already aggregatable
	actual = mapElasticField(store.fieldDefs, "agent.ip")
	assert.Equal(tester, "agent.ip", actual)

	// Does not exist as valid keyword
	actual = mapElasticField(store.fieldDefs, "event.acknowledged")
	assert.Equal(tester, "event.acknowledged", actual)

	// Both non-keyword and keyword variants are aggregatable
	actual = unmapElasticField(store.fieldDefs, "agent.ip.keyword")
	assert.Equal(tester, "agent.ip.keyword", actual)

	// Only keyword variant is aggregatable
	actual = unmapElasticField(store.fieldDefs, "smb.service.keyword")
	assert.Equal(tester, "smb.service", actual)

	// Neither are aggregatable
	actual = unmapElasticField(store.fieldDefs, "event.acknowledged")
	assert.Equal(tester, "event.acknowledged", actual)
}

func TestFieldMappingCollisions(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := os.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	var testTable = []struct {
		given    string
		expected string
	}{
		{"event.module", "event.module.keyword"},
		{"event.category", "event.category.keyword"},
		{"event.dataset", "event.dataset.keyword"},
		{"event.kind", "event.kind.keyword"},
		{"event.outcome", "event.outcome.keyword"},
		{"event.type", "event.type.keyword"},
		{"event.timezone", "event.timezone.keyword"},
	}

	for _, test := range testTable {
		tester.Run("given="+test.given, func(t *testing.T) {
			actual := mapElasticField(store.fieldDefs, test.given)
			assert.Equal(tester, test.expected, actual)
		})
	}
}

func TestFieldMappingCache(tester *testing.T) {
	store := &ElasticEventstore{}

	json, err := os.ReadFile("fieldcaps_response.json")
	assert.Nil(tester, err)
	store.cacheFieldsFromJson(string(json))

	field := store.fieldDefs["smb.service"]
	if assert.NotNil(tester, field) {
		assert.Equal(tester, "smb.service", field.name)
		assert.Equal(tester, "text", field.fieldType)
		assert.False(tester, field.aggregatable)
		assert.True(tester, field.searchable)
	}

	fieldKeyword := store.fieldDefs["smb.service.keyword"]
	if assert.NotNil(tester, fieldKeyword) {
		assert.Equal(tester, "smb.service.keyword", fieldKeyword.name)
		assert.Equal(tester, "keyword", fieldKeyword.fieldType)
		assert.False(tester, field.aggregatable)
		assert.True(tester, field.searchable)
	}
}

func TestTransformIndex(tester *testing.T) {
	assert.Equal(tester, "test", transformIndex("test"))

	actual := transformIndex("test_{today}")
	match, _ := regexp.MatchString("test_[0-9]{4}.[0-9]{2}.[0-9]{2}", actual)
	assert.True(tester, match, "expected transformed index to contain a date")
}

func TestReadErrorFromJson(tester *testing.T) {
	json := `{"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	err := readErrorFromJson(json)
	assert.Error(tester, err)
	expected := `some type: some reason -> {"error":{"type":"some type","reason":"some reason"},"something.else":"yes"}`
	actual := fmt.Sprintf("%v", err)
	assert.Equal(tester, expected, actual)
}

func TestDisableCrossClusterIndexing(tester *testing.T) {
	store := &ElasticEventstore{}
	indexes := make([]string, 2)
	indexes[0] = "*:so-*"
	indexes[1] = "my-*"
	newIndexes := store.disableCrossClusterIndexing(indexes)
	assert.Equal(tester, len(indexes), len(newIndexes))
	assert.Equal(tester, "so-*", newIndexes[0])
	assert.Equal(tester, "my-*", newIndexes[1])
}

func TestScrollSunnyDay(t *testing.T) {
	ctx := context.Background()

	client, transport := modmock.NewMockClient(t)

	// the first response, all good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 70,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "1",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// second response, still good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 52,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "2",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// 3rd and final doc, still good, no problems
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 70,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 5,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "3",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// ClearScroll
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"succeeded":true,"num_freed":1}`)),
	}, nil)

	store := &ElasticEventstore{
		esClient:      client,
		cacheTime:     time.Now().Add(time.Hour),
		fieldDefs:     make(map[string]*FieldDefinition),
		maxScrollSize: 10000,
		maxLogLength:  math.MaxInt,
	}

	criteria := &model.EventScrollCriteria{
		ParsedQuery: &model.Query{},
	}
	criteria.RawQuery = `_index:"*:so-detection" AND so_kind:"detection" AND so_detection.engine:"suricata" AND so_detection.isCommunity:"true"`
	err := criteria.ParsedQuery.Parse(criteria.RawQuery)
	assert.Nil(t, err)

	results, err := store.Scroll(ctx, criteria, []string{"myIndex"})

	assert.Nil(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 3, results.TotalEvents)
	assert.Equal(t, 3, len(results.Events))
	assert.Equal(t, criteria, results.Criteria)
	assert.Equal(t, "1", results.Events[0].Payload["so_detection.publicId"])
	assert.Equal(t, "2", results.Events[1].Payload["so_detection.publicId"])
	assert.Equal(t, "3", results.Events[2].Payload["so_detection.publicId"])

	reqs := transport.GetRequests()

	assert.Equal(t, 4, len(reqs))

	// Scroll Requests
	req := reqs[0]
	assert.NotNil(t, req)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "/myIndex/_search", req.URL.Path)
	assert.Contains(t, req.URL.RawQuery, "pretty=true")
	assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")
	assert.Contains(t, req.URL.RawQuery, "track_total_hits=true")

	body, err := io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"_index: \"*:so-detection\" AND so_kind: \"detection\" AND so_detection.engine: \"suricata\" AND so_detection.isCommunity: \"true\""}}],"must_not":[],"should":[]}},"size":10000}`, string(body))

	for _, req := range reqs[1:2] {
		assert.NotNil(t, req)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "/_search/scroll", req.URL.Path)
		assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")

		body, err = io.ReadAll(req.Body)
		assert.Nil(t, err)
		assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
	}

	// ClearScroll Request
	req = reqs[3]
	assert.NotNil(t, req)
	assert.Equal(t, "DELETE", req.Method)
	assert.Equal(t, "/_search/scroll", req.URL.Path)

	body, err = io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
}

func TestScrollInitialScrollError(t *testing.T) {
	ctx := context.Background()

	client, transport := modmock.NewMockClient(t)

	// the first response, problem
	transport.AddResponse(&http.Response{
		StatusCode: 500,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"error" : {
				"root_cause" : [
					{
						"type" : "uncategorized_execution_exception",
						"reason" : "Failed execution"
					}
				],
				"type" : "connect_transport_exception",
				"reason" : "[][10.66.159.47:9300] connect_exception",
				"caused_by" : {
					"type" : "uncategorized_execution_exception",
					"reason" : "Failed execution",
					"caused_by" : {
						"type" : "execution_exception",
						"reason" : "io.netty.channel.AbstractChannel$AnnotatedNoRouteToHostException: No route to host: /10.66.159.47:9300",
						"caused_by" : {
							"type" : "annotated_no_route_to_host_exception",
							"reason" : "No route to host: /10.66.159.47:9300",
							"caused_by" : {
								"type" : "no_route_to_host_exception",
								"reason" : "No route to host"
							}
						}
					}
				}
			},
			"status": 500
		}`)),
	}, nil)

	// ClearScroll
	transport.AddResponse(nil, fmt.Errorf("could not connect"))

	store := &ElasticEventstore{
		esClient:      client,
		cacheTime:     time.Now().Add(time.Hour),
		fieldDefs:     make(map[string]*FieldDefinition),
		maxScrollSize: 10000,
		maxLogLength:  math.MaxInt,
		index:         "myIndex",
	}

	criteria := &model.EventScrollCriteria{
		ParsedQuery: &model.Query{},
	}
	criteria.RawQuery = `_index:"*:so-detection" AND so_kind:"detection" AND so_detection.engine:"suricata" AND so_detection.isCommunity:"true"`
	err := criteria.ParsedQuery.Parse(criteria.RawQuery)
	assert.Nil(t, err)

	results, err := store.Scroll(ctx, criteria, nil)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "connect_transport_exception: [][10.66.159.47:9300] connect_exception -> {\n\t\t\t\"error\" : {\n\t\t\t\t\"root_cause\" : [\n\t\t\t\t\t{\n\t\t\t\t\t\t\"type\" : \"uncategorized_execution_exception\",\n\t\t\t\t\t\t\"reason\" : \"Failed execution\"\n\t\t\t\t\t}\n\t\t\t\t],\n\t\t\t\t\"type\" : \"connect_transport_exception\",\n\t\t\t\t\"reason\" : \"[][10.66.159.47:9300] connect_exception\",\n\t\t\t\t\"caused_by\" : {\n\t\t\t\t\t\"type\" : \"uncategorized_execution_exception\",\n\t\t\t\t\t\"reason\" : \"Failed execution\",\n\t\t\t\t\t\"caused_by\" : {\n\t\t\t\t\t\t\"type\" : \"execution_exception\",\n\t\t\t\t\t\t\"reason\" : \"io.netty.channel.AbstractChannel$AnnotatedNoRouteToHostException: No route to host: /10.66.159.47:9300\",\n\t\t\t\t\t\t\"caused_by\" : {\n\t\t\t\t\t\t\t\"type\" : \"annotated_no_route_to_host_exception\",\n\t\t\t\t\t\t\t\"reason\" : \"No route to host: /10.66.159.47:9300\",\n\t\t\t\t\t\t\t\"caused_by\" : {\n\t\t\t\t\t\t\t\t\"type\" : \"no_route_to_host_exception\",\n\t\t\t\t\t\t\t\t\"reason\" : \"No route to host\"\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t},\n\t\t\t\"status\": 500\n\t\t}")
	assert.NotNil(t, results)
	assert.Equal(t, 0, results.TotalEvents)
	assert.Equal(t, 0, len(results.Events))
	assert.Equal(t, criteria, results.Criteria)

	reqs := transport.GetRequests()

	assert.Equal(t, 1, len(reqs))

	// Scroll Requests
	req := reqs[0]
	assert.NotNil(t, req)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "/myIndex/_search", req.URL.Path)
	assert.Contains(t, req.URL.RawQuery, "pretty=true")
	assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")
	assert.Contains(t, req.URL.RawQuery, "track_total_hits=true")

	body, err := io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"_index: \"*:so-detection\" AND so_kind: \"detection\" AND so_detection.engine: \"suricata\" AND so_detection.isCommunity: \"true\""}}],"must_not":[],"should":[]}},"size":10000}`, string(body))
}

func TestScrollMidScrollError(t *testing.T) {
	ctx := context.Background()

	client, transport := modmock.NewMockClient(t)

	// the first response, all good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 70,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "1",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// second response, still good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 52,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "2",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// 3rd response, problem
	transport.AddResponse(&http.Response{
		StatusCode: 500,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"error" : {
				"root_cause" : [
					{
						"type" : "uncategorized_execution_exception",
						"reason" : "Failed execution"
					}
				],
				"type" : "connect_transport_exception",
				"reason" : "[][10.66.159.47:9300] connect_exception",
				"caused_by" : {
					"type" : "uncategorized_execution_exception",
					"reason" : "Failed execution",
					"caused_by" : {
						"type" : "execution_exception",
						"reason" : "io.netty.channel.AbstractChannel$AnnotatedNoRouteToHostException: No route to host: /10.66.159.47:9300",
						"caused_by" : {
							"type" : "annotated_no_route_to_host_exception",
							"reason" : "No route to host: /10.66.159.47:9300",
							"caused_by" : {
								"type" : "no_route_to_host_exception",
								"reason" : "No route to host"
							}
						}
					}
				}
			},
			"status": 500
		}`)),
	}, nil)

	// ClearScroll
	transport.AddResponse(nil, fmt.Errorf("could not connect"))

	store := &ElasticEventstore{
		esClient:      client,
		cacheTime:     time.Now().Add(time.Hour),
		fieldDefs:     make(map[string]*FieldDefinition),
		maxScrollSize: 10000,
		maxLogLength:  math.MaxInt,
		index:         "myIndex",
	}

	criteria := &model.EventScrollCriteria{
		ParsedQuery: &model.Query{},
	}
	criteria.RawQuery = `_index:"*:so-detection" AND so_kind:"detection" AND so_detection.engine:"suricata" AND so_detection.isCommunity:"true"`
	err := criteria.ParsedQuery.Parse(criteria.RawQuery)
	assert.Nil(t, err)

	results, err := store.Scroll(ctx, criteria, nil)

	assert.NotNil(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 3, results.TotalEvents)
	assert.Equal(t, 2, len(results.Events))
	assert.Equal(t, criteria, results.Criteria)
	assert.Equal(t, "1", results.Events[0].Payload["so_detection.publicId"])
	assert.Equal(t, "2", results.Events[1].Payload["so_detection.publicId"])

	reqs := transport.GetRequests()

	assert.Equal(t, 7, len(reqs)) // automatic retry on error inflates this

	// Scroll Requests
	req := reqs[0]
	assert.NotNil(t, req)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "/myIndex/_search", req.URL.Path)
	assert.Contains(t, req.URL.RawQuery, "pretty=true")
	assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")
	assert.Contains(t, req.URL.RawQuery, "track_total_hits=true")

	body, err := io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"_index: \"*:so-detection\" AND so_kind: \"detection\" AND so_detection.engine: \"suricata\" AND so_detection.isCommunity: \"true\""}}],"must_not":[],"should":[]}},"size":10000}`, string(body))

	for _, req := range reqs[1:2] {
		assert.NotNil(t, req)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "/_search/scroll", req.URL.Path)
		assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")

		body, err = io.ReadAll(req.Body)
		assert.Nil(t, err)
		assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
	}

	// ClearScroll Request
	for _, req = range reqs[3:6] {
		assert.NotNil(t, req)
		assert.Equal(t, "DELETE", req.Method)
		assert.Equal(t, "/_search/scroll", req.URL.Path)
	}

	// all of the requests are pointers to the same object with the same body,
	// we can't seek this body so only read/check it once
	body, err = io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
}

func TestScrollClearScroll404(t *testing.T) {
	ctx := context.Background()

	h := memory.New()
	log.SetHandler(h)
	log.SetLevel(log.DebugLevel)

	client, transport := modmock.NewMockClient(t)

	// first response, all good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 70,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "1",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// second response, still good
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 52,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "2",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// third response, last page
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"_scroll_id" : "MyScrollID",
			"took" : 48,
			"timed_out" : false,
			"_shards" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0,
				"failed" : 0
			},
			"_clusters" : {
				"total" : 1,
				"successful" : 1,
				"skipped" : 0
			},
			"hits" : {
				"total" : {
					"value" : 3,
					"relation" : "eq"
				},
				"max_score" : 4.279684,
				"hits" : [
					{
						"_index" : "manager:so-detection",
						"_id" : "crED25ABBp4oOLSg7eY0",
						"_score" : 4.279684,
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269516253Z",
							"so_detection" : {
								"createTime" : "2024-07-22T15:16:17.244146895Z",
								"userId" : "3475de3d-dc89-40fb-b07f-611406dd7fe8",
								"publicId" : "3",
								"title" : "Security Onion IDH - REDIS Action Command Attempt",
								"severity" : "critical",
								"author" : "Security Onion Solutions",
								"description" : "Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.",
								"content" : "",
								"isEnabled" : true,
								"isReporting" : false,
								"isCommunity" : true,
								"engine" : "suricata",
								"language" : "suricata",
								"overrides" : [ ],
								"tags" : null,
								"ruleset" : "securityonion-resources",
								"license" : "Elastic-2.0"
							},
							"so_kind" : "detection"
						}
					}
				]
			}
		}`)),
	}, nil)

	// ClearScroll returns 404
	transport.AddResponse(&http.Response{
		StatusCode: 404,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{"succeeded":true,"num_freed":0}`)),
	}, nil)

	store := &ElasticEventstore{
		esClient:      client,
		cacheTime:     time.Now().Add(time.Hour),
		fieldDefs:     make(map[string]*FieldDefinition),
		maxScrollSize: 10000,
		maxLogLength:  math.MaxInt,
		index:         "myIndex",
	}

	criteria := &model.EventScrollCriteria{
		ParsedQuery: &model.Query{},
	}
	criteria.RawQuery = `_index:"*:so-detection" AND so_kind:"detection" AND so_detection.engine:"suricata" AND so_detection.isCommunity:"true"`
	err := criteria.ParsedQuery.Parse(criteria.RawQuery)
	assert.Nil(t, err)

	results, err := store.Scroll(ctx, criteria, nil)

	assert.Nil(t, err)
	assert.NotNil(t, results)
	assert.Equal(t, 3, results.TotalEvents)
	assert.Equal(t, 3, len(results.Events))
	assert.Equal(t, criteria, results.Criteria)
	assert.Equal(t, "1", results.Events[0].Payload["so_detection.publicId"])
	assert.Equal(t, "2", results.Events[1].Payload["so_detection.publicId"])
	assert.Equal(t, "3", results.Events[2].Payload["so_detection.publicId"])

	// Verify no log entries about scroll close errors
	for _, entry := range h.Entries {
		assert.NotContains(t, entry.Message, "call to close scroll failed")
		assert.NotContains(t, entry.Message, "error closing scroll")
	}

	reqs := transport.GetRequests()

	assert.Equal(t, 4, len(reqs))

	// Initial search request
	req := reqs[0]
	assert.NotNil(t, req)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "/myIndex/_search", req.URL.Path)
	assert.Contains(t, req.URL.RawQuery, "pretty=true")
	assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")
	assert.Contains(t, req.URL.RawQuery, "track_total_hits=true")

	body, err := io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"query":{"bool":{"filter":[],"must":[{"query_string":{"analyze_wildcard":true,"default_field":"*","query":"_index: \"*:so-detection\" AND so_kind: \"detection\" AND so_detection.engine: \"suricata\" AND so_detection.isCommunity: \"true\""}}],"must_not":[],"should":[]}},"size":10000}`, string(body))

	// Scroll requests
	for _, req := range reqs[1:3] {
		assert.NotNil(t, req)
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "/_search/scroll", req.URL.Path)
		assert.Contains(t, req.URL.RawQuery, "scroll=60000ms")

		body, err = io.ReadAll(req.Body)
		assert.Nil(t, err)
		assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
	}

	// ClearScroll request
	req = reqs[3]
	assert.NotNil(t, req)
	assert.Equal(t, "DELETE", req.Method)
	assert.Equal(t, "/_search/scroll", req.URL.Path)

	body, err = io.ReadAll(req.Body)
	assert.Nil(t, err)
	assert.Equal(t, `{"scroll_id":"MyScrollID"}`, string(body))
}

func TestAddUpdateScript(t *testing.T) {
	client, _ := modmock.NewMockClient(t)

	store := &ElasticEventstore{
		esClient:      client,
		cacheTime:     time.Now().Add(time.Hour),
		fieldDefs:     make(map[string]*FieldDefinition),
		maxScrollSize: 10000,
		maxLogLength:  math.MaxInt,
		index:         "myIndex",
	}

	timeNow := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	// Test unacknowledge (ack=false)
	criteria := model.NewEventUpdateCriteria()
	store.AddAckEscalateUpdateScripts(criteria, timeNow, false, false, "admin")
	assert.Len(t, criteria.UpdateScripts, 1)
	assert.Equal(t, "ctx._source.event.acknowledged = false;", criteria.UpdateScripts[0])

	// Test acknowledge without escalate
	criteria = model.NewEventUpdateCriteria()
	store.AddAckEscalateUpdateScripts(criteria, timeNow, true, false, "admin")
	assert.Len(t, criteria.UpdateScripts, 1)
	expected := `
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
			`
	assert.Equal(t, expected, criteria.UpdateScripts[0])
	assert.Equal(t, "admin", criteria.Params["userId"])
	assert.Equal(t, int64(1257894000000), criteria.Params["nowMillis"])

	// Test acknowledge with escalate
	criteria = model.NewEventUpdateCriteria()
	store.AddAckEscalateUpdateScripts(criteria, timeNow, true, true, "admin")
	assert.Len(t, criteria.UpdateScripts, 1)
	assert.Equal(t, true, criteria.Params["escBool"])
	assert.Contains(t, criteria.UpdateScripts[0], "esc_bool = params.escBool")
	assert.Contains(t, criteria.UpdateScripts[0], "ctx._source.event.escalated_by = params.userId;")

	// Test investigation case without session ID
	criteria = model.NewEventUpdateCriteria()
	store.AddInvestigationUpdateScripts(criteria, timeNow, "admin", false)
	assert.Len(t, criteria.UpdateScripts, 1)
	expected = `
			boolean track_timing = params.trackTiming;
			Instant now_instant = Instant.ofEpochMilli(params.nowMillis);
			ZonedDateTime now_date = ZonedDateTime.ofInstant(now_instant, ZoneId.of('Z'));
			
			ctx._source.event.investigated = true;
			ctx._source.event.investigated_by = params.userId;
			if (track_timing) {
				ctx._source.event.investigated_timestamp = now_date;
			}
			`
	assert.Equal(t, expected, criteria.UpdateScripts[0])
	assert.Equal(t, "admin", criteria.Params["userId"])

	// Test investigation case with session ID
	criteria = model.NewEventUpdateCriteria()
	store.AddInvestigationUpdateScripts(criteria, timeNow, "admin", false, "test-session-123")
	assert.Len(t, criteria.UpdateScripts, 1)
	expected = `
			boolean track_timing = params.trackTiming;
			Instant now_instant = Instant.ofEpochMilli(params.nowMillis);
			ZonedDateTime now_date = ZonedDateTime.ofInstant(now_instant, ZoneId.of('Z'));
			
			ctx._source.event.investigated = true;
			ctx._source.event.investigated_by = params.userId;
			ctx._source.event.investigation_session_id = params.sessionId;
			if (track_timing) {
				ctx._source.event.investigated_timestamp = now_date;
			}
			`
	assert.Equal(t, expected, criteria.UpdateScripts[0])
	assert.Equal(t, "test-session-123", criteria.Params["sessionId"])

	// Test investigation delete case
	criteria = model.NewEventUpdateCriteria()
	store.AddInvestigationUpdateScripts(criteria, timeNow, "admin", true)
	assert.Len(t, criteria.UpdateScripts, 1)
	expected = `
		if (ctx._source.event.containsKey('investigation_session_id')) {
			ctx._source.event.remove('investigation_session_id');
		}
	`
	assert.Equal(t, expected, criteria.UpdateScripts[0])
}

func TestSearchPermissionsAuthorized(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)

	client, transport := modmock.NewMockClient(t)
	store := &ElasticEventstore{
		esClient: client,
		server:   srv,
	}

	// refresh cache
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
		"took" : 70,
		"timed_out" : false,
		"_shards" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0,
			"failed" : 0
		},
		"_clusters" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0
		},
		"hits" : {
			"total" : {
				"value" : 3,
				"relation" : "eq"
			},
			"max_score" : 4.279684,
			"hits" : []
		}
	}`)),
	}, nil)

	// search
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
		"took" : 70,
		"timed_out" : false,
		"_shards" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0,
			"failed" : 0
		},
		"_clusters" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0
		},
		"hits" : {
			"total" : {
				"value" : 3,
				"relation" : "eq"
			},
			"max_score" : 4.279684,
			"hits" : []
		}
	}`)),
	}, nil)

	criteria := model.NewEventSearchCriteria()
	err := criteria.Populate("_id:*", "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "0", "0")
	assert.NoError(t, err)

	results, err := store.Search(srv.Context, criteria)
	assert.NoError(t, err)
	assert.NotNil(t, results)

	// msearch
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
		"took" : 70,
		"timed_out" : false,
		"_shards" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0,
			"failed" : 0
		},
		"_clusters" : {
			"total" : 1,
			"successful" : 1,
			"skipped" : 0
		},
		"hits" : {
			"total" : {
				"value" : 3,
				"relation" : "eq"
			},
			"max_score" : 4.279684,
			"hits" : []
		}
	}`)),
	}, nil)

	criteria2 := model.NewEventMSearchCriteria()
	err = criteria2.Populate("myIndex", "_id:*")
	assert.NoError(t, err)

	results2, err := store.MSearch(srv.Context, []*model.EventMSearchCriteria{criteria2})
	assert.NoError(t, err)
	assert.NotNil(t, results2)
}

func TestSearchPermissionsUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()

	client, _ := modmock.NewMockClient(t)
	store := &ElasticEventstore{
		esClient: client,
		server:   srv,
	}

	criteria := model.NewEventSearchCriteria()
	err := criteria.Populate("_id:*", "2020-01-02T12:13:14Z - 2020-01-02T13:13:14Z", time.RFC3339, "America/New_York", "0", "0")
	assert.NoError(t, err)

	results, err := store.Search(srv.Context, criteria)
	assert.Error(t, err)
	unauth := err.(*model.Unauthorized)
	assert.Equal(t, "fake-subject", unauth.Subject)
	assert.Equal(t, "read", unauth.Operation)
	assert.Equal(t, "events", unauth.Target)
	assert.Nil(t, results)

	criteria2 := model.NewEventMSearchCriteria()
	err = criteria2.Populate("myIndex", "_id:*")
	assert.NoError(t, err)

	results2, err := store.MSearch(srv.Context, []*model.EventMSearchCriteria{criteria2})
	assert.Error(t, err)
	unauth = err.(*model.Unauthorized)
	assert.Equal(t, "fake-subject", unauth.Subject)
	assert.Equal(t, "read", unauth.Operation)
	assert.Equal(t, "events", unauth.Target)
	assert.Nil(t, results2)
}

func TestAddParameterToFilter(t *testing.T) {
	store := &ElasticEventstore{}
	filter := model.NewFilter()

	json := `{"hits":{"hits":[{"_source":{"suricata":{"capture_file":"/path/to/pcap"}}}]}}`
	store.addParameterToFilter(json, "suricata.capture_file", filter)
	assert.Equal(t, "/path/to/pcap", filter.Parameters["suricata.capture_file"])

	// Test overwrite
	json2 := `{"hits":{"hits":[{"_source":{"suricata":{"capture_file":"/new/path"}}}]}}`
	store.addParameterToFilter(json2, "suricata.capture_file", filter)
	assert.Equal(t, "/new/path", filter.Parameters["suricata.capture_file"])

	// Test empty value
	json3 := `{"hits":{"hits":[{"_source":{"suricata":{}}}]}}`
	store.addParameterToFilter(json3, "suricata.capture_file", filter)
	assert.Equal(t, "/new/path", filter.Parameters["suricata.capture_file"], "should not have overwritten with empty")
}

func TestPopulateJobFromDocQuery(t *testing.T) {
	ctx := context.Background()
	client, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := &ElasticEventstore{
		esClient:          client,
		server:            srv,
		index:             "myIndex",
		esSearchOffsetMs:  1000,
		timeShiftMs:       500,
		defaultDurationMs: 60000,
	}

	// Primary search response
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"hits" : {
				"total" : {
					"value" : 1,
					"relation" : "eq"
				},
				"hits" : [
					{
						"_source" : {
							"@timestamp" : "2024-07-22T15:54:30.269Z",
							"source" : { "ip": "1.1.1.1", "port": 1111 },
							"destination" : { "ip": "2.2.2.2", "port": 2222 },
							"network" : { "transport": "tcp" },
							"suricata" : { "capture_file": "/path/to/suricata.pcap" },
							"observer" : { "name": "sensor1" }
						}
					}
				]
			}
		}`)),
	}, nil)

	job := model.NewJob()
	err := store.PopulateJobFromDocQuery(ctx, "_id", "some-id", "2024-07-22T15:54:30.269Z", job)
	assert.NoError(t, err)
	assert.Equal(t, "/path/to/suricata.pcap", job.Filter.Parameters["suricata.capture_file"])
	assert.Equal(t, "sensor1", job.NodeId)
	assert.Equal(t, "1.1.1.1", job.Filter.SrcIp)
	assert.Equal(t, "tcp", job.Filter.Protocol)

	// Check begin/end times
	// timestamp: 2024-07-22T15:54:30.269Z
	// duration: 60000ms
	// timeShift: 500ms
	// begin = timestamp - 60000 - 500 = timestamp - 60500ms
	// end = timestamp + 60000 + 500 = timestamp + 60500ms
	ts, _ := time.Parse(time.RFC3339, "2024-07-22T15:54:30.269Z")
	expectedBegin := ts.Add(time.Duration(-60500) * time.Millisecond)
	expectedEnd := ts.Add(time.Duration(60500) * time.Millisecond)
	assert.True(t, expectedBegin.Equal(job.Filter.BeginTime))
	assert.True(t, expectedEnd.Equal(job.Filter.EndTime))
}

func TestPopulateJobFromDocQuery_InjectionAttack(t *testing.T) {
	ctx := context.Background()
	client, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := &ElasticEventstore{
		esClient:          client,
		server:            srv,
		index:             "myIndex",
		esSearchOffsetMs:  1000,
		timeShiftMs:       500,
		defaultDurationMs: 60000,
	}

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"hits":{"total":{"value":0}}}`)),
	}, nil)

	job := model.NewJob()
	attackID := `some-id" }, "must_not": [ { "match_all": {} } ], "filter": { "match": { "secret": "leaked`
	err := store.PopulateJobFromDocQuery(ctx, "_id", attackID, "2024-07-22T15:54:30.269Z", job)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ID")

	reqs := transport.GetRequests()
	assert.Equal(t, 0, len(reqs))
}

func TestAddAcknowledgeScript_InjectionAttack(t *testing.T) {
	updateCriteria := model.NewEventUpdateCriteria()
	store := &ElasticEventstore{}

	attackUser := `admin'; ctx._source.secret = 'leaked`
	store.addAcknowledgeScript(updateCriteria, time.Now(), true, attackUser)

	script := updateCriteria.UpdateScripts[0]
	assert.Contains(t, script, `ctx._source.event.acknowledged_by = params.userId;`)
	assert.Equal(t, attackUser, updateCriteria.Params["userId"])
}

func TestAddInvestigateScript_InjectionAttack(t *testing.T) {
	updateCriteria := model.NewEventUpdateCriteria()
	store := &ElasticEventstore{}

	attackUser := `admin'; ctx._source.secret = 'leaked`
	attackSession := `session'; ctx._source.other = 'leaked`
	store.addInvestigateScript(updateCriteria, time.Now(), attackUser, attackSession)

	script := updateCriteria.UpdateScripts[0]
	assert.Contains(t, script, `ctx._source.event.investigated_by = params.userId;`)
	assert.Contains(t, script, `ctx._source.event.investigation_session_id = params.sessionId;`)
	assert.Equal(t, attackUser, updateCriteria.Params["userId"])
	assert.Equal(t, attackSession, updateCriteria.Params["sessionId"])
}

func TestPopulateJobFromDocQuery_TunnelPath(t *testing.T) {
	ctx := context.Background()
	client, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := &ElasticEventstore{
		esClient:          client,
		server:            srv,
		index:             "myIndex",
		lookupTunnelParent: true,
	}

	// 1. Initial response with tunnel parent
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body: io.NopCloser(strings.NewReader(`{
			"hits": {"total": {"value": 1}, "hits": [{
				"_source": {
					"log": { "id": { "tunnel_parents": ["tunnel-uid-123"] } },
					"@timestamp": "2024-07-22T15:54:30.269Z"
				}
			}]}
		}`)),
	}, nil)

	// 2. Tunnel lookup response
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body: io.NopCloser(strings.NewReader(`{
			"hits": {"total": {"value": 1}, "hits": [{
				"_source": {
					"source": { "ip": "10.0.0.1", "port": 1234 },
					"destination": { "ip": "10.0.0.2", "port": 80 },
					"network": { "transport": "tcp" }
				}
			}]}
		}`)),
	}, nil)

	job := model.NewJob()
	err := store.PopulateJobFromDocQuery(ctx, "_id", "some-id", "2024-07-22T15:54:30.269Z", job)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", job.Filter.SrcIp)
	assert.Equal(t, "10.0.0.2", job.Filter.DstIp)
}

func TestPopulateJobFromDocQuery_ZeekPath_Injection(t *testing.T) {
	ctx := context.Background()
	client, transport := modmock.NewMockClient(t)
	srv := server.NewFakeAuthorizedServer(nil)
	store := &ElasticEventstore{
		esClient:          client,
		server:            srv,
		index:             "myIndex",
	}

	// 1. Initial response with missing IP/Port and malicious fuid
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body: io.NopCloser(strings.NewReader(`{
			"hits": {"total": {"value": 1}, "hits": [{
				"_source": {
					"log": { "id": { "fuid": "F-attack\"; ctx._source.secret='leaked" } },
					"network": { "transport": "tcp" },
					"@timestamp": "2024-07-22T15:54:30.269Z"
				}
			}]}
		}`)),
	}, nil)

	// 2. Zeek File search (should be called with escaped query)
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"hits":{"total":{"value":0}}}`)),
	}, nil)

	job := model.NewJob()
	_ = store.PopulateJobFromDocQuery(ctx, "_id", "some-id", "2024-07-22T15:54:30.269Z", job)

	reqs := transport.GetRequests()
	assert.GreaterOrEqual(t, len(reqs), 2)
	body, _ := io.ReadAll(reqs[1].Body)
	// Check that the Zeek File query is escaped
	assert.Contains(t, string(body), `F-attack\\\"; ctx._source.secret='leaked`)
}

func TestMSearch_Index_Injection(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	client, transport := modmock.NewMockClient(t)
	store := &ElasticEventstore{
		esClient: client,
		server:   srv,
	}
	ctx := context.Background()

	attackIndex := `my-index" OR { "injected": "header" }`
	criteria := []*model.EventMSearchCriteria{
		{
			Index:    attackIndex,
			RawQuery: "*",
		},
	}
	criteria[0].ParsedQuery = model.NewQuery()
	criteria[0].ParsedQuery.Parse(criteria[0].RawQuery)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"responses":[]}`)),
	}, nil)

	_, _ = store.MSearch(ctx, criteria)

	reqs := transport.GetRequests()
	assert.NotEmpty(t, reqs)
	
	var foundReq *http.Request
	for _, req := range reqs {
		if req.Body != nil {
			foundReq = req
			break
		}
	}
	assert.NotNil(t, foundReq)
	body, _ := io.ReadAll(foundReq.Body)
	assert.Contains(t, string(body), `{"index":"my-index\" OR { \"injected\": \"header\" }"}`)
}

func TestScroll_InjectionAttacks(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	client, transport := modmock.NewMockClient(t)
	store := &ElasticEventstore{
		esClient:      client,
		server:        srv,
		index:         "events",
		maxScrollSize: 100,
	}
	ctx := context.Background()

	criteria := &model.EventScrollCriteria{}
	criteria.RawQuery = "*"
	criteria.ParsedQuery = model.NewQuery()
	criteria.ParsedQuery.Parse(criteria.RawQuery)

	attackIndex := `my-index" OR { "injected": "index" }`
	attackScrollID := `my-scroll-id" OR { "injected": "scroll" }`

	// 1. Mock field caps
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"fields":{}}`)),
	}, nil)

	// 2. Initial search response
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
			"took": 1, 
			"timed_out": false, 
			"_shards": {"total": 1, "successful": 1, "failed": 0}, 
			"_scroll_id": %q, 
			"hits":{"total":2, "hits":[{"_index":"events", "_id":"1", "_source":{"@timestamp":"2024-07-22T15:54:30.269Z"}}]}
		}`, attackScrollID))),
	}, nil)

	// 3. Subsequent scroll response
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body: io.NopCloser(strings.NewReader(`{"took": 1, "timed_out": false, "_shards": {"total": 1, "successful": 1, "failed": 0}, "hits":{"total":2, "hits":[]}}`)),
	}, nil)

	_, err := store.Scroll(ctx, criteria, []string{attackIndex})
	assert.NoError(t, err)

	reqs := transport.GetRequests()
	var searchReq, scrollReq *http.Request
	for _, req := range reqs {
		if strings.Contains(req.URL.Path, "_search") && !strings.Contains(req.URL.Path, "scroll") {
			searchReq = req
		} else if strings.Contains(req.URL.Path, "scroll") {
			scrollReq = req
		}
	}

	assert.NotNil(t, searchReq, "Should have found a Search request")
	if searchReq != nil {
		// Verify the index is in the URL path (unescaped in the mock, but proving it's passed)
		assert.Contains(t, searchReq.URL.Path, `my-index"`)
	}

	assert.NotNil(t, scrollReq, "Should have found a Scroll request")
	if scrollReq != nil {
		body, _ := io.ReadAll(scrollReq.Body)
		assert.Contains(t, string(body), `"scroll_id":"my-scroll-id\" OR { \"injected\": \"scroll\" }"`)
	}
}
