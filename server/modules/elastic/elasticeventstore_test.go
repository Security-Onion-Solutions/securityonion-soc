// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

	"github.com/security-onion-solutions/securityonion-soc/model"
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
