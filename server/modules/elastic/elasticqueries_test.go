// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/security-onion-solutions/securityonion-soc/server"
	modmock "github.com/security-onion-solutions/securityonion-soc/server/modules/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestCancelQueryMissing(t *testing.T) {
	store := NewElasticEventstore(server.NewFakeAuthorizedServer(nil))

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	// Mock the Elasticsearch client
	mockEsClient, transport := modmock.NewMockClient(t)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader("{}")),
	}, nil)

	store.esAllClients = []*elasticsearch.Client{mockEsClient}
	store.esClient = mockEsClient

	// Create a mock active query
	queryId := "test-query"

	// Call the CancelQuery function with the ID of the mock query
	err := store.CancelQuery(ctx, queryId)

	// Assert that the function returns without an error
	assert.ErrorContains(t, err, "query not found")
}

func TestCancelQuery(t *testing.T) {
	store := NewElasticEventstore(server.NewFakeAuthorizedServer(nil))

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	// Mock the Elasticsearch client
	mockEsClient, transport := modmock.NewMockClient(t)

	existingTasks := `
		{
		"nodes" : {
			"oTUltX4IQMOUUVeiohTt8A" : {
			"name" : "H5dfFeA",
			"transport_address" : "127.0.0.1:9300",
			"host" : "127.0.0.1",
			"ip" : "127.0.0.1:9300",
			"tasks" : {
				"oTUltX4IQMOUUVeiohTt8A:464" : {
				"node" : "oTUltX4IQMOUUVeiohTt8A",
				"id" : 464,
				"type" : "transport",
				"action" : "indices:data/read/search",
				"description" : "indices[test], types[test], search_type[QUERY_THEN_FETCH], source[{\"query\":...}]",
				"start_time_in_millis" : 1483478610008,
				"running_time_in_nanos" : 13991383,
				"cancellable" : true
				}
			}
			}
		}
		}
	`
	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(existingTasks)),
	}, nil)

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}, nil)

	store.esAllClients = []*elasticsearch.Client{mockEsClient}
	store.esClient = mockEsClient

	// Create a mock active query
	queryId := "oTUltX4IQMOUUVeiohTt8A:464"

	// Call the CancelQuery function with the ID of the mock query
	err := store.CancelQuery(ctx, queryId)

	// Assert that the function returns without an error
	assert.NoError(t, err)
}

func TestConvertFromElasticQueryTaskResults(t *testing.T) {
	// Mock the Elasticsearch client
	mockEsClient, _ := modmock.NewMockClient(t)

	// Prepare a sample Elasticsearch task list response
	content := `
	{
		"nodes": {
			"node-1": {
				"name": "node-1",
				"transport_address": "127.0.0.1:9300",
				"host": "127.0.0.1",
				"ip": "127.0.0.1",
				"tasks": {
					"12345": {
						"cancellable": true,
						"action": "indices:data/read/search",
						"type": "transport",
						"start_time_in_millis": 1678886400000,
						"running_time_in_nanos": 100000000,
						"parent_task_id": ""
					},
					"67890": {
						"cancellable": false,
						"action": "cluster:monitor/tasks/lists",
						"type": "persistent",
						"start_time_in_millis": 1678886400000,
						"running_time_in_nanos": 200000000,
						"parent_task_id": ""
					}
				}
			}
		}
	}
	`

	// Call the convertFromElasticQueryTaskResults function
	tasks, err := convertFromElasticQueryTaskResults(content, mockEsClient, "myGrid", true)

	// Assert that the function returns the active queries without an error
	assert.NoError(t, err)
	assert.Len(t, tasks, 1)

	// Call the convertFromElasticQueryTaskResults function with filter = false
	tasks, err = convertFromElasticQueryTaskResults(content, mockEsClient, "myGrid", false)

	// Assert that the function returns the active queries without an error
	assert.NoError(t, err)
	assert.Len(t, tasks, 2)

	// Verify the contents of the returned query
	assert.Equal(t, "12345", tasks[0].TaskId)
	assert.Equal(t, true, tasks[0].Cancellable)
	assert.Equal(t, "transport (indices:data/read/search)", tasks[0].Details)
	assert.Equal(t, "myGrid", tasks[0].GridId)

	assert.Equal(t, "67890", tasks[1].TaskId)
	assert.Equal(t, false, tasks[1].Cancellable)
	assert.Equal(t, "persistent (cluster:monitor/tasks/lists)", tasks[1].Details)
	assert.Equal(t, "myGrid", tasks[1].GridId)
}

func TestConvertFromElasticQueryTaskResultsError(t *testing.T) {
	// Mock the Elasticsearch client
	mockEsClient, _ := modmock.NewMockClient(t)

	// Prepare an invalid Elasticsearch task list response
	content := `
	{
		"nodes": {
			"node-1": {
				"name": "node-1",
				"transport_address": "127.0.0.1:9300",
				"host": "127.0.0.1",
				"ip": "127.0.0.1",
				"tasks": {
					"12345": {
						"cancellable": true,
						"action": "indices:data/read/search",
						"type": "transport",
						"start_time_in_millis": "invalid",
						"running_time_in_nanos": 100000000,
						"parent_task_id": ""
					}
				}
			}
		}
	}
	`

	// Call the convertFromElasticQueryTaskResults function
	_, err := convertFromElasticQueryTaskResults(content, mockEsClient, "myGrid", true)

	// Assert that the function returns an error
	assert.Error(t, err)
}

func TestGetActiveQueries(t *testing.T) {
	store := NewElasticEventstore(server.NewFakeAuthorizedServer(nil))

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	// Mock the Elasticsearch client
	mockEsClient, transport := modmock.NewMockClient(t)

	content := `
	{
		"nodes": {
			"node-1": {
				"name": "node-1",
				"transport_address": "127.0.0.1:9300",
				"host": "127.0.0.1",
				"ip": "127.0.0.1",
				"tasks": {
					"12345": {
						"cancellable": true,
						"action": "indices:data/read/search",
						"type": "transport",
						"start_time_in_millis": 1678886400000,
						"running_time_in_nanos": 100000000,
						"parent_task_id": ""
					}
				}
			}
		}
	}
	`

	transport.AddResponse(&http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
		},
		Body: io.NopCloser(strings.NewReader(content)),
	}, nil)

	store.esAllClients = []*elasticsearch.Client{mockEsClient}
	store.esClient = mockEsClient

	// Call the GetActiveQueries function
	tasks, err := store.GetActiveQueries(ctx, true)

	// Assert that the function returns the active queries without an error
	assert.NoError(t, err)
	assert.Len(t, tasks, 1)

	// Verify the contents of the returned query
	assert.Equal(t, "12345", tasks[0].TaskId)
	assert.Equal(t, true, tasks[0].Cancellable)
	assert.Equal(t, "transport (indices:data/read/search)", tasks[0].Details)
	assert.Equal(t, "", tasks[0].GridId)
}

func TestGetActiveQueriesUnauthorized(t *testing.T) {
	store := NewElasticEventstore(server.NewFakeUnauthorizedServer())
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	// Call the GetActiveQueries function
	_, err := store.GetActiveQueries(ctx, true)

	// Assert that the function returns an error
	assert.Error(t, err)
	assert.ErrorContains(t, err, "not authorized")
}
