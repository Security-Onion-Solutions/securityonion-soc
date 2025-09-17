// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/security-onion-solutions/securityonion-soc/json"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func (store *ElasticEventstore) CancelQuery(ctx context.Context, queryId string) error {
	err := store.server.CheckAuthorized(ctx, "delete", "queries")
	if err != nil {
		return err
	}

	return store.cancelQuery(ctx, queryId)
}

func (store *ElasticEventstore) cancelQuery(ctx context.Context, queryId string) error {
	queries, _ := store.getActiveQueries(ctx, false)
	for _, query := range queries {
		if query.TaskId == queryId {
			resp, err := query.EsClient.Tasks.Cancel(
				store.esClient.Tasks.Cancel.WithContext(ctx),
				store.esClient.Tasks.Cancel.WithTaskID(queryId))
			respJson, _ := json.WriteJson(resp)
			log.WithFields(log.Fields{
				"cancelQueryResponse": string(respJson),
				"queryId":             queryId,
			}).WithError(err).Debug("Received elastic query cancelation response")
			return err
		}
	}
	return errors.New("query not found")
}

func (store *ElasticEventstore) GetActiveQueries(ctx context.Context, filter bool) ([]*model.QueryTask, error) {
	err := store.server.CheckAuthorized(ctx, "read", "queries")
	if err != nil {
		return nil, err
	}

	return store.getActiveQueries(ctx, filter)
}

func (store *ElasticEventstore) getActiveQueries(ctx context.Context, filter bool) ([]*model.QueryTask, error) {
	tasks := make([]*model.QueryTask, 0)
	var err error
	for _, client := range store.esAllClients {
		response, clientErr := store.esClient.Tasks.List(store.esClient.Tasks.List.WithContext(ctx))
		if err != nil {
			err = clientErr
			continue
		}

		defer response.Body.Close()

		body, readErr := io.ReadAll(response.Body)
		if err != nil {
			err = readErr
			continue
		}

		gridId := ""
		serverTasks, convertErr := convertFromElasticQueryTaskResults(string(body), client, gridId, filter)
		if convertErr != nil {
			err = convertErr
			continue
		}

		tasks = append(tasks, serverTasks...)
	}

	return tasks, err
}

type ElasticTask struct {
	Cancelable   bool   `json:"cancellable"`
	Action       string `json:"action"`
	Type         string `json:"type"`
	StartTime    int64  `json:"start_time_in_millis"`
	ElapsedNanos int64  `json:"running_time_in_nanos"`
	ParentTaskId string `json:"parent_task_id"`
}

type ElasticNodeTasks struct {
	Name             string                 `json:"name"`
	TransportAddress string                 `json:"transport_address"`
	Host             string                 `json:"host"`
	Ip               string                 `json:"ip"`
	Tasks            map[string]ElasticTask `json:"tasks"`
}

type ElasticTaskResults struct {
	Nodes map[string]ElasticNodeTasks `json:"nodes"`
}

func convertFromElasticQueryTaskResults(content string, client *elasticsearch.Client, gridId string, filter bool) ([]*model.QueryTask, error) {
	elasticTaskResults := ElasticTaskResults{}
	err := json.LoadJson([]byte(content), &elasticTaskResults)
	if err != nil {
		return nil, err
	}

	tasks := make([]*model.QueryTask, 0)
	for _, node := range elasticTaskResults.Nodes {
		for taskId, task := range node.Tasks {
			// Optionally filter out permanent, child, non-cancelable tasks, and this list query itself
			log.WithField("elasticTask", task).Debug("Found active Elasticsearch task")
			include := true
			if filter {
				if !task.Cancelable {
					include = false
				} else if task.Type == "persistent" {
					include = false
				} else if len(task.ParentTaskId) > 0 {
					include = false
				} else if task.Action == "cluster:monitor/tasks/lists" {
					include = false
				}
			}
			if include {
				queryTask := &model.QueryTask{
					TaskId:     taskId,
					Cancelable: task.Cancelable,
					Details:    fmt.Sprintf("%s (%s)", task.Type, task.Action),
					StartTime:  time.Unix(0, task.StartTime*int64(time.Millisecond)),
					ElapsedMs:  task.ElapsedNanos / (1000 * 1000),
					GridId:     gridId,
					EsClient:   client,
				}
				tasks = append(tasks, queryTask)
			}
		}
	}

	return tasks, nil
}
