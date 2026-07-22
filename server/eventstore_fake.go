// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type FakeEventstore struct {
	InputDocuments        []map[string]interface{}
	InputContexts         []context.Context
	InputIndexes          []string
	InputIds              []string
	InputSearchCriterias  []*model.EventSearchCriteria
	InputMSearchCriterias [][]*model.EventMSearchCriteria
	InputUpdateCriterias  []*model.EventUpdateCriteria
	InputAckCriterias     []*model.EventAckCriteria
	InputScrollCriterias  []*model.EventScrollCriteria
	InputScrollIndexes    [][]string
	InputExplainIndexes   []string
	InputExplainShards    []int64
	InputExplainPrimaries []bool
	Err                   error
	HealthReportJson      string
	HealthReportErr       error
	ClusterSettingsJson   string
	ClusterSettingsErr    error
	NodesJson             string
	NodesErr              error
	ShardsJson            string
	ShardsErr             error
	ExplainResults        []FakeExplainResult
	SearchResults         []*model.EventSearchResults
	MSearchResults        []*model.EventMSearchResults
	IndexResults          []*model.EventIndexResults
	UpdateResults         []*model.EventUpdateResults
	ScrollResults         []*model.EventScrollResults
	searchCount           int
	msearchCount          int
	indexCount            int
	updateCount           int
	scrollCount           int
	explainCount          int
}

// One ExplainAllocation outcome; calls beyond the configured results return
// the zero value.
type FakeExplainResult struct {
	Json string
	Err  error
}

func NewFakeEventstore() *FakeEventstore {
	store := &FakeEventstore{}
	store.InputDocuments = make([]map[string]interface{}, 0)
	store.InputContexts = make([]context.Context, 0)
	store.InputIndexes = make([]string, 0)
	store.InputIds = make([]string, 0)
	store.InputSearchCriterias = make([]*model.EventSearchCriteria, 0)
	store.InputUpdateCriterias = make([]*model.EventUpdateCriteria, 0)
	store.InputAckCriterias = make([]*model.EventAckCriteria, 0)
	store.InputScrollCriterias = make([]*model.EventScrollCriteria, 0)
	store.SearchResults = make([]*model.EventSearchResults, 0)
	store.SearchResults = append(store.SearchResults, model.NewEventSearchResults())
	store.IndexResults = make([]*model.EventIndexResults, 0)
	store.IndexResults = append(store.IndexResults, model.NewEventIndexResults())
	store.UpdateResults = make([]*model.EventUpdateResults, 0)
	store.UpdateResults = append(store.UpdateResults, model.NewEventUpdateResults())
	store.ScrollResults = make([]*model.EventScrollResults, 0)
	store.ScrollResults = append(store.ScrollResults, model.NewEventScrollResults())
	return store
}

func (store *FakeEventstore) Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputSearchCriterias = append(store.InputSearchCriterias, criteria)
	if store.searchCount >= len(store.SearchResults) {
		store.searchCount = len(store.SearchResults) - 1
	}
	result := store.SearchResults[store.searchCount]
	store.searchCount += 1
	return result, store.Err
}

func (store *FakeEventstore) MSearch(context context.Context, criteria []*model.EventMSearchCriteria) (*model.EventMSearchResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputMSearchCriterias = append(store.InputMSearchCriterias, criteria)
	if store.msearchCount >= len(store.MSearchResults) {
		store.msearchCount = len(store.MSearchResults) - 1
	}
	result := store.MSearchResults[store.msearchCount]
	store.msearchCount += 1
	return result, store.Err
}

func (store *FakeEventstore) EventSearch(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputSearchCriterias = append(store.InputSearchCriterias, criteria)
	if store.searchCount >= len(store.SearchResults) {
		store.searchCount = len(store.SearchResults) - 1
	}
	result := store.SearchResults[store.searchCount]
	store.searchCount += 1
	return result, store.Err
}

func (store *FakeEventstore) Index(context context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputIndexes = append(store.InputIndexes, index)
	store.InputDocuments = append(store.InputDocuments, document)
	store.InputIds = append(store.InputIds, id)
	if store.indexCount >= len(store.IndexResults) {
		store.indexCount = len(store.IndexResults) - 1
	}
	result := store.IndexResults[store.indexCount]
	store.indexCount += 1
	return result, store.Err
}

func (store *FakeEventstore) Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputUpdateCriterias = append(store.InputUpdateCriterias, criteria)
	if store.updateCount >= len(store.UpdateResults) {
		store.updateCount = len(store.UpdateResults) - 1
	}
	result := store.UpdateResults[store.updateCount]
	store.updateCount += 1
	return result, store.Err
}

func (store *FakeEventstore) Delete(context context.Context, index string, id string) error {
	store.InputContexts = append(store.InputContexts, context)
	store.InputIndexes = append(store.InputIndexes, index)
	store.InputIds = append(store.InputIds, id)
	return store.Err
}

func (store *FakeEventstore) Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputAckCriterias = append(store.InputAckCriterias, criteria)
	if store.updateCount >= len(store.UpdateResults) {
		store.updateCount = len(store.UpdateResults) - 1
	}
	result := store.UpdateResults[store.updateCount]
	store.updateCount += 1
	return result, store.Err
}

func (store *FakeEventstore) Scroll(context context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error) {
	store.InputContexts = append(store.InputContexts, context)
	store.InputScrollCriterias = append(store.InputScrollCriterias, criteria)
	store.InputScrollIndexes = append(store.InputScrollIndexes, indexes)
	if store.scrollCount >= len(store.ScrollResults) {
		store.scrollCount = len(store.ScrollResults) - 1
	}
	result := store.ScrollResults[store.scrollCount]
	store.scrollCount += 1
	return result, store.Err
}

func (store *FakeEventstore) GetActiveQueries(context context.Context, filter bool) ([]*model.QueryTask, error) {
	fakeTask1 := &model.QueryTask{
		GridId:     "abc",
		TaskId:     "abc:123",
		Details:    "something",
		Cancelable: false,
		StartTime:  time.Now(),
	}

	fakeTask2 := &model.QueryTask{
		GridId:     "",
		TaskId:     "xyz:456",
		Details:    "something else",
		Cancelable: true,
		StartTime:  time.Now(),
	}

	tasks := make([]*model.QueryTask, 0)
	tasks = append(tasks, fakeTask1)
	tasks = append(tasks, fakeTask2)
	return tasks, nil
}

func (store *FakeEventstore) CancelQuery(context context.Context, queryId string) error {
	return errors.New("query not found")
}

func (store *FakeEventstore) ClusterHealthReport(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.HealthReportJson, store.HealthReportErr
}

func (store *FakeEventstore) ClusterSettings(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.ClusterSettingsJson, store.ClusterSettingsErr
}

func (store *FakeEventstore) ListNodes(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.NodesJson, store.NodesErr
}

func (store *FakeEventstore) ListShards(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.ShardsJson, store.ShardsErr
}

func (store *FakeEventstore) ExplainAllocation(ctx context.Context, index string, shard int64, primary bool) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	store.InputExplainIndexes = append(store.InputExplainIndexes, index)
	store.InputExplainShards = append(store.InputExplainShards, shard)
	store.InputExplainPrimaries = append(store.InputExplainPrimaries, primary)
	var result FakeExplainResult
	if store.explainCount < len(store.ExplainResults) {
		result = store.ExplainResults[store.explainCount]
	}
	store.explainCount += 1
	return result.Json, result.Err
}
