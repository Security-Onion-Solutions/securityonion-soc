// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

type FakeEventstore struct {
	InputDocuments       []map[string]interface{}
	InputContexts        []context.Context
	InputIndexes         []string
	InputIds             []string
	InputSearchCriterias []*model.EventSearchCriteria
	InputUpdateCriterias []*model.EventUpdateCriteria
	InputAckCriterias    []*model.EventAckCriteria
	Err                  error
	SearchResults        []*model.EventSearchResults
	IndexResults         []*model.EventIndexResults
	UpdateResults        []*model.EventUpdateResults
	searchCount          int
	indexCount           int
	updateCount          int
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
	store.SearchResults = make([]*model.EventSearchResults, 0, 0)
	store.SearchResults = append(store.SearchResults, model.NewEventSearchResults())
	store.IndexResults = make([]*model.EventIndexResults, 0, 0)
	store.IndexResults = append(store.IndexResults, model.NewEventIndexResults())
	store.UpdateResults = make([]*model.EventUpdateResults, 0, 0)
	store.UpdateResults = append(store.UpdateResults, model.NewEventUpdateResults())
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
