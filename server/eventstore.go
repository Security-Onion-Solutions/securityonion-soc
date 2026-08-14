// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// FindEventBySocId finds the event matching the given SOC id (log.id.uid,
// event.id, or _id), or nil if none matched. A non-zero ts bounds the search
// to +/-24h around it before falling back to an unbounded search.
func FindEventBySocId(ctx context.Context, store Eventstore, id string, ts time.Time) (*model.EventRecord, error) {
	if !ts.IsZero() {
		dateRange := ts.Add(-24*time.Hour).Format(time.RFC3339) + " - " + ts.Add(24*time.Hour).Format(time.RFC3339)

		event, err := findEventBySocId(ctx, store, id, dateRange)
		if err != nil || event != nil {
			return event, err
		}
	}

	dateRange := "1970-01-01T00:00:00Z - " + time.Now().Format(time.RFC3339)

	return findEventBySocId(ctx, store, id, dateRange)
}

func findEventBySocId(ctx context.Context, store Eventstore, id string, dateRange string) (*model.EventRecord, error) {
	query := fmt.Sprintf(`log.id.uid:"%[1]s" OR event.id:"%[1]s" OR _id:"%[1]s"`, id)
	criteria := model.NewEventSearchCriteria()

	err := criteria.Populate(query, dateRange, time.RFC3339, "", "0", "1")
	if err != nil {
		return nil, fmt.Errorf("failed to populate event search criteria: %w", err)
	}

	events, err := store.Search(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for alert: %w", err)
	}
	if events.TotalEvents == 0 || len(events.Events) == 0 {
		return nil, nil
	}

	return events.Events[0], nil
}

type Eventstore interface {
	Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error)
	MSearch(context context.Context, criteria []*model.EventMSearchCriteria) (*model.EventMSearchResults, error)
	Scroll(context context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error)
	Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error)
	Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
	Delete(context context.Context, index string, id string) error
	Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error)
	GetActiveQueries(context context.Context, filter bool) ([]*model.QueryTask, error)
	CancelQuery(context context.Context, queryId string) error

	// GetEventsHealth diagnoses the backend's own datastore and reports it in
	// the shared model: indicators and findings ranked most severe first,
	// optional sections best-effort with failures recorded in Errors.
	GetEventsHealth(ctx context.Context) (*model.EventsHealth, error)
}
