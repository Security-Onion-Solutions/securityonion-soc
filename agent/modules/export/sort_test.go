// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestSortRelatedEvent(t *testing.T) {
	export := NewExport(nil) // Need an instance to call the method

	// Helper to create a RelatedEvent with specific fields
	// Corrected: Removed 'id' parameter as model.RelatedEvent does not have an 'Id' field.
	createRelatedEvent := func(fields map[string]interface{}) *model.RelatedEvent {
		return &model.RelatedEvent{
			Fields: fields,
		}
	}

	// Test Case 1: Empty list
	t.Run("EmptyList", func(t *testing.T) {
		list := []*model.RelatedEvent{}
		sortedList := export.sortRelatedEvents("id", "asc", list)
		assert.Empty(t, sortedList)
	})

	// Test Case 2: Sort by string field (ID) ascending
	t.Run("SortRelatedEventsAsc", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{"id": "event2"}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "asc", list)
		assert.Equal(t, "event1", sortedList[0].Fields["id"])
		assert.Equal(t, "event2", sortedList[1].Fields["id"])
		assert.Equal(t, "event3", sortedList[2].Fields["id"])
	})

	// Test Case 3: Sort by string field (ID) descending
	t.Run("SortRelatedEventsDesc", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{"id": "event2"}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "desc", list)
		assert.Equal(t, "event3", sortedList[0].Fields["id"])
		assert.Equal(t, "event2", sortedList[1].Fields["id"])
		assert.Equal(t, "event1", sortedList[2].Fields["id"])

	})

	// Test Case 4: Sort by numeric field (count) ascending
	t.Run("SortByCountAsc", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"count": 3}),
			createRelatedEvent(map[string]interface{}{"count": 1}),
			createRelatedEvent(map[string]interface{}{"count": 2}),
		}
		sortedList := export.sortRelatedEvents("fields:count", "asc", list)
		assert.Equal(t, 1, sortedList[0].Fields["count"])
		assert.Equal(t, 2, sortedList[1].Fields["count"])
		assert.Equal(t, 3, sortedList[2].Fields["count"])

	})

	// Test Case 5: Sort by numeric field (count) descending
	t.Run("SortByCountDesc", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"count": 3}),
			createRelatedEvent(map[string]interface{}{"count": 1}),
			createRelatedEvent(map[string]interface{}{"count": 2}),
		}
		sortedList := export.sortRelatedEvents("fields:count", "desc", list)
		assert.Equal(t, 3, sortedList[0].Fields["count"])
		assert.Equal(t, 2, sortedList[1].Fields["count"])
		assert.Equal(t, 1, sortedList[2].Fields["count"])
	})

	// Test Case 6: Sort by time.Time field (timestamp) ascending
	t.Run("SortByTimestampAsc", func(t *testing.T) {
		now := time.Now()
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-2 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-1 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-3 * time.Hour)}),
		}
		expected := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-3 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-2 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"timestamp": now.Add(-1 * time.Hour)}),
		}
		sortedList := export.sortRelatedEvents("fields:timestamp", "asc", list)
		assert.Equal(t, expected, sortedList)
	})

	// Test Case 7: Sort by time.Time field (timestamp) descending
	t.Run("SortByTimestampDesc", func(t *testing.T) {
		now := time.Now()
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "1", "timestamp": now.Add(-2 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"id": "2", "timestamp": now.Add(-1 * time.Hour)}),
			createRelatedEvent(map[string]interface{}{"id": "3", "timestamp": now.Add(-3 * time.Hour)}),
		}
		sortedList := export.sortRelatedEvents("fields:timestamp", "desc", list)
		assert.Equal(t, "2", sortedList[0].Fields["id"])
		assert.Equal(t, "1", sortedList[1].Fields["id"])
		assert.Equal(t, "3", sortedList[2].Fields["id"])
	})

	// Test Case 8: Handle nil RelatedEvent pointers
	t.Run("HandleNilRelatedEvent", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			nil,
			createRelatedEvent(map[string]interface{}{"id": "event2"}),
		}
		expected := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			nil,
			createRelatedEvent(map[string]interface{}{"id": "event2"}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "asc", list)
		assert.Equal(t, expected, sortedList)
	})

	// Test Case 9: Handle nil Fields map
	t.Run("HandleNilFieldsMap", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			{Fields: nil}, // Corrected: Removed Id field
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
		}
		expected := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			{Fields: nil}, // Corrected: Removed Id field
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "asc", list)
		assert.Equal(t, expected, sortedList)
	})

	// Test Case 10: Handle missing sort field in some events
	t.Run("HandleMissingSortField", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{}), // Missing 'id' field
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
		}
		// The behavior for missing fields is to return false, which means their relative order is preserved.
		// The current implementation places items with missing fields at the end when sorting ascending.
		expected := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
			createRelatedEvent(map[string]interface{}{}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "asc", list)
		assert.Equal(t, expected, sortedList)
	})

	// Test Case 11: Handle missing sort field in some events (descending)
	t.Run("HandleMissingSortFieldDesc", func(t *testing.T) {
		list := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{}), // Missing 'id' field
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
		}
		// The behavior for missing fields is to return false, which means their relative order is preserved.
		// The current implementation places items with missing fields at the end when sorting descending.
		expected := []*model.RelatedEvent{
			createRelatedEvent(map[string]interface{}{"id": "event3"}),
			createRelatedEvent(map[string]interface{}{"id": "event1"}),
			createRelatedEvent(map[string]interface{}{}),
		}
		sortedList := export.sortRelatedEvents("fields:id", "desc", list)
		assert.Equal(t, expected, sortedList)
	})
}
