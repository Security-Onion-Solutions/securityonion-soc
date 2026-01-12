// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"reflect"
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

func TestSortMetrics(t *testing.T) {
	export := &Export{}

	// Helper function to convert [10]string to []interface{}
	convertToIfaceSlice := func(arr [10]string) []interface{} {
		ifaceSlice := make([]interface{}, len(arr))
		for i, v := range arr {
			ifaceSlice[i] = v
		}
		return ifaceSlice
	}

	metrics := []*model.EventMetric{
		{Keys: convertToIfaceSlice([10]string{"b", "x", "", "", "", "", "", "", "", ""}), Value: 2},
		{Keys: convertToIfaceSlice([10]string{"a", "y", "", "", "", "", "", "", "", ""}), Value: 3},
		{Keys: convertToIfaceSlice([10]string{"c", "z", "", "", "", "", "", "", "", ""}), Value: 1},
	}

	tests := []struct {
		field    string
		dir      string
		expected []*model.EventMetric
	}{
		{
			field: "key0",
			dir:   "asc",
			expected: []*model.EventMetric{
				metrics[1], // "a"
				metrics[0], // "b"
				metrics[2], // "c"
			},
		},
		{
			field: "key0",
			dir:   "desc",
			expected: []*model.EventMetric{
				metrics[2], // "c"
				metrics[0], // "b"
				metrics[1], // "a"
			},
		},
		{
			field: "key1",
			dir:   "asc",
			expected: []*model.EventMetric{
				metrics[0], // "x"
				metrics[1], // "y"
				metrics[2], // "z"
			},
		},
		{
			field: "value",
			dir:   "asc",
			expected: []*model.EventMetric{
				metrics[2], // 1
				metrics[0], // 2
				metrics[1], // 3
			},
		},
		{
			field: "value",
			dir:   "desc",
			expected: []*model.EventMetric{
				metrics[1], // 3
				metrics[0], // 2
				metrics[2], // 1
			},
		},
	}

	for _, tt := range tests {
		// Copy metrics to avoid in-place sorting affecting other tests
		input := make([]*model.EventMetric, len(metrics))
		copy(input, metrics)
		result := export.sortMetrics(tt.field, tt.dir, input)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("sortMetrics(%q, %q) = %v, want %v", tt.field, tt.dir, result, tt.expected)
		}
	}
}

func TestSortAssistantMessages(t *testing.T) {
	export := NewExport(nil)

	// Helper to create a StoredMessage
	createMsg := func(id, sessionId, role string, createTime *time.Time) *model.StoredMessage {
		return &model.StoredMessage{
			Auditable: model.Auditable{
				Id:         id,
				CreateTime: createTime,
			},
			SessionId: sessionId,
			Message:   &model.Message{Role: role},
		}
	}

	now := time.Now()
	time1 := now.Add(-3 * time.Hour)
	time2 := now.Add(-2 * time.Hour)
	time3 := now.Add(-1 * time.Hour)

	// Test sorting by ID
	t.Run("SortById", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg3", "session1", "user", &time1),
			createMsg("msg1", "session1", "user", &time2),
			createMsg("msg2", "session1", "assistant", &time3),
		}
		sortedList := export.sortAssistantMessages("id", "asc", list)
		assert.Equal(t, "msg1", sortedList[0].Id)
		assert.Equal(t, "msg2", sortedList[1].Id)
		assert.Equal(t, "msg3", sortedList[2].Id)
	})

	// Test sorting by CreateTime
	t.Run("SortByCreateTime", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg1", "session1", "user", &time2),
			createMsg("msg2", "session1", "assistant", &time3),
			createMsg("msg3", "session1", "user", &time1),
		}
		sortedList := export.sortAssistantMessages("createtime", "asc", list)
		assert.Equal(t, "msg3", sortedList[0].Id)
		assert.Equal(t, "msg1", sortedList[1].Id)
		assert.Equal(t, "msg2", sortedList[2].Id)
	})

	// Test sorting by SessionId
	t.Run("SortBySessionId", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg1", "session3", "user", &time1),
			createMsg("msg2", "session1", "assistant", &time2),
			createMsg("msg3", "session2", "user", &time3),
		}
		sortedList := export.sortAssistantMessages("sessionid", "asc", list)
		assert.Equal(t, "session1", sortedList[0].SessionId)
		assert.Equal(t, "session2", sortedList[1].SessionId)
		assert.Equal(t, "session3", sortedList[2].SessionId)
	})

	// Test sorting by Role
	t.Run("SortByRole", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg1", "session1", "user", &time1),
			createMsg("msg2", "session1", "assistant", &time2),
			createMsg("msg3", "session1", "user", &time3),
		}
		sortedList := export.sortAssistantMessages("role", "asc", list)
		assert.Equal(t, "assistant", sortedList[0].Message.Role)
		assert.Equal(t, "user", sortedList[1].Message.Role)
	})

	// Test handling nil Message
	t.Run("HandleNilMessage", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg1", "session1", "user", &time1),
			{Auditable: model.Auditable{Id: "msg2"}, SessionId: "session1", Message: nil},
			createMsg("msg3", "session1", "assistant", &time3),
		}
		sortedList := export.sortAssistantMessages("role", "asc", list)
		assert.Nil(t, sortedList[1].Message)
	})

	// Test descending sort
	t.Run("SortDescending", func(t *testing.T) {
		list := []*model.StoredMessage{
			createMsg("msg1", "session1", "user", &time1),
			createMsg("msg2", "session1", "assistant", &time2),
			createMsg("msg3", "session1", "user", &time3),
		}
		sortedList := export.sortAssistantMessages("id", "desc", list)
		assert.Equal(t, "msg3", sortedList[0].Id)
		assert.Equal(t, "msg2", sortedList[1].Id)
		assert.Equal(t, "msg1", sortedList[2].Id)
	})
}

func TestSortAssistantSessionDetails(t *testing.T) {
	export := NewExport(nil)

	now := time.Now()
	time1 := now.Add(-3 * time.Hour)
	time2 := now.Add(-2 * time.Hour)
	time3 := now.Add(-1 * time.Hour)

	createSession := func(id, sessionId, title string, createTime *time.Time) *model.AssistantSessionDetails {
		return &model.AssistantSessionDetails{
			Session: &model.AssistantSession{
				Auditable: model.Auditable{Id: id, CreateTime: createTime},
				SessionId: sessionId,
				Title:     title,
			},
		}
	}

	t.Run("SortByIdAsc", func(t *testing.T) {
		list := []*model.AssistantSessionDetails{
			createSession("session3", "chat_3", "C", &time1),
			createSession("session1", "chat_1", "A", &time2),
			createSession("session2", "chat_2", "B", &time3),
		}
		sorted := export.SortAssistantSessionDetails("id", "asc", list)
		assert.Equal(t, "session1", sorted[0].Session.Id)
		assert.Equal(t, "session2", sorted[1].Session.Id)
		assert.Equal(t, "session3", sorted[2].Session.Id)
	})

	t.Run("SortByTitleDesc", func(t *testing.T) {
		list := []*model.AssistantSessionDetails{
			createSession("s1", "c1", "Alpha", &time1),
			createSession("s2", "c2", "Charlie", &time2),
			createSession("s3", "c3", "Bravo", &time3),
		}
		sorted := export.SortAssistantSessionDetails("title", "desc", list)
		assert.Equal(t, "Charlie", sorted[0].Session.Title)
		assert.Equal(t, "Bravo", sorted[1].Session.Title)
		assert.Equal(t, "Alpha", sorted[2].Session.Title)
	})

	t.Run("SortByCreateTime", func(t *testing.T) {
		list := []*model.AssistantSessionDetails{
			createSession("s1", "c1", "A", &time2),
			createSession("s2", "c2", "B", &time3),
			createSession("s3", "c3", "C", &time1),
		}
		sorted := export.SortAssistantSessionDetails("createtime", "asc", list)
		assert.Equal(t, "s3", sorted[0].Session.Id)
		assert.Equal(t, "s1", sorted[1].Session.Id)
		assert.Equal(t, "s2", sorted[2].Session.Id)
	})

	t.Run("HandleNilValues", func(t *testing.T) {
		list := []*model.AssistantSessionDetails{
			createSession("s1", "c1", "A", &time1),
			nil,
			{Session: nil},
		}
		sorted := export.SortAssistantSessionDetails("id", "asc", list)
		assert.NotNil(t, sorted[0].Session)
		assert.Nil(t, sorted[1])
		assert.Nil(t, sorted[2].Session)
	})
}
