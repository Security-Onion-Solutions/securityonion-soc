// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
)

func TestParseRangeAllowRelative(t *testing.T) {
	testCases := []struct {
		name             string
		rangeStart       string
		rangeEnd         string
		format           string
		expectStart      string        // Exact string match (if non-empty)
		expectEnd        string        // Exact string match (if non-empty)
		expectDelta      time.Duration // Expected time difference between start and end
		deltaTolerance   time.Duration // Tolerance for time difference (defaults to 5 seconds)
		checkMidnight    bool          // Verify start time is at midnight (for "today")
		checkSeparator   bool          // Verify " - " separator (default true)
		checkNonEmpty    bool          // Verify result is not empty (default true)
		expectParseable  bool          // Verify both parts are parseable as dates (default false)
		expectStartOrder bool          // Verify start is before end (default false)
	}{
		{
			name:             "default empty values",
			rangeStart:       "",
			rangeEnd:         "",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      24 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -1h to now",
			rangeStart:       "-1h",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      1 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -24h to now",
			rangeStart:       "-24h",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      24 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -7d to now",
			rangeStart:       "-7d",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      7 * 24 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -30m to now",
			rangeStart:       "-30m",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      30 * time.Minute,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -5h to now",
			rangeStart:       "-5h",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      5 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -3d to now",
			rangeStart:       "-3d",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      3 * 24 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: -2h to now (ordering test)",
			rangeStart:       "-2h",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			expectDelta:      2 * time.Hour,
			deltaTolerance:   5 * time.Second,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:             "relative time: today to now",
			rangeStart:       "today",
			rangeEnd:         "now",
			format:           "2006/01/02 3:04:05 PM",
			checkMidnight:    true,
			checkSeparator:   true,
			checkNonEmpty:    true,
			expectParseable:  true,
			expectStartOrder: true,
		},
		{
			name:           "absolute times with correct format",
			rangeStart:     "2025/01/15 10:00:00 AM",
			rangeEnd:       "2025/01/15 11:00:00 AM",
			format:         "2006/01/02 3:04:05 PM",
			expectStart:    "2025/01/15 10:00:00 AM",
			expectEnd:      "2025/01/15 11:00:00 AM",
			checkSeparator: true,
			checkNonEmpty:  true,
		},
		{
			name:           "mixed: relative start, absolute end",
			rangeStart:     "-1h",
			rangeEnd:       "2025/01/15 11:00:00 AM",
			format:         "2006/01/02 3:04:05 PM",
			expectEnd:      "2025/01/15 11:00:00 AM",
			checkSeparator: true,
			checkNonEmpty:  true,
		},
		{
			name:           "mixed: absolute start, relative end",
			rangeStart:     "2025/01/15 10:00:00 AM",
			rangeEnd:       "now",
			format:         "2006/01/02 3:04:05 PM",
			expectStart:    "2025/01/15 10:00:00 AM",
			checkSeparator: true,
			checkNonEmpty:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				result := parseRangeAllowRelative(tc.rangeStart, tc.rangeEnd, tc.format)

				// Basic validations
				if tc.checkNonEmpty {
					assert.NotEmpty(t, result, "Result should not be empty")
				}

				if tc.checkSeparator {
					assert.Contains(t, result, " - ", "Result should contain ' - ' separator")
				}

				// Split the result
				parts := splitRange(result)
				if tc.checkSeparator {
					assert.Len(t, parts, 2, "Result should have exactly 2 parts")
				}

				// Check exact matches
				if tc.expectStart != "" {
					assert.Contains(t, result, tc.expectStart, "Result should contain expected start time")
				}
				if tc.expectEnd != "" {
					assert.Contains(t, result, tc.expectEnd, "Result should contain expected end time")
				}

				// Parse times if needed for further validation
				if tc.expectParseable || tc.expectDelta > 0 || tc.checkMidnight || tc.expectStartOrder {
					if len(parts) != 2 {
						t.Fatal("Cannot proceed with time parsing - invalid parts count")
					}

					startTime, err := time.Parse("2006/01/02 3:04:05 PM", parts[0])
					assert.NoError(t, err, "Start time should be parseable")

					endTime, err := time.Parse("2006/01/02 3:04:05 PM", parts[1])
					assert.NoError(t, err, "End time should be parseable")

					// Check time ordering
					if tc.expectStartOrder {
						assert.True(t, startTime.Before(endTime) || startTime.Equal(endTime), "Start time should be before end time")
					}

					// Check time delta
					if tc.expectDelta > 0 {
						tolerance := tc.deltaTolerance
						if tolerance == 0 {
							tolerance = 5 * time.Second
						}
						duration := endTime.Sub(startTime)
						assert.InDelta(t, tc.expectDelta, duration, float64(tolerance),
							"Duration should be approximately %v", tc.expectDelta)
					}

					// Check midnight for "today"
					if tc.checkMidnight {
						assert.Equal(t, 0, startTime.Hour(), "Today should start at hour 0")
						assert.Equal(t, 0, startTime.Minute(), "Today should start at minute 0")
						assert.Equal(t, 0, startTime.Second(), "Today should start at second 0")

						// Verify start is before or equal to end
						// Note: We don't assert same day because if this test runs exactly at midnight,
						// "today" (start) could be computed on Day N while "now" (end) could be Day N+1.
						// This is acceptable behavior - the function works correctly, it's just a timing edge case.
						assert.True(t, startTime.Before(endTime) || startTime.Equal(endTime),
							"Start time should be before or equal to end time")

						// Verify they're within 24 hours of each other (sanity check)
						duration := endTime.Sub(startTime)
						assert.LessOrEqual(t, duration, 24*time.Hour,
							"Duration from 'today' to 'now' should be less than 24 hours")
					}
				}
			})
		})
	}
}

// Helper function to split range result
func splitRange(rangeStr string) []string {
	// Split on " - " and trim spaces
	var parts []string
	for i := 0; i < len(rangeStr); i++ {
		if i+3 <= len(rangeStr) && rangeStr[i:i+3] == " - " {
			parts = append(parts, rangeStr[:i])
			parts = append(parts, rangeStr[i+3:])
			break
		}
	}
	return parts
}

func TestPopulateOverridesFromMaps(t *testing.T) {
	testCases := []struct {
		name         string
		inputMaps    []map[string]any
		includeTimes bool
		expected     []*model.Override
	}{
		{
			name:         "empty input",
			inputMaps:    []map[string]any{},
			includeTimes: false,
			expected:     []*model.Override{},
		},
		{
			name: "single suppress override without times",
			inputMaps: []map[string]any{
				{
					"type":      "suppress",
					"isEnabled": true,
					"note":      "Test suppress note",
					"ip":        "192.168.1.0/24",
					"track":     "by_src",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					Note:      "Test suppress note",
					OverrideParameters: model.OverrideParameters{
						IP:    util.Ptr("192.168.1.0/24"),
						Track: util.Ptr("by_src"),
					},
				},
			},
		},
		{
			name: "single threshold override with times",
			inputMaps: []map[string]any{
				{
					"type":          "threshold",
					"isEnabled":     true,
					"note":          "Test threshold note",
					"thresholdType": "limit",
					"track":         "by_dst",
					"count":         float64(10),
					"seconds":       float64(60),
					"createdAt":     "2024-01-15T10:00:00Z",
					"updatedAt":     "2024-01-15T11:00:00Z",
				},
			},
			includeTimes: true,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					Note:      "Test threshold note",
					CreatedAt: mustParseTime("2024-01-15T10:00:00Z"),
					UpdatedAt: mustParseTime("2024-01-15T11:00:00Z"),
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("limit"),
						Track:         util.Ptr("by_dst"),
						Count:         util.Ptr(10),
						Seconds:       util.Ptr(60),
					},
				},
			},
		},
		{
			name: "modify override",
			inputMaps: []map[string]any{
				{
					"type":      "modify",
					"isEnabled": false,
					"note":      "Test modify note",
					"regex":     "content:xyz",
					"value":     "content:abc",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeModify,
					IsEnabled: false,
					Note:      "Test modify note",
					OverrideParameters: model.OverrideParameters{
						Regex: util.Ptr("content:xyz"),
						Value: util.Ptr("content:abc"),
					},
				},
			},
		},
		{
			name: "customFilter override",
			inputMaps: []map[string]any{
				{
					"type":         "customFilter",
					"isEnabled":    true,
					"note":         "Test custom filter note",
					"customFilter": "sofilter:\n  user.name: test",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeCustomFilter,
					IsEnabled: true,
					Note:      "Test custom filter note",
					OverrideParameters: model.OverrideParameters{
						CustomFilter: util.Ptr("sofilter:\n  user.name: test"),
					},
				},
			},
		},
		{
			name: "multiple overrides with mixed types",
			inputMaps: []map[string]any{
				{
					"type":      "suppress",
					"isEnabled": true,
					"note":      "First override",
					"ip":        "10.0.0.0/8",
					"track":     "by_either",
				},
				{
					"type":          "threshold",
					"isEnabled":     false,
					"note":          "Second override",
					"thresholdType": "both",
					"track":         "by_src",
					"count":         float64(5),
					"seconds":       float64(120),
				},
				{
					"type":      "modify",
					"isEnabled": true,
					"note":      "Third override",
					"regex":     "pattern",
					"value":     "replacement",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					Note:      "First override",
					OverrideParameters: model.OverrideParameters{
						IP:    util.Ptr("10.0.0.0/8"),
						Track: util.Ptr("by_either"),
					},
				},
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: false,
					Note:      "Second override",
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("both"),
						Track:         util.Ptr("by_src"),
						Count:         util.Ptr(5),
						Seconds:       util.Ptr(120),
					},
				},
				{
					Type:      model.OverrideTypeModify,
					IsEnabled: true,
					Note:      "Third override",
					OverrideParameters: model.OverrideParameters{
						Regex: util.Ptr("pattern"),
						Value: util.Ptr("replacement"),
					},
				},
			},
		},
		{
			name: "override with times excluded when includeTimes is false",
			inputMaps: []map[string]any{
				{
					"type":      "suppress",
					"isEnabled": true,
					"note":      "Test note",
					"ip":        "172.16.0.0/12",
					"track":     "by_dst",
					"createdAt": "2024-01-15T10:00:00Z",
					"updatedAt": "2024-01-15T11:00:00Z",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					Note:      "Test note",
					OverrideParameters: model.OverrideParameters{
						IP:    util.Ptr("172.16.0.0/12"),
						Track: util.Ptr("by_dst"),
					},
				},
			},
		},
		{
			name: "override with invalid time format (should be skipped)",
			inputMaps: []map[string]any{
				{
					"type":      "suppress",
					"isEnabled": true,
					"note":      "Test note",
					"ip":        "192.168.0.0/16",
					"track":     "by_src",
					"createdAt": "invalid-time-format",
					"updatedAt": "2024-01-15T11:00:00Z",
				},
			},
			includeTimes: true,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					Note:      "Test note",
					UpdatedAt: mustParseTime("2024-01-15T11:00:00Z"),
					OverrideParameters: model.OverrideParameters{
						IP:    util.Ptr("192.168.0.0/16"),
						Track: util.Ptr("by_src"),
					},
				},
			},
		},
		{
			name: "override with missing optional fields",
			inputMaps: []map[string]any{
				{
					"type":      "suppress",
					"isEnabled": true,
					// note is missing
					"ip":    "10.10.10.0/24",
					"track": "by_src",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					Note:      "",
					OverrideParameters: model.OverrideParameters{
						IP:    util.Ptr("10.10.10.0/24"),
						Track: util.Ptr("by_src"),
					},
				},
			},
		},
		{
			name: "override with all pointer fields",
			inputMaps: []map[string]any{
				{
					"type":          "threshold",
					"isEnabled":     true,
					"note":          "Complete override",
					"thresholdType": "threshold",
					"track":         "by_dst",
					"count":         float64(100),
					"seconds":       float64(300),
					"regex":         "should_be_ignored_for_threshold",
					"value":         "should_be_ignored_for_threshold",
					"ip":            "should_be_ignored_for_threshold",
					"customFilter":  "should_be_ignored_for_threshold",
				},
			},
			includeTimes: false,
			expected: []*model.Override{
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					Note:      "Complete override",
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("threshold"),
						Track:         util.Ptr("by_dst"),
						Count:         util.Ptr(100),
						Seconds:       util.Ptr(300),
						Regex:         util.Ptr("should_be_ignored_for_threshold"),
						Value:         util.Ptr("should_be_ignored_for_threshold"),
						IP:            util.Ptr("should_be_ignored_for_threshold"),
						CustomFilter:  util.Ptr("should_be_ignored_for_threshold"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := populateOverridesFromMaps(tc.inputMaps, tc.includeTimes)

			assert.Equal(t, len(tc.expected), len(result), "Number of overrides should match")

			for i, expectedOverride := range tc.expected {
				if i >= len(result) {
					t.Fatalf("Expected override at index %d but result is too short", i)
				}

				actualOverride := result[i]

				assert.Equal(t, expectedOverride.Type, actualOverride.Type, "Override type should match")
				assert.Equal(t, expectedOverride.IsEnabled, actualOverride.IsEnabled, "IsEnabled should match")
				assert.Equal(t, expectedOverride.Note, actualOverride.Note, "Note should match")

				// Check times if includeTimes was true
				if tc.includeTimes {
					if !expectedOverride.CreatedAt.IsZero() {
						assert.Equal(t, expectedOverride.CreatedAt, actualOverride.CreatedAt, "CreatedAt should match")
					}
					if !expectedOverride.UpdatedAt.IsZero() {
						assert.Equal(t, expectedOverride.UpdatedAt, actualOverride.UpdatedAt, "UpdatedAt should match")
					}
				} else {
					// When includeTimes is false, times should be zero
					assert.True(t, actualOverride.CreatedAt.IsZero(), "CreatedAt should be zero when includeTimes is false")
					assert.True(t, actualOverride.UpdatedAt.IsZero(), "UpdatedAt should be zero when includeTimes is false")
				}

				// Check pointer fields using util.Equal
				assert.True(t, util.Equal(expectedOverride.Regex, actualOverride.Regex), "Regex should match")
				assert.True(t, util.Equal(expectedOverride.Value, actualOverride.Value), "Value should match")
				assert.True(t, util.Equal(expectedOverride.Track, actualOverride.Track), "Track should match")
				assert.True(t, util.Equal(expectedOverride.IP, actualOverride.IP), "IP should match")
				assert.True(t, util.Equal(expectedOverride.ThresholdType, actualOverride.ThresholdType), "ThresholdType should match")
				assert.True(t, util.Equal(expectedOverride.Count, actualOverride.Count), "Count should match")
				assert.True(t, util.Equal(expectedOverride.Seconds, actualOverride.Seconds), "Seconds should match")
				assert.True(t, util.Equal(expectedOverride.CustomFilter, actualOverride.CustomFilter), "CustomFilter should match")
			}
		})
	}
}

// Helper function for tests
func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
