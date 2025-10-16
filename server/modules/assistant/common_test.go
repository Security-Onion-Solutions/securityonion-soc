// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"testing"
	"testing/synctest"
	"time"

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
						assert.True(t, startTime.Before(endTime), "Start time should be before end time")
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

						// Verify it's today's date
						now := time.Now()
						assert.Equal(t, now.Year(), startTime.Year(), "Year should match today")
						assert.Equal(t, now.Month(), startTime.Month(), "Month should match today")
						assert.Equal(t, now.Day(), startTime.Day(), "Day should match today")
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
