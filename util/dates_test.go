// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseTimeString(t *testing.T) {
	const expectedDelta = time.Second

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	testCases := []struct {
		name         string
		input        string
		expectedTime *time.Time
	}{
		{
			name:         "now keyword",
			input:        "now",
			expectedTime: Ptr(now),
		},
		{
			name:         "NOW case insensitive",
			input:        "NOW",
			expectedTime: Ptr(now),
		},
		{
			name:         "today keyword",
			input:        "today",
			expectedTime: Ptr(today),
		},
		{
			name:         "TODAY case insensitive",
			input:        "TODAY",
			expectedTime: Ptr(today),
		},
		{
			name:         "whitespace around now",
			input:        "  now  ",
			expectedTime: Ptr(now),
		},
		{
			name:         "whitespace around today",
			input:        "  today  ",
			expectedTime: Ptr(today),
		},
		{
			name:         "1 minute ago",
			input:        "-1m",
			expectedTime: Ptr(now.Add(-1 * time.Minute)),
		},
		{
			name:         "5 minutes ago",
			input:        "-5m",
			expectedTime: Ptr(now.Add(-5 * time.Minute)),
		},
		{
			name:         "1 hour ago",
			input:        "-1h",
			expectedTime: Ptr(now.Add(-1 * time.Hour)),
		},
		{
			name:         "24 hours ago",
			input:        "-24h",
			expectedTime: Ptr(now.Add(-24 * time.Hour)),
		},
		{
			name:         "1 day ago",
			input:        "-1d",
			expectedTime: Ptr(now.Add(-24 * time.Hour)),
		},
		{
			name:         "7 days ago",
			input:        "-7d",
			expectedTime: Ptr(now.Add(-7 * 24 * time.Hour)),
		},
		{
			name:         "0 minutes ago",
			input:        "-0m",
			expectedTime: Ptr(now),
		},
		{
			name:         "999 days ago",
			input:        "-999d",
			expectedTime: Ptr(now.Add(-999 * 24 * time.Hour)),
		},
		{
			name:         "whitespace around relative time",
			input:        "  -1h  ",
			expectedTime: Ptr(now.Add(-1 * time.Hour)),
		},
		{
			name:         "invalid unit",
			input:        "-1x",
			expectedTime: nil,
		},
		{
			name:         "invalid number",
			input:        "-abc",
			expectedTime: nil,
		},
		{
			name:         "missing minus sign",
			input:        "1h",
			expectedTime: nil,
		},
		{
			name:         "just minus sign",
			input:        "-",
			expectedTime: nil,
		},
		{
			name:         "empty string",
			input:        "",
			expectedTime: nil,
		},
		{
			name:         "random string",
			input:        "invalid",
			expectedTime: nil,
		},
		{
			name:         "ISO date format",
			input:        "2023-12-25 15:30:45",
			expectedTime: nil,
		},
		{
			name:         "human readable date",
			input:        "Dec 25, 2023",
			expectedTime: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseRelativeTimeString(tc.input)

			if tc.expectedTime == nil {
				assert.Equal(t, tc.input, result, "Should return input unchanged for invalid format")
				return
			}

			// Parse the result back to a time to verify it's correct
			// The formatSOTime function formats in the local timezone, so we need to parse it back in the same timezone
			parsedTime, err := time.ParseInLocation("2006/01/02 3:04:05 PM", result, tc.expectedTime.Location())
			assert.NoError(t, err, "Result should be parseable as SO time format")

			// Check that the parsed time is within expected delta of the expected time
			diff := parsedTime.Sub(*tc.expectedTime)
			if diff < 0 {
				diff = -diff
			}

			assert.True(t, diff <= expectedDelta,
				"Parsed time %v should be within %v of expected time %v (diff: %v)",
				parsedTime, expectedDelta, *tc.expectedTime, diff)
		})
	}
}

func TestFormatSOTime(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Time
		expected string
	}{
		{
			name:     "afternoon time",
			input:    time.Date(2023, 12, 25, 14, 30, 45, 0, time.UTC),
			expected: "2023/12/25 2:30:45 PM",
		},
		{
			name:     "midnight",
			input:    time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: "2023/01/01 12:00:00 AM",
		},
		{
			name:     "noon",
			input:    time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC),
			expected: "2023/06/15 12:00:00 PM",
		},
		{
			name:     "11:59 PM",
			input:    time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			expected: "2023/12/31 11:59:59 PM",
		},
		{
			name:     "single digit month/day",
			input:    time.Date(2023, 2, 5, 9, 5, 3, 100, time.UTC),
			expected: "2023/02/05 9:05:03 AM",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := FormatSOTime(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUnitToDuration(t *testing.T) {
	tests := []struct {
		Name           string
		Input          string
		ExpectedOutput time.Duration
	}{
		{
			Name: "no input",
		},
		{
			Name:  "bad input",
			Input: "x",
		},
		{
			Name:           "second",
			Input:          "s",
			ExpectedOutput: time.Second,
		},
		{
			Name:           "minutes",
			Input:          "m",
			ExpectedOutput: time.Minute,
		},
		{
			Name:           "hours",
			Input:          "h",
			ExpectedOutput: time.Hour,
		},
		{
			Name:           "days",
			Input:          "d",
			ExpectedOutput: 24 * time.Hour,
		},
		{
			Name:           "weeks",
			Input:          "w",
			ExpectedOutput: 7 * 24 * time.Hour,
		},
		{
			Name:           "year",
			Input:          "y",
			ExpectedOutput: 365 * 24 * time.Hour,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result := UnitToDuration(test.Input)
			assert.Equal(t, test.ExpectedOutput, result)
		})
	}
}
