// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

func TestParseDate(t *testing.T) {
	formats := []string{"2006-01-02", "2006/01/02", "2006_01_02"}

	tests := []struct {
		Name        string
		Date        string
		ExpOutput   string
		ShouldError bool
	}{
		{
			Name:      "Valid date w/Slashes",
			Date:      "2021/01/01",
			ExpOutput: "2021-01-01 00:00:00 +0000 UTC",
		},
		{
			Name:      "Valid date w/Dashes",
			Date:      "2023-10-14",
			ExpOutput: "2023-10-14 00:00:00 +0000 UTC",
		},
		{
			Name:      "Valid date w/Underscores",
			Date:      "2022_05_30",
			ExpOutput: "2022-05-30 00:00:00 +0000 UTC",
		},
		{
			Name:        "Invalid date",
			Date:        "2022-05-30T12:00:00",
			ShouldError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			output, err := ParseDate(test.Date, formats)

			if test.ShouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unable to parse date string")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.ExpOutput, output.String())
			}
		})
	}
}

func TestParseDateRange(t *testing.T) {
	format := "2006/01/02 3:04:05 PM"

	tests := []struct {
		Name           string
		DateRange      string
		Format         string
		Zone           string
		ExpectedStart  string
		ExpectedEnd    string
		ShouldError    bool
		UseDefaultTime bool
	}{
		{
			Name:          "Valid date range with UTC",
			DateRange:     "2023/01/15 10:00:00 AM - 2023/01/15 5:00:00 PM",
			Format:        format,
			Zone:          "UTC",
			ExpectedStart: "2023-01-15 10:00:00 +0000 UTC",
			ExpectedEnd:   "2023-01-15 17:00:00 +0000 UTC",
		},
		{
			Name:          "Valid date range with America/New_York",
			DateRange:     "2023/06/01 9:00:00 AM - 2023/06/01 6:00:00 PM",
			Format:        format,
			Zone:          "America/New_York",
			ExpectedStart: "2023-06-01 09:00:00 -0400 EDT",
			ExpectedEnd:   "2023-06-01 18:00:00 -0400 EDT",
		},
		{
			Name:          "Valid date range with whitespace",
			DateRange:     "  2023/03/10 1:00:00 PM  -  2023/03/10 11:59:59 PM  ",
			Format:        format,
			Zone:          "UTC",
			ExpectedStart: "2023-03-10 13:00:00 +0000 UTC",
			ExpectedEnd:   "2023-03-10 23:59:59 +0000 UTC",
		},
		{
			Name:          "Valid date range spanning multiple days",
			DateRange:     "2023/12/25 12:00:00 AM - 2023/12/31 11:59:59 PM",
			Format:        format,
			Zone:          "UTC",
			ExpectedStart: "2023-12-25 00:00:00 +0000 UTC",
			ExpectedEnd:   "2023-12-31 23:59:59 +0000 UTC",
		},
		{
			Name:           "Empty date range defaults to last 24 hours",
			DateRange:      "",
			Format:         format,
			Zone:           "UTC",
			UseDefaultTime: true,
		},
		{
			Name:           "Invalid format (no separator) defaults to last 24 hours",
			DateRange:      "2023/01/15 10:00:00 AM",
			Format:         format,
			Zone:           "UTC",
			UseDefaultTime: true,
		},
		{
			Name:        "Invalid start date format",
			DateRange:   "invalid - 2023/01/15 5:00:00 PM",
			Format:      format,
			Zone:        "UTC",
			ShouldError: true,
		},
		{
			Name:        "Invalid end date format",
			DateRange:   "2023/01/15 10:00:00 AM - invalid",
			Format:      format,
			Zone:        "UTC",
			ShouldError: true,
		},
		{
			Name:          "Invalid timezone defaults to UTC",
			DateRange:     "2023/02/20 3:00:00 PM - 2023/02/20 9:00:00 PM",
			Format:        format,
			Zone:          "Invalid/Timezone",
			ExpectedStart: "2023-02-20 15:00:00 +0000 UTC",
			ExpectedEnd:   "2023-02-20 21:00:00 +0000 UTC",
		},
		{
			Name:          "Date range with Europe/London timezone",
			DateRange:     "2023/07/15 2:30:00 PM - 2023/07/15 10:30:00 PM",
			Format:        format,
			Zone:          "Europe/London",
			ExpectedStart: "2023-07-15 14:30:00 +0100 BST",
			ExpectedEnd:   "2023-07-15 22:30:00 +0100 BST",
		},
		{
			Name:          "Relative date range 1h",
			DateRange:     "now-1h:now",
			Format:        format,
			Zone:          "UTC",
			UseDefaultTime: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			start, end, err := ParseDateRange(test.DateRange, test.Format, test.Zone)

			if test.ShouldError {
				assert.Error(t, err)
			} else if test.UseDefaultTime {
				assert.NoError(t, err)
				// Verify it returns a 24-hour range ending at approximately now
				diff := time.Since(end)
				assert.True(t, diff < time.Second*5, "End time should be close to now")
				assert.Equal(t, 24*time.Hour, end.Sub(start), "Range should be 24 hours")
			} else {
				assert.NoError(t, err)
				if test.DateRange == "now-1h:now" {
					assert.Equal(t, time.Hour, end.Sub(start))
				} else {
					assert.Equal(t, test.ExpectedStart, start.String())
					assert.Equal(t, test.ExpectedEnd, end.String())
				}
			}
		})
	}
}
