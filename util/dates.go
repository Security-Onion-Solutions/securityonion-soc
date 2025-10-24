// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseRelativeTimeString parses various time formats used by Security Onion
func ParseRelativeTimeString(timeStr string) string {
	now := time.Now()
	timeStr = strings.TrimSpace(timeStr)

	// Handle "now"
	if strings.ToLower(timeStr) == "now" {
		return FormatSOTime(now)
	}

	// Handle "today"
	if strings.ToLower(timeStr) == "today" {
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		return FormatSOTime(today)
	}

	// Handle relative times like "-1h", "-24h", "-7d"
	if strings.HasPrefix(timeStr, "-") {
		relativeTime := strings.TrimPrefix(timeStr, "-")

		// Parse number and unit
		re := regexp.MustCompile(`^(\d+)([mhd])$`)
		matches := re.FindStringSubmatch(relativeTime)
		if len(matches) == 3 {
			amount, _ := strconv.Atoi(matches[1])
			unit := matches[2]

			duration := UnitToDuration(unit) * time.Duration(amount)

			return FormatSOTime(now.Add(-duration))
		}
	}

	// Return as-is if not a recognized format
	return timeStr
}

// FormatSOTime formats time in Security Onion's expected format
func FormatSOTime(t time.Time) string {
	// Security Onion uses "2006/01/02 3:04:05 PM" format
	return t.Format("2006/01/02 3:04:05 PM")
}

func UnitToDuration(unit string) time.Duration {
	var duration time.Duration
	switch unit {
	case "s":
		duration = time.Second
	case "m":
		duration = time.Minute
	case "h":
		duration = time.Hour
	case "d":
		duration = 24 * time.Hour
	case "w":
		duration = 7 * 24 * time.Hour
	case "y":
		duration = 365 * 24 * time.Hour
	}

	return duration
}

func ParseDate(dateString string, layouts []string) (time.Time, error) {
	for _, layout := range layouts {
		t, err := time.Parse(layout, dateString)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date string: %s", dateString)
}

func ParseDateRange(dateRange string, format string, zone string) (time.Time, time.Time, error) {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		loc, _ = time.LoadLocation("UTC")
	}

	rangeParts := strings.Split(dateRange, " - ")
	if len(rangeParts) != 2 {
		end := time.Now()
		begin := end.Add(time.Duration(-24) * time.Hour)

		return begin, end, nil
	}

	startParam := strings.TrimSpace(rangeParts[0])
	endParam := strings.TrimSpace(rangeParts[1])

	start, err := time.ParseInLocation(format, startParam, loc)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	end, err := time.ParseInLocation(format, endParam, loc)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return start, end, nil
}
