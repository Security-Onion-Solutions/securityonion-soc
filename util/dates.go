// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package util

import (
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

			var duration time.Duration
			switch unit {
			case "s":
				duration = time.Duration(amount) * time.Second
			case "m":
				duration = time.Duration(amount) * time.Minute
			case "h":
				duration = time.Duration(amount) * time.Hour
			case "d":
				duration = time.Duration(amount) * 24 * time.Hour
			case "w":
				duration = time.Duration(amount) * 7 * 24 * time.Hour
			case "y":
				duration = time.Duration(amount) * 365 * 24 * time.Hour
			}

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
