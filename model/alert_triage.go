// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	alertTriageEpoch = "1970-01-01T00:00:00Z"
	// Failed sessions a group may accumulate before the scan stops returning it, applied when a
	// param omits or zeroes the cap so no group is ever retried without bound.
	DefaultAlertTriageMaxFailures = 3
)

// AlertTriageObject is the event sub-object holding triage state, e.g. so_alerttriage.
func AlertTriageObject(schemaPrefix string) string { return schemaPrefix + "alerttriage" }

func AlertTriageFieldSessionId(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "session_id")
}

func AlertTriageFieldFailedCount(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "failed_count")
}

func AlertTriageFieldRunIds(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "automation_run_ids")
}

func alertTriageField(schemaPrefix, name string) string {
	return "event." + AlertTriageObject(schemaPrefix) + "." + name
}

// AlertTriageUpdate attaches an automation's investigation session to the alerts matched by
// Query, either as the one successful session or as another failed attempt.
type AlertTriageUpdate struct {
	// Search-only OQL selecting the alerts.
	Query string
	// Bounds of the scan that found the alerts; anything newer waits for the next scan.
	Floor   time.Time
	Ceiling time.Time
	// Expected document count; above the eventstore's async threshold Elasticsearch runs the
	// update as a task that is polled to completion instead of holding the request open.
	Count     int
	RunId     string
	SessionId string
	Failed    bool
}

func (update *AlertTriageUpdate) Validate() error {
	switch {
	case update.RunId == "":
		return errors.New("alert triage update requires a run id")
	case update.SessionId == "":
		return errors.New("alert triage update requires a session id")
	case update.Ceiling.IsZero():
		return errors.New("alert triage update requires a ceiling")
	case update.Floor.After(update.Ceiling):
		return errors.New("alert triage update floor must not be after its ceiling")
	}
	return validateAlertTriageSearch(update.Query)
}

// validateAlertTriageSearch rejects anything past the search segment, since the query is spliced
// into a larger expression.
func validateAlertTriageSearch(str string) error {
	if strings.TrimSpace(str) == "" {
		return errors.New("alert triage query must not be empty")
	}
	query := NewQuery()
	if err := query.Parse(str); err != nil {
		return err
	}
	if len(query.Segments) != 1 || query.Segments[0].Kind() != SegmentKind_Search {
		return errors.New("alert triage query must be search-only")
	}
	return nil
}

// BuildAlertTriageUnprocessedQuery scopes filter to alerts with no successful session that have not
// failed maxFailures times yet. Filter and result are search segments only; append any groupby
// afterwards.
func BuildAlertTriageUnprocessedQuery(schemaPrefix, filter string, maxFailures int) (string, error) {
	if maxFailures <= 0 {
		maxFailures = DefaultAlertTriageMaxFailures
	}
	base := "tags:alert AND NOT event.acknowledged:true AND NOT _exists_:" + AlertTriageFieldSessionId(schemaPrefix) +
		" AND NOT " + AlertTriageFieldFailedCount(schemaPrefix) + ":>=" + strconv.Itoa(maxFailures)
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return base, nil
	}
	if err := validateAlertTriageSearch(filter); err != nil {
		return "", err
	}
	return "(" + base + ") AND (" + filter + ")", nil
}

// BuildAlertTriageQuery selects every alert the given run touched, failed attempts included.
func BuildAlertTriageQuery(schemaPrefix, runId string) string {
	segment := NewSearchSegmentEmpty()
	segment.AddFilter(AlertTriageFieldRunIds(schemaPrefix), runId, false, true, false)
	return segment.String()
}

// AlertTriageDateRange is floor to ceiling, or the epoch to ceiling when there is no floor.
func AlertTriageDateRange(floor time.Time, ceiling time.Time) string {
	begin := alertTriageEpoch
	if !floor.IsZero() {
		begin = floor.UTC().Format(time.RFC3339)
	}
	return begin + " - " + ceiling.UTC().Format(time.RFC3339)
}
