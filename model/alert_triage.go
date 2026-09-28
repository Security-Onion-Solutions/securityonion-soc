// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// Failed runs a group may accumulate before the scan stops returning it, applied when a
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

// AlertTriageUpdate attaches an automation's investigation to the alerts matched by Query,
// either as the one successful session or as the runs that failed it.
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
	// Every run that failed the alerts' work item; required when Failed.
	FailedRunIds []string
}

func (update *AlertTriageUpdate) Validate() error {
	switch {
	case update.RunId == "":
		return errors.New("alert triage update requires a run id")
	case !update.Failed && update.SessionId == "":
		return errors.New("alert triage update requires a session id")
	case update.Failed && (len(update.FailedRunIds) == 0 || slices.Contains(update.FailedRunIds, "")):
		return errors.New("failed alert triage update requires its failed run ids")
	case update.Floor.IsZero():
		return errors.New("alert triage update requires a floor")
	case update.Ceiling.IsZero():
		return errors.New("alert triage update requires a ceiling")
	case update.Floor.After(update.Ceiling):
		return errors.New("alert triage update floor must not be after its ceiling")
	}
	return ValidateAlertTriageSearch(update.Query)
}

// ValidateAlertTriageSearch rejects anything past the search segment, since the query is spliced
// into a larger expression.
func ValidateAlertTriageSearch(str string) error {
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
	if err := ValidateAlertTriageSearch(filter); err != nil {
		return "", err
	}
	return "(" + base + ") AND (" + filter + ")", nil
}

// BuildAlertTriageGroupTerms renders one groupby bucket as the search terms that select it again.
func BuildAlertTriageGroupTerms(fields []string, keys []any) (string, error) {
	if len(fields) == 0 || len(fields) != len(keys) {
		return "", fmt.Errorf("alert triage group has %d fields but %d keys", len(fields), len(keys))
	}
	segment := NewSearchSegmentEmpty()
	for i, field := range fields {
		// The aggregation drops the missing-bucket marker from the field it groups on.
		field = strings.TrimSuffix(field, "*")
		value, scalar, err := alertTriageKeyValue(keys[i])
		if err != nil {
			return "", err
		}
		if err := segment.AddFilter(field, value, scalar, true, false); err != nil {
			return "", err
		}
	}
	return segment.String(), nil
}

func alertTriageKeyValue(key any) (string, bool, error) {
	switch v := key.(type) {
	case string:
		return v, false, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true, nil
	case bool:
		return strconv.FormatBool(v), true, nil
	}
	return "", false, fmt.Errorf("alert triage group key %v has unsupported type %T", key, key)
}

// BuildAlertTriageQuery selects every alert the given run touched, failed attempts included.
func BuildAlertTriageQuery(schemaPrefix, runId string) string {
	segment := NewSearchSegmentEmpty()
	segment.AddFilter(AlertTriageFieldRunIds(schemaPrefix), runId, false, true, false)
	return segment.String()
}

// AlertTriageDateRange is floor to ceiling.
func AlertTriageDateRange(floor time.Time, ceiling time.Time) string {
	return floor.UTC().Format(time.RFC3339) + " - " + ceiling.UTC().Format(time.RFC3339)
}
