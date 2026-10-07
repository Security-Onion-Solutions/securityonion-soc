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

	AlertTriageAssessmentLikelyMalicious = "likely_malicious"
	AlertTriageAssessmentNeedsReview     = "needs_review"
	AlertTriageAssessmentLikelyBenign    = "likely_benign"
)

func IsValidAlertTriageAssessment(assessment string) bool {
	switch assessment {
	case AlertTriageAssessmentLikelyMalicious, AlertTriageAssessmentNeedsReview, AlertTriageAssessmentLikelyBenign:
		return true
	}
	return false
}

// AlertTriageObject is the event sub-object holding triage state, e.g. so_alerttriage.
func AlertTriageObject(schemaPrefix string) string { return schemaPrefix + "alerttriage" }

// AlertInvestigationsObject is the event list of manual investigations, e.g. so_investigations.
// Each entry holds session_id, user_id and, when timing is licensed, timestamp.
func AlertInvestigationsObject(schemaPrefix string) string { return schemaPrefix + "investigations" }

func AlertInvestigationsField(schemaPrefix string) string {
	return "event." + AlertInvestigationsObject(schemaPrefix)
}

func AlertTriageFieldSessionId(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "session_id")
}

func AlertTriageFieldFailedCount(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "failed_count")
}

func AlertTriageFieldAssessment(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "assessment")
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
	// The agent's conclusion for the group; set only on success.
	Assessment string
	Failed     bool
	// Every run that failed the alerts' work item; required when Failed.
	FailedRunIds []string
}

func (update *AlertTriageUpdate) Validate() error {
	switch {
	case update.RunId == "":
		return errors.New("alert triage update requires a run id")
	case !update.Failed && update.SessionId == "":
		return errors.New("alert triage update requires a session id")
	case !update.Failed && !IsValidAlertTriageAssessment(update.Assessment):
		return fmt.Errorf("alert triage update has an invalid assessment %q", update.Assessment)
	case update.Failed && update.Assessment != "":
		return errors.New("failed alert triage update must not carry a assessment")
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
		" AND NOT " + AlertTriageGivenUpClause(schemaPrefix, maxFailures)
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

func AlertTriageFieldFailedSessionIds(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "failed_session_ids")
}

func AlertTriageFieldFailedRunIds(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "failed_run_ids")
}

func AlertTriageFieldRunId(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "automation_run_id")
}

func AlertTriageFieldTimestamp(schemaPrefix string) string {
	return alertTriageField(schemaPrefix, "timestamp")
}

// AlertTriageGivenUpClause matches alerts whose group has failed maxFailures times: the scan skips them, the run history counts them.
func AlertTriageGivenUpClause(schemaPrefix string, maxFailures int) string {
	return AlertTriageFieldFailedCount(schemaPrefix) + ":>=" + strconv.Itoa(maxFailures)
}

// @Description One alert as an automation run left it: what it is and what the ledger records about it.
type AlertTriageAlert struct {
	Id        string `json:"id" example:"AZmQ3f7c1kX9pLqR2sT4"`
	Timestamp string `json:"timestamp" example:"2026-09-15T15:58:41.000Z"`
	RuleName  string `json:"ruleName,omitempty" example:"ET MALWARE Suspicious PowerShell"`
	Severity  string `json:"severity,omitempty" example:"high"`
	// The session whose report covers this alert; empty until one succeeds.
	SessionId string `json:"sessionId,omitempty" example:"9b7c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"`
	// The successful session's assessment: likely_malicious, needs_review or likely_benign.
	Assessment string `json:"assessment,omitempty" example:"needs_review"`
	// Sessions that produced no report for this alert.
	FailedSessionIds []string `json:"failedSessionIds"`
	// Runs that failed this alert's group; the retry budget.
	FailedRunIds []string `json:"failedRunIds"`
	FailedCount  int      `json:"failedCount" example:"1"`
	// The run that last wrote to this alert; another run's id means it was recorded again later.
	LatestRunId string `json:"latestRunId,omitempty" example:"3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"`
	// When the ledger was last written.
	TriageTime string `json:"triageTime,omitempty" example:"2026-09-15T16:02:41Z"`
}
