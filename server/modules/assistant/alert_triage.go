// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

	"github.com/apex/log"
)

func init() {
	k := &AlertTriageKind{}
	knownAutomationKinds[k.GetName()] = k
}

const (
	alertTriageKindName        = "alert_triage"
	alertTriageDefaultGroupCap = 25
)

var (
	ErrAlertTriageStoreUnsupported     = errors.New("ERROR_ALERT_TRIAGE_STORE_UNSUPPORTED")
	ErrAlertTriageUpdateNotImplemented = errors.New("ERROR_ALERT_TRIAGE_UPDATE_NOT_IMPLEMENTED")
)

// AlertTriageKind groups unprocessed alerts, investigates the latest alert of each group in a
// headless session, and records that session on every alert in the group.
type AlertTriageKind struct{}

// alertTriageParams is what GetParamSchema describes, as stored.
type alertTriageParams struct {
	Filter           string   `json:"filter"`
	GroupBy          []string `json:"groupBy"`
	MaxGroupsPerScan int      `json:"maxGroupsPerScan"`
	MaxFailures      int      `json:"maxFailures"`
	Floor            string   `json:"floor"`

	floor time.Time
}

// alertTriagePayload is what a work item carries: enough to select its alerts again and to
// fetch the one alert the agent is handed.
type alertTriagePayload struct {
	GroupFilter          string    `json:"groupFilter"`
	Floor                time.Time `json:"floor"`
	Ceiling              time.Time `json:"ceiling"`
	LatestAlertId        string    `json:"latestAlertId"`
	LatestAlertTimestamp string    `json:"latestAlertTimestamp"`
	Count                int       `json:"count"`
}

func (k *AlertTriageKind) GetName() string        { return alertTriageKindName }
func (k *AlertTriageKind) GetDisplayName() string { return "Alert Triage" }
func (k *AlertTriageKind) GetDescription() string {
	return "Groups unprocessed alerts, has an agent investigate the latest alert of each group, and records the agent's report on every alert in the group."
}

func (k *AlertTriageKind) GetParamSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"filter": {
					Type:        "string",
					Description: "OQL search narrowing which alerts are triaged; blank means every alert",
				},
				"groupBy": {
					Type:        "array",
					Description: "Fields whose values define a group; one investigation per group",
					Items:       map[string]model.ToolSchemaProperty{"field": {Type: "string", Description: "An alert field name, e.g. rule.name"}},
				},
				"maxGroupsPerScan": {
					Type:        "integer",
					Description: "Groups investigated per scan; the rest wait for a later scan",
					Default:     alertTriageDefaultGroupCap,
				},
				"maxFailures": {
					Type:        "integer",
					Description: "Failed runs before a group is given up",
					Default:     model.DefaultAlertTriageMaxFailures,
				},
				"floor": {
					Type:        "string",
					Description: "RFC3339 time; alerts before it are never triaged. Blank means the automation's create time. Never earlier than the automationSettings.alertTriageEpoch setting",
				},
			},
			Required: []string{"groupBy"},
		},
	}
}

func (k *AlertTriageKind) ValidateParams(raw json.RawMessage) error {
	_, err := parseAlertTriageParams(raw)

	return err
}

// parseAlertTriageParams decodes and defaults the params. Strict on purpose: a misspelled
// field must not silently widen the scan.
func parseAlertTriageParams(raw json.RawMessage) (*alertTriageParams, error) {
	params := &alertTriageParams{}

	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(params); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidAutomationParams, err)
		}
	}

	if len(params.GroupBy) == 0 {
		return nil, fmt.Errorf("%w: groupBy requires at least one field", ErrInvalidAutomationParams)
	}

	for i, field := range params.GroupBy {
		field = strings.TrimSpace(field)

		if field == "" || strings.ContainsAny(field, " \t\r\n|\"'") || strings.HasPrefix(field, "-") || strings.Trim(field, "*") == "" {
			return nil, fmt.Errorf("%w: groupBy field %q is not a field name", ErrInvalidAutomationParams, field)
		}

		params.GroupBy[i] = field
	}

	if err := model.NewQuery().Parse("tags:alert | groupby " + strings.Join(params.GroupBy, " ")); err != nil {
		return nil, fmt.Errorf("%w: groupBy: %v", ErrInvalidAutomationParams, err)
	}

	params.Filter = strings.TrimSpace(params.Filter)
	if params.Filter != "" {
		if err := model.ValidateAlertTriageSearch(params.Filter); err != nil {
			return nil, fmt.Errorf("%w: filter: %v", ErrInvalidAutomationParams, err)
		}
	}

	switch {
	case params.MaxGroupsPerScan < 0:
		return nil, fmt.Errorf("%w: maxGroupsPerScan must not be negative", ErrInvalidAutomationParams)
	case params.MaxGroupsPerScan == 0:
		params.MaxGroupsPerScan = alertTriageDefaultGroupCap
	}

	switch {
	case params.MaxFailures < 0:
		return nil, fmt.Errorf("%w: maxFailures must not be negative", ErrInvalidAutomationParams)
	case params.MaxFailures == 0:
		params.MaxFailures = model.DefaultAlertTriageMaxFailures
	}

	params.Floor = strings.TrimSpace(params.Floor)
	if params.Floor != "" {
		floor, err := time.Parse(time.RFC3339, params.Floor)
		if err != nil {
			return nil, fmt.Errorf("%w: floor must be RFC3339: %v", ErrInvalidAutomationParams, err)
		}

		params.floor = floor
	}

	return params, nil
}

// alertTriageFloor is the param, else the automation's create time, clamped to the epoch.
func alertTriageFloor(params *alertTriageParams, task *model.Automation, epoch time.Time) time.Time {
	floor := params.floor
	if floor.IsZero() && task.CreateTime != nil {
		floor = *task.CreateTime
	}

	if floor.Before(epoch) {
		return epoch
	}

	return floor
}

// alertTriageMetricName is the aggregation carrying the full compound key; the converter names
// one per groupby level and drops the missing-bucket marker from each field.
func alertTriageMetricName(fields []string) string {
	trimmed := make([]string, 0, len(fields))
	for _, field := range fields {
		trimmed = append(trimmed, strings.TrimSuffix(field, "*"))
	}

	return "groupby_0|" + strings.Join(trimmed, "|")
}

// alertTriageRun is one Execute: the parsed definition and what the scan learned.
type alertTriageRun struct {
	run     *AutomationRun
	params  *alertTriageParams
	updater server.AlertTriageUpdater
	// Every unprocessed alert in scope, before grouping; the scan and each group lookup start here.
	base    string
	floor   time.Time
	ceiling time.Time
	// Groups with an item still open, keyed by their terms, which the scan must not enqueue again.
	open    map[string]struct{}
	handles []*execpool.Handle
}

type alertTriageGroup struct {
	terms string
	count int
}

func (k *AlertTriageKind) Execute(ctx context.Context, run *AutomationRun) error {
	params, err := parseAlertTriageParams(run.Task.Params)
	if err != nil {
		return err
	}

	updater, ok := run.Srv.Assistantstore.(server.AlertTriageUpdater)
	if !ok {
		return ErrAlertTriageStoreUnsupported
	}

	base, err := model.BuildAlertTriageUnprocessedQuery(updater.AlertTriageSchemaPrefix(), params.Filter, params.MaxFailures)
	if err != nil {
		return err
	}

	r := &alertTriageRun{
		run:     run,
		params:  params,
		updater: updater,
		base:    base,
		floor:   alertTriageFloor(params, run.Task, run.AlertTriageEpoch),
		open:    map[string]struct{}{},
	}

	r.reclaim(ctx)

	var errs []error

	if ctx.Err() == nil {
		errs = append(errs, r.scan(ctx))
	}

	if ctx.Err() == nil {
		errs = append(errs, r.claim(ctx))
	}

	errs = append(errs, run.Await(r.handles))

	if ctx.Err() != nil {
		return context.Cause(ctx)
	}

	return errors.Join(errs...)
}

// reclaim settles the work a previous run left open before anything new is looked for, giving
// up on items out of retries and marking the rest open so the scan does not enqueue them again.
func (r *alertTriageRun) reclaim(ctx context.Context) {
	logger := log.FromContext(ctx)

	for _, item := range r.run.OpenItems {
		switch item.State {
		case model.AutomationWorkItemPending:
			if len(item.FailedRunIds) >= r.params.MaxFailures && r.giveUp(ctx, item) {
				continue
			}
		case model.AutomationWorkItemApplying:
			r.apply(ctx, item)
		case model.AutomationWorkItemRunning:
			logger.WithField("workItemId", item.Id).Warn("alert triage item is running with no job; leaving it for reconciliation")
		}

		r.open[item.GroupKey] = struct{}{}
	}
}

// claim claims and submits pending items, oldest first, until none is claimable or the pool is
// full. An item this run fails is never claimed again by it, so the loop ends.
func (r *alertTriageRun) claim(ctx context.Context) error {
	var errs []error

	for ctx.Err() == nil {
		item, handle, err := r.run.ClaimAndSubmit(ctx, r.run.Task.Agent, r.params.MaxFailures, r.workItem)
		if item == nil {
			if err != nil {
				errs = append(errs, err)
			}

			break
		}

		if errors.Is(err, execpool.ErrDuplicate) {
			continue
		}

		if err != nil {
			// The pool has no room; the rest wait for the next run.
			errs = append(errs, err)

			break
		}

		r.handles = append(r.handles, handle)
	}

	return errors.Join(errs...)
}

// scan finds the unprocessed groups, the latest alert of each, and enqueues one item per group.
// Dispatch is left to claim.
func (r *alertTriageRun) scan(ctx context.Context) error {
	// Second precision, so the bounds stored on the items are exactly the bounds queried.
	r.ceiling = time.Now().UTC().Truncate(time.Second)

	groups, err := r.groups(ctx)
	if err != nil || len(groups) == 0 {
		return err
	}

	items, err := r.latestAlerts(ctx, groups)
	if err != nil || len(items) == 0 {
		return err
	}

	inserted, err := r.run.Store.EnsureAutomationWorkItems(ctx, r.run.RunId, items)
	if err != nil {
		return err
	}

	log.FromContext(ctx).WithFields(log.Fields{
		"groups":   len(groups),
		"enqueued": len(inserted),
	}).Info("alert triage scan finished")

	return nil
}

func (r *alertTriageRun) dateRange() string {
	return model.AlertTriageDateRange(r.floor, r.ceiling)
}

// groups runs the groupby and rebuilds each bucket's terms, skipping groups already open and
// stopping at the per-scan cap.
func (r *alertTriageRun) groups(ctx context.Context) ([]alertTriageGroup, error) {
	logger := log.FromContext(ctx)

	// Open groups still come back from the aggregation, so ask for enough buckets to see past them.
	limit := r.params.MaxGroupsPerScan + len(r.open)

	criteria := model.NewEventSearchCriteria()
	if err := criteria.Populate(r.base+" | groupby "+strings.Join(r.params.GroupBy, " "), r.dateRange(), time.RFC3339, "", strconv.Itoa(limit), "0"); err != nil {
		return nil, err
	}

	results, err := r.run.Srv.Eventstore.Search(ctx, criteria)
	if err != nil {
		return nil, err
	}

	if len(results.Errors) > 0 {
		return nil, fmt.Errorf("alert triage scan failed: %s", strings.Join(results.Errors, "; "))
	}

	groups := make([]alertTriageGroup, 0)

	for _, metric := range results.Metrics[alertTriageMetricName(r.params.GroupBy)] {
		if len(groups) == r.params.MaxGroupsPerScan {
			break
		}

		terms, err := model.BuildAlertTriageGroupTerms(r.params.GroupBy, metric.Keys)
		if err != nil {
			logger.WithError(err).Warn("skipping an alert group whose key cannot be rebuilt")

			continue
		}

		if _, isOpen := r.open[terms]; isOpen {
			continue
		}

		groups = append(groups, alertTriageGroup{terms: terms, count: int(metric.Value)})
	}

	return groups, nil
}

// latestAlerts fetches the newest unprocessed alert of every group in one request and builds
// the items to enqueue. A group whose search failed or came back empty is left for a later scan.
func (r *alertTriageRun) latestAlerts(ctx context.Context, groups []alertTriageGroup) ([]*model.AutomationWorkItem, error) {
	logger := log.FromContext(ctx)

	filters := make([]string, 0, len(groups))
	criterias := make([]*model.EventMSearchCriteria, 0, len(groups))

	for _, group := range groups {
		filter := r.base + " AND " + group.terms
		filters = append(filters, filter)

		criteria := model.NewEventSearchCriteria()
		if err := criteria.Populate(filter, r.dateRange(), time.RFC3339, "", "0", "1"); err != nil {
			return nil, err
		}

		criteria.SortFields = []*model.SortCriteria{{Field: "@timestamp", Order: "desc"}}

		criterias = append(criterias, &model.EventMSearchCriteria{EventSearchCriteria: *criteria})
	}

	results, err := r.run.Srv.Eventstore.MSearch(ctx, criterias)

	answered := 0
	if results != nil {
		answered = len(results.Responses)
	}

	if answered != len(groups) {
		if err == nil {
			err = fmt.Errorf("alert triage latest-alert search answered %d of %d groups", answered, len(groups))
		}

		return nil, err
	}

	if err != nil {
		logger.WithError(err).Warn("some alert groups could not be searched; leaving them for a later scan")
	}

	items := make([]*model.AutomationWorkItem, 0, len(groups))

	for i, response := range results.Responses {
		if len(response.Errors) > 0 || len(response.Events) == 0 {
			continue
		}

		alert := response.Events[0]

		payload, err := json.Marshal(alertTriagePayload{
			GroupFilter:          filters[i],
			Floor:                r.floor,
			Ceiling:              r.ceiling,
			LatestAlertId:        alert.Id,
			LatestAlertTimestamp: alert.Timestamp,
			Count:                groups[i].count,
		})
		if err != nil {
			return nil, err
		}

		items = append(items, &model.AutomationWorkItem{
			AutomationId: r.run.Task.Id,
			GroupKey:     groups[i].terms,
			Payload:      payload,
		})
	}

	return items, nil
}

// workItem is the job for one claimed group. Nothing runs its session yet, so every attempt
// fails.
func (r *alertTriageRun) workItem(ctx context.Context, item *model.AutomationWorkItem) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}

	return r.fail(ctx, item, "", ErrAlertTriageUpdateNotImplemented)
}

// fail records that this run failed the item, on the item and on its alerts, and gives the item
// up once it is out of retries. The alerts are updated first, so a given-up group never comes
// back from the scan.
func (r *alertTriageRun) fail(ctx context.Context, item *model.AutomationWorkItem, sessionId string, cause error) error {
	logger := log.FromContext(ctx)

	failed, err := r.run.Store.FailAutomationWorkItemRun(ctx, item.Id, cause.Error())
	if errors.Is(err, database.ErrAutomationWorkItemNotFound) {
		// A params change swept it while the job ran.
		logger.Info("alert triage item was finalized before its failure was recorded")

		return nil
	}

	if err != nil {
		return err
	}

	logger.WithError(cause).WithFields(log.Fields{
		"failures":    len(failed.FailedRunIds),
		"maxFailures": r.params.MaxFailures,
	}).Warn("alert triage item failed")

	if err := r.updateFailedAlerts(ctx, failed, sessionId); err != nil {
		return err
	}

	if len(failed.FailedRunIds) < r.params.MaxFailures {
		return nil
	}

	return r.end(ctx, failed)
}

// giveUp ends a pending item that is out of retries, reporting whether it did. One whose alerts
// cannot be updated stays pending, unclaimable, for the next run to try again.
func (r *alertTriageRun) giveUp(ctx context.Context, item *model.AutomationWorkItem) bool {
	logger := log.FromContext(ctx).WithField("workItemId", item.Id)

	if err := r.updateFailedAlerts(ctx, item, ""); err != nil {
		logger.WithError(err).Warn("unable to record failures on an alert triage group; retrying next run")

		return false
	}

	if err := r.end(ctx, item); err != nil {
		logger.WithError(err).Warn("unable to give up an alert triage item; retrying next run")

		return false
	}

	return true
}

func (r *alertTriageRun) end(ctx context.Context, item *model.AutomationWorkItem) error {
	err := r.run.Store.FailAutomationWorkItem(ctx, item.Id, item.Error)
	if errors.Is(err, database.ErrAutomationWorkItemNotFound) {
		return nil
	}

	if err == nil {
		log.FromContext(ctx).WithFields(log.Fields{
			"workItemId":      item.Id,
			"runsFailedCount": len(item.FailedRunIds),
			"maxFailures":     r.params.MaxFailures,
		}).Warn("alert triage item is out of retries; giving up its group")
	}

	return err
}

// updateFailedAlerts records every run that failed the item on each of the group's alerts.
func (r *alertTriageRun) updateFailedAlerts(ctx context.Context, item *model.AutomationWorkItem, sessionId string) error {
	payload := &alertTriagePayload{}
	if err := json.Unmarshal(item.Payload, payload); err != nil {
		// Its alerts cannot be found, so there is nothing to record and nothing to hold the item for.
		log.FromContext(ctx).WithError(err).WithField("workItemId", item.Id).Error("alert triage item has an unreadable payload")

		return nil
	}

	_, err := r.updater.AlertTriageUpdate(ctx, &model.AlertTriageUpdate{
		Query:        payload.GroupFilter,
		Floor:        payload.Floor,
		Ceiling:      payload.Ceiling,
		Count:        payload.Count,
		RunId:        r.run.RunId,
		SessionId:    sessionId,
		Failed:       true,
		FailedRunIds: item.FailedRunIds,
	})

	return err
}

// apply is where an item with a persisted session result records it on the group's alerts.
func (r *alertTriageRun) apply(ctx context.Context, item *model.AutomationWorkItem) {
	log.FromContext(ctx).WithField("workItemId", item.Id).WithError(ErrAlertTriageUpdateNotImplemented).
		Warn("alert triage item has a result to apply; leaving it applying")
}

// alertTriageObjective opens the session: one alert standing for its group, and a request for a
// report a person will read.
func alertTriageObjective(alert map[string]any, count int, groupFilter string) string {
	fields, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		fields = []byte(fmt.Sprintf("%v", alert))
	}

	return fmt.Sprintf(`Investigate the alert below. It is the most recent of %d unprocessed alerts matching:
%s

Alert:
%s`, count, groupFilter, fields)
}
