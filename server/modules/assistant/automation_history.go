// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
)

const (
	defaultAutomationRunPageSize  = 50
	maxAutomationRunPageSize      = 500
	defaultAutomationAlertLimit   = 500
	maxAutomationAlertLimit       = 10000
	automationThoughtPreviewRunes = 300
	// Real terms (names, IDs, error codes) are far shorter; this only bounds an abusive pattern.
	maxAutomationRunSearchRunes = 256
)

var ErrAutomationRunNotFound = database.ErrAutomationRunNotFound

// automationHistoryStore is what the run history reads; *database.Store satisfies it.
type automationHistoryStore interface {
	GetAutomationRun(ctx context.Context, runId string) (*model.AutomationRunRecord, error)
	ListAutomationRuns(ctx context.Context, query database.AutomationRunQuery) ([]*model.AutomationRunRecord, error)
	ListAutomationWorkItems(ctx context.Context, runId string) ([]*model.AutomationWorkItem, error)
	CountOpenAutomationWorkItems(ctx context.Context, automationId string) (map[model.AutomationWorkItemState]int, error)
	CountAutomationWorkItemsByRun(ctx context.Context, runIds []string) (map[string]map[model.AutomationWorkItemState]int, error)
	CountAutomationRuns(ctx context.Context, query database.AutomationRunQuery) (int, error)
}

func (ac *AssistantCoordinator) GetAutomationRunHistory(ctx context.Context, automationId string, limit, offset int) (*model.AutomationRunHistory, error) {
	if err := ac.srv.CheckAuthorized(ctx, "read", "automations"); err != nil {
		return nil, err
	}

	if ac.store == nil {
		return nil, ErrNoDatabase
	}

	automationId, err := canonicalAutomationId(automationId)
	if err != nil {
		return nil, ErrAutomationNotFound
	}

	return ac.automationRunHistory(ctx, ac.store, automationId, limit, offset)
}

func (ac *AssistantCoordinator) GetAutomationRunDetails(ctx context.Context, automationId, runId string, alertLimit int) (*model.AutomationRunDetails, error) {
	if err := ac.srv.CheckAuthorized(ctx, "read", "automations"); err != nil {
		return nil, err
	}

	if ac.store == nil {
		return nil, ErrNoDatabase
	}

	automationId, err := canonicalAutomationId(automationId)
	if err != nil {
		return nil, ErrAutomationNotFound
	}

	runId, err = canonicalAutomationId(runId)
	if err != nil {
		return nil, ErrAutomationRunNotFound
	}

	return ac.automationRunDetails(ctx, ac.store, automationId, runId, alertLimit)
}

// ListAutomationRuns pages through finished runs across every automation, newest first.
func (ac *AssistantCoordinator) ListAutomationRuns(ctx context.Context, filter *model.AutomationRunFilter) (*model.AutomationRunPage, error) {
	if err := ac.srv.CheckAuthorized(ctx, "read", "automations"); err != nil {
		return nil, err
	}

	if ac.store == nil {
		return nil, ErrNoDatabase
	}

	return ac.automationRunPage(ctx, ac.store, filter)
}

func (ac *AssistantCoordinator) automationRunPage(ctx context.Context, store automationHistoryStore, filter *model.AutomationRunFilter) (*model.AutomationRunPage, error) {
	automationId := filter.AutomationId
	if automationId != "" {
		var err error
		if automationId, err = canonicalAutomationId(automationId); err != nil {
			return nil, ErrAutomationNotFound
		}
	}

	search := strings.TrimSpace(filter.Search)
	if utf8.RuneCountInString(search) > maxAutomationRunSearchRunes {
		return nil, fmt.Errorf("%w: search must be at most %d characters", ErrInvalidAutomationParams, maxAutomationRunSearchRunes)
	}

	automations, unreadable, err := ac.scanAutomations(ctx)
	if err != nil {
		return nil, err
	}

	// Names live in config, not the database, so a name match becomes ids.
	names := map[string]string{}
	searchIds := []string{}
	needle := strings.ToLower(search)

	for _, automation := range automations {
		names[automation.Id] = automation.DisplayName

		if search != "" && strings.Contains(strings.ToLower(automation.DisplayName), needle) {
			searchIds = append(searchIds, automation.Id)
		}
	}

	searchRunId := ""
	if id, err := uuid.Parse(search); err == nil {
		searchRunId = id.String()
	}

	limit := clampAutomationLimit(filter.Limit, defaultAutomationRunPageSize, maxAutomationRunPageSize)

	query := database.AutomationRunQuery{
		AutomationId:        automationId,
		Finished:            true,
		HideEmpty:           filter.HideEmpty,
		Search:              search,
		SearchAutomationIds: searchIds,
		SearchRunId:         searchRunId,
		Limit:               limit + 1,
		Offset:              max(filter.Offset, 0),
	}

	runs, err := store.ListAutomationRuns(ctx, query)
	if err != nil {
		return nil, err
	}

	hasMore := len(runs) > limit
	if hasMore {
		runs = runs[:limit]
	}

	runIds := make([]string, len(runs))
	for i, run := range runs {
		runIds[i] = run.Id
	}

	counts, err := store.CountAutomationWorkItemsByRun(ctx, runIds)
	if err != nil {
		return nil, err
	}

	page := &model.AutomationRunPage{
		Runs:    make([]*model.AutomationRunListing, 0, len(runs)),
		HasMore: hasMore,
	}

	if filter.Count {
		total, err := store.CountAutomationRuns(ctx, query)
		if err != nil {
			return nil, err
		}

		page.Total = &total
	}

	for _, run := range runs {
		itemCounts := counts[run.Id]
		if itemCounts == nil {
			itemCounts = map[model.AutomationWorkItemState]int{}
		}

		name, defined := names[run.AutomationId]

		page.Runs = append(page.Runs, &model.AutomationRunListing{
			AutomationRunSummary: model.AutomationRunSummary{AutomationRunRecord: *run, ItemCounts: itemCounts},
			DisplayName:          name,
			// An unreadable stored entry may be the one this run belongs to.
			AutomationDeleted: !defined && unreadable == 0,
		})
	}

	return page, nil
}

func (ac *AssistantCoordinator) automationRunHistory(ctx context.Context, store automationHistoryStore, automationId string, limit, offset int) (*model.AutomationRunHistory, error) {
	desc, err := ac.describeAutomation(ctx, automationId)
	if err != nil {
		return nil, err
	}

	limit = clampAutomationLimit(limit, defaultAutomationRunPageSize, maxAutomationRunPageSize)
	offset = max(offset, 0)

	// One past the page tells whether there is a next one without counting.
	runs, err := store.ListAutomationRuns(ctx, database.AutomationRunQuery{AutomationId: automationId, Limit: limit + 1, Offset: offset})
	if err != nil {
		return nil, err
	}

	if desc.Deleted && offset == 0 && len(runs) == 0 {
		return nil, ErrAutomationNotFound
	}

	hasMore := len(runs) > limit
	if hasMore {
		runs = runs[:limit]
	}

	runIds := make([]string, len(runs))
	for i, run := range runs {
		runIds[i] = run.Id
	}

	counts, err := store.CountAutomationWorkItemsByRun(ctx, runIds)
	if err != nil {
		return nil, err
	}

	open, err := store.CountOpenAutomationWorkItems(ctx, automationId)
	if err != nil {
		return nil, err
	}

	history := &model.AutomationRunHistory{
		AutomationId:      automationId,
		DisplayName:       desc.DisplayName,
		AutomationDeleted: desc.Deleted,
		Backlog: model.AutomationBacklog{
			Pending:  open[model.AutomationWorkItemPending],
			Running:  open[model.AutomationWorkItemRunning],
			Applying: open[model.AutomationWorkItemApplying],
		},
		Runs:    make([]*model.AutomationRunSummary, 0, len(runs)),
		HasMore: hasMore,
	}

	for _, run := range runs {
		itemCounts := counts[run.Id]
		if itemCounts == nil {
			itemCounts = map[model.AutomationWorkItemState]int{}
		}

		history.Runs = append(history.Runs, &model.AutomationRunSummary{AutomationRunRecord: *run, ItemCounts: itemCounts})
	}

	return history, nil
}

func (ac *AssistantCoordinator) automationRunDetails(ctx context.Context, store automationHistoryStore, automationId, runId string, alertLimit int) (*model.AutomationRunDetails, error) {
	run, err := store.GetAutomationRun(ctx, runId)
	if err != nil {
		return nil, err
	}

	if run.AutomationId != automationId {
		return nil, ErrAutomationRunNotFound
	}

	desc, err := ac.describeAutomation(ctx, automationId)
	if err != nil {
		return nil, err
	}

	items, err := store.ListAutomationWorkItems(ctx, runId)
	if err != nil {
		return nil, err
	}

	sessions, err := ac.automationRunSessions(ctx, store, items)
	if err != nil {
		return nil, err
	}

	ledger, err := ac.automationRunAlerts(ctx, run, items, desc.MaxFailures, clampAutomationLimit(alertLimit, defaultAutomationAlertLimit, maxAutomationAlertLimit))
	if err != nil {
		return nil, err
	}

	return &model.AutomationRunDetails{
		Run:               run,
		AutomationId:      automationId,
		DisplayName:       desc.DisplayName,
		AutomationDeleted: desc.Deleted,
		Items:             items,
		Sessions:          sessions,
		Alerts:            ledger.alerts,
		AlertTotal:        ledger.total,
		AlertsExpired:     ledger.present && ledger.total == 0 && automationWroteAlerts(run, items),
		MaxFailures:       desc.MaxFailures,
		GivenUpAlerts:     ledger.givenUp,
	}, nil
}

// automationDescription is what history shows of the automation itself.
type automationDescription struct {
	DisplayName string
	Deleted     bool
	// The alert triage failure cap; 0 when the automation is not a readable alert triage.
	MaxFailures int
}

// describeAutomation treats a deleted automation as a description rather than an error.
func (ac *AssistantCoordinator) describeAutomation(ctx context.Context, id string) (automationDescription, error) {
	automation, err := ac.GetAutomation(ctx, id)
	if errors.Is(err, ErrAutomationNotFound) {
		return automationDescription{Deleted: true}, nil
	}
	if err != nil {
		return automationDescription{}, err
	}

	desc := automationDescription{DisplayName: automation.DisplayName}
	if automation.AutomationKind == alertTriageKindName {
		if params, err := parseAlertTriageParams(automation.Params); err == nil {
			desc.MaxFailures = params.MaxFailures
		}
	}

	return desc, nil
}

func clampAutomationLimit(value, fallback, ceiling int) int {
	if value <= 0 {
		return fallback
	}

	return min(value, ceiling)
}

// automationRunSessions summarizes every attempt on the items from one session lookup and one history lookup.
func (ac *AssistantCoordinator) automationRunSessions(ctx context.Context, store automationHistoryStore, items []*model.AutomationWorkItem) ([]*model.AutomationRunSession, error) {
	sessions := make([]*model.AutomationRunSession, 0)

	ids := make([]string, 0)
	for _, item := range items {
		ids = append(ids, item.SessionIds...)
	}

	if len(ids) == 0 {
		return sessions, nil
	}

	// At most one row per automation, and an item can be held by a later run than this one.
	inFlight, err := store.ListAutomationRuns(ctx, database.AutomationRunQuery{InFlight: true})
	if err != nil {
		return nil, err
	}

	open := openAutomationRuns(inFlight)

	stored := map[string]*model.AssistantSession{}
	histories := map[string][]*model.StoredMessage{}

	if ac.srv.Assistantstore != nil {
		// The outlines below carry each session's last message, so the store need not derive it.
		found, err := ac.srv.Assistantstore.GetSessions(ctx,
			model.GetSessionsWithSessionIds(ids),
			model.GetSessionsWithIncludeDeleted(true),
			model.GetSessionsWithAutomationSessions(true),
			model.GetSessionsWithMessageMeta(false))
		if err != nil {
			return nil, err
		}

		fetched, err := ac.srv.Assistantstore.GetChatHistoryOutlines(ctx, found)
		if err != nil {
			return nil, err
		}

		for i, session := range found {
			stored[session.SessionId] = session
			histories[session.SessionId] = fetched[i]
		}
	}

	live := map[string]bool{}
	for _, phase := range ac.AgentSessionPhases() {
		live[phase.RootSessionId] = true
	}

	for _, item := range items {
		for i, id := range item.SessionIds {
			summary := &model.AutomationRunSession{
				SessionId: id,
				ItemId:    item.Id,
				RunId:     automationAttemptRun(item, i),
				Outcome:   automationSessionOutcome(item, i, live[id], open),
				Steps:     []model.AutomationRunStep{},
			}

			session, ok := stored[id]
			if !ok {
				summary.Missing = true
				sessions = append(sessions, summary)

				continue
			}

			history := histories[id]

			summary.Agent = session.Model
			summary.CreateTime = session.CreateTime
			summary.UpdateTime = session.UpdateTime
			if len(history) > 0 && history[len(history)-1].CreateTime != nil {
				summary.UpdateTime = history[len(history)-1].CreateTime
			}
			summary.MessageCount = session.MessageCount
			summary.Steps = automationRunSteps(history)

			sessions = append(sessions, summary)
		}
	}

	return sessions, nil
}

// automationAttemptRun names the run behind an attempt. SessionRunIds lines up with the end of
// SessionIds: the two are only appended together, so the newest sessions are the ones with a
// recorded run. Older ones, from before runs were recorded, keep the positional mapping: the
// failed runs in order, then the run holding the item.
func automationAttemptRun(item *model.AutomationWorkItem, index int) string {
	if recorded := index - (len(item.SessionIds) - len(item.SessionRunIds)); recorded >= 0 && recorded < len(item.SessionRunIds) &&
		item.SessionRunIds[recorded] != "" {
		return item.SessionRunIds[recorded]
	}

	if index < len(item.FailedRunIds) {
		return item.FailedRunIds[index]
	}

	return item.RunId
}

// openAutomationRuns maps each run still in flight to whether a Stop has marked it.
func openAutomationRuns(runs []*model.AutomationRunRecord) map[string]bool {
	open := map[string]bool{}

	for _, run := range runs {
		if !run.State.IsTerminal() {
			open[run.Id] = run.StoppedBy != ""
		}
	}

	return open
}

// automationSessionOutcome reads an attempt's fate off its item and the run behind it. open is
// every run in flight, mapped to whether it is stopping.
//
// The last rule relies on only a user's Stop returning an item to the queue uncharged after a
// session has run; RequeueAutomationWorkItem is only called before one starts. A kind that
// requeues after a session breaks that and has to revisit this.
func automationSessionOutcome(item *model.AutomationWorkItem, index int, live bool, open map[string]bool) string {
	newest := index == len(item.SessionIds)-1
	run := automationAttemptRun(item, index)

	// An apply that failed and was replayed adds no session, so its report still counts.
	if newest && (item.State == model.AutomationWorkItemDone || item.State == model.AutomationWorkItemApplying) {
		return model.AutomationRunOutcomeReport
	}

	if slices.Contains(item.FailedRunIds, run) {
		return model.AutomationRunOutcomeFailed
	}

	if newest && run == item.RunId {
		switch item.State {
		case model.AutomationWorkItemFailed:
			return model.AutomationRunOutcomeFailed
		case model.AutomationWorkItemRunning:
			stopping, inFlight := open[run]

			switch {
			case live:
				return model.AutomationRunOutcomeRunning
			case !inFlight:
				// A store error left the item held by a run that has since closed; the next run
				// recovers it as interrupted.
				return model.AutomationRunOutcomeFailed
			case stopping:
				// The stopping run won't start it.
				return model.AutomationRunOutcomeStopped
			}

			// It hasn't reached its first phase yet.
			return model.AutomationRunOutcomeRunning
		}
	}

	return model.AutomationRunOutcomeStopped
}

// automationRunSteps walks a transcript into thought previews and tool calls, each call
// carrying the status of its result.
func automationRunSteps(history []*model.StoredMessage) []model.AutomationRunStep {
	steps := []model.AutomationRunStep{}

	status := map[string]string{}
	for _, msg := range history {
		if msg.Message == nil {
			continue
		}

		for _, block := range msg.Message.ContentBlocks {
			if block.ToolResult != nil {
				status[block.ToolResult.ToolUseId] = automationToolStatus(block.ToolResult)
			}
		}
	}

	for _, msg := range history {
		if msg.Message == nil || msg.Message.Role != "assistant" {
			continue
		}

		if msg.Message.Thoughts != "" {
			text, truncated := truncateRunes(msg.Message.Thoughts, automationThoughtPreviewRunes)
			steps = append(steps, model.AutomationRunStep{Kind: model.AutomationRunStepThought, Text: text, Truncated: truncated})
		}

		for _, block := range dedupeToolUses(msg.Message.ContentBlocks) {
			if block.Type != "tool_use" {
				continue
			}

			step := model.AutomationRunStep{Kind: model.AutomationRunStepTool, Name: block.Name, Status: model.AutomationToolStatusPending}
			if s, ok := status[block.Id]; ok {
				step.Status = s
			}

			steps = append(steps, step)
		}
	}

	return steps
}

func automationToolStatus(result *model.ToolResult) string {
	switch {
	case result.Status == model.AutomationToolStatusRejected:
		return model.AutomationToolStatusRejected
	case result.IsError || result.Status == model.AutomationToolStatusError:
		return model.AutomationToolStatusError
	}

	return model.AutomationToolStatusOk
}

func truncateRunes(s string, n int) (string, bool) {
	count := 0
	for i := range s {
		if count == n {
			return strings.TrimRightFunc(s[:i], unicode.IsSpace), true
		}
		count++
	}

	return s, false
}

// automationRunLedger is what the alert indices say about one run.
type automationRunLedger struct {
	// False when the store keeps no ledger, so nothing was searched.
	present bool
	alerts  []*model.AlertTriageAlert
	total   int
	givenUp int
}

// automationRunAlerts reads the ledger for one run: the alerts carrying its id and, when the
// cap is known, how many of them belong to a group that is out of retries.
func (ac *AssistantCoordinator) automationRunAlerts(ctx context.Context, run *model.AutomationRunRecord, items []*model.AutomationWorkItem, maxFailures, alertLimit int) (*automationRunLedger, error) {
	ledger := &automationRunLedger{alerts: make([]*model.AlertTriageAlert, 0)}

	updater, ok := ac.srv.Assistantstore.(server.AlertTriageUpdater)
	if !ok || ac.srv.Eventstore == nil {
		return ledger, nil
	}

	ledger.present = true
	prefix := updater.AlertTriageSchemaPrefix()
	dateRange := model.AlertTriageDateRange(automationAlertFloor(ac.getAlertTriageEpoch(), items), time.Now())

	results, err := ac.searchAutomationAlerts(ctx, model.BuildAlertTriageQuery(prefix, run.Id), dateRange, alertLimit)
	if err != nil {
		return nil, err
	}

	ledger.total = results.TotalEvents
	for _, event := range results.Events {
		ledger.alerts = append(ledger.alerts, alertTriageAlertFromEvent(prefix, event))
	}

	if maxFailures > 0 && ledger.total > 0 {
		givenUp := model.BuildAlertTriageQuery(prefix, run.Id) + " AND " + model.AlertTriageGivenUpClause(prefix, maxFailures)

		counted, err := ac.searchAutomationAlerts(ctx, givenUp, dateRange, 0)
		if err != nil {
			return nil, err
		}

		ledger.givenUp = counted.TotalEvents
	}

	return ledger, nil
}

func (ac *AssistantCoordinator) searchAutomationAlerts(ctx context.Context, query, dateRange string, size int) (*model.EventSearchResults, error) {
	criteria := model.NewEventSearchCriteria()
	if err := criteria.Populate(query, dateRange, time.RFC3339, "", "0", strconv.Itoa(size)); err != nil {
		return nil, err
	}

	criteria.SortFields = []*model.SortCriteria{{Field: "@timestamp", Order: "desc"}}

	results, err := ac.srv.Eventstore.Search(ctx, criteria)
	if err != nil {
		return nil, err
	}

	if len(results.Errors) > 0 {
		return nil, fmt.Errorf("automation alert search failed: %s", strings.Join(results.Errors, "; "))
	}

	return results, nil
}

// automationAlertFloor is the earliest an alert of these items can be: the epoch, or an
// item's own floor from before the epoch moved. Never zero, which a date range cannot carry.
func automationAlertFloor(epoch time.Time, items []*model.AutomationWorkItem) time.Time {
	var floor time.Time
	if epoch.After(time.Unix(0, 0)) {
		floor = epoch
	}

	for _, item := range items {
		payload, err := decodeAlertTriagePayload(item)
		if err != nil || payload.Floor.IsZero() {
			continue
		}

		if floor.IsZero() || payload.Floor.Before(floor) {
			floor = payload.Floor
		}
	}

	if floor.IsZero() {
		floor = time.Unix(0, 0)
	}

	return floor.UTC()
}

// automationWroteAlerts reports whether the run finished or failed an item, either of which puts
// its id on the group's alerts.
func automationWroteAlerts(run *model.AutomationRunRecord, items []*model.AutomationWorkItem) bool {
	if !run.State.IsTerminal() {
		return false
	}

	for _, item := range items {
		if (item.State == model.AutomationWorkItemDone && item.RunId == run.Id) || slices.Contains(item.FailedRunIds, run.Id) {
			return true
		}
	}

	return false
}

// alertTriageAlertFromEvent reads the ledger off a flattened hit.
func alertTriageAlertFromEvent(prefix string, event *model.EventRecord) *model.AlertTriageAlert {
	return &model.AlertTriageAlert{
		Id:               event.Id,
		Timestamp:        event.Timestamp,
		RuleName:         payloadString(event.Payload, "rule.name"),
		Severity:         payloadString(event.Payload, "event.severity_label"),
		SessionId:        payloadString(event.Payload, model.AlertTriageFieldSessionId(prefix)),
		Assessment:       payloadInt(event.Payload, model.AlertTriageFieldAssessment(prefix)),
		FailedSessionIds: payloadStrings(event.Payload, model.AlertTriageFieldFailedSessionIds(prefix)),
		FailedRunIds:     payloadStrings(event.Payload, model.AlertTriageFieldFailedRunIds(prefix)),
		FailedCount:      payloadInt(event.Payload, model.AlertTriageFieldFailedCount(prefix)),
		LatestRunId:      payloadString(event.Payload, model.AlertTriageFieldRunId(prefix)),
		TriageTime:       payloadString(event.Payload, model.AlertTriageFieldTimestamp(prefix)),
	}
}

func payloadString(payload map[string]any, key string) string {
	value, _ := payload[key].(string)

	return value
}

func payloadStrings(payload map[string]any, key string) []string {
	values := []string{}

	switch v := payload[key].(type) {
	case []string:
		values = append(values, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	case string:
		values = append(values, v)
	}

	return values
}

func payloadInt(payload map[string]any, key string) int {
	switch v := payload[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()

		return int(n)
	}

	return 0
}
