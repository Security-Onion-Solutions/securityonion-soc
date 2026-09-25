// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/apex/log"
)

var _ server.AlertTriageUpdater = (*ElasticAssistantstore)(nil)

// Locals and params carry a triage prefix so the script composes with the other update scripts.
func (store *ElasticAssistantstore) addAlertTriageScript(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, update *model.AlertTriageUpdate) {
	updateCriteria.Params["triageNowMillis"] = timeNow.UnixMilli()
	updateCriteria.Params["triageRunId"] = update.RunId
	updateCriteria.Params["triageSessionId"] = update.SessionId
	updateCriteria.Params["triageObject"] = model.AlertTriageObject(store.schemaPrefix)

	script := `
			Instant triage_instant = Instant.ofEpochMilli(params.triageNowMillis);
			ZonedDateTime triage_date = ZonedDateTime.ofInstant(triage_instant, ZoneId.of('Z'));
			if (ctx._source.event == null) {
				ctx._source.event = [:];
			}
			if (ctx._source.event[params.triageObject] == null) {
				ctx._source.event[params.triageObject] = [:];
			}
			def triage_rec = ctx._source.event[params.triageObject];`

	if update.Failed {
		script += `
			if (triage_rec.failed_session_ids == null) {
				triage_rec.failed_session_ids = [];
			}
			if (!triage_rec.failed_session_ids.contains(params.triageSessionId)) {
				triage_rec.failed_session_ids.add(params.triageSessionId);
				triage_rec.failed_count = triage_rec.failed_session_ids.size();`
	} else {
		script += `
			if (triage_rec.session_id == null) {
				triage_rec.session_id = params.triageSessionId;`
	}

	script += `
				if (triage_rec.automation_run_ids == null) {
					triage_rec.automation_run_ids = [];
				}
				if (!triage_rec.automation_run_ids.contains(params.triageRunId)) {
					triage_rec.automation_run_ids.add(params.triageRunId);
				}
				triage_rec.automation_run_id = params.triageRunId;
				triage_rec.timestamp = triage_date;
			}
			`
	updateCriteria.AddUpdateScript(script)
}

func (store *ElasticAssistantstore) AlertTriageUpdate(ctx context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error) {
	if err := update.Validate(); err != nil {
		return nil, err
	}

	now := time.Now()
	criteria := model.NewEventUpdateCriteria()
	query := update.Query
	if !update.Failed {
		query = "(NOT _exists_:" + model.AlertTriageFieldSessionId(store.schemaPrefix) + ") AND (" + query + ")"
	}
	if err := criteria.Populate(query, model.AlertTriageDateRange(update.Floor, update.Ceiling), time.RFC3339, "", "0", "0"); err != nil {
		return nil, err
	}

	store.addAlertTriageScript(criteria, now, update)
	criteria.Asynchronous = update.Count > store.eventstore.asyncThreshold

	log.FromContext(ctx).WithFields(log.Fields{
		"automationRunId":       update.RunId,
		"sessionId":             update.SessionId,
		"failedUpdateCount":     update.Failed,
		"successfulUpdateCount": update.Count,
		"isAsync":               criteria.Asynchronous,
	}).Info("Updating alert triage")

	results, tasks, err := store.eventstore.runUpdate(ctx, criteria)
	if err == nil && len(tasks) > 0 {
		status := store.eventstore.aggregateAsyncUpdate(ctx, tasks, results.TaskIds)
		results.UpdatedCount += status.Updated
		results.Errors = append(results.Errors, status.Errors...)
	}
	if err == nil && len(results.Errors) > 0 {
		err = fmt.Errorf("alert triage update failed: %s", strings.Join(results.Errors, "; "))
	}

	results.Complete()
	return results, err
}
