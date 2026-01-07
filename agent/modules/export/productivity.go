// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"bytes"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

const PRODUCTIVITY_REPORT_TEMPLATE_NAME = "productivity_report.md"

func (export *Export) getProductivityDetailsFromServer(job *model.Job) (*ProductivityTemplateInput, error) {
	var err error

	eventLimit := export.getEventLimit(job)
	metricLimit := export.getMetricLimit(job)

	eventResults := &model.EventSearchResults{}
	eventQuery := `_index:"*:logs-*" AND NOT tags:alert | groupby event.module, event.dataset`
	_, err = export.queryEventData(eventQuery, job.Filter, metricLimit, NO_EVENTS, eventResults)
	if err != nil {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).WithError(err).Error("failed to get event metrics")

		return nil, err
	}

	templateInput := &ProductivityTemplateInput{
		BeginDate: job.Filter.BeginTime,
		EndDate:   job.Filter.EndTime,
	}

	templateInput.TotalEvents = eventResults.TotalEvents
	for metric, value := range eventResults.Metrics {
		metricParts := strings.SplitN(metric, "|", 2)
		if len(metricParts) > 1 {
			metricName := metricParts[1]
			switch metricName {
			case "event.module":
				templateInput.TotalEventsByModule = export.expandMetricsWithTotal(value, float64(templateInput.TotalEvents))
			case "event.module|event.dataset":
				templateInput.TotalEventsByModuleDataset = export.expandMetricsWithTotal(value, float64(templateInput.TotalEvents))
			}
		}
	}

	alertResults := &model.EventSearchResults{}
	alertQuery := `tags:alert | groupby event.escalated | groupby event.acknowledged, event.escalated | groupby event.module, event.severity_label | groupby event.severity_label, event.acknowledged, event.escalated | groupby rule.category | groupby rule.ruleset`
	_, err = export.queryEventData(alertQuery, job.Filter, metricLimit, NO_EVENTS, alertResults)
	if err != nil {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).WithError(err).Error("failed to get alert metrics")

		return nil, err
	}

	templateInput.TotalAlerts = alertResults.TotalEvents
	for metric, value := range alertResults.Metrics {
		metricParts := strings.SplitN(metric, "|", 2)
		if len(metricParts) > 1 {
			metricName := metricParts[1]
			switch metricName {
			case "event.escalated":
				templateInput.TotalAlertsByEscalated = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.acknowledged":
				templateInput.TotalAlertsByAcknowledged = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.acknowledged|event.escalated":
				templateInput.TotalAlertsByAcknowledgedEscalated = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.module":
				templateInput.TotalAlertsByModule = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.module|event.severity_label":
				templateInput.TotalAlertsByModuleSeverityLabel = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.severity_label":
				templateInput.TotalAlertsBySeverityLabel = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.severity_label|event.acknowledged":
				templateInput.TotalAlertsBySeverityLabelAcknowledged = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "event.severity_label|event.acknowledged|event.escalated":
				templateInput.TotalAlertsBySeverityLabelAcknowledgedEscalated = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "rule.category":
				templateInput.TotalAlertsByCategory = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			case "rule.ruleset":
				templateInput.TotalAlertsByRuleset = export.expandMetricsWithTotal(value, float64(templateInput.TotalAlerts))
			}
		}
	}

	caseResults := &model.EventSearchResults{}
	caseQuery := `_index: "*:so-case" AND so_kind: case | groupby so_case.status | groupby so_case.status, so_case.assigneeId | groupby so_case.assigneeId | groupby so_case.severity | groupby so_case.priority | groupby so_case.tlp | groupby so_case.pap | groupby so_case.category | groupby so_case.tags`
	_, err = export.queryEventData(caseQuery, job.Filter, metricLimit, eventLimit, caseResults)
	if err != nil {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).WithError(err).Error("failed to get case metrics")

		return nil, err
	}

	closedCount := 0
	secondsToComplete := 0.0
	for _, event := range caseResults.Events {
		if event.Payload["so_case.createTime"] == nil || event.Payload["so_case.completeTime"] == nil {
			continue
		}
		createTimeStr := event.Payload["so_case.createTime"].(string)
		completeTimeStr := event.Payload["so_case.completeTime"].(string)

		createTime, err := time.Parse(time.RFC3339, createTimeStr)
		if err != nil {
			log.WithFields(log.Fields{
				"jobId":   job.Id,
				"eventId": event.Id,
			}).WithError(err).Error("failed to parse case create time")
			continue
		}
		completeTime, err := time.Parse(time.RFC3339, completeTimeStr)
		if err != nil {
			log.WithFields(log.Fields{
				"jobId":   job.Id,
				"eventId": event.Id,
			}).WithError(err).Error("failed to parse case complete time")
			continue
		}
		if completeTime.After(createTime) {
			secondsToComplete += completeTime.Sub(createTime).Seconds()
		}
		closedCount++
	}
	templateInput.AverageHoursToComplete += secondsToComplete / float64(closedCount) / SECONDS_PER_HOUR

	templateInput.TotalCases = caseResults.TotalEvents
	for metric, value := range caseResults.Metrics {
		metricParts := strings.SplitN(metric, "|", 2)
		if len(metricParts) > 1 {
			metricName := metricParts[1]
			switch metricName {
			case "so_case.status":
				templateInput.TotalCasesByStatus = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.status|so_case.assigneeId":
				templateInput.TotalCasesByStatusAssignee = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.assigneeId":
				templateInput.TotalCasesByAssignee = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.severity":
				templateInput.TotalCasesBySeverity = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.priority":
				templateInput.TotalCasesByPriority = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.tlp":
				templateInput.TotalCasesByTlp = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.pap":
				templateInput.TotalCasesByPap = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.category":
				templateInput.TotalCasesByCategory = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			case "so_case.tags":
				templateInput.TotalCasesByTags = export.expandMetricsWithTotal(value, float64(templateInput.TotalCases))
			}
		}

	}

	commentResults := &model.EventSearchResults{}
	commentQuery := `_index: "*:so-case" AND so_kind: comment | groupby so_comment.userId`
	_, err = export.queryEventData(commentQuery, job.Filter, metricLimit, eventLimit, commentResults)
	if err != nil {
		log.WithFields(log.Fields{
			"jobId": job.Id,
		}).WithError(err).Error("failed to get comment metrics")

		return nil, err
	}

	templateInput.TotalComments = commentResults.TotalEvents
	for metric, value := range commentResults.Metrics {
		metricParts := strings.SplitN(metric, "|", 2)
		if len(metricParts) > 1 {
			metricName := metricParts[1]
			switch metricName {
			case "so_comment.userId":
				templateInput.TotalCommentsByUserId = export.expandMetricsWithTotal(value, float64(templateInput.TotalComments))
			}
		}
	}

	if len(commentResults.Events) == eventLimit {
		templateInput.Error = "Additional comment data may have been excluded due to reporting data limits"
	}

	for _, event := range commentResults.Events {
		hours := event.Payload["so_comment.hours"].(float64)
		userId := event.Payload["so_comment.userId"].(string)
		templateInput.TotalHours += hours
		templateInput.TotalHoursByUserId = export.addMetric(templateInput.TotalHoursByUserId, []interface{}{userId}, hours)
	}
	export.expandMetrics(templateInput.TotalHoursByUserId)

	return templateInput, nil
}

type ProductivityTemplateInput struct {
	Error     string
	BeginDate time.Time
	EndDate   time.Time

	TotalEvents                int
	TotalEventsByModule        []*model.EventMetric
	TotalEventsByModuleDataset []*model.EventMetric

	TotalAlerts                                     int
	TotalAlertsByEscalated                          []*model.EventMetric
	TotalAlertsByAcknowledged                       []*model.EventMetric
	TotalAlertsByAcknowledgedEscalated              []*model.EventMetric
	TotalAlertsByModule                             []*model.EventMetric
	TotalAlertsByModuleSeverityLabel                []*model.EventMetric
	TotalAlertsBySeverityLabel                      []*model.EventMetric
	TotalAlertsBySeverityLabelAcknowledged          []*model.EventMetric
	TotalAlertsBySeverityLabelAcknowledgedEscalated []*model.EventMetric
	TotalAlertsByCategory                           []*model.EventMetric
	TotalAlertsByRuleset                            []*model.EventMetric

	TotalCases                 int
	AverageHoursToEscalate     float64
	AverageHoursToComplete     float64
	TotalCasesByStatus         []*model.EventMetric
	TotalCasesByStatusAssignee []*model.EventMetric
	TotalCasesByAssignee       []*model.EventMetric
	TotalCasesBySeverity       []*model.EventMetric
	TotalCasesByPriority       []*model.EventMetric
	TotalCasesByTlp            []*model.EventMetric
	TotalCasesByPap            []*model.EventMetric
	TotalCasesByCategory       []*model.EventMetric
	TotalCasesByTags           []*model.EventMetric

	TotalComments         int
	TotalCommentsByUserId []*model.EventMetric

	TotalHours         float64
	TotalHoursByUserId []*model.EventMetric
}

func (export *Export) generateProductivityReport(job *model.Job) ([]byte, error) {
	templateInput, err := export.getProductivityDetailsFromServer(job)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = export.templates.ExecuteTemplate(&buf, PRODUCTIVITY_REPORT_TEMPLATE_NAME, templateInput)

	return buf.Bytes(), err
}

func (export *Export) getProductivityExportParams(templatePath string) []string {
	return export.getPdfExportParams(templatePath+"/standard", PRODUCTIVITY_REPORT_TEMPLATE_NAME)
}
