// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func (export *Export) getGenericDetailsFromServer(job *model.Job, queries map[string]*CustomQuery) (*GenericTemplateInput, error) {
	var err error

	templateInput := &GenericTemplateInput{
		BeginDate: job.Filter.BeginTime,
		EndDate:   job.Filter.EndTime,
	}

	for name, query := range queries {
		if query.Oql == "" {
			log.WithFields(log.Fields{
				"jobId":     job.Id,
				"queryName": name,
			}).Warn("skipping query with no OQL")
			continue
		}
		eventResults := &model.EventSearchResults{}
		_, err = export.queryEventData(query.Oql, job.Filter, query.MetricLimit, query.EventLimit, eventResults)
		if err != nil {
			log.WithFields(log.Fields{
				"jobId":           job.Id,
				"customQueryOql":  query.Oql,
				"customQueryName": name,
			}).WithError(err).Error("failed to get event metrics for custom query")

			return nil, err
		}

		for metric, value := range eventResults.Metrics {
			metric := strings.ReplaceAll(metric, "|", "_")
			value = export.expandMetricsWithTotal(value, float64(eventResults.TotalEvents))
			templateInput.Results[name].Metrics[metric] = value
		}
		templateInput.Results[name] = eventResults
	}

	return templateInput, nil
}

type CustomQuery struct {
	Oql         string
	MetricLimit int
	EventLimit  int
}

type GenericTemplateInput struct {
	Error     string
	BeginDate time.Time
	EndDate   time.Time

	Results map[string]*model.EventSearchResults
}

func (export *Export) generateGenericReport(job *model.Job, templateName string) ([]byte, error) {
	templatePath := export.templatePath + "/" + templateName + ".md"
	query_options := export.getParamsFromTemplate(templatePath, "query.", "")

	var queries map[string]*CustomQuery
	for _, query_option := range query_options {
		pieces := strings.SplitN(query_option, "=", 2)
		if len(pieces) != 2 {
			log.WithFields(log.Fields{
				"jobId":             job.Id,
				"customQueryOption": query_option,
			}).Warn("invalid query option format, expected 'key = value'")
			continue
		}
		key := strings.TrimSpace(pieces[0])
		value := strings.TrimSpace(pieces[1])

		// Now split apart the key into the query name and the query attribute
		keyParts := strings.SplitN(key, ".", 2)
		if len(keyParts) != 2 {
			log.WithFields(log.Fields{
				"jobId":                    job.Id,
				"customQueryNameAttribute": key,
			}).Warn("invalid query option format, expected 'query.name.attribute'")
			continue
		}
		queryName := keyParts[0]
		queryAttribute := keyParts[1]
		switch strings.ToLower(queryAttribute) {
		case "oql":
			if query, exists := queries[queryName]; exists {
				query.Oql = value
			} else {
				queries[queryName] = &CustomQuery{
					Oql:         queryAttribute,
					MetricLimit: export.getMetricLimit(job),
					EventLimit:  export.getEventLimit(job),
				}
			}
		case "metriclimit":
			metricLimit, err := strconv.Atoi(value)
			if err != nil {
				log.WithFields(log.Fields{
					"jobId":             job.Id,
					"customQueryOption": query_option,
				}).WithError(err).Warn("failed to parse metric limit from query option")
				continue
			}
			if query, exists := queries[queryName]; exists {
				query.MetricLimit = metricLimit
			} else {
				queries[queryName] = &CustomQuery{
					Oql:         "",
					MetricLimit: metricLimit,
					EventLimit:  export.getEventLimit(job),
				}
			}
		case "eventlimit":
			eventLimit, err := strconv.Atoi(value)
			if err != nil {
				log.WithFields(log.Fields{
					"jobId":             job.Id,
					"customQueryOption": query_option,
				}).WithError(err).Warn("failed to parse event limit from query option")
				continue
			}
			if query, exists := queries[queryName]; exists {
				query.EventLimit = eventLimit
			} else {
				queries[queryName] = &CustomQuery{
					Oql:         "",
					MetricLimit: export.getMetricLimit(job),
					EventLimit:  eventLimit,
				}
			}
		default:
			log.WithFields(log.Fields{
				"jobId":                job.Id,
				"customQueryName":      queryName,
				"customQueryAttribute": queryAttribute,
			}).Warn("unknown query attribute in template options")
			continue
		}
	}
	if len(queries) == 0 {
		log.WithFields(log.Fields{
			"jobId":        job.Id,
			"templateName": templateName,
		}).Warn("no custom queries found in template options")
		return nil, nil
	}

	templateInput, err := export.getGenericDetailsFromServer(job, queries)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = export.templates.ExecuteTemplate(&buf, templateName, templateInput)

	return buf.Bytes(), err
}

func (export *Export) getGenericTemplateName(job *model.Job) string {
	if templateName, exists := job.Filter.Parameters["template"]; exists {
		return templateName.(string)
	}
	return ""
}
