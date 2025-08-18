// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"bytes"
	"fmt"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

const CASE_REPORT_TEMPLATE_NAME = "case_report.md"

func (export *Export) getCaseDetailsFromServer(caseId string) (*CaseTemplateInput, error) {

	caseTemplateInput := &CaseTemplateInput{}

	// Get case data
	_, err := export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/%s", caseId), nil, &caseTemplateInput.Case)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case")

		return caseTemplateInput, err
	}

	// Get case comments
	_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/comments/%s", caseId), nil, &caseTemplateInput.Comments)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case comments")
	}
	caseTemplateInput.TotalHours = 0.0
	for _, comment := range caseTemplateInput.Comments {
		caseTemplateInput.TotalHours += comment.Hours
	}

	// Get attachments
	_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/artifacts/attachments?id=%s", caseId), nil, &caseTemplateInput.Attachments)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case attachments")
	}

	// Get attachments
	_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/artifacts/evidence?id=%s", caseId), nil, &caseTemplateInput.Observables)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case observables")
	}

	// Get related events
	_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/events/%s", caseId), nil, &caseTemplateInput.RelatedEvents)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case events")
	}

	for _, event := range caseTemplateInput.RelatedEvents {
		if len(event.Fields) > 0 {
			// Prepare the map for template rendering (removing periods to make subfields referenceable, etc)
			for key, value := range event.Fields {
				event.Fields[export.prepareKeyForTemplate(key)] = value
			}

			// Extract the detection rule if this an alert event
			if tags, ok := event.Fields["tags"]; ok {
				if tagInterfaces, ok := tags.([]interface{}); ok {
					for _, tagInterface := range tagInterfaces {
						if tag, ok := tagInterface.(string); ok {
							if tag == "alert" {
								detectionExists := false
								// Check if the detection already exists in the case template input
								for _, detection := range caseTemplateInput.Detections {
									if detection.PublicID == event.Fields["rule.uuid"] {
										detectionExists = true
										break
									}
								}
								if !detectionExists {
									detection := &model.Detection{}
									_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/detection/public/%s", event.Fields["rule.uuid"]), nil, detection)
									if err != nil {
										log.WithFields(log.Fields{
											"eventId": event.Id,
										}).WithError(err).Error("failed to get detection for event")
									} else {
										caseTemplateInput.Detections = append(caseTemplateInput.Detections, detection)
									}
								}
								break
							}
						}
					}
				}
			}
		}
	}

	// Get history
	_, err = export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/case/history/%s", caseId), nil, &caseTemplateInput.History)
	if err != nil {
		log.WithFields(log.Fields{
			"caseId": caseId,
		}).WithError(err).Error("failed to get case history")
	}

	return caseTemplateInput, nil
}

type CaseTemplateInput struct {
	Case          *model.Case
	Comments      []*model.Comment
	Attachments   []*model.Artifact
	Observables   []*model.Artifact
	Detections    []*model.Detection
	RelatedEvents []*model.RelatedEvent
	History       []*model.Auditable
	TotalHours    float64
}

func (export *Export) generateCaseReport(caseId string) ([]byte, error) {
	caseTemplateInput, err := export.getCaseDetailsFromServer(caseId)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = export.templates.ExecuteTemplate(&buf, CASE_REPORT_TEMPLATE_NAME, caseTemplateInput)

	return buf.Bytes(), err
}

func (export *Export) getCaseExportParams(templatePath string) []string {
	return export.getPdfExportParams(templatePath+"/standard", CASE_REPORT_TEMPLATE_NAME)
}
