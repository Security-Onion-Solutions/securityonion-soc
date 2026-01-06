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

const ASSISTANT_SESSION_REPORT_TEMPLATE_NAME = "assistant_session_report.md"

func (export *Export) getAssistantSessionDetailsFromServer(sessionId string) (*AssistantSessionTemplateInput, error) {

	sessionTemplateInput := &AssistantSessionTemplateInput{}

	sessionDetails := &model.AssistantSessionDetails{}
	_, err := export.agent.Client.SendAuthorizedObject("GET", fmt.Sprintf("/api/assistant/sessions/%s", sessionId), nil, sessionDetails)
	if err != nil {
		log.WithFields(log.Fields{
			"sessionId": sessionId,
		}).WithError(err).Error("failed to get assistant session")

		return sessionTemplateInput, err
	}

	sessionTemplateInput.Session = sessionDetails.Session
	sessionTemplateInput.History = sessionDetails.History

	return sessionTemplateInput, nil
}

type AssistantSessionTemplateInput struct {
	Session *model.AssistantSession
	History []*model.StoredMessage
}

func (export *Export) generateAssistantSessionReport(sessionId string) ([]byte, error) {
	sessionTemplateInput, err := export.getAssistantSessionDetailsFromServer(sessionId)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = export.templates.ExecuteTemplate(&buf, ASSISTANT_SESSION_REPORT_TEMPLATE_NAME, sessionTemplateInput)

	return buf.Bytes(), err
}

func (export *Export) getAssistantSessionExportParams(templatePath string) []string {
	return export.getPdfExportParams(templatePath+"/standard", ASSISTANT_SESSION_REPORT_TEMPLATE_NAME)
}
