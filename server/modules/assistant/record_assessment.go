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
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
)

const recordAssessmentToolName = "record_assessment"

func init() {
	t := &RecordAssessmentTool{}
	knownTools[t.GetName()] = t
}

// RecordAssessmentTool carries the triage agent's assessment to SOC as a number, so it is
// read the same whatever language the agent writes its report in. It writes nothing itself:
// the alert triage run records the last valid call when the session ends.
type RecordAssessmentTool struct{}

func (t *RecordAssessmentTool) GetName() string {
	return recordAssessmentToolName
}

// The description and schema are read by the model, never shown in the UI, so they are not localized.
func (t *RecordAssessmentTool) GetDescription() string {
	return `Record your assessment of the alert you are triaging. Call it once your assessment is settled,
	before you write the final report, and again if you revise it; the last call is the one recorded on
	the alerts. Only available during alert triage.`
}

func (t *RecordAssessmentTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"assessment": {
					Type: "integer",
					Description: fmt.Sprintf("Exactly one of: %d for LIKELY MALICIOUS, %d for NEEDS REVIEW, %d for LIKELY BENIGN.",
						model.AlertTriageAssessmentLikelyMalicious, model.AlertTriageAssessmentNeedsReview, model.AlertTriageAssessmentLikelyBenign),
				},
			},
			Required: []string{"assessment"},
		},
	}
}

type recordAssessmentArgs struct {
	Assessment int `json:"assessment"`
}

func (t *RecordAssessmentTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	result = &model.ToolResponse{
		ToolName:       t.GetName(),
		OnBehalfOfUser: userId,
	}

	start := time.Now()
	defer func() {
		if result != nil {
			result.TimeToExecute = time.Since(start)
		}
	}()

	args, err := parseRecordAssessmentArgs(req.Params)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("invalid record_assessment params")
		return nil, err
	}

	result.Parameters = args

	_, rootSession := resolveRootSession(ctx, srv, req.SessionId)
	if rootSession == nil || rootSession.Type != alertTriageKindName {
		logger.Error("record_assessment called outside an alert triage session")
		return nil, errors.New("ERROR_ASSISTANT_ASSESSMENT_OUTSIDE_TRIAGE")
	}

	result.Result = fmt.Sprintf("Assessment %d recorded. It is written to the alerts when this triage ends.", args.Assessment)

	return result, nil
}

// parseRecordAssessmentArgs reads a record_assessment call's input, rejecting any value other
// than a known assessment.
func parseRecordAssessmentArgs(params json.RawMessage) (*recordAssessmentArgs, error) {
	args := &recordAssessmentArgs{}
	if err := json.Unmarshal(params, args); err != nil {
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	if !model.IsValidAlertTriageAssessment(args.Assessment) {
		return nil, fmt.Errorf("ERROR_ASSISTANT_INVALID_ASSESSMENT: assessment must be %d, %d or %d", model.AlertTriageAssessmentLikelyMalicious, model.AlertTriageAssessmentNeedsReview, model.AlertTriageAssessmentLikelyBenign)
	}

	return args, nil
}
