// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestRecordAssessmentTool_Registered(t *testing.T) {
	tool := &RecordAssessmentTool{}

	assert.Equal(t, "record_assessment", tool.GetName())
	assert.Same(t, knownTools["record_assessment"], knownTools[tool.GetName()])
	assert.NotEmpty(t, tool.GetDescription())

	schema := tool.GetSchema().Json
	assert.Equal(t, []string{"assessment"}, schema.Required)
	assert.Equal(t, "integer", schema.Properties["assessment"].Type)
	assert.Contains(t, schema.Properties["assessment"].Description, "90 for LIKELY MALICIOUS")
}

func TestRecordAssessmentTool_Execute(t *testing.T) {
	triageTree := []*model.AssistantSession{
		{SessionId: "triage", Type: alertTriageKindName, EntityId: "alert-1"},
		{SessionId: "child", ParentSessionId: "triage"},
	}
	chat := []*model.AssistantSession{{SessionId: "chat"}}

	tests := []struct {
		name      string
		sessionId string
		params    string
		sessions  []*model.AssistantSession
		getErr    error
		wantErr   string
		want      string
	}{
		{name: "records in a triage session", sessionId: "triage", params: `{"assessment":90}`, sessions: triageTree, want: "Assessment 90 recorded"},
		{name: "accepts each assessment", sessionId: "triage", params: `{"assessment":10}`, sessions: triageTree, want: "Assessment 10 recorded"},
		{name: "rejects an unknown value", sessionId: "triage", params: `{"assessment":75}`, sessions: triageTree, wantErr: "ERROR_ASSISTANT_INVALID_ASSESSMENT"},
		{name: "rejects a missing value", sessionId: "triage", params: `{}`, sessions: triageTree, wantErr: "ERROR_ASSISTANT_INVALID_ASSESSMENT"},
		{name: "rejects a word", sessionId: "triage", params: `{"assessment":"LIKELY BENIGN"}`, sessions: triageTree, wantErr: "ERROR_ASSISTANT_UNMARSHAL_PARAMS"},
		{name: "refused in a chat", sessionId: "chat", params: `{"assessment":90}`, sessions: chat, wantErr: "ERROR_ASSISTANT_ASSESSMENT_OUTSIDE_TRIAGE"},
		{name: "a sub-session resolves to its triage root", sessionId: "child", params: `{"assessment":50}`, sessions: triageTree, want: "Assessment 50 recorded"},
		{name: "refused when the session cannot be found", sessionId: "triage", params: `{"assessment":90}`, sessions: triageTree, getErr: errors.New("down"), wantErr: "ERROR_ASSISTANT_ASSESSMENT_OUTSIDE_TRIAGE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			srv := &server.Server{Assistantstore: sessionTreeStore(ctrl, tt.sessions, tt.getErr)}
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

			result, err := (&RecordAssessmentTool{}).Execute(ctx, srv, &model.ToolRequest{SessionId: tt.sessionId, ToolUseId: "tu-1", Params: json.RawMessage(tt.params)})

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, result)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "record_assessment", result.ToolName)
			assert.Equal(t, "user-1", result.OnBehalfOfUser)
			assert.Contains(t, result.Result, tt.want)
		})
	}
}
