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
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var _ AutomationKind = (*fakeAutomationKind)(nil)

type fakeAutomationKind struct {
	name        string
	displayName string
	description string
	schema      model.JSONSchema
	validateErr error
	executeFunc func(ctx context.Context, run *AutomationRun) error
}

func (f *fakeAutomationKind) GetName() string                  { return f.name }
func (f *fakeAutomationKind) GetDisplayName() string           { return f.displayName }
func (f *fakeAutomationKind) GetDescription() string           { return f.description }
func (f *fakeAutomationKind) GetParamSchema() model.JSONSchema { return f.schema }
func (f *fakeAutomationKind) ValidateParams(json.RawMessage) error {
	return f.validateErr
}

func (f *fakeAutomationKind) Execute(ctx context.Context, run *AutomationRun) error {
	if f.executeFunc != nil {
		return f.executeFunc(ctx, run)
	}

	return nil
}

func schemaWithProperty(name string) model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type:       "object",
			Properties: map[string]model.ToolSchemaProperty{name: {Type: "string"}},
		},
	}
}

// TestKnownAutomationKindsRegistration passes vacuously until a kind ships. It
// exists to catch the copy-paste registration that keys a kind by another kind's
// name, which nothing else would fail on: the catalog would simply be missing an
// entry.
func TestKnownAutomationKindsRegistration(t *testing.T) {
	for key, kind := range knownAutomationKinds {
		assert.NotEmpty(t, key)
		assert.Equal(t, key, kind.GetName())
	}
}

func TestExposeAutomationKindsSortsByName(t *testing.T) {
	ac := &AssistantCoordinator{AutomationKindLibrary: map[string]AutomationKind{}}

	for _, name := range []string{"zeta", "alpha", "mid"} {
		ac.AutomationKindLibrary[name] = &fakeAutomationKind{
			name:        name,
			displayName: strings.ToUpper(name),
			description: name + " description",
			schema:      schemaWithProperty(name + "_param"),
		}
	}

	kinds := ac.exposeAutomationKinds()
	require.Len(t, kinds, 3)

	assert.Equal(t, []string{"alpha", "mid", "zeta"}, []string{kinds[0].Name, kinds[1].Name, kinds[2].Name})

	assert.Equal(t, "ALPHA", kinds[0].DisplayName)
	assert.Equal(t, "alpha description", kinds[0].Description)
	require.NotNil(t, kinds[0].ParamSchema.Json)
	assert.Contains(t, kinds[0].ParamSchema.Json.Properties, "alpha_param")
}

func TestExposeAutomationKindsEmpty(t *testing.T) {
	ac := &AssistantCoordinator{AutomationKindLibrary: map[string]AutomationKind{}}

	kinds := ac.exposeAutomationKinds()
	assert.NotNil(t, kinds)
	assert.Empty(t, kinds)

	// An agentic grid with no kinds must send [] rather than null so the form can
	// tell "nothing to offer" from "feature absent".
	raw, err := json.Marshal(model.AssistantParameters{AvailableAutomationKinds: kinds})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"availableAutomationKinds":[]`)
}

func TestLookupAutomationKind(t *testing.T) {
	fake := &fakeAutomationKind{name: "alert_triage"}
	ac := &AssistantCoordinator{
		AutomationKindLibrary: map[string]AutomationKind{"alert_triage": fake},
	}

	found, err := ac.lookupAutomationKind("alert_triage")
	require.NoError(t, err)
	assert.Same(t, fake, found)

	_, err = ac.lookupAutomationKind("nope")
	assert.ErrorIs(t, err, ErrAutomationKindNotFound)

	// A task can outlive its kind, and the engine resolves kinds before it has a
	// library in some startup orders, so a nil map must not panic.
	empty := &AssistantCoordinator{}
	_, err = empty.lookupAutomationKind("alert_triage")
	assert.ErrorIs(t, err, ErrAutomationKindNotFound)
}

func TestValidateParamsErrorIsMappable(t *testing.T) {
	fake := &fakeAutomationKind{
		name:        "alert_triage",
		validateErr: fmt.Errorf("%w: sample_size is required", ErrInvalidAutomationParams),
	}

	err := fake.ValidateParams(json.RawMessage(`{}`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAutomationParams))

	// respondConfigWrite matches on the message substring rather than the sentinel,
	// so wrapping must not hide the error key from the status mapping.
	assert.True(t, strings.Contains(err.Error(), "ERROR_AUTOMATION_PARAMS_INVALID"))
}

func TestAutomationRunPlumbing(t *testing.T) {
	srv := &server.Server{}
	task := &model.Automation{
		Name:   "Nightly Alert Triage",
		Kind:   "alert_triage",
		Owner:  "owner-1",
		Params: json.RawMessage(`{"sampleSize":5}`),
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var gotReq *model.AgentSessionRequest

	manager := servermock.NewMockAssistantManager(ctrl)
	manager.EXPECT().RunAgentSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *model.AgentSessionRequest) (*model.AgentSessionResult, error) {
			gotReq = req

			return &model.AgentSessionResult{SessionId: "session-9", FinalText: `{"recommendation":"ack"}`, Turns: 3}, nil
		})
	srv.AssistantManager = manager

	var gotRun *AutomationRun

	fake := &fakeAutomationKind{
		name: "alert_triage",
		executeFunc: func(ctx context.Context, run *AutomationRun) error {
			gotRun = run

			// A kind reaches the headless driver through the server it was handed,
			// which is the whole reason AutomationRun carries no runner of its own.
			result, err := run.Srv.AssistantManager.RunAgentSession(ctx, &model.AgentSessionRequest{
				Objective: "triage group A",
				Agent:     "Hunter",
				OwnerId:   run.Task.Owner,
				MaxTurns:  8,
			})
			if err != nil {
				return err
			}

			assert.Equal(t, "session-9", result.SessionId)

			return nil
		},
	}

	run := &AutomationRun{Srv: srv, Task: task, RunId: "run-7"}

	require.NoError(t, fake.Execute(context.Background(), run))

	require.NotNil(t, gotRun)
	assert.Same(t, srv, gotRun.Srv)
	assert.Same(t, task, gotRun.Task)
	assert.Equal(t, "run-7", gotRun.RunId)

	require.NotNil(t, gotReq)
	assert.Equal(t, "triage group A", gotReq.Objective)
	assert.Equal(t, "Hunter", gotReq.Agent)
	assert.Equal(t, "owner-1", gotReq.OwnerId)
	assert.Equal(t, 8, gotReq.MaxTurns)
}

func TestExposeAgentsPublishesAutomationKinds(t *testing.T) {
	ac, _ := builtinMergeCoordinator()
	ac.AutomationKindLibrary = map[string]AutomationKind{
		"alert_triage": &fakeAutomationKind{
			name:        "alert_triage",
			displayName: "Alert Triage",
			description: "Groups, samples and triages alerts",
			schema:      schemaWithProperty("sample_size"),
		},
	}

	ac.exposeAgents()

	published := ac.srv.Config.ClientParams.AssistantParams.AvailableAutomationKinds
	require.Len(t, published, 1)
	assert.Equal(t, "alert_triage", published[0].Name)
	assert.Equal(t, "Alert Triage", published[0].DisplayName)
	require.NotNil(t, published[0].ParamSchema.Json)
	assert.Contains(t, published[0].ParamSchema.Json.Properties, "sample_size")
}
