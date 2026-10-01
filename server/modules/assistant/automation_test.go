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
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

// automationConfigstore records whole settings rather than just values, and counts callback
// registrations.
type automationConfigstore struct {
	fakeConfigstore

	updates    []*model.Setting
	updateErr  error
	registered []string
	// Lets an ordering test see where the write falls among the steps around it.
	onUpdate func()
}

func (f *automationConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	if f.updateErr != nil {
		return f.updateErr
	}

	f.updates = append(f.updates, setting)

	if f.onUpdate != nil {
		f.onUpdate()
	}

	return nil
}

func (f *automationConfigstore) RegisterConfigSettingCallback(settingID string, handler server.ConfigSettingCallbackHandler) {
	f.registered = append(f.registered, settingID)
}

var _ server.ConfigSettingCallbackRegistrar = (*automationConfigstore)(nil)

func automationCoordinator(cfg *automationConfigstore) *AssistantCoordinator {
	return automationCoordinatorAs(cfg, true)
}

func automationCoordinatorAs(cfg *automationConfigstore, authorized bool) *AssistantCoordinator {
	ac := &AssistantCoordinator{
		srv: &server.Server{
			Context:     context.Background(),
			Config:      &config.ServerConfig{},
			Configstore: cfg,
			Authorizer:  rbac.FakeAuthorizer{Authorized: authorized},
		},
		AutomationKindLibrary: map[string]AutomationKind{
			"alert_triage": &fakeAutomationKind{name: "alert_triage"},
		},
	}
	seedAutomationAgent(ac)

	return ac
}

// seedAutomationAgent makes automationTestAgent resolvable: defined, enabled, mapped to an
// enabled model.
func seedAutomationAgent(ac *AssistantCoordinator) {
	ac.srv.Config.ClientParams.AssistantParams.AvailableModels = []model.ModelParameters{
		{ID: "test-model", Adapter: "MyAdapter", Enabled: true},
	}
	ac.agents = map[string]model.Agent{automationTestAgent: {Name: automationTestAgent, Enabled: true}}
	ac.agentMapping = map[string]string{automationTestAgent: "test-model@MyAdapter"}
}

// Identity is a UUID, so a save that is meant to succeed has to use one.
const (
	automationTestId      = "5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"
	otherAutomationTestId = "1d7e3a44-88b6-4c0f-9a21-70f5e9c3b812"
	automationTestAgent   = "Investigator"
)

func automationSaveCtx() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
}

// validAutomation is everything SaveAutomation requires. Each test mutates the one field
// it is about, so a rejection can only come from that field.
func validAutomation() *model.Automation {
	return &model.Automation{
		DisplayName:     "Nightly",
		AutomationKind:  "alert_triage",
		Agent:           automationTestAgent,
		IntervalSeconds: 300,
	}
}

func storedAutomation(id, displayName string) *model.Automation {
	return &model.Automation{
		Auditable:       model.Auditable{Id: id, UserId: "user-1"},
		DisplayName:     displayName,
		AutomationKind:  "alert_triage",
		Agent:           automationTestAgent,
		IntervalSeconds: 300,
	}
}

// automationsSetting is the stored list holding these automations, in order.
func automationsSetting(t *testing.T, automations ...*model.Automation) *model.Setting {
	t.Helper()

	raw, err := json.Marshal(append([]*model.Automation{}, automations...))
	require.NoError(t, err)

	return &model.Setting{Id: ConfigSettingAutomations, Value: string(raw)}
}

// rawAutomationsSetting is the stored list holding these elements verbatim, so a test can
// store one that does not decode.
func rawAutomationsSetting(elements ...string) *model.Setting {
	return &model.Setting{Id: ConfigSettingAutomations, Value: "[" + strings.Join(elements, ",") + "]"}
}

func automationJSON(t *testing.T, automation *model.Automation) string {
	t.Helper()

	raw, err := json.Marshal(automation)
	require.NoError(t, err)

	return string(raw)
}

// writtenAutomations decodes a write of the stored list.
func writtenAutomations(t *testing.T, setting *model.Setting) []*model.Automation {
	t.Helper()

	require.Equal(t, ConfigSettingAutomations, setting.Id)

	automations := []*model.Automation{}
	require.NoError(t, json.Unmarshal([]byte(setting.Value), &automations))

	return automations
}

func automationTestStore(mDB *mockdb.MockDB) *database.Store {
	mDB.On("Migrate", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	s, err := database.New(context.Background(), mDB)
	if err != nil {
		panic(err)
	}

	return s
}

// expectEmptyAutomationRunReconcile scripts the reconcile pass Start runs as it builds the
// store: a transaction whose updates match nothing.
func expectEmptyAutomationRunReconcile(mDB *mockdb.MockDB) {
	mTx := &mockdb.MockTx{}
	mRows := &mockdb.MockRows{}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	mTx.On("Query", mock.Anything, mock.Anything).Return(mRows, nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Rollback", mock.Anything).Return(nil)

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
}

// Passes vacuously until a kind ships. It exists to catch the copy-paste registration that
// keys a kind by another kind's name, which nothing else would fail on.
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

	// An agentic grid with no kinds must send [] rather than null so the form can tell
	// "nothing to offer" from "feature absent".
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

	// A task can outlive its kind, and the engine resolves kinds before it has a library
	// in some startup orders, so a nil map must not panic.
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

	// respondConfigWrite matches on the message substring rather than the sentinel, so
	// wrapping must not hide the error key from the status mapping.
	assert.True(t, strings.Contains(err.Error(), "ERROR_AUTOMATION_PARAMS_INVALID"))
}

func TestAutomationRunPlumbing(t *testing.T) {
	srv := &server.Server{}
	task := &model.Automation{
		Auditable:      model.Auditable{Id: "automation-1", UserId: "user-1"},
		AutomationKind: "alert_triage",
		Params:         json.RawMessage(`{"sampleSize":5}`),
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

			// A kind reaches the headless driver through the server it was handed, which
			// is why AutomationRun carries no runner of its own.
			result, err := run.Srv.AssistantManager.RunAgentSession(ctx, &model.AgentSessionRequest{
				Objective: "triage group A",
				Agent:     "Hunter",
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

func TestListAutomationsReadsTheStoredList(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		automationsSetting(t, storedAutomation(automationTestId, "Nightly"), storedAutomation(otherAutomationTestId, "Hourly")),
		// Engine settings live in a sibling object whose name starts the same way.
		{Id: ConfigSettingAutomationTickInterval, Value: "60"},
		{Id: ConfigSettingAlertTriageEpoch, Value: "2026-09-24T00:00:00Z"},
	}

	ac := automationCoordinator(cfg)

	automations, unreadable, err := ac.scanAutomations(context.Background())
	require.NoError(t, err)
	assert.Zero(t, unreadable)
	require.Len(t, automations, 2)
	assert.Equal(t, automationTestId, automations[0].Id)
	assert.Equal(t, "Nightly", automations[0].DisplayName)
	assert.Equal(t, "automation", automations[0].Kind)
	assert.Equal(t, otherAutomationTestId, automations[1].Id)
}

func TestListAutomationsSkipsUnreadableEntries(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{rawAutomationsSetting(
		`"not an automation"`,
		automationJSON(t, storedAutomation(automationTestId, "Good")),
	)}

	ac := automationCoordinator(cfg)

	automations, unreadable, err := ac.scanAutomations(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, unreadable)
	require.Len(t, automations, 1)
	assert.Equal(t, automationTestId, automations[0].Id)
}

// A hand-edited entry can name anything, and everything durable keys on the id, so one that
// no uuid column would accept is skipped rather than handed to the store.
func TestListAutomationsSkipsANonUuidId(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t,
		storedAutomation("nightly", "Hand Edited"),
		storedAutomation("", "No Id"),
		storedAutomation(automationTestId, "Good"),
	)}

	ac := automationCoordinator(cfg)

	automations, unreadable, err := ac.scanAutomations(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, unreadable)
	require.Len(t, automations, 1)
	assert.Equal(t, automationTestId, automations[0].Id)
}

func TestListAutomationsListsARepeatedIdOnce(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t,
		storedAutomation(automationTestId, "First"),
		storedAutomation(automationTestId, "Second"),
	)}

	ac := automationCoordinator(cfg)

	automations, unreadable, err := ac.scanAutomations(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, unreadable, "a repeat is not trusted as a deletion baseline")
	require.Len(t, automations, 1)
	assert.Equal(t, "First", automations[0].DisplayName)
}

func TestListAutomationsTreatsABlankSettingAsEmpty(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{{Id: ConfigSettingAutomations, Value: "  "}}

	automations, unreadable, err := automationCoordinator(cfg).scanAutomations(context.Background())

	require.NoError(t, err)
	assert.Zero(t, unreadable)
	assert.Empty(t, automations)
}

// Every automation is unknown when the list itself cannot be read, so nothing may act on it.
func TestAStoredListThatIsNotAnArrayRefusesEveryPath(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{{Id: ConfigSettingAutomations, Value: `{"not":"a list"}`}}

	ac := automationCoordinator(cfg)

	_, err := ac.ListAutomations(context.Background())
	assert.Error(t, err)

	_, err = ac.GetAutomation(context.Background(), automationTestId)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrAutomationNotFound)

	assert.Error(t, ac.SaveAutomation(automationSaveCtx(), validAutomation()))
	assert.Error(t, ac.DeleteAutomation(context.Background(), automationTestId))
	assert.Empty(t, cfg.updates, "a corrupt list is never overwritten")
}

func TestSaveAutomationAssignsIdAndWritesTheList(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.NotEmpty(t, automation.Id, "the server assigns identity")

	// A read stamps this, so a save has to agree or the two paths hand the UI different shapes.
	assert.Equal(t, "automation", automation.Kind)

	require.Len(t, cfg.updates, 1)
	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 1)
	assert.Equal(t, automation.Id, written[0].Id)
}

func TestSaveAutomationAppendsAndKeepsTheOthers(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{rawAutomationsSetting(
		automationJSON(t, storedAutomation(automationTestId, "Nightly")),
		`"not an automation"`,
	)}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	require.Len(t, cfg.updates, 1)

	stored := []json.RawMessage{}
	require.NoError(t, json.Unmarshal([]byte(cfg.updates[0].Value), &stored))
	require.Len(t, stored, 3)
	assert.Contains(t, string(stored[0]), automationTestId)
	assert.JSONEq(t, `"not an automation"`, string(stored[1]), "an unreadable entry survives someone else's save")
	assert.Contains(t, string(stored[2]), automation.Id)
}

func TestSaveAutomationUpdatesInPlace(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t,
		storedAutomation(automationTestId, "Nightly"),
		storedAutomation(otherAutomationTestId, "Hourly"),
	)}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId
	automation.DisplayName = "Renamed"

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, automationTestId, automation.Id, "an existing id is not reassigned")

	require.Len(t, cfg.updates, 1)
	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 2)
	assert.Equal(t, automationTestId, written[0].Id)
	assert.Equal(t, "Renamed", written[0].DisplayName)
	assert.Equal(t, otherAutomationTestId, written[1].Id)
	assert.Equal(t, "Hourly", written[1].DisplayName)
}

func TestSaveAutomationDropsARepeatOfItsId(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t,
		storedAutomation(automationTestId, "First"),
		storedAutomation(otherAutomationTestId, "Hourly"),
		storedAutomation(automationTestId, "Second"),
	)}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	require.Len(t, cfg.updates, 1)
	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 2)
	assert.Equal(t, automationTestId, written[0].Id)
	assert.Equal(t, "Nightly", written[0].DisplayName)
	assert.Equal(t, otherAutomationTestId, written[1].Id)
}

// The handler puts the path id here, so a body carrying an unknown id is a PUT to something
// that does not exist, not a create at an id of the client's choosing.
func TestSaveAutomationRejectsAnUnknownId(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId

	err := ac.SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrAutomationNotFound)
	assert.Empty(t, cfg.updates)
}

func TestSaveAutomationRejectsANonUuidId(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = "nightly.triage"

	err := ac.SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

func TestSaveAutomationRejectsAnEmptyDisplayName(t *testing.T) {
	cfg := &automationConfigstore{}

	automation := validAutomation()
	automation.DisplayName = "   "

	err := automationCoordinator(cfg).SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

// The cap is on characters an admin typed, so a multi-byte name is measured the same way
// an ASCII one is.
func TestSaveAutomationCapsTheDisplayNameInRunes(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	atCap := validAutomation()
	atCap.DisplayName = strings.Repeat("夜", MaxAutomationDisplayNameLength)

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), atCap))
	assert.Len(t, cfg.updates, 1)

	tooLong := validAutomation()
	tooLong.DisplayName = strings.Repeat("a", MaxAutomationDisplayNameLength+1)

	assert.ErrorIs(t, ac.SaveAutomation(automationSaveCtx(), tooLong), ErrInvalidAutomationParams)
	assert.Len(t, cfg.updates, 1, "nothing more is written")
}

// Zero is what an omitted field decodes to, and the scheduler would treat it as always due.
func TestSaveAutomationRejectsANonPositiveInterval(t *testing.T) {
	cfg := &automationConfigstore{}

	automation := validAutomation()
	automation.IntervalSeconds = 0

	err := automationCoordinator(cfg).SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

func TestSaveAutomationRequiresAnAvailableAgent(t *testing.T) {
	tests := []struct {
		name  string
		agent string
		setup func(ac *AssistantCoordinator)
	}{
		{"blank", " ", nil},
		{"unknown", "Nobody", nil},
		{"disabled", automationTestAgent, func(ac *AssistantCoordinator) {
			ac.agents[automationTestAgent] = model.Agent{Name: automationTestAgent}
		}},
		{"unmapped", automationTestAgent, func(ac *AssistantCoordinator) {
			delete(ac.agentMapping, automationTestAgent)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			ac := automationCoordinator(cfg)

			if tt.setup != nil {
				tt.setup(ac)
			}

			automation := validAutomation()
			automation.Enabled = true
			automation.Agent = tt.agent

			err := ac.SaveAutomation(automationSaveCtx(), automation)

			assert.ErrorIs(t, err, ErrInvalidAutomationParams)
			assert.Empty(t, cfg.updates)
		})
	}
}

func TestSaveAutomationDisabledKeepsALostAgent(t *testing.T) {
	t.Run("create disabled with an unknown agent", func(t *testing.T) {
		cfg := &automationConfigstore{}
		ac := automationCoordinator(cfg)

		automation := validAutomation()
		automation.Agent = "Nobody"

		require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))
		assert.Len(t, cfg.updates, 1)
	})

	t.Run("edit and disable after the agent went away", func(t *testing.T) {
		cfg := &automationConfigstore{}
		cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}
		ac := automationCoordinator(cfg)
		ac.agents[automationTestAgent] = model.Agent{Name: automationTestAgent}

		automation := validAutomation()
		automation.Id = automationTestId
		automation.Params = json.RawMessage(`{"limit":5}`)

		require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))
		assert.Len(t, cfg.updates, 1)
	})

	t.Run("enabling still needs the agent", func(t *testing.T) {
		cfg := &automationConfigstore{}
		cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}
		ac := automationCoordinator(cfg)
		ac.agents[automationTestAgent] = model.Agent{Name: automationTestAgent}

		automation := validAutomation()
		automation.Id = automationTestId
		automation.Enabled = true

		assert.ErrorIs(t, ac.SaveAutomation(automationSaveCtx(), automation), ErrInvalidAutomationParams)
		assert.Empty(t, cfg.updates)
	})
}

func TestSaveAutomationRejectsAKindChange(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)
	ac.AutomationKindLibrary["other_kind"] = &fakeAutomationKind{name: "other_kind"}

	automation := validAutomation()
	automation.Id = automationTestId
	automation.AutomationKind = "other_kind"

	err := ac.SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

func TestSaveAutomationStampsCreatorAndCreateTime(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.UserId = "somebody-else"

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, "user-1", automation.UserId)
	require.NotNil(t, automation.CreateTime)
	require.NotNil(t, automation.UpdateTime)
}

func TestSaveAutomationKeepsTheOriginalCreatorOnUpdate(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId
	automation.UserId = "second-admin"
	automation.DisplayName = "Renamed"

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, "user-1", automation.UserId, "the creator is not reassigned by an edit")
	require.Len(t, cfg.updates, 1)
}

func TestSaveAutomationRequiresARequestor(t *testing.T) {
	cfg := &automationConfigstore{}

	err := automationCoordinator(cfg).SaveAutomation(context.Background(), validAutomation())

	assert.Error(t, err)
	assert.Empty(t, cfg.updates)
}

// The settings system has no pre-save hook, so this is the only place params are checked.
func TestSaveAutomationRejectsParamsTheKindRefuses(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	ac.AutomationKindLibrary["alert_triage"] = &fakeAutomationKind{
		name:        "alert_triage",
		validateErr: ErrInvalidAutomationParams,
	}

	automation := validAutomation()
	automation.Params = json.RawMessage(`{}`)

	err := ac.SaveAutomation(context.Background(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates, "nothing is written when validation fails")
}

func TestSaveAutomationRejectsUnknownKind(t *testing.T) {
	cfg := &automationConfigstore{}

	automation := validAutomation()
	automation.AutomationKind = "nope"

	err := automationCoordinator(cfg).SaveAutomation(context.Background(), automation)

	assert.ErrorIs(t, err, ErrAutomationKindNotFound)
	assert.Empty(t, cfg.updates)
}

// Delete must not be blocked by the run, and must leave it whatever it has already claimed.
func TestDeleteAutomationProceedsWhileARunIsInFlight(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	expectSweep(mDB, ErrAutomationDeleted, 1)

	cancelled := false
	release := ac.registerAutomationRun(automationTestId, func(error) { cancelled = true })
	defer release()

	require.NoError(t, ac.DeleteAutomation(context.Background(), automationTestId))

	require.Len(t, cfg.updates, 1)
	assert.Empty(t, writtenAutomations(t, cfg.updates[0]))
	assert.False(t, cancelled, "an in-flight run is often the reason for the delete")
	mDB.AssertExpectations(t)
}

// Work nothing will ever claim, because the automation that would have claimed it is gone.
func TestDeleteAutomationDropsPendingWork(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	expectSweep(mDB, ErrAutomationDeleted, 2)

	require.NoError(t, ac.DeleteAutomation(context.Background(), automationTestId))

	mDB.AssertExpectations(t)
}

// The removal lands first, so work the failed sweep left behind is orphaned rather than
// stranded: the next Start reaches it, because the automation is gone.
func TestDeleteAutomationReportsASweepFailureAfterRemoving(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return((*mockdb.MockRows)(nil), errors.New("postgres is down"))

	assert.Error(t, ac.DeleteAutomation(context.Background(), automationTestId))
	require.Len(t, cfg.updates, 1)
	assert.Empty(t, writtenAutomations(t, cfg.updates[0]))
}

func TestDeleteAutomationRemovesOnlyItsId(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{rawAutomationsSetting(
		automationJSON(t, storedAutomation(otherAutomationTestId, "Hourly")),
		automationJSON(t, storedAutomation(automationTestId, "Nightly")),
		`"not an automation"`,
	)}

	ac := automationCoordinator(cfg)

	require.NoError(t, ac.DeleteAutomation(context.Background(), automationTestId))

	require.Len(t, cfg.updates, 1)

	stored := []json.RawMessage{}
	require.NoError(t, json.Unmarshal([]byte(cfg.updates[0].Value), &stored))
	require.Len(t, stored, 2)
	assert.Contains(t, string(stored[0]), otherAutomationTestId)
	assert.JSONEq(t, `"not an automation"`, string(stored[1]))
}

// The permission check comes before the existence probe, so an unauthorized requestor cannot
// tell a stored id from one that was never there.
func TestDeleteAutomationRefusesAnUnknownIdWithoutRevealingIt(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinatorAs(cfg, false)

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, ac.DeleteAutomation(context.Background(), otherAutomationTestId), &unauthorized)
}

// Neither the removal nor the sweep can be undone, so a requestor the removal would reject
// must not reach either.
func TestDeleteAutomationRefusesBeforeSweepingWhenConfigWriteIsDenied(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinatorAs(cfg, false)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, ac.DeleteAutomation(context.Background(), automationTestId), &unauthorized)
	assert.Empty(t, cfg.updates)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "a denied delete must not touch work items")
	}
}

func TestOnConfigSettingUpdatedHandlesAutomationSettings(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	ac.isAgentic = true
	ac.agents = map[string]model.Agent{"Hunter": {}}

	ac.OnConfigSettingUpdated(context.Background(), &model.Setting{Id: ConfigSettingAutomations}, false)

	assert.True(t, ac.automationsDirty.Load())
	assert.Len(t, ac.agents, 1, "an automation change must not rebuild the agent library")
}

func TestRegisterConfigCallbacksWatchesTheAutomations(t *testing.T) {
	cfg := &automationConfigstore{}

	automationCoordinator(cfg).registerConfigCallbacks()

	assert.Contains(t, cfg.registered, ConfigSettingAutomations)
}

func TestAutomationPathsRequireAConfigstore(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}

	_, listErr := ac.ListAutomations(context.Background())
	_, getErr := ac.GetAutomation(context.Background(), "id")
	saveErr := ac.SaveAutomation(context.Background(), &model.Automation{})
	deleteErr := ac.DeleteAutomation(context.Background(), "id")

	for _, err := range []error{listErr, getErr, saveErr, deleteErr} {
		assert.ErrorIs(t, err, ErrConfigstoreUnavailable)
	}
}

// configReadRefusingConfigstore refuses the config/read-checked reads, as the real one does for an analyst.
type configReadRefusingConfigstore struct {
	automationConfigstore
}

func (c *configReadRefusingConfigstore) GetSettings(ctx context.Context, includeDefault bool) ([]*model.Setting, error) {
	return nil, model.NewUnauthorized("analyst-1", "read", "config")
}

func (c *configReadRefusingConfigstore) GetSetting(ctx context.Context, id string) (*model.Setting, error) {
	return nil, model.NewUnauthorized("analyst-1", "read", "config")
}

// Analysts hold automations/read but not config/read.
func TestListAndGetAutomationNeedOnlyAutomationsRead(t *testing.T) {
	cfg := &configReadRefusingConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(&cfg.automationConfigstore)
	ac.srv.Configstore = cfg

	analyst := context.WithValue(context.Background(), web.ContextKeyRequestorId, "analyst-1")

	automations, err := ac.ListAutomations(analyst)
	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, "Nightly", automations[0].DisplayName)

	automation, err := ac.GetAutomation(analyst, automationTestId)
	require.NoError(t, err)
	assert.Equal(t, "Nightly", automation.DisplayName)
}

// unreadyConfigstore waits on its context like the real one before its first load.
type unreadyConfigstore struct {
	automationConfigstore
}

func (u *unreadyConfigstore) LookupSetting(ctx context.Context, id string) (*model.Setting, error) {
	<-ctx.Done()

	return nil, ctx.Err()
}

// A read that never saw the request's cancellation would deadlock the bubble.
func TestListAndGetAutomationStopWithTheRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ac := automationCoordinator(&automationConfigstore{})
		ac.srv.Configstore = &unreadyConfigstore{}

		ctx, cancel := context.WithCancel(automationSaveCtx())
		cancel()

		_, listErr := ac.ListAutomations(ctx)
		_, getErr := ac.GetAutomation(ctx, automationTestId)

		assert.ErrorIs(t, listErr, context.Canceled)
		assert.ErrorIs(t, getErr, context.Canceled)
	})
}

func TestListAndGetAutomationRequireAutomationsRead(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinatorAs(cfg, false)

	_, listErr := ac.ListAutomations(automationSaveCtx())
	_, getErr := ac.GetAutomation(automationSaveCtx(), automationTestId)

	for _, err := range []error{listErr, getErr} {
		var unauthorized *model.Unauthorized
		require.ErrorAs(t, err, &unauthorized)
		assert.Equal(t, "read", unauthorized.Operation)
		assert.Equal(t, "automations", unauthorized.Target)
	}
}

func TestReconcileAutomationRunsLogsRatherThanFailing(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Begin", mock.Anything).Return((*mockdb.MockTx)(nil), errors.New("postgres is down"))

	ac := &AssistantCoordinator{store: automationTestStore(mDB)}

	// A stuck run strands one automation; it must not stop the assistant starting.
	assert.NotPanics(t, func() { ac.reconcileAutomationRuns(context.Background()) })

	mDB.AssertExpectations(t)
}

// The concrete store must satisfy the interface kinds are handed. Asserted here so the
// production build of this package never imports the database package just to prove it.
var _ AutomationStore = (*database.Store)(nil)

// storedAutomationWithParams seeds an automation whose params a save can then change.
func storedAutomationWithParams(id, params string) *model.Automation {
	automation := storedAutomation(id, "Nightly")
	automation.Params = json.RawMessage(params)

	return automation
}

// sqlLike matches a statement carrying every fragment.
func sqlLike(subs ...string) any {
	return mock.MatchedBy(func(sql string) bool {
		for _, sub := range subs {
			if !strings.Contains(sql, sub) {
				return false
			}
		}

		return true
	})
}

// rowsYielding returns a Rows that reports n changed rows, which is how the sweeps count
// what they failed.
func rowsYielding(n int) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}

	for i := 0; i < n; i++ {
		mRows.On("Next").Return(true).Once()
	}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

// expectSweep scripts a work item sweep carrying cause and reports how many rows it claims
// to have failed.
func expectSweep(mDB *mockdb.MockDB, cause error, failed int) *mock.Call {
	mRows := rowsYielding(failed)

	return mDB.On("Query", mock.Anything, sqlLike("UPDATE automation_work_items", "state = 'failed'"),
		automationTestId, cause.Error()).Return(mRows, nil)
}

// paramsChangeCoordinator seeds one stored automation and a store whose sweep is scripted.
func paramsChangeCoordinator(t *testing.T, storedParams string) (*AssistantCoordinator, *automationConfigstore, *mockdb.MockDB) {
	t.Helper()

	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomationWithParams(automationTestId, storedParams))}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	return ac, cfg, mDB
}

func automationWithParams(params string) *model.Automation {
	automation := validAutomation()
	automation.Id = automationTestId
	automation.Params = json.RawMessage(params)

	return automation
}

// Nothing is discarded until the new definition is durable, and the run has to stop before
// the sweep, or it claims an item the sweep is about to fail.
func TestSaveAutomationWritesBeforeInterruptingAndSweeping(t *testing.T) {
	ac, cfg, mDB := paramsChangeCoordinator(t, `{"limit":10}`)

	var order []string

	cfg.onUpdate = func() { order = append(order, "write") }
	expectSweep(mDB, ErrAutomationParamsChanged, 2).Run(func(mock.Arguments) { order = append(order, "sweep") })

	release := ac.registerAutomationRun(automationTestId, func(cause error) {
		order = append(order, "cancel")
		assert.ErrorIs(t, cause, ErrAutomationParamsChanged)
	})
	defer release()

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`)))

	assert.Equal(t, []string{"write", "cancel", "sweep"}, order)
}

func TestSaveAutomationSweepsWithNoRunRegistered(t *testing.T) {
	ac, cfg, mDB := paramsChangeCoordinator(t, `{"limit":10}`)

	expectSweep(mDB, ErrAutomationParamsChanged, 1)

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`)))

	assert.Len(t, cfg.updates, 1)
	mDB.AssertExpectations(t)
}

// The params are raw JSON, so a byte comparison would drop the queue on a reformat.
func TestSaveAutomationKeepsWorkWhenParamsAreOnlyReformatted(t *testing.T) {
	ac, cfg, mDB := paramsChangeCoordinator(t, `{"a":1,"b":[1,2]}`)

	cancelled := false
	release := ac.registerAutomationRun(automationTestId, func(error) { cancelled = true })
	defer release()

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(),
		automationWithParams(` { "b": [1, 2], "a": 1 } `)))

	assert.False(t, cancelled)
	assert.Len(t, cfg.updates, 1)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "unchanged params must not touch work items")
	}
}

func TestSaveAutomationSweepsNothingOnCreate(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	automation := validAutomation()
	automation.Params = json.RawMessage(`{"limit":10}`)

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "a create has no earlier work to drop")
	}
}

// Postgres is optional, and an automation must still be editable without it.
func TestSaveAutomationSurvivesWithoutAStore(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomationWithParams(automationTestId, `{"limit":10}`))}

	ac := automationCoordinator(cfg)

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`)))
	assert.Len(t, cfg.updates, 1)
}

// The write lands first, so the save stands and the caller is told only that the cleanup
// behind it did not finish.
func TestSaveAutomationReportsASweepFailureAfterWriting(t *testing.T) {
	ac, cfg, mDB := paramsChangeCoordinator(t, `{"limit":10}`)

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return((*mockdb.MockRows)(nil), errors.New("postgres is down"))

	err := ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`))

	assert.Error(t, err)
	assert.Len(t, cfg.updates, 1, "the new definition is durable even when its sweep fails")
}

func TestSaveAutomationRefusesBeforeSweepingWhenConfigWriteIsDenied(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomationWithParams(automationTestId, `{"limit":10}`))}

	ac := automationCoordinatorAs(cfg, false)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	err := ac.SaveAutomation(automationSaveCtx(), automationWithParams(`{"limit":25}`))

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, err, &unauthorized)
	assert.Empty(t, cfg.updates)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "a denied save must not touch work items")
	}
}

func TestReleasingAnAutomationRunStopsItBeingInterrupted(t *testing.T) {
	ac := &AssistantCoordinator{}

	cancelled := false
	release := ac.registerAutomationRun(automationTestId, func(error) { cancelled = true })
	release()

	ac.interruptAutomationRun(automationTestId)
	ac.interruptAutomationRun(otherAutomationTestId)

	assert.False(t, cancelled)
}

func TestDeleteAutomationRejectsAnUnknownId(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	assert.ErrorIs(t, ac.DeleteAutomation(context.Background(), automationTestId), ErrAutomationNotFound)
	assert.Empty(t, cfg.updates)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "an id that was never stored must not touch work items")
	}
}

// expectOrphanSweep scripts the startup sweep and reports the live ids it was given.
func expectOrphanSweep(mDB *mockdb.MockDB, failed int) *[]string {
	live := &[]string{}

	mDB.On("Query", mock.Anything, sqlLike("NOT (automation_id = ANY($1::uuid[]))"), mock.Anything, ErrAutomationDeleted.Error()).
		Run(func(args mock.Arguments) {
			ids, _ := args.Get(2).([]string)
			*live = ids
		}).
		Return(rowsYielding(failed), nil)

	return live
}

func TestSweepOrphanedAutomationWorkDropsOrphanedWork(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	live := expectOrphanSweep(mDB, 3)

	ac.sweepOrphanedAutomationWork(context.Background())

	assert.Equal(t, []string{automationTestId}, *live, "a stored automation's work is not orphaned")
	mDB.AssertExpectations(t)
}

// Deleting the last automation is the likeliest way to strand work, so an empty grid still
// sweeps rather than treating "nothing live" as "nothing to do".
func TestSweepOrphanedAutomationWorkSweepsWhenNoAutomationIsDefined(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	live := expectOrphanSweep(mDB, 1)

	ac.sweepOrphanedAutomationWork(context.Background())

	assert.Empty(t, *live)
	mDB.AssertExpectations(t)
}

// An unreadable automation is indistinguishable from a deleted one, so the sweep would drop
// a live automation's queue.
func TestSweepOrphanedAutomationWorkSkipsTheSweepWhenAnAutomationIsUnreadable(t *testing.T) {
	for name, setting := range map[string]*model.Setting{
		"one entry": rawAutomationsSetting(automationJSON(t, storedAutomation(automationTestId, "Nightly")), `"not an automation"`),
		"the list":  {Id: ConfigSettingAutomations, Value: "{not json"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			cfg.settings = []*model.Setting{setting}

			ac := automationCoordinator(cfg)

			mDB := &mockdb.MockDB{}
			ac.store = automationTestStore(mDB)

			ac.sweepOrphanedAutomationWork(context.Background())

			for _, call := range mDB.Calls {
				assert.Equal(t, "Migrate", call.Method, "partial knowledge must not drop work")
			}
		})
	}
}

// Without Postgres there are no work items to sweep.
func TestSweepOrphanedAutomationWorkSurvivesWithoutAStore(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	assert.NotPanics(t, func() { ac.sweepOrphanedAutomationWork(context.Background()) })
}

// seedBuiltinAutomation gives a bare coordinator the shipped automations, as Init would.
func seedBuiltinAutomation(ac *AssistantCoordinator) *model.Automation {
	ac.setupBuiltinAutomations()

	return ac.builtinAutomations[BuiltinAlertTriageAutomationId]
}

// storedBuiltinAutomation is a stored copy of the builtin with every fixed field altered, so a
// test can tell what the overlay kept from what it restored.
func storedBuiltinAutomation(enabled bool, agent string) *model.Automation {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	return &model.Automation{
		Auditable:       model.Auditable{Id: BuiltinAlertTriageAutomationId, UserId: "user-1", CreateTime: &created},
		DisplayName:     "Renamed",
		AutomationKind:  "other_kind",
		Agent:           agent,
		Enabled:         enabled,
		IntervalSeconds: 7,
		Params:          json.RawMessage(`{"groupBy":["x"]}`),
	}
}

func assertBuiltinFixedFields(t *testing.T, builtin, automation *model.Automation) {
	t.Helper()

	assert.Equal(t, BuiltinAlertTriageAutomationId, automation.Id)
	assert.Equal(t, "automation", automation.Kind)
	assert.True(t, automation.IsSystem)
	assert.Equal(t, builtin.DisplayName, automation.DisplayName)
	assert.Equal(t, builtin.AutomationKind, automation.AutomationKind)
	assert.Equal(t, builtin.IntervalSeconds, automation.IntervalSeconds)
	assert.JSONEq(t, string(builtin.Params), string(automation.Params))
}

func TestListAutomationsIncludesTheBuiltinAsShipped(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automations, unreadable, err := ac.scanAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Zero(t, unreadable)

	assertBuiltinFixedFields(t, builtin, automations[0])
	assert.False(t, automations[0].Enabled, "shipped disabled")
	assert.Equal(t, builtin.Agent, automations[0].Agent)
	assert.Nil(t, automations[0].CreateTime)
	assert.Empty(t, automations[0].UserId)
}

func TestListAutomationsOverlaysOnlyWhatAStoredBuiltinMayChange(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t,
		storedAutomation(automationTestId, "Nightly"),
		storedBuiltinAutomation(true, "Hunter"),
	)}

	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automations, err := ac.ListAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 2, "a stored builtin is not listed twice")

	assert.Equal(t, automationTestId, automations[0].Id)
	assert.False(t, automations[0].IsSystem)

	assertBuiltinFixedFields(t, builtin, automations[1])
	assert.True(t, automations[1].Enabled)
	assert.Equal(t, "Hunter", automations[1].Agent)
	assert.Equal(t, "user-1", automations[1].UserId)
	require.NotNil(t, automations[1].CreateTime)
	assert.Equal(t, 2026, automations[1].CreateTime.Year())
}

// A malformed stored copy still counts as unreadable, which holds the orphan sweep; the
// builtin itself is listed as shipped rather than lost.
func TestListAutomationsRestoresAnUnreadableBuiltin(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		rawAutomationsSetting(`{"id":"` + BuiltinAlertTriageAutomationId + `","intervalSeconds":"not a number"}`),
	}

	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automations, unreadable, err := ac.scanAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, 1, unreadable)

	assertBuiltinFixedFields(t, builtin, automations[0])
	assert.False(t, automations[0].Enabled)
}

// The flag is what a UI locks fields and hides delete on, so a hand-edited entry cannot claim it.
func TestUnmarshalAutomationIgnoresAStoredIsSystem(t *testing.T) {
	automation, err := unmarshalAutomation(json.RawMessage(
		`{"id":"` + automationTestId + `","displayName":"Nightly","automationKind":"alert_triage","isSystem":true}`))

	require.NoError(t, err)
	assert.False(t, automation.IsSystem)
}

func TestGetAutomationReturnsTheBuiltinAsShippedWithoutAStoredCopy(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automation, err := ac.GetAutomation(context.Background(), BuiltinAlertTriageAutomationId)
	require.NoError(t, err)

	assertBuiltinFixedFields(t, builtin, automation)
	assert.False(t, automation.Enabled)

	// The copy handed out must not alias the definition.
	automation.Params[0] = ' '
	assert.JSONEq(t, string(builtin.Params), string(ac.builtinAutomations[BuiltinAlertTriageAutomationId].Params))
}

func TestGetAutomationOverlaysAStoredBuiltin(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedBuiltinAutomation(true, "Hunter"))}

	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automation, err := ac.GetAutomation(context.Background(), BuiltinAlertTriageAutomationId)
	require.NoError(t, err)

	assertBuiltinFixedFields(t, builtin, automation)
	assert.True(t, automation.Enabled)
	assert.Equal(t, "Hunter", automation.Agent)
	assert.Equal(t, "user-1", automation.UserId)
}

func TestGetAutomationFallsBackToTheShippedAgentWhenTheStoredOneIsBlank(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedBuiltinAutomation(true, " "))}

	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automation, err := ac.GetAutomation(context.Background(), BuiltinAlertTriageAutomationId)
	require.NoError(t, err)

	assert.True(t, automation.Enabled)
	assert.Equal(t, builtin.Agent, automation.Agent)
}

func TestGetAutomationStillRequiresAConfigstoreForTheBuiltin(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}
	seedBuiltinAutomation(ac)

	_, err := ac.GetAutomation(context.Background(), BuiltinAlertTriageAutomationId)

	assert.ErrorIs(t, err, ErrConfigstoreUnavailable)
}

// The first save is the create: it records the creator, under the fixed id rather than a
// generated one.
func TestSaveAutomationCreatesTheBuiltinUnderItsFixedId(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	automation := &model.Automation{
		Auditable:       model.Auditable{Id: BuiltinAlertTriageAutomationId},
		IsSystem:        true,
		DisplayName:     "Renamed",
		AutomationKind:  "other_kind",
		Agent:           automationTestAgent,
		Enabled:         true,
		IntervalSeconds: 7,
		Params:          json.RawMessage(`{"groupBy":["x"]}`),
	}

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	// The caller's value is what the handler answers with.
	assertBuiltinFixedFields(t, builtin, automation)
	assert.True(t, automation.Enabled)
	assert.Equal(t, automationTestAgent, automation.Agent)
	assert.Equal(t, "user-1", automation.UserId)
	assert.NotNil(t, automation.CreateTime)

	require.Len(t, cfg.updates, 1)
	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 1)

	// The stored copy is complete, so a build without the overlay still reads a valid automation.
	stored := written[0]
	assert.Equal(t, BuiltinAlertTriageAutomationId, stored.Id)
	assert.Equal(t, builtin.DisplayName, stored.DisplayName)
	assert.Equal(t, builtin.IntervalSeconds, stored.IntervalSeconds)
	assert.JSONEq(t, string(builtin.Params), string(stored.Params))
	assert.True(t, stored.Enabled)
}

// The creator is settled by the builtin's first save; no later edit, enabling included, moves it.
func TestSaveAutomationBuiltinCreatorIsSettledAtFirstSave(t *testing.T) {
	cases := []struct {
		name          string
		storedEnabled bool
		enabled       bool
		agent         string
		wantCreator   string
	}{
		{"enabling keeps the creator", false, true, automationTestAgent, "user-1"},
		{"an edit while enabled keeps the creator", true, true, automationTestAgent, "user-1"},
		{"disabling keeps the creator", true, false, "Hunter", "user-1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			cfg.settings = []*model.Setting{automationsSetting(t, storedBuiltinAutomation(c.storedEnabled, "Hunter"))}

			ac := automationCoordinator(cfg)
			seedBuiltinAutomation(ac)

			automation := &model.Automation{
				Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId},
				IsSystem:  true,
				Enabled:   c.enabled,
				Agent:     c.agent,
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-2")
			require.NoError(t, ac.SaveAutomation(ctx, automation))

			assert.Equal(t, c.wantCreator, automation.UserId)
			require.NotNil(t, automation.CreateTime)
			assert.Equal(t, 2026, automation.CreateTime.Year(), "the create time never moves")
			assert.Equal(t, c.agent, automation.Agent)
			assert.Equal(t, c.enabled, automation.Enabled)
			require.Len(t, cfg.updates, 1)
		})
	}
}

func TestSaveAutomationEnablingAStoredAutomationKeepsItsCreator(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId
	automation.Enabled = true

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-2")
	require.NoError(t, ac.SaveAutomation(ctx, automation))

	assert.Equal(t, "user-1", automation.UserId)
}

// A first save that leaves the builtin disabled still records its creator.
func TestSaveAutomationFirstSaveOfADisabledBuiltinSettlesItsCreator(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	automation := &model.Automation{Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId}, IsSystem: true}
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.False(t, automation.Enabled)
	assert.Equal(t, "user-1", automation.UserId)
	assert.NotNil(t, automation.CreateTime)

	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 1)
	assert.Equal(t, "user-1", written[0].UserId)
}

// Enabling with nothing but the flag is a complete definition: what the tick and the kind read
// comes from the shipped builtin and the stamp.
func TestSaveAutomationEnablingTheBuiltinWithAMinimalBodyIsRunnable(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	builtin := seedBuiltinAutomation(ac)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-2")
	require.NoError(t, ac.SaveAutomation(ctx, &model.Automation{
		Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId},
		IsSystem:  true,
		Enabled:   true,
	}))
	cfg.settings = []*model.Setting{cfg.updates[0]}

	automations, err := ac.ListAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 1)

	automation := automations[0]
	assertBuiltinFixedFields(t, builtin, automation)
	assert.True(t, automation.Enabled)
	assert.Equal(t, "user-2", automation.UserId)
	assert.Equal(t, builtin.Agent, automation.Agent)
	assert.NotNil(t, automation.CreateTime)
	assert.True(t, automationDue(automation, nil, time.Now()))

	_, _, err = ac.resolveAgent(automation.Agent)
	require.NoError(t, err)
}

func TestSaveAutomationRejectsAnIsSystemThatDisagreesWithTheId(t *testing.T) {
	cases := []struct {
		name       string
		automation *model.Automation
	}{
		{"a create claiming to be system", func() *model.Automation {
			a := validAutomation()
			a.IsSystem = true

			return a
		}()},
		{"a custom automation claiming to be system", func() *model.Automation {
			a := validAutomation()
			a.Id = automationTestId
			a.IsSystem = true

			return a
		}()},
		{"the builtin denying it", &model.Automation{
			Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId},
			Enabled:   true,
			Agent:     automationTestAgent,
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			cfg.settings = []*model.Setting{automationsSetting(t, storedAutomation(automationTestId, "Nightly"))}

			ac := automationCoordinator(cfg)
			seedBuiltinAutomation(ac)

			err := ac.SaveAutomation(automationSaveCtx(), c.automation)

			assert.ErrorIs(t, err, ErrInvalidAutomationParams)
			assert.ErrorContains(t, err, "isSystem")
			assert.Empty(t, cfg.updates)
		})
	}
}

func TestSaveAutomationRequiresAnAvailableAgentForTheBuiltin(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	automation := &model.Automation{
		Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId},
		IsSystem:  true,
		Enabled:   true,
		Agent:     "Nobody",
	}

	assert.ErrorIs(t, ac.SaveAutomation(automationSaveCtx(), automation), ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

// The tick already runs the shipped params, so the open work was derived from them even when
// the stored copy predates a build that changed them.
func TestSaveAutomationKeepsTheBuiltinWorkWhenItsParamsChangedBetweenBuilds(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedBuiltinAutomation(true, automationTestAgent))}

	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	cancelled := false
	release := ac.registerAutomationRun(BuiltinAlertTriageAutomationId, func(error) { cancelled = true })
	defer release()

	automation := &model.Automation{
		Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId},
		IsSystem:  true,
		Enabled:   true,
		Agent:     automationTestAgent,
	}

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.False(t, cancelled)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "a builtin save must not touch work items")
	}

	// The stored copy catches up to the shipped params.
	written := writtenAutomations(t, cfg.updates[0])
	require.Len(t, written, 1)
	assert.JSONEq(t, string(ac.builtinAutomations[BuiltinAlertTriageAutomationId].Params), string(written[0].Params))
}

func TestSaveAutomationKeepsTheBuiltinWorkWhenOnlyEnabledChanges(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	// A stored copy written by this build carries the fixed params.
	first := &model.Automation{Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId}, IsSystem: true, Agent: automationTestAgent}
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), first))
	cfg.settings = []*model.Setting{cfg.updates[0]}

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	cancelled := false
	release := ac.registerAutomationRun(BuiltinAlertTriageAutomationId, func(error) { cancelled = true })
	defer release()

	second := &model.Automation{Auditable: model.Auditable{Id: BuiltinAlertTriageAutomationId}, IsSystem: true, Enabled: true, Agent: automationTestAgent}
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), second))

	assert.False(t, cancelled)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "unchanged params must not touch work items")
	}
}

func TestDeleteAutomationRefusesTheBuiltin(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, storedBuiltinAutomation(true, automationTestAgent))}

	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	assert.ErrorIs(t, ac.DeleteAutomation(context.Background(), BuiltinAlertTriageAutomationId), ErrSystemAutomationUndeletable)
	assert.Empty(t, cfg.updates)

	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "a refused delete must not touch work items")
	}
}

func TestDeleteAutomationChecksAuthorizationBeforeRefusingTheBuiltin(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinatorAs(cfg, false)
	seedBuiltinAutomation(ac)

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, ac.DeleteAutomation(context.Background(), BuiltinAlertTriageAutomationId), &unauthorized)
}

// The builtin is live from the first start, so its queue is never orphaned.
func TestSweepOrphanedAutomationWorkKeepsTheBuiltinBeforeItsFirstSave(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	seedBuiltinAutomation(ac)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	live := expectOrphanSweep(mDB, 0)

	ac.sweepOrphanedAutomationWork(context.Background())

	assert.Equal(t, []string{BuiltinAlertTriageAutomationId}, *live)
	mDB.AssertExpectations(t)
}
