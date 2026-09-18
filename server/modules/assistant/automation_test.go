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
	"os"
	"strings"
	"testing"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
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

// automationConfigstore records whole settings rather than just values, so a test can assert
// on DuplicatedFromID, and counts callback registrations.
type automationConfigstore struct {
	fakeConfigstore

	updates    []*model.Setting
	removals   []string
	updateErr  error
	registered []string
}

func (f *automationConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	if f.updateErr != nil {
		return f.updateErr
	}

	if remove {
		f.removals = append(f.removals, setting.Id)
	} else {
		f.updates = append(f.updates, setting)
	}

	return nil
}

func (f *automationConfigstore) RegisterConfigSettingCallback(settingID string, handler server.ConfigSettingCallbackHandler) {
	f.registered = append(f.registered, settingID)
}

var _ server.ConfigSettingCallbackRegistrar = (*automationConfigstore)(nil)

func automationCoordinator(cfg *automationConfigstore) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{Context: context.Background(), Configstore: cfg},
		AutomationKindLibrary: map[string]AutomationKind{
			"alert_triage": &fakeAutomationKind{name: "alert_triage"},
		},
	}
}

// Identity is a UUID, so a save that is meant to succeed has to use one.
const (
	automationTestId      = "5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"
	otherAutomationTestId = "1d7e3a44-88b6-4c0f-9a21-70f5e9c3b812"
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
		IntervalSeconds: 300,
	}
}

func storedAutomation(t *testing.T, id, displayName string) *model.Setting {
	t.Helper()

	raw, err := json.Marshal(&model.Automation{
		Auditable:       model.Auditable{Id: id, UserId: "user-1"},
		DisplayName:     displayName,
		AutomationKind:  "alert_triage",
		IntervalSeconds: 300,
	})
	require.NoError(t, err)

	return &model.Setting{Id: automationSettingId(id), Value: string(raw)}
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
				OwnerId:   run.Task.UserId,
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
	assert.Equal(t, "user-1", gotReq.OwnerId)
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

func TestListAutomationsFiltersByPrefix(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		storedAutomation(t, automationTestId, "Nightly"),
		// The template is an annotation anchor, not an automation.
		{Id: ConfigSettingAutomationTemplate, Value: ""},
		// A neighbouring setting that merely shares the module prefix.
		{Id: ConfigSettingAgents, Value: `{"name":"Hunter"}`},
	}

	ac := automationCoordinator(cfg)

	automations, err := ac.ListAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, automationTestId, automations[0].Id)
	assert.Equal(t, "Nightly", automations[0].DisplayName)
}

func TestListAutomationsSkipsUnreadableEntries(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		{Id: automationSettingId(otherAutomationTestId), Value: "{not json"},
		storedAutomation(t, automationTestId, "Good"),
	}

	automations, err := automationCoordinator(cfg).ListAutomations(context.Background())

	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, automationTestId, automations[0].Id)
}

// A hand-edited pillar entry can name anything, and everything durable keys on the id, so
// one that no uuid column would accept is skipped rather than handed to the store.
func TestListAutomationsSkipsANonUuidId(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		storedAutomation(t, "nightly", "Hand Edited"),
		storedAutomation(t, automationTestId, "Good"),
	}

	automations, err := automationCoordinator(cfg).ListAutomations(context.Background())

	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, automationTestId, automations[0].Id)
}

func TestUnmarshalAutomationPrefersTheSettingId(t *testing.T) {
	automation, err := unmarshalAutomation(
		automationSettingId(automationTestId),
		`{"id":"`+otherAutomationTestId+`","displayName":"Nightly","automationKind":"alert_triage"}`)

	require.NoError(t, err)
	assert.Equal(t, automationTestId, automation.Id)
}

func TestSaveAutomationAssignsIdAndDuplicatesTemplate(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.NotEmpty(t, automation.Id, "the server assigns identity")
	require.Len(t, cfg.updates, 1)
	assert.Equal(t, automationSettingId(automation.Id), cfg.updates[0].Id)

	// Without this the setting resolves no definition, loses its forced type, and the
	// value is expanded into a nested YAML mapping.
	assert.Equal(t, ConfigSettingAutomationTemplate, cfg.updates[0].DuplicatedFromID)
}

// The metadata is resolved on every write, not remembered from the first one.
func TestSaveAutomationKeepsDuplicatedFromIdOnUpdate(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	require.Len(t, cfg.updates, 1)
	assert.Equal(t, automationTestId, automation.Id, "an existing id is not reassigned")
	assert.Equal(t, ConfigSettingAutomationTemplate, cfg.updates[0].DuplicatedFromID)
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

func TestSaveAutomationRejectsAKindChange(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{storedAutomation(t, automationTestId, "Nightly")}

	ac := automationCoordinator(cfg)
	ac.AutomationKindLibrary["other_kind"] = &fakeAutomationKind{name: "other_kind"}

	automation := validAutomation()
	automation.Id = automationTestId
	automation.AutomationKind = "other_kind"

	err := ac.SaveAutomation(automationSaveCtx(), automation)

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates)
}

func TestSaveAutomationStampsOwnerAndCreateTime(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.UserId = "somebody-else"

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, "user-1", automation.UserId)
	require.NotNil(t, automation.CreateTime)
	require.NotNil(t, automation.UpdateTime)
}

func TestSaveAutomationKeepsTheOriginalOwnerOnUpdate(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{storedAutomation(t, automationTestId, "Nightly")}

	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId
	automation.UserId = "second-admin"
	automation.DisplayName = "Renamed"

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, "user-1", automation.UserId, "the owner is not reassigned by an edit")
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

func TestSaveAutomationRegistersEachSettingOnce(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := validAutomation()
	automation.Id = automationTestId

	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))
	require.NoError(t, ac.SaveAutomation(automationSaveCtx(), automation))

	assert.Equal(t, []string{automationSettingId(automationTestId)}, cfg.registered)
}

// Delete must not be blocked by the run
func TestDeleteAutomationProceedsWhileARunIsInFlight(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)

	require.NoError(t, ac.DeleteAutomation(context.Background(), automationTestId))

	assert.Equal(t, []string{automationSettingId(automationTestId)}, cfg.removals)

	// AssertNotCalled with no argument matchers never matches a recorded call, so the
	// methods are checked directly. Migrate is the store's own construction.
	for _, call := range mDB.Calls {
		assert.Equal(t, "Migrate", call.Method, "delete must not touch run state")
	}
}

func TestDeleteAutomationTreatsMissingPillarAsAlreadyGone(t *testing.T) {
	cfg := &automationConfigstore{updateErr: os.ErrNotExist}
	ac := automationCoordinator(cfg)

	assert.NoError(t, ac.DeleteAutomation(context.Background(), automationTestId))
}

// automationSettingId("template") is the template setting itself, so an unguarded delete
// removes the annotation anchor every automation inherits its forced type from.
func TestDeleteAutomationRefusesTheTemplate(t *testing.T) {
	cfg := &automationConfigstore{}

	err := automationCoordinator(cfg).DeleteAutomation(context.Background(), "template")

	assert.ErrorIs(t, err, ErrAutomationNotFound)
	assert.Empty(t, cfg.removals)
}

func TestGetAutomationRefusesTheTemplate(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{{Id: ConfigSettingAutomationTemplate, Value: ""}}

	_, err := automationCoordinator(cfg).GetAutomation(context.Background(), "template")

	assert.ErrorIs(t, err, ErrAutomationNotFound)
}

// Automation setting ids are generated, so the switch in OnConfigSettingUpdated cannot name
// them; without its own branch an automation change falls through to the agent reload.
func TestOnConfigSettingUpdatedHandlesAutomationSettings(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	ac.isAgentic = true
	ac.agents = map[string]model.Agent{"Hunter": {}}

	ac.OnConfigSettingUpdated(context.Background(),
		&model.Setting{Id: automationSettingId(automationTestId)}, false)

	assert.Len(t, ac.agents, 1, "an automation change must not rebuild the agent library")
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
