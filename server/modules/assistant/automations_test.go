// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// automationConfigstore records whole settings rather than just values, so a test can
// assert on DuplicatedFromID, and counts callback registrations.
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

func TestListAutomationsFiltersByPrefix(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		storedAutomation(t, "5c0b1f2e", "Nightly"),
		// The template is an annotation anchor, not an automation.
		{Id: ConfigSettingAutomationTemplate, Value: ""},
		// A neighbouring setting that merely shares the module prefix.
		{Id: ConfigSettingAgents, Value: `{"name":"Hunter"}`},
	}

	ac := automationCoordinator(cfg)

	automations, err := ac.ListAutomations(context.Background())
	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, "5c0b1f2e", automations[0].Id)
	assert.Equal(t, "Nightly", automations[0].DisplayName)
}

// A malformed automation is reachable any time an admin edits the raw setting, and it must
// not take the readable ones down with it.
func TestListAutomationsSkipsUnreadableEntries(t *testing.T) {
	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{
		{Id: automationSettingId("broken"), Value: "{not json"},
		storedAutomation(t, "good", "Good"),
	}

	automations, err := automationCoordinator(cfg).ListAutomations(context.Background())

	require.NoError(t, err)
	require.Len(t, automations, 1)
	assert.Equal(t, "good", automations[0].Id)
}

// The setting id is where the value actually lives, so it wins over whatever the body says.
// Everything durable keys on that id.
func TestUnmarshalAutomationPrefersTheSettingId(t *testing.T) {
	automation, err := unmarshalAutomation(
		automationSettingId("real-id"),
		`{"id":"stale-id","displayName":"Nightly","automationKind":"alert_triage"}`)

	require.NoError(t, err)
	assert.Equal(t, "real-id", automation.Id)
}

func TestSaveAutomationAssignsIdAndDuplicatesTemplate(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := &model.Automation{
		Auditable:      model.Auditable{UserId: "user-1"},
		DisplayName:    "Nightly",
		AutomationKind: "alert_triage",
	}

	require.NoError(t, ac.SaveAutomation(context.Background(), automation))

	assert.NotEmpty(t, automation.Id, "the server assigns identity")
	require.Len(t, cfg.updates, 1)
	assert.Equal(t, automationSettingId(automation.Id), cfg.updates[0].Id)

	// Without this the setting resolves no definition, loses its forced type, and the
	// value is expanded into a nested YAML mapping instead of staying one automation.
	assert.Equal(t, ConfigSettingAutomationTemplate, cfg.updates[0].DuplicatedFromID)
}

// Updating an existing automation must carry DuplicatedFromID too -- the metadata is
// resolved on every write, not remembered from the first one.
func TestSaveAutomationKeepsDuplicatedFromIdOnUpdate(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := &model.Automation{
		Auditable:      model.Auditable{Id: "existing", UserId: "user-1"},
		AutomationKind: "alert_triage",
	}

	require.NoError(t, ac.SaveAutomation(context.Background(), automation))

	require.Len(t, cfg.updates, 1)
	assert.Equal(t, "existing", automation.Id, "an existing id is not reassigned")
	assert.Equal(t, ConfigSettingAutomationTemplate, cfg.updates[0].DuplicatedFromID)
}

// The settings system has no pre-save hook, so this is the only place params are checked.
func TestSaveAutomationRejectsParamsTheKindRefuses(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)
	ac.AutomationKindLibrary["alert_triage"] = &fakeAutomationKind{
		name:        "alert_triage",
		validateErr: ErrInvalidAutomationParams,
	}

	err := ac.SaveAutomation(context.Background(), &model.Automation{
		AutomationKind: "alert_triage",
		Params:         json.RawMessage(`{}`),
	})

	assert.ErrorIs(t, err, ErrInvalidAutomationParams)
	assert.Empty(t, cfg.updates, "nothing is written when validation fails")
}

func TestSaveAutomationRejectsUnknownKind(t *testing.T) {
	cfg := &automationConfigstore{}

	err := automationCoordinator(cfg).SaveAutomation(context.Background(), &model.Automation{
		AutomationKind: "nope",
	})

	assert.ErrorIs(t, err, ErrAutomationKindNotFound)
	assert.Empty(t, cfg.updates)
}

// Registering the same setting twice would deliver every update twice, and there is no way
// to unregister, so the guard has to be on this side.
func TestSaveAutomationRegistersEachSettingOnce(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	automation := &model.Automation{
		Auditable:      model.Auditable{Id: "same-id", UserId: "user-1"},
		AutomationKind: "alert_triage",
	}

	require.NoError(t, ac.SaveAutomation(context.Background(), automation))
	require.NoError(t, ac.SaveAutomation(context.Background(), automation))

	assert.Equal(t, []string{automationSettingId("same-id")}, cfg.registered)
}

// Deleting is what stops an automation scheduling again, so it must not be blocked by the
// run that is the reason someone wants it gone. The open run finishes on its own; nothing
// starts another, because scheduling reads config and the config is now absent.
func TestDeleteAutomationProceedsWhileARunIsInFlight(t *testing.T) {
	cfg := &automationConfigstore{}
	ac := automationCoordinator(cfg)

	mDB := &mockdb.MockDB{}
	ac.store = automationTestStore(mDB)
	expectRunRows(mDB, "running")

	require.NoError(t, ac.DeleteAutomation(context.Background(), "5c0b1f2e"))

	assert.Equal(t, []string{automationSettingId("5c0b1f2e")}, cfg.removals)

	// Run history outlives the automation, and tearing it down under a live run would pull
	// the rows out from beneath it.
	mDB.AssertNotCalled(t, "Begin", mock.Anything)
}

// A pillar file that was never created reports the missing file rather than nothing-to-do,
// so an automation that is already gone would otherwise fail to delete.
func TestDeleteAutomationTreatsMissingPillarAsAlreadyGone(t *testing.T) {
	cfg := &automationConfigstore{updateErr: os.ErrNotExist}
	ac := automationCoordinator(cfg)

	assert.NoError(t, ac.DeleteAutomation(context.Background(), "5c0b1f2e"))
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

func automationTestStore(mDB *mockdb.MockDB) *database.Store {
	mDB.On("Migrate", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	s, err := database.New(context.Background(), mDB)
	if err != nil {
		panic(err)
	}

	return s
}

// expectRunRows scripts ListAutomationRuns returning one run in the given state.
func expectRunRows(mDB *mockdb.MockDB, state string) {
	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = "run-1"
			*(args.Get(1).(*string)) = "5c0b1f2e"
			*(args.Get(2).(*string)) = state
		}).Return(nil).Once()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(mRows, nil)
}
