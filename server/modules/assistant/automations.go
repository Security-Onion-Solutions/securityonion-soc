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

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	// Each automation is its own setting so that config history, and therefore rollback,
	// is per automation: reverting one leaves the others alone. A single setting holding
	// them all would revert every automation at once.
	ConfigSettingAutomationsPrefix = "soc.config.server.modules.assistant.automations."

	// The annotated setting every automation is written as a duplicate of. It never holds
	// a value; it exists so instances inherit its syntax, forced type and description
	// rather than being treated as unknown settings.
	ConfigSettingAutomationTemplate = ConfigSettingAutomationsPrefix + "template"
)

var ErrConfigstoreUnavailable = errors.New("ERROR_CONFIGSTORE_UNAVAILABLE")

func automationSettingId(id string) string {
	return ConfigSettingAutomationsPrefix + id
}

// automationIdFromSetting returns the automation id a setting holds, or "" when the setting
// is not an automation. The template is excluded: it is an annotation anchor, not an
// automation.
func automationIdFromSetting(settingId string) string {
	if settingId == ConfigSettingAutomationTemplate {
		return ""
	}

	id := strings.TrimPrefix(settingId, ConfigSettingAutomationsPrefix)
	if id == settingId || id == "" || strings.Contains(id, ".") {
		return ""
	}

	return id
}

// unmarshalAutomation decodes one stored automation. The setting id is authoritative for
// Id: the body is whatever was last written, while the id is where the value actually
// lives, and everything durable -- runs, work items, alert stamps -- keys on it.
func unmarshalAutomation(settingId, value string) (*model.Automation, error) {
	id := automationIdFromSetting(settingId)
	if id == "" {
		return nil, fmt.Errorf("setting %s is not an automation", settingId)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("automation %s has no value", id)
	}

	automation := &model.Automation{}
	if err := json.Unmarshal([]byte(value), automation); err != nil {
		return nil, fmt.Errorf("automation %s is not valid JSON: %w", id, err)
	}

	automation.Id = id
	automation.Kind = "automation"

	return automation, nil
}

// ListAutomations returns every stored automation.
func (ac *AssistantCoordinator) ListAutomations(ctx context.Context) ([]*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	settings, err := ac.srv.Configstore.GetSettings(ctx, true)
	if err != nil {
		return nil, err
	}

	automations := []*model.Automation{}

	for _, setting := range settings {
		if automationIdFromSetting(setting.Id) == "" {
			continue
		}

		automation, err := unmarshalAutomation(setting.Id, setting.Value)
		if err != nil {
			// One malformed automation must not hide the rest, and an admin editing the
			// raw setting can produce one at any time.
			log.FromContext(ctx).WithError(err).WithField("settingId", setting.Id).
				Warn("skipping unreadable automation")

			continue
		}

		automations = append(automations, automation)
	}

	return automations, nil
}

// GetAutomation returns a single automation by Id
func (ac *AssistantCoordinator) GetAutomation(ctx context.Context, id string) (*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if id == "" {
		return nil, database.ErrAutomationNotFound
	}

	setting, err := ac.srv.Configstore.GetSetting(ctx, automationSettingId(id))
	if err != nil {
		return nil, err
	}

	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return nil, database.ErrAutomationNotFound
	}

	return unmarshalAutomation(setting.Id, setting.Value)
}

// SaveAutomation creates or replaces one automation. The kind validates the params.
func (ac *AssistantCoordinator) SaveAutomation(ctx context.Context, automation *model.Automation) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	if automation == nil {
		return ErrInvalidAutomationParams
	}

	kind, err := ac.lookupAutomationKind(automation.AutomationKind)
	if err != nil {
		return err
	}

	if err := kind.ValidateParams(automation.Params); err != nil {
		return err
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	if automation.Id == "" {
		automation.Id = uuid.NewString()
	}

	encoded, err := json.Marshal(automation)
	if err != nil {
		return err
	}

	// DuplicatedFromID is required on every write, not only the first. Without it
	// UpdateSetting cannot resolve a definition, takes its unknown-setting branch, and
	// blanks the inherited metadata -- including the forced type that keeps this value a
	// JSON scalar instead of being expanded into a nested YAML mapping.
	err = ac.srv.Configstore.UpdateSetting(ctx, &model.Setting{
		Id:               automationSettingId(automation.Id),
		Value:            string(encoded),
		DuplicatedFromID: ConfigSettingAutomationTemplate,
	}, false)
	if err != nil {
		return err
	}

	ac.watchAutomationSetting(automation.Id)

	return nil
}

// DeleteAutomation removes an automation, allowing in-flight runs to finish.
func (ac *AssistantCoordinator) DeleteAutomation(ctx context.Context, id string) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	if id == "" {
		return database.ErrAutomationNotFound
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	setting := model.NewSetting(automationSettingId(id))

	if err := ac.srv.Configstore.UpdateSetting(ctx, setting, true); err != nil {
		// Removing from a pillar file that was never created reports the missing file
		// rather than treating it as nothing to do, so an automation that is already gone
		// would otherwise fail to delete.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// watchAutomationSetting subscribes to one automation's setting so an edit or a revert made
// from the config screen reaches the coordinator.
//
// Callbacks dispatch on an exact setting id, so a dynamically created automation has to be
// registered as it appears rather than up front. Registration appends, so registering the
// same id twice would deliver every update twice; watchedAutomations is what prevents that.
// There is no way to unregister, so a deleted automation leaves a subscription behind that
// simply never fires again.
func (ac *AssistantCoordinator) watchAutomationSetting(id string) {
	registrar, ok := ac.srv.Configstore.(server.ConfigSettingCallbackRegistrar)
	if !ok {
		return
	}

	ac.agentMu.Lock()
	defer ac.agentMu.Unlock()

	if ac.watchedAutomations == nil {
		ac.watchedAutomations = map[string]bool{}
	}

	if ac.watchedAutomations[id] {
		return
	}

	ac.watchedAutomations[id] = true

	registrar.RegisterConfigSettingCallback(automationSettingId(id), ac)
}

// watchStoredAutomations subscribes to every automation that already exists, so edits made
// from the config screen to automations this process did not create still reach it.
func (ac *AssistantCoordinator) watchStoredAutomations(ctx context.Context) {
	automations, err := ac.ListAutomations(ctx)
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("unable to list automations; config changes will not hot-reload")

		return
	}

	for _, automation := range automations {
		ac.watchAutomationSetting(automation.Id)
	}
}
