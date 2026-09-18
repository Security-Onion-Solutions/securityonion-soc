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
	"time"
	"unicode/utf8"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/google/uuid"
)

const (
	// One setting per automation, so config history and rollback are per automation.
	ConfigSettingAutomationsPrefix = "soc.config.server.modules.assistant.automations."

	// An annotation anchor that never holds a value; instances duplicate it to inherit
	// its syntax, forced type and description.
	ConfigSettingAutomationTemplate = ConfigSettingAutomationsPrefix + "template"

	// A label for one row in a list, so it is capped well below what the setting could
	// hold.
	MaxAutomationDisplayNameLength = 100
)

// Wrap ErrInvalidAutomationParams with %w to name the offending field: respondConfigWrite
// matches on the message substring, so the wrapped form still maps to the right status.
var (
	ErrAutomationNotFound      = errors.New("ERROR_AUTOMATION_NOT_FOUND")
	ErrAutomationKindNotFound  = errors.New("ERROR_AUTOMATION_KIND_NOT_FOUND")
	ErrInvalidAutomationParams = errors.New("ERROR_AUTOMATION_PARAMS_INVALID")
	ErrConfigstoreUnavailable  = errors.New("ERROR_CONFIGSTORE_UNAVAILABLE")
)

type AutomationKind interface {
	GetName() string
	GetDisplayName() string
	GetDescription() string
	GetParamSchema() model.JSONSchema
	// ValidateParams inspects the raw params without modifying them; kinds apply their
	// defaults when they unmarshal inside Execute.
	ValidateParams(params json.RawMessage) error
	Execute(ctx context.Context, run *AutomationRun) error
}

// Written only from package init(), like knownTools, so it needs no lock. Lookups go
// through AssistantCoordinator.AutomationKindLibrary so a test can substitute a kind.
var knownAutomationKinds = map[string]AutomationKind{}

type AutomationRun struct {
	Srv  *server.Server
	Task *model.Automation
	// Unique per execution and stamped on the sessions it creates. Not the scheduler's
	// dedupe key, which is the automation id.
	RunId string

	// Never nil: a run is not opened at all without Postgres, so kinds do not check.
	Store AutomationStore

	// Every unfinished item for this task, oldest first. A kind drains this rather than
	// rescanning, so resumption arrives as data rather than a second method.
	OpenItems []*model.AutomationWorkItem
}

func (ac *AssistantCoordinator) lookupAutomationKind(name string) (AutomationKind, error) {
	kind, ok := ac.AutomationKindLibrary[name]
	if !ok {
		return nil, ErrAutomationKindNotFound
	}

	return kind, nil
}

func automationSettingId(id string) string {
	return ConfigSettingAutomationsPrefix + id
}

// isAutomationId reports whether id can address an automation.
func isAutomationId(id string) bool {
	_, err := uuid.Parse(id)

	return err == nil
}

// automationIdFromSetting returns the automation id a setting holds, or "" when the setting
// is not an automation. The template is excluded: it is an annotation anchor.
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

// unmarshalAutomation decodes one stored automation. The setting id is authoritative for Id:
// it is where the value actually lives, and everything durable keys on it.
func unmarshalAutomation(settingId, value string) (*model.Automation, error) {
	id := automationIdFromSetting(settingId)
	if id == "" {
		return nil, fmt.Errorf("setting %s is not an automation", settingId)
	}

	// A hand-edited pillar entry can name anything; only a UUID survives the store's
	// uuid columns, so reject it here rather than at the first query.
	if !isAutomationId(id) {
		return nil, fmt.Errorf("automation id %s is not a UUID", id)
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
			// One malformed automation must not hide the rest.
			log.FromContext(ctx).WithError(err).WithField("settingId", setting.Id).
				Warn("skipping unreadable automation")

			continue
		}

		automations = append(automations, automation)
	}

	return automations, nil
}

func (ac *AssistantCoordinator) GetAutomation(ctx context.Context, id string) (*model.Automation, error) {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return nil, ErrConfigstoreUnavailable
	}

	if !isAutomationId(id) {
		return nil, ErrAutomationNotFound
	}

	setting, err := ac.srv.Configstore.GetSetting(ctx, automationSettingId(id))
	if err != nil {
		return nil, err
	}

	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return nil, ErrAutomationNotFound
	}

	return unmarshalAutomation(setting.Id, setting.Value)
}

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

	if err := validateAutomation(automation); err != nil {
		return err
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	if err := ac.stampAutomation(ctx, automation); err != nil {
		return err
	}

	encoded, err := json.Marshal(automation)
	if err != nil {
		return err
	}

	// Without DuplicatedFromID, UpdateSetting resolves no definition and blanks the
	// inherited forced type, expanding this value into a nested YAML mapping.
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

// validateAutomation checks what the kind cannot: what an automation is called and how
// often it runs belong to the automation rather than to its params.
func validateAutomation(automation *model.Automation) error {
	name := strings.TrimSpace(automation.DisplayName)

	if name == "" {
		return fmt.Errorf("%w: displayName is required", ErrInvalidAutomationParams)
	}

	// Runes, not bytes: the cap is on what an admin typed, not on its encoding.
	if utf8.RuneCountInString(name) > MaxAutomationDisplayNameLength {
		return fmt.Errorf("%w: displayName must be at most %d characters",
			ErrInvalidAutomationParams, MaxAutomationDisplayNameLength)
	}

	if automation.IntervalSeconds <= 0 {
		return fmt.Errorf("%w: intervalSeconds must be positive", ErrInvalidAutomationParams)
	}

	return nil
}

// stampAutomation settles the fields an automation does not set for itself: identity, owner
// and timestamps. Caller holds configWriteMu, which is what makes the read of the stored copy
// and the write that follows it one edit rather than two. Nothing is written back to
// automation until every check has passed, so a rejected save leaves it as it arrived.
func (ac *AssistantCoordinator) stampAutomation(ctx context.Context, automation *model.Automation) error {
	id := automation.Id

	if id == "" {
		id = uuid.NewString()
	} else if !isAutomationId(id) {
		return fmt.Errorf("%w: id must be a UUID", ErrInvalidAutomationParams)
	}

	existing, err := ac.GetAutomation(ctx, id)
	if err != nil && !errors.Is(err, ErrAutomationNotFound) {
		return err
	}

	now := time.Now()
	createTime := &now
	userId := ""

	if existing == nil {
		requestor, ok := ctx.Value(web.ContextKeyRequestorId).(string)
		if !ok {
			return errors.New("context is missing RequestorId")
		}

		userId = requestor
	} else {
		// Existing runs and work items hold payloads only the original kind can read.
		if existing.AutomationKind != automation.AutomationKind {
			return fmt.Errorf("%w: automationKind cannot be changed", ErrInvalidAutomationParams)
		}

		// The owner is the identity unattended sessions execute as, so an edit by a second
		// admin must not silently hand them that user's RBAC.
		createTime = existing.CreateTime
		userId = existing.UserId
	}

	automation.Id = id
	automation.CreateTime = createTime
	automation.UpdateTime = &now
	automation.UserId = userId

	return nil
}

// DeleteAutomation removes an automation, allowing in-flight runs to finish.
func (ac *AssistantCoordinator) DeleteAutomation(ctx context.Context, id string) error {
	if ac.srv == nil || ac.srv.Configstore == nil {
		return ErrConfigstoreUnavailable
	}

	// Without this, DeleteAutomation("template") removes the annotation anchor every
	// automation inherits its forced type from.
	if !isAutomationId(id) {
		return ErrAutomationNotFound
	}

	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	setting := model.NewSetting(automationSettingId(id))

	if err := ac.srv.Configstore.UpdateSetting(ctx, setting, true); err != nil {
		// Removing from a pillar file that was never created reports the missing file.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// watchAutomationSetting subscribes to one automation's setting. Registration appends and
// cannot be undone, so watchedAutomations is what keeps a second one from doubling every
// update.
func (ac *AssistantCoordinator) watchAutomationSetting(id string) {
	registrar, ok := ac.srv.Configstore.(server.ConfigSettingCallbackRegistrar)
	if !ok {
		return
	}

	ac.watchMu.Lock()
	defer ac.watchMu.Unlock()

	if ac.watchedAutomations == nil {
		ac.watchedAutomations = map[string]bool{}
	}

	if ac.watchedAutomations[id] {
		return
	}

	ac.watchedAutomations[id] = true

	registrar.RegisterConfigSettingCallback(automationSettingId(id), ac)
}

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

// reconcileAutomationRuns closes out runs a previous process left open and requeues the work
// they had in flight. Called once from Start, before anything can schedule, which is the
// window in which every open run is known to be abandoned. A failure is logged rather than
// returned: an unreachable reconcile must not stop the assistant serving chat.
func (ac *AssistantCoordinator) reconcileAutomationRuns(ctx context.Context) {
	logger := log.FromContext(ctx)

	result, err := ac.store.ReconcileAutomationRuns(ctx)
	if err != nil {
		logger.WithError(err).Error("assistant: automation run reconciliation failed")

		return
	}

	if result.FailedRuns == 0 && result.ResetItems == 0 {
		return
	}

	logger.WithFields(log.Fields{
		"failedRuns": result.FailedRuns,
		"resetItems": result.ResetItems,
	}).Info("assistant: recovered automation runs left open by a previous process")
}
