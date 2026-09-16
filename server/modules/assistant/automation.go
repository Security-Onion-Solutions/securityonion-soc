// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type AutomationKind interface {
	GetName() string
	GetDisplayName() string
	GetDescription() string
	GetParamSchema() model.JSONSchema
	// ValidateParams inspects the raw params without modifying them; the caller
	// stores exactly the bytes it validated. Kinds apply their defaults where tools
	// do, when they unmarshal inside Execute.
	ValidateParams(params json.RawMessage) error
	// Execute owns everything before, during and after the LLM turns: it gathers its
	// own work, starts and awaits its own sessions, and applies its own outcomes.
	// Nothing generic models any of that, so the scheduler never has to assume a
	// kind is shaped like any particular kind.
	Execute(ctx context.Context, run *AutomationRun) error
}

// knownAutomationKinds is written only from package init(), like knownTools, so it
// needs no lock. Lookups go through AssistantCoordinator.AutomationKindLibrary so a
// test can substitute a kind without mutating the global.
var knownAutomationKinds = map[string]AutomationKind{}

// ErrAutomationKindNotFound is returned when a task names a kind this build does not
// have, which happens to a task stored by a newer version or by a build with a kind
// since removed.
var ErrAutomationKindNotFound = errors.New("ERROR_AUTOMATION_KIND_NOT_FOUND")

// ErrInvalidAutomationParams is what a kind's ValidateParams returns so the save path
// can answer 400 without knowing the kind. Wrap it with %w to name the offending
// field: respondConfigWrite matches on the message substring, so the wrapped form
// still maps to the right status and errors.Is still works.
var ErrInvalidAutomationParams = errors.New("ERROR_AUTOMATION_PARAMS_INVALID")

// AutomationRun is one execution of one automation: the kind is the template, this
// is the instance of it that runs. Passed by pointer so a field can be added later
// without touching every kind. It carries no way to run a session of its own; kinds
// go through Srv.AssistantManager.RunAgentSession.
type AutomationRun struct {
	Srv  *server.Server
	Task *model.Automation
	// Unique per execution and stamped on the sessions it creates, so an outcome can
	// be traced back to its transcript. Not the scheduler's dedupe key, which is the
	// automation name: two runs of one automation must never be in flight at once.
	RunId string
}

// lookupAutomationKind is unexported because every caller is in this package; the
// server package reaches automations through AssistantManager methods, never through
// the registry.
func (ac *AssistantCoordinator) lookupAutomationKind(name string) (AutomationKind, error) {
	kind, ok := ac.AutomationKindLibrary[name]
	if !ok {
		return nil, ErrAutomationKindNotFound
	}

	return kind, nil
}
