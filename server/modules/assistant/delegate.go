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
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	// do not add this tool to knownTools since it should only be used by agents
	// with explicit permission to delegate with it
}

type DelegateTool struct {
	agentName    string
	agentDisplay string
	agentDesc    string
}

func NewDelegateTool(agentName, agentDisplay, agentDesc string) *DelegateTool {
	return &DelegateTool{
		agentName:    agentName,
		agentDisplay: agentDisplay,
		agentDesc:    agentDesc,
	}
}

var invalidToolNameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeDelegateToolName builds a provider-valid tool name
// (^[a-zA-Z0-9_-]{1,64}$) from an agent selector. The "@" -> "_at_" mapping
// runs first so a legacy id@adapter selector produces the same tool name as
// previous releases.
func sanitizeDelegateToolName(selector string) string {
	name := strings.ReplaceAll(selector, "@", "_at_")
	name = invalidToolNameChars.ReplaceAllString(name, "_")

	const prefix = "delegate_to_"
	if len(prefix)+len(name) > 64 {
		name = name[:64-len(prefix)]
	}

	return prefix + name
}

func (t *DelegateTool) GetName() string {
	return sanitizeDelegateToolName(t.agentName)
}

func (t *DelegateTool) GetDescription() string {
	return "This tool delegates work to another agent: " + t.agentName + "\n" +
		"Agent Description: " + t.agentDesc
}

func (t *DelegateTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"objective": {
					Type:        "string",
					Description: "The outcome to achieve, stated as a goal. Describe what success looks like, not the steps to get there.",
				},
				"context": {
					Type:        "string",
					Description: "All background the subagent needs but cannot otherwise know: prior findings, definitions of domain terms, why this matters.",
				},
				"expected_output": {
					Type:        "string",
					Description: "The form the result should take, e.g. 'a ranked list of candidate libraries with one-line tradeoff notes' or 'a yes/no with supporting evidence'.",
				},
				"constraints": {
					Type:        "string",
					Description: "Scope boundaries, things explicitly out of scope, time/effort budget",
				},
			},
			Required: []string{"objective", "context", "expected_output"},
		},
	}
}

type DelegateArgs struct {
	Objective      string `json:"objective"`
	Context        string `json:"context"`
	ExpectedOutput string `json:"expected_output"`
	Constraints    string `json:"constraints,omitempty"`
}

func (t *DelegateTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", string(req.Params)).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &DelegateArgs{}
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

	err = json.Unmarshal([]byte(req.Params), args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	content := fmt.Sprintf("Objective: %s\n\nContext: %s\n\nExpected Output: %s\n\nConstraints: %s", args.Objective, args.Context, args.ExpectedOutput, args.Constraints)

	// Don't run the sub-agent here. Return a kickoff marker so the coordinator can
	// create the linked child session, seed this objective as its first message,
	// and stream the sub-agent's first turn. The parent's delegate tool_use is left
	// unresolved (parked) until the sub-agent finishes and the backend folds its
	// result back into the parent session.
	result.Result = model.DelegationKickoff{
		ChildSessionId: uuid.NewString(),
		ChildModel:     t.agentName,
		Objective:      content,
		AgentName:      t.agentDisplay,
	}

	return result, nil
}
