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
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &QueryReportsTool{}
	knownTools[t.GetName()] = t
}

type QueryReportsTool struct{}

func (t *QueryReportsTool) GetName() string {
	return "query_reports"
}

func (t *QueryReportsTool) GetDescription() string {
	return "List the report templates configured in Security Onion (built-in 'standard' reports and the " +
		"fixed 'custom' report slots), including which custom slots are empty and available to fill. " +
		"Optionally pass a filename to return that report's full template content. Use this to see what " +
		"reports exist (e.g. before authoring a new one) or to inspect a report's definition."
}

func (t *QueryReportsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"filename": {
					Type: "string",
					Description: "Optional. The filename of a specific report (e.g. \"generic_report2.md\") to " +
						"return full template content for. Omit to list all reports.",
				},
			},
		},
	}
}

type queryReportsArgs struct {
	Filename string `json:"filename,omitempty"`
}

type reportSummary struct {
	Filename string `json:"filename"`
	Title    string `json:"title"`
	Type     string `json:"type"`
	Empty    bool   `json:"empty"`
}

type reportDetail struct {
	Filename string `json:"filename"`
	Title    string `json:"title"`
	Type     string `json:"type"`
	Empty    bool   `json:"empty"`
	Content  string `json:"content"`
}

func (t *QueryReportsTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "read", "config")
	if err != nil {
		logger.WithError(err).Error("user is not authorized to query reports")
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &queryReportsArgs{}
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

	err = json.Unmarshal(req.Params, args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	if srv.Configstore == nil {
		logger.Error("config store is not available")
		return nil, errors.New("ERROR_ASSISTANT_CONFIG_STORE_UNAVAILABLE")
	}

	slots, err := loadReportSlots(ctx, srv)
	if err != nil {
		logger.WithError(err).Error("failed to load report slots")
		return nil, errors.New("ERROR_ASSISTANT_LOAD_REPORT_SLOTS")
	}

	if name := strings.TrimSpace(args.Filename); name != "" {
		for _, s := range slots {
			if s.Filename == name {
				result.Result = reportDetail{
					Filename: s.Filename,
					Title:    s.Setting.Title,
					Type:     s.Kind,
					Empty:    s.isEmpty(),
					Content:  s.effectiveContent(),
				}
				return result, nil
			}
		}

		result.Result = fmt.Sprintf("Report %q not found", name)
		return result, nil
	}

	sort.Slice(slots, func(i, j int) bool {
		if slots[i].Kind != slots[j].Kind {
			return slots[i].Kind < slots[j].Kind
		}
		if slots[i].Slot != slots[j].Slot {
			return slots[i].Slot < slots[j].Slot
		}
		return slots[i].Filename < slots[j].Filename
	})

	reports := make([]reportSummary, 0, len(slots))
	for _, s := range slots {
		reports = append(reports, reportSummary{
			Filename: s.Filename,
			Title:    s.Setting.Title,
			Type:     s.Kind,
			Empty:    s.isEmpty(),
		})
	}

	if len(reports) == 0 {
		result.Result = "No reports found"
		return result, nil
	}

	logger.WithField("reportsFound", len(reports)).Info("query executed successfully")

	result.Result = reports

	return result, nil
}
