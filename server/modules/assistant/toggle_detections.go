// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &ToggleDetectionsTool{}
	knownTools[t.GetName()] = t
}

type ToggleDetectionsTool struct{}

func (t *ToggleDetectionsTool) GetName() string {
	return "toggle_detections"
}

func (t *ToggleDetectionsTool) GetDescription() string {
	return "Enable or disable detections in Security Onion (per the user's request) by querying for them with a search filter.\n" +
		"- Search for detections by referencing any potentially relevant field(s), whichever you see fit from the ones described to you.\n" +
		"- *IMPORTANT* All queries should include `AND _index:\"*:so-detection\" AND so_kind:detection` appended to the end. The quotes around *:so-detection MUST be included.\n" +
		"- When searching for detections, specify a date range of 999 days ago unless advised otherwise.\n" +
		"- Examples for wild cards in the oql_query:\n" +
		"  - Search terms cannot begin with a wildcard (e.g., `*xyz` the wildcard is ignored, but `xyz*` is valid)\n" +
		"  - When using wildcards, do not wrap the value in quotes, instead use parentheses (e.g., `so_detection.title:(A B*)` is valid, but `so_detection.title:\"A B*\"` will not work as expected)"
}

func (t *ToggleDetectionsTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"search_filter": {
					Type: "string",
					Description: "OQL search filter to find matching detections. Here is a run-down of each of the potentially relevant fields you might want to use in your query:\n" +
						"- so_detection.id: The ID assigned to this detection by the server. This is a read-only field. Example: \"gQKCepgBAWAm-kn2lYs2\"\n" +
						"- so_detection.createTime: The date and time that this detection was created. This is a read-only field. Example: \"2024-11-14T15:03:22Z\"\n" +
						"- so_detection.userId: The ID of the user that created this detection. Example: \"dcbe6004-f6e0-4579-9f98-9576201ffb29\"\n" +
						"- so_detection.publicId: The public ID shared across all Security Onion grids. Example: \"923421c7-9b1e-45d4-80cc-e21d060c8723\"\n" +
						"- so_detection.title: Summarized title of the detection. Example: \"Security Onion - Grid Node Login Failure (SSH)\"\n" +
						"- so_detection.severity: The severity classification of this detection. This MUST be either \"unknown\", \"informational\", \"low\", \"medium\", \"high\", or \"critical\".\n" +
						"- so_detection.author: The original author of this detection. This can be a mixture of email address, organization name, first name, or any freeform value. Example: \"Security Onion Solutions\"\n" +
						"- so_detection.category: Used for categorizing this detection into a broader grouping such as firewalls or web servers. Example: \"ps_script\"\n" +
						"- so_detection.description: Brief explanation of this detection. Example: \"Detects when a user fails to login to a grid node via SSH. Review associated logs for username and source IP.\"\n" +
						"- so_detection.content: The underlying detection rule source content. Example: \"title: CobaltStrike Named Pipe\\nid: ...\\n logsource:\\n ...\\ncondition: selection\\nfalsepositives:\\n...\"\n" +
						"- so_detection.isEnabled: Indicates whether this detection is currently enabled in the Security Onion grid. Example: true\n" +
						"- so_detection.isCommunity: Indicates whether this detection originated from a community ruleset. Duplicated detections will show 'false'. Example: true\n" +
						"- so_detection.engine: The engine that processes this detection.\n" +
						"- so_detection.language: The language that this detection uses. This MUST be either \"sigma\", \"suricata\", or \"yara\".\n" +
						"- so_detection.overrides: A list of tuning overrides that apply to this detection.\n" +
						"- so_detection.tags: An optional list of user-defined tags, useful for grouping similar detections together.\n" +
						"- so_detection.ruleset: The name of the ruleset from which this detection originated, or __custom__ if the ruleset was created outside of a ruleset. Example: \"__custom__\"\n" +
						"- so_detection.license: The license that applies to this detection. Example: \"DRL\"\n" +
						"- so_detection.sourceCreated: The date and time when the underlying detection rule source was created. This is not when the detection was added to this grid.\n" +
						"- so_detection.sourceUpdated: The date and time when the underlying detection rule source was last updated. This is not when the detection was updated in this grid.\n" +
						"- so_detection.product: Used by Sigma rules for filtering log outputs to a specific product, such as the Windows eventlog types. Example: \"windows\"\n" +
						"- so_detection.service: Used by Sigma rules for filtering a subset of log outputs to a specific server. Example: \"sshd\"\n" +
						"- @timestamp: The date and time when this detection was last created/updated/modified. Example: \"2025-11-12T19:38:17.413984706Z\"",
				},
				"enable": {
					Type:        "boolean",
					Description: "This is a boolean value based on whether the user wants to enable or disable the detections at hand. A value of true corresponds to the enable operation, and false corresponds to the disable operation.",
				},
				"range_start": {
					Type:        "string",
					Description: "Optional start time for the query range (e.g., \"-1h\", \"2023/10/26 10:00:00 AM\"). Default is 24 hours ago (\"-24h\")",
				},
				"range_end": {
					Type:        "string",
					Description: "Optional end time for the query range (e.g., \"now\", \"2023/10/26 12:00:00 PM\"). Default is now.",
				},
				"range_format": {
					Type:        "string",
					Description: "Format of the date range (default: \"2006/01/02 3:04:05 PM\"). The format must be specified using Go's time package's reference layout format. Required if either range_start or range_end is provided.",
				},
				"limit": {
					Type: "integer",
					Description: `The maximum number of detections to return. Unless some kind of limit is applicable to the user's request, this field should be left out.
						Here's an example where "limit" would be useful: "enable the 5 most recent suricata detections".`,
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type toggleDetectionsArgs struct {
	SearchFilter string `json:"search_filter"`
	Enable       bool   `json:"enable"`
	RangeStart   string `json:"range_start,omitempty"`
	RangeEnd     string `json:"range_end,omitempty"`
	RangeFormat  string `json:"range_format,omitempty"`
	Limit        int    `json:"limit"`
}

func (t *ToggleDetectionsTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, fmt.Errorf("user is not authorized to write detections: %w", err)
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &toggleDetectionsArgs{}
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

	err = json.Unmarshal([]byte(params), args)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal params: %w", err)
	}

	result.Parameters = args

	query := args.SearchFilter

	if query != "" && !strings.Contains(query, "NOT metadata.raw_index:") {
		query = fmt.Sprintf(`(%s) AND NOT metadata.raw_index:"logs-soc-so"`, query)
	} else if query == "" {
		query = `NOT metadata.raw_index:"logs-soc-so"`
	}

	var detectLimit int
	if args.Limit > 0 {
		detectLimit = args.Limit
	} else {
		detectLimit = 10000
	}

	detectEvents, err := srv.Detectionstore.QueryWithRange(ctx, query, args.RangeStart, args.RangeEnd, args.RangeFormat, detectLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to search for detections with query %s: %w", query, err)
	}

	detects, err := srv.Detectionstore.ConvertEventsToDetections(ctx, detectEvents)
	if err != nil {
		return nil, fmt.Errorf("unable to convert events to detections: %w", err)
	}

	if len(detects) == 0 {
		result.Result = "No detections found"
		return result, nil
	}

	logger.WithField("detectionsFound", len(detects)).Info("query executed successfully")

	bulkStats, err := srv.Detectionstore.BulkUpdateDetections(ctx, args.Enable, detects, logger)
	if err != nil {
		logger.WithError(err).Error("error updating detections")
		return nil, fmt.Errorf("error updating detections: %w", err)
	}

	syncDetects := bulkStats.NeedToSync
	syncStart := time.Now()
	errMap := map[string]string{}
	errList := []error{}

	byEngine := map[model.EngineName][]*model.Detection{}
	for _, detectCurr := range syncDetects {
		byEngine[detectCurr.Engine] = append(byEngine[detectCurr.Engine], detectCurr)
	}

	srv.DetectionEngines.Range(func(n, engineInt interface{}) bool {
		name := n.(model.EngineName)
		engine := engineInt.(server.DetectionEngine)

		if len(byEngine[name]) != 0 {
			var eMap map[string]string

			eMap, err = engine.SyncLocalDetections(ctx, byEngine[name])
			for sid, e := range eMap {
				errMap[sid] = e
			}
			if err != nil {
				errList = append(errList, err)
			}
		}

		return true
	})

	if len(errList) != 0 {
		logger.WithError(err).Error("unable to sync detections")
		return nil, fmt.Errorf("unable to sync detections: %v", errList)
	}

	if len(errMap) != 0 {
		logger.WithField("errMap", errMap).Error("unable to sync detections")
		return nil, fmt.Errorf("unable to sync detections: %v", errMap)
	}

	syncDur := time.Since(syncStart)

	var opString string
	if args.Enable {
		opString = "Enabled"
	} else {
		opString = "Disabled"
	}

	result.Result = fmt.Sprintf(
		"Successfully %s %d detections. %s=%d, Audited=%d, Filtered=%d, Errors=%v, UpdateDuration=%s, SyncDuration=%s",
		opString,
		bulkStats.Updated,
		opString,
		bulkStats.Updated,
		bulkStats.Audited,
		bulkStats.Filtered,
		bulkStats.ErrMap,
		bulkStats.UpdateDuration,
		syncDur,
	)

	return result, nil
}
