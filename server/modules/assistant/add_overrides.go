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
	t := &AddOverridesTool{}
	knownTools[t.GetName()] = t
}

type AddOverridesTool struct{}

func (t *AddOverridesTool) GetName() string {
	return "add_overrides"
}

func (t *AddOverridesTool) GetDescription() string {
	return `Add one or more new overrides to existing detection(s) per the user's request. Search for detections by referencing any potentially relevant field(s), whichever you see fit from the ones described to you.
	- *IMPORTANT* All detections MUST be of the same language/engine (Suricata or Sigma). Otherwise, the new override(s) won't be compatible with some of them.
	- *IMPORTANT* All queries should include 'AND _index:"*:so-detection" AND so_kind:detection' appended to the end. The quotes around *:so-detection MUST be included.
	- When searching for detections, specify a date range of 999 days ago unless advised otherwise.
	- Examples for wild cards in the oql_query:
	  - Search terms cannot begin with a wildcard (e.g., "*xyz" the wildcard is ignored, but "xyz*" is valid)
	  - When using wildcards, do not wrap the value in quotes, instead use parentheses (e.g., so_detection.title:(A B*) is valid, but so_detection.title:"A B*" will not work as expected)
	The types of overrides and the fields for each override can vary between the Suricata and Sigma languages.
	YARA does not have overrides. The 5 fields that all overrides do share in common, no matter the language, are "isEnabled", "createdAt", "updatedAt", "type", and "note".
	The "note" field is the only one that can be empty. Here is a run-down of the language-specific override types and their respective fields and potential values:
	Suricata:
	- 3 different values for "type": "modify", "suppress", and "threshold"
	  - "modify" overrides also have the fields "regex" and "value".
	  - "suppress" overrides also have the fields "track" and "ip". The "track" field can ONLY take ONE of the following 3 values: "by_dst", "by_src", or "by_either". The "ip" field can be in CIDR notation or a Suricata variable.
	  - "threshold" overrides also have the fields "thresholdType", "track", "count", and "seconds". The "track" field can only take one of 2 values: "by_dst" or "by_src". The "thresholdType" field can only take one of 3 values: "threshold", "limit", or "both".
	Sigma:
	- Only 1 value for "type": "customFilter"
	  - "customFilter" overrides also have a field called "customFilter", where you put the actual filter.
	*IMPORTANT* When creating a new override, DO NOT include createdAt or updatedAt fields for the new override.`
}

func (t *AddOverridesTool) GetSchema() model.JSONSchema {
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
				"overrides": {
					Type: "array",
					Items: map[string]model.ToolSchemaProperty{
						"override": {
							Description: "Each of these objects represents an individual override.",
							Type:        "object",
							Items: map[string]model.ToolSchemaProperty{
								"isEnabled": {
									Type:        "boolean",
									Description: "Indicates whether this override is enabled.",
								},
								"createdAt": {
									Type:        "string",
									Description: "The date and time when this override was created. This field should not be included for newly created overrides, and it also should not be modified.",
								},
								"updatedAt": {
									Type:        "string",
									Description: "The date and time when this override was last modified. This field should not be included for newly created overrides, and it also should not be modified.",
								},
								"type": {
									Type:        "string",
									Description: "The type of override; available values vary between detection engines.",
								},
								"note": {
									Type:        "string",
									Description: "An optional operational note for this override.",
								},
								"regex": {
									Type:        "string",
									Description: "(suricata only) Regular expression for matching modify overrides.",
								},
								"value": {
									Type:        "string",
									Description: "(suricata only) The value needing to match the regex in order for this override to apply.",
								},
								"track": {
									Type:        "string",
									Description: "(suricata only) Track type for suppress and threshold overrides (by_either only applies to suppress overrides).",
								},
								"ip": {
									Type:        "string",
									Description: "(suricata only) The IP address or network value.",
								},
								"thresholdType": {
									Type:        "string",
									Description: "(suricata only) Threshold type, for threshold overrides.",
								},
								"count": {
									Type:        "integer",
									Description: "(suricata only) For treshold overrides, this is the number of occurrences allowed, within the given seconds interval, before this detection triggers an alert. Must be non-negative and greater than 0.",
								},
								"seconds": {
									Type:        "integer",
									Description: "(suricata only) For treshold overrides, this is the number of seconds that the occurrence threshold must occur within. Must be non-negative and greater than 0.",
								},
								"customFilter": {
									Type:        "string",
									Description: "(elastalert only) The custom filter applied to Sigma detections before the detection will trigger an alert.",
								},
							},
						},
					},
					Description: `The new overrides to add to the detections at hand. These will be appended to the existing overrides block for each queried detection.
					This field should be a list of the new override(s), as an array of objects. Note that even in the case where there is only one new override being added,
					this new override should still be placed inside an array. Here is an example input for this field, in the case where the user wants
					to append two new overrides to each of the detections returned by the search_filter:
[
	{
		"note": "",
		"seconds": 60,
		"isEnabled": true,
		"count": 10,
		"type": "threshold",
		"track": "by_src",
		"thresholdType": "both",
	},
	{
		"note": "Override Note",
		"regex": "rev:1;",
		"isEnabled": true,
		"type": "modify",
		"value": "rev:2;",
	}
]
					If used as input, the above example should be passed as an array of objects. The above "overrides" argument is only the *new* overrides that the user wants to add to the given detection(s).
					This argument should NOT include any existing overrides from the given detections' so_detection.overrides blocks, only new ones.`,
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
						Here's an example where "limit" would be useful: "add the following override to the 5 most recent suricata detections: ...".`,
				},
			},
			Required: []string{"search_filter"},
		},
	}
}

type AddOverridesArgs struct {
	SearchFilter string           `json:"search_filter"`
	Overrides    []map[string]any `json:"overrides"`
	RangeStart   string           `json:"range_start,omitempty"`
	RangeEnd     string           `json:"range_end,omitempty"`
	RangeFormat  string           `json:"range_format,omitempty"`
	Limit        int              `json:"limit"`
}

func (t *AddOverridesTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "detections")
	if err != nil {
		return nil, fmt.Errorf("user is not authorized to write detections: %w", err)
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &AddOverridesArgs{}
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

	newOverrides := populateOverridesFromMaps(args.Overrides, false)

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

	engInt, ok := srv.DetectionEngines.Load(detects[0].Engine)
	if !ok {
		logger.WithField("detectionEngine", detects[0].Engine).Error("unsupported engine")
		return nil, fmt.Errorf("unsupported engine %s", detects[0].Engine)
	}

	engine := engInt.(server.DetectionEngine)

	bulkStats, err := srv.Detectionstore.BulkAddOverrides(ctx, newOverrides, detects, logger)
	if err != nil {
		logger.WithError(err).Error("error adding overrides")
		return nil, fmt.Errorf("error adding overrides: %w", err)
	}

	syncDetects := bulkStats.NeedToSync
	syncStart := time.Now()

	errMap, err := engine.SyncLocalDetections(ctx, syncDetects)
	if err != nil {
		logger.WithError(err).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detections: %w", err)
	}

	if len(errMap) != 0 {
		logger.WithField("errMap", errMap).Error("unable to sync detection")
		return nil, fmt.Errorf("unable to sync detections: %v", errMap)
	}

	syncDur := time.Since(syncStart)

	plural := ""
	if len(newOverrides) > 1 {
		plural = "s"
	}

	result.Result = fmt.Sprintf(
		"Successfully added %d override%s to %d detections. Updated=%d, Audited=%d, Errors=%v, UpdateDuration=%s, SyncDuration=%s",
		len(newOverrides),
		plural,
		bulkStats.Updated,
		bulkStats.Updated,
		bulkStats.Audited,
		bulkStats.ErrMap,
		bulkStats.UpdateDuration,
		syncDur,
	)

	return result, nil
}
