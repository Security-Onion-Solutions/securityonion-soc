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
	"text/template"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

func init() {
	t := &UpdateCustomReportTool{}
	knownTools[t.GetName()] = t
}

type UpdateCustomReportTool struct{}

func (t *UpdateCustomReportTool) GetName() string {
	return "update_custom_report"
}

func (t *UpdateCustomReportTool) GetDescription() string {
	return "Author or update a custom report for Security Onion from the user's request. Provide the " +
		"complete report template in 'content'. By default the report is saved into the next free custom " +
		"report slot (slot 1 is the shipped example; slots 2-9 are user-fillable). To update an existing " +
		"report instead, pass its 'filename' (use query_reports to find it). The report is saved as a grid " +
		"configuration setting and deployed to the grid. Follow the custom report authoring guidelines " +
		"when composing the content, and include a title block so the report has a display name."
}

func (t *UpdateCustomReportTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"content": {
					Type: "string",
					Description: "The complete custom report template as Markdown: a title block (title line " +
						"followed by a line of '='), one or more /* query.<name>.oql = <OQL> */ directives " +
						"(optionally metricLimit/eventLimit), and a Go text/template body that renders the query " +
						"results via .Results.<name> (.TotalEvents, .Metrics, .Events). Pass an empty string " +
						"together with 'filename' to clear/reset that report back to empty, freeing the slot.",
				},
				"filename": {
					Type: "string",
					Description: "Optional. The filename of an existing custom report to update, overwrite, or " +
						"clear (e.g. \"generic_report2.md\"). Use query_reports to find it. If omitted, the report " +
						"is saved into the next free slot.",
				},
			},
			Required: []string{"content"},
		},
	}
}

type updateCustomReportArgs struct {
	Content  string `json:"content"`
	Filename string `json:"filename,omitempty"`
}

func (t *UpdateCustomReportTool) Execute(ctx context.Context, srv *server.Server, params string, auxData string) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx)

	logger.WithField("toolParameters", params).Info("running tool for assistant")

	err = srv.CheckAuthorized(ctx, "write", "config")
	if err != nil {
		logger.WithError(err).Error("user is not authorized to generate custom reports")
		return nil, errors.New("ERROR_PERMISSION_DENIED")
	}

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &updateCustomReportArgs{}
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
		logger.WithError(err).WithField("toolParams", params).Error("failed to unmarshal tool params")
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

	custom := customReportSlots(slots)

	if strings.TrimSpace(args.Content) == "" {
		name := strings.TrimSpace(args.Filename)
		if name == "" {
			return nil, errors.New("ERROR_ASSISTANT_TEMPLATE_FILENAME_NEEDED")
		}

		target, ferr := findCustomSlotByName(custom, name)
		if ferr != nil {
			return nil, ferr
		}

		if strings.TrimSpace(target.Setting.Value) == "" {
			result.Result = fmt.Sprintf("Custom report %s has no saved content to clear.", target.Filename)
			return result, nil
		}

		if err = srv.Configstore.UpdateSetting(ctx, &model.Setting{Id: target.Setting.Id, Value: ""}, false); err != nil {
			logger.WithError(err).WithField("settingId", target.Setting.Id).Error("failed to clear custom report setting")
			return nil, errors.New("ERROR_ASSISTANT_CLEAR_REPORT_TEMPLATE")
		}

		deployed := deployReportModule(ctx, srv, logger)
		logger.WithFields(log.Fields{
			"filename":  target.Filename,
			"settingId": target.Setting.Id,
			"deployed":  deployed,
		}).Info("custom report cleared")

		result.Result = fmt.Sprintf("Cleared custom report slot %s. %s", target.Filename, deployNoteFor(deployed))
		return result, nil
	}

	if err = validateReportTemplate(args.Content); err != nil {
		logger.WithError(err).Warn("authored report template failed validation")
		return nil, fmt.Errorf("ERROR_ASSISTANT_REPORT_TEMPLATE_INVALID: %w", err)
	}

	target, updating, err := selectReportSlot(custom, args.Filename)
	if err != nil {
		return nil, err
	}

	setting := &model.Setting{Id: target.Setting.Id, Value: args.Content}
	if err = srv.Configstore.UpdateSetting(ctx, setting, false); err != nil {
		logger.WithError(err).WithField("settingId", setting.Id).Error("failed to save custom report setting")
		return nil, errors.New("ERROR_ASSISTANT_SAVE_REPORT_TEMPLATE")
	}

	deployed := deployReportModule(ctx, srv, logger)

	title := parseReportTitle([]byte(args.Content), target.Filename)

	verb := "Created"
	if updating {
		verb = "Updated"
	}

	logger.WithFields(log.Fields{
		"reportTitle": title,
		"filename":    target.Filename,
		"settingId":   target.Setting.Id,
		"updating":    updating,
		"deployed":    deployed,
	}).Info("custom report saved")

	result.Result = fmt.Sprintf("%s custom report %q in slot %s. %s", verb, title, target.Filename, deployNoteFor(deployed))

	return result, nil
}

func customReportSlots(slots []reportSlot) []reportSlot {
	custom := []reportSlot{}
	for _, s := range slots {
		if s.Kind == "custom" {
			custom = append(custom, s)
		}
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].Slot < custom[j].Slot })
	return custom
}

func findCustomSlotByName(custom []reportSlot, name string) (reportSlot, error) {
	for _, s := range custom {
		if s.Filename == name {
			return s, nil
		}
	}
	valid := make([]string, 0, len(custom))
	for _, s := range custom {
		valid = append(valid, s.Filename)
	}
	return reportSlot{}, fmt.Errorf("%q is not a custom report; valid options are: %s", name, strings.Join(valid, ", "))
}

func selectReportSlot(custom []reportSlot, filename string) (reportSlot, bool, error) {
	if name := strings.TrimSpace(filename); name != "" {
		s, err := findCustomSlotByName(custom, name)
		if err != nil {
			return reportSlot{}, false, err
		}
		return s, true, nil
	}

	for _, s := range custom {
		if s.Slot >= 2 && s.isEmpty() {
			return s, false, nil
		}
	}

	return reportSlot{}, false, fmt.Errorf("ERROR_ASSISTANT_ALL_REPORT_SLOTS_IN_USE")
}

func deployReportModule(ctx context.Context, srv *server.Server, logger log.Interface) bool {
	if srv.AdminConfigstore == nil {
		return false
	}
	if err := srv.AdminConfigstore.SyncModule(ctx, reportSaltModule, true); err != nil {
		logger.WithError(err).WithField("module", reportSaltModule).Warn("custom report change saved but grid sync failed")
		return false
	}
	return true
}

func deployNoteFor(deployed bool) string {
	if deployed {
		return "A grid sync was started to apply the change; it will take effect shortly."
	}
	return "Synchronize the grid to apply the change."
}

var reportTemplateFuncs = []string{
	"getUserDetail", "formatDateTime", "join", "lower", "upper",
	"sortHistory", "sortComments", "sortRelatedEvents", "sortArtifacts",
	"sortDetections", "sortMetrics", "sortAssistantMessages",
	"sortAssistantSessionDetails", "formatNumber", "parseJSON", "toJSON",
	"add", "stripEmoji",
}

func validateReportTemplate(content string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("report template is empty")
	}

	funcs := template.FuncMap{}
	for _, name := range reportTemplateFuncs {
		funcs[name] = func(args ...interface{}) interface{} { return nil }
	}

	if _, err := template.New("custom_report").Funcs(funcs).Parse(content); err != nil {
		return fmt.Errorf("failed to parse as a Go text/template: %w", err)
	}

	if !hasOqlQueryDirective(content) {
		return errors.New("must define at least one /* query.<name>.oql = ... */ directive")
	}

	return nil
}

func hasOqlQueryDirective(content string) bool {
	const prefix = "/* query."

	for _, line := range strings.Split(content, "\n") {
		start := strings.Index(line, prefix)
		if start < 0 {
			continue
		}

		body := line[start+len(prefix):]
		end := strings.Index(body, "*/")
		if end < 0 {
			continue
		}
		body = strings.TrimSpace(body[:end])

		kv := strings.SplitN(body, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		parts := strings.SplitN(key, ".", 2)
		if len(parts) != 2 {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(parts[1]), "oql") && value != "" {
			return true
		}
	}

	return false
}
