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
	"sort"
	"strings"
	"text/template"
	"time"
	"unicode"

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
	return "Author, update, or clear a custom report for Security Onion. The template is saved as a grid " +
		"configuration setting and deployed to the grid. Custom reports fill 9 fixed slots: slot 1 is the " +
		"shipped example and slots 2-9 are user-fillable, and without a 'filename' the report goes into the " +
		"next free slot. Pass an empty 'content' with a 'filename' to clear that report and free its slot."
}

func (t *UpdateCustomReportTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"content": {
					Type: "string",
					Description: `The complete report template as Markdown, in three parts.

1. QUERY DIRECTIVES -- one per line at the very top, above the title, wrapped exactly so:
   {{- /* query.<name>.oql = <OQL> */ -}}
   {{- /* query.<name>.metricLimit = 50 */ -}}   (optional, as is eventLimit)

2. TITLE BLOCK -- a title line, then a line of '='. The title becomes the display name.

3. BODY -- Go text/template over .Results.<name>: .TotalEvents (int), .Events, .Metrics.
   - Event fields are in .Payload by dotted name: index $e.Payload "rule.name" (not
     index $e "rule.name"). Events also have .Id, .Time, .Timestamp, .Source, .Type, .Score.
   - .Metrics maps groupby_<n>_<fields, dots as underscores> to metric lists: an OQL ending
     "| groupby source.ip" (spaces, no colon) gives .Metrics.groupby_0_source_ip. Range that
     key, not .Metrics. Entries have .Keys, .Value, .Ratio, .Percentage; order them with
     sortMetrics "Value" "desc" $list -- the list is the LAST argument.
   - ASCII only (no emoji, em dashes, arrows, smart quotes); pipe dynamic text through
     stripEmoji.
   - An action alone on a line still emits that line's newline, and one blank line ends a
     Markdown table early. Around table rows, trim standalone actions ({{- $n := 0 -}})
     and close row loops with {{- end }}.`,
				},
				"filename": {
					Type: "string",
					Description: "Optional. Which existing custom report to target, e.g. \"generic_report2.md\". " +
						"Use query_reports to list them.",
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

func (t *UpdateCustomReportTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

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

		// Slot 1 ships the example report; clearing it would blank that example on the grid.
		if target.Slot == 1 {
			return nil, fmt.Errorf("%s is the shipped example report and cannot be cleared; overwrite it with new content instead", target.Filename)
		}

		if strings.TrimSpace(target.Setting.Value) == "" {
			result.Result = fmt.Sprintf("Custom report %s has no saved content to clear.", target.Filename)
			return result, nil
		}

		// Remove the override rather than saving an empty one, so the slot returns to its default.
		if err = srv.Configstore.UpdateSetting(ctx, &model.Setting{Id: target.Setting.Id}, true); err != nil {
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

const queryDirectivePrefix = "/* query."

func reportTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"getUserDetail":     func(attr string, userId string) string { return "" },
		"formatDateTime":    func(format string, t *time.Time) string { return "" },
		"join":              strings.Join,
		"lower":             strings.ToLower,
		"upper":             strings.ToUpper,
		"sortHistory":       func(f, d string, l []*model.Auditable) []*model.Auditable { return l },
		"sortComments":      func(f, d string, l []*model.Comment) []*model.Comment { return l },
		"sortRelatedEvents": func(f, d string, l []*model.RelatedEvent) []*model.RelatedEvent { return l },
		"sortArtifacts":     func(f, d string, l []*model.Artifact) []*model.Artifact { return l },
		"sortDetections":    func(f, d string, l []*model.Detection) []*model.Detection { return l },
		"sortMetrics":       func(f, d string, l []*model.EventMetric) []*model.EventMetric { return l },
		"sortAssistantMessages": func(f, d string, l []*model.StoredMessage) []*model.StoredMessage {
			return l
		},
		"sortAssistantSessionDetails": func(f, d string, l []*model.AssistantSessionDetails) []*model.AssistantSessionDetails {
			return l
		},
		"formatNumber": func(format string, language string, value interface{}) string { return "" },
		"parseJSON":    func(data interface{}) map[string]interface{} { return map[string]interface{}{} },
		"toJSON":       func(data interface{}) string { return "" },
		"add":          func(a, b int) int { return a + b },
		"stripEmoji":   func(text string) string { return text },
	}
}

type reportTemplateInput struct {
	Error     string
	BeginDate time.Time
	EndDate   time.Time
	Results   map[string]*model.EventSearchResults
}

func validateReportTemplate(content string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("report template is empty")
	}

	tmpl, err := template.New("custom_report").Funcs(reportTemplateFuncs()).Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse as a Go text/template: %w", err)
	}

	if !hasOqlQueryDirective(content) {
		return errors.New("must define at least one /* query.<name>.oql = ... */ directive")
	}

	if err := validateReportDirectives(content); err != nil {
		return err
	}

	if err := validateReportOql(content); err != nil {
		return err
	}

	if err := validateReportASCII(content); err != nil {
		return err
	}

	if err := validateReportResultNames(content); err != nil {
		return err
	}

	rendered := &strings.Builder{}
	if err := tmpl.Execute(rendered, syntheticReportInput(content)); err != nil {
		return fmt.Errorf("template failed to render against sample data: %w", err)
	}

	return validateRenderedTables(rendered.String())
}

var tableSeparator = regexp.MustCompile(`^\|[\s\-:|]+\|$`)

func isTableRow(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "|")
}

func isTableSeparator(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.Contains(trimmed, "-") && tableSeparator.MatchString(trimmed)
}

func validateRenderedTables(rendered string) error {
	lines := strings.Split(rendered, "\n")

	for i := 0; i+2 < len(lines); i++ {
		if !isTableRow(lines[i]) || strings.TrimSpace(lines[i+1]) != "" || !isTableRow(lines[i+2]) {
			continue
		}

		// A blank line followed by a header and its separator is a second table, not a break.
		if i+3 < len(lines) && isTableSeparator(lines[i+3]) {
			continue
		}

		return fmt.Errorf("a blank line splits a Markdown table before the row %q, so every row after it renders as plain text; trim the standalone action that emits that newline ({{- ... -}}) or close the row loop with {{- end }}", strings.TrimSpace(lines[i+2]))
	}

	return nil
}

var resultReference = regexp.MustCompile(`\.Results\.([A-Za-z_][A-Za-z0-9_]*)`)

func validateReportResultNames(content string) error {
	declared := map[string]bool{}
	names := []string{}

	for _, directive := range oqlDirectives(content) {
		declared[directive.Name] = true
		names = append(names, directive.Name)
	}

	for _, match := range resultReference.FindAllStringSubmatch(content, -1) {
		if !declared[match[1]] {
			return fmt.Errorf("body reads .Results.%s but no query declares %q; declared queries are: %s", match[1], match[1], strings.Join(names, ", "))
		}
	}

	return nil
}

func syntheticReportInput(content string) *reportTemplateInput {
	now := time.Now()
	input := &reportTemplateInput{
		BeginDate: now,
		EndDate:   now,
		Results:   map[string]*model.EventSearchResults{},
	}

	for _, directive := range oqlDirectives(content) {
		results := &model.EventSearchResults{
			TotalEvents: 2,
			Events:      []*model.EventRecord{sampleEventRecord(), sampleEventRecord()},
			Metrics:     map[string][]*model.EventMetric{},
		}

		for key, arity := range groupByMetricKeys(directive.Value) {
			results.Metrics[key] = []*model.EventMetric{sampleEventMetric(arity), sampleEventMetric(arity)}
		}

		input.Results[directive.Name] = results
	}

	return input
}

func sampleEventRecord() *model.EventRecord {
	return &model.EventRecord{
		Source:    "sample",
		Time:      time.Now(),
		Timestamp: time.Now().Format(time.RFC3339),
		Id:        "sample-id",
		Payload:   map[string]interface{}{},
	}
}

func sampleEventMetric(arity int) *model.EventMetric {
	keys := make([]interface{}, arity)
	for i := range keys {
		keys[i] = "sample"
	}

	return &model.EventMetric{
		Keys:       keys,
		Value:      1,
		Ratio:      0.5,
		Percentage: 50,
	}
}

func groupByMetricKeys(oql string) map[string]int {
	keys := map[string]int{}

	idx := strings.Index(strings.ToLower(oql), "| groupby ")
	if idx < 0 {
		return keys
	}

	segment := oql[idx+len("| groupby "):]
	if end := strings.Index(segment, "|"); end >= 0 {
		segment = segment[:end]
	}

	fields := strings.FieldsFunc(segment, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
	for i, field := range fields {
		fields[i] = strings.ReplaceAll(strings.TrimSuffix(field, "*"), ".", "_")
	}

	for depth := 1; depth <= len(fields); depth++ {
		keys["groupby_0_"+strings.Join(fields[:depth], "_")] = depth
	}

	return keys
}

func validateReportDirectives(content string) error {
	lines := strings.Split(content, "\n")
	titleLine := titleUnderlineIndex(lines)

	for i, line := range lines {
		if !strings.Contains(line, queryDirectivePrefix) {
			continue
		}

		if titleLine >= 0 && i > titleLine {
			return fmt.Errorf("line %d places a query directive below the title block; move every directive above the title, or its comment's trim markers will run the title's '=' underline into the following line", i+1)
		}

		if strings.Count(line, queryDirectivePrefix) > 1 {
			return fmt.Errorf("line %d declares more than one query directive; only the first is read, so put each directive on its own line", i+1)
		}

		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
			return fmt.Errorf("line %d must wrap its query directive in a template comment, e.g. {{- /* query.<name>.oql = ... */ -}}, otherwise it renders as literal text in the report", i+1)
		}
	}

	return nil
}

func validateReportASCII(content string) error {
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, queryDirectivePrefix) {
			continue
		}

		for _, r := range line {
			if r > unicode.MaxASCII {
				return fmt.Errorf("line %d contains the non-ASCII character %q; the report renderer handles ASCII only, so avoid emoji, em dashes, arrows and smart quotes, and pipe dynamic text through stripEmoji", i+1, r)
			}
		}
	}

	return nil
}

func hasOqlQueryDirective(content string) bool {
	return len(oqlDirectives(content)) > 0
}

type oqlDirective struct {
	Line  int
	Name  string
	Value string
}

func oqlDirectives(content string) []oqlDirective {
	found := []oqlDirective{}

	for i, line := range strings.Split(content, "\n") {
		start := strings.Index(line, queryDirectivePrefix)
		if start < 0 {
			continue
		}

		body := line[start+len(queryDirectivePrefix):]
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
			found = append(found, oqlDirective{Line: i, Name: strings.TrimSpace(parts[0]), Value: value})
		}
	}

	return found
}

var oqlSegmentKinds = []string{"groupby", "sortby", "table"}

func validateReportOql(content string) error {
	for _, directive := range oqlDirectives(content) {
		lowered := strings.ToLower(directive.Value)

		for _, kind := range oqlSegmentKinds {
			if strings.Contains(lowered, kind+":") {
				return fmt.Errorf("line %d writes %q in its OQL; the segment keyword is separated by a space, e.g. | %s source.ip", directive.Line+1, kind+":", kind)
			}
		}
	}

	return nil
}
