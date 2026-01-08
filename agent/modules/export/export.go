// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package export

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/agent"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"golang.org/x/text/message"
)

const DEFAULT_EXECUTABLE_PATH = "scripts/md2pdf"
const DEFAULT_TMP_PATH = "/tmp"
const DEFAULT_SYNTAX_PATH = "syntax_files"
const DEFAULT_TEMPLATE_PATH = "/opt/sensoroni/templates/reports"
const DEFAULT_TIMEOUT_MS = 1200000
const DEFAULT_CACHE_REFRESH_INTERVAL_MS = 10000
const DEFAULT_METRIC_LIMIT = 10000
const DEFAULT_EVENT_LIMIT = 10000
const DEFAULT_CSV_SEPARATOR = ","

const NO_EVENTS = 0
const SECONDS_PER_HOUR = 3600.0

type Export struct {
	config                 module.ModuleConfig
	agent                  *agent.Agent
	executablePath         string
	tmpPath                string
	timeoutMs              int
	syntaxPath             string
	templatePath           string
	templates              *template.Template
	usersById              map[string]*model.User
	lastRefreshTime        time.Time
	cacheRefreshIntervalMs int // in milliseconds
	exportMetricLimit      int
	exportEventLimit       int
	csvSeparator           string
}

func NewExport(agt *agent.Agent) *Export {
	return &Export{
		agent: agt,
	}
}

func (export *Export) PrerequisiteModules() []string {
	return nil
}

func (export *Export) Init(cfg module.ModuleConfig) error {
	var err error
	export.config = cfg
	export.executablePath = module.GetStringDefault(cfg, "executablePath", DEFAULT_EXECUTABLE_PATH)
	export.tmpPath = stripTrailingSlash(module.GetStringDefault(cfg, "tmpPath", DEFAULT_TMP_PATH))
	export.timeoutMs = module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
	export.syntaxPath = stripTrailingSlash(module.GetStringDefault(cfg, "syntaxPath", DEFAULT_SYNTAX_PATH))
	export.templatePath = stripTrailingSlash(module.GetStringDefault(cfg, "templatePath", DEFAULT_TEMPLATE_PATH))
	export.cacheRefreshIntervalMs = module.GetIntDefault(cfg, "cacheRefreshIntervalMs", DEFAULT_CACHE_REFRESH_INTERVAL_MS)
	export.exportMetricLimit = module.GetIntDefault(cfg, "exportMetricLimit", DEFAULT_METRIC_LIMIT)
	export.exportEventLimit = module.GetIntDefault(cfg, "exportEventLimit", DEFAULT_EVENT_LIMIT)
	export.csvSeparator = module.GetStringDefault(cfg, "csvSeparator", DEFAULT_CSV_SEPARATOR)

	if export.agent == nil {
		err = errors.New("unable to invoke JobMgr.AddJobProcessor due to nil agent")
	} else {
		export.agent.JobMgr.AddJobProcessor(export)
	}
	return err
}

func (export *Export) Start() error {
	return nil
}

func (export *Export) Stop() error {
	return nil
}

func (export *Export) IsRunning() bool {
	return false
}

func (export *Export) ProcessJob(job *model.Job, reader io.ReadCloser) (io.ReadCloser, error) {
	if job.GetKind() != model.JOB_KIND_EXPORT {
		log.WithFields(log.Fields{
			"jobId": job.Id,
			"kind":  job.GetKind(),
		}).Debug("Skipping export processor due to unsupported job")
		return reader, nil
	}

	if len(job.Filter.Parameters) == 0 {
		return reader, errors.New("missing required parameters for export")
	}

	// Get required parameters
	exportType, ok := job.Filter.Parameters["type"].(string)
	if !ok {
		return reader, errors.New("missing required parameter: type")
	}

	export.populateCache()

	if export.templates == nil {
		return reader, errors.New("failed to load templates for export")
	}

	// Generate export content
	switch exportType {
	case "tabular":
		records, err := export.getTabularData(job)
		if err != nil {
			return reader, fmt.Errorf("failed to generate tabular data: %v", err)
		}

		csvReader, size, err := export.convertToCsv(records, export.csvSeparator)
		if err != nil {
			return reader, fmt.Errorf("failed to generate CSV: %v", err)
		}

		job.Size = size
		job.FileExtension = "csv"

		// Return content as reader
		return io.NopCloser(csvReader), nil
	case "case":
		exportId, ok := job.Filter.Parameters["id"].(string)
		if !ok {
			return reader, errors.New("missing required parameter: id")
		}

		// Generate report content
		content, err := export.generateCaseReport(exportId)
		if err != nil {
			return reader, fmt.Errorf("failed to generate case report markdown: %v", err)
		}

		params := export.getCaseExportParams(export.templatePath)
		pdfReader, size, err := export.convertMdToPdf(job.Id, content, params)
		if err != nil {
			return reader, fmt.Errorf("failed to generate PDF: %v", err)
		}

		job.Size = size
		job.FileExtension = "pdf"

		// Return content as reader
		return io.NopCloser(pdfReader), nil
	case "assistant_session":
		sessionId, ok := job.Filter.Parameters["id"].(string)
		if !ok {
			return reader, errors.New("missing required parameter: id")
		}

		// Generate report content
		content, err := export.generateAssistantSessionReport(sessionId)
		if err != nil {
			return reader, fmt.Errorf("failed to generate assistant session report markdown: %v", err)
		}

		params := export.getAssistantSessionExportParams(export.templatePath)
		pdfReader, size, err := export.convertMdToPdf(job.Id, content, params)
		if err != nil {
			return reader, fmt.Errorf("failed to generate PDF: %v", err)
		}

		job.Size = size
		job.FileExtension = "pdf"

		// Return content as reader
		return io.NopCloser(pdfReader), nil
	case "productivity":
		// Generate report content
		content, err := export.generateProductivityReport(job)
		if err != nil {
			return reader, fmt.Errorf("failed to generate productivity report markdown: %v", err)
		}

		params := export.getProductivityExportParams(export.templatePath)
		pdfReader, size, err := export.convertMdToPdf(job.Id, content, params)
		if err != nil {
			return reader, fmt.Errorf("failed to generate PDF: %v", err)
		}

		job.Size = size
		job.FileExtension = "pdf"

		// Return content as reader
		return io.NopCloser(pdfReader), nil
	default:
		templateName := exportType
		if templateName == "" {
			return reader, fmt.Errorf("missing required parameter: template for export type %s", exportType)
		} else if strings.Contains(templateName, "/") {
			return reader, fmt.Errorf("invalid template type %s", exportType)
		}

		// Generate report content
		content, err := export.generateGenericReport(job, templateName)
		if err != nil {
			return reader, fmt.Errorf("failed to generate generic report markdown: %v", err)
		}

		params := export.getPdfExportParams(filepath.Join(export.templatePath, "custom"), templateName)

		pdfReader, size, err := export.convertMdToPdf(job.Id, content, params)
		if err != nil {
			return reader, fmt.Errorf("failed to generate PDF: %v", err)
		}

		job.Size = size
		job.FileExtension = "pdf"

		// Return content as reader
		return io.NopCloser(pdfReader), nil
	}
}

func (export *Export) populateCache() {
	if export.lastRefreshTime.IsZero() || time.Since(export.lastRefreshTime) > time.Millisecond*time.Duration(export.cacheRefreshIntervalMs) {
		export.populateUsersCache()
		export.populateTemplatesCache()
		export.lastRefreshTime = time.Now()
	}
}

func (export *Export) populateUsersCache() {
	log.Info("Refreshing user cache for export module")
	userMap := make(map[string]*model.User)
	var users []*model.User
	found, err := export.agent.Client.SendAuthorizedObject("GET", "/api/users", nil, &users)
	if err != nil {
		log.WithError(err).Error("Failed to fetch users during export cache refresh")
		return
	}
	if !found {
		log.Warn("Users not found during export cache refresh")
		return
	}

	for _, user := range users {
		userMap[user.Id] = user
	}
	export.usersById = userMap
}

func (export *Export) populateTemplatesCache() {
	log.WithFields(log.Fields{
		"templatePath": export.templatePath,
	}).Info("Refreshing templates cache for export module")
	master := template.New("export").Funcs(template.FuncMap{
		"getUserDetail":               export.getUserDetail,
		"formatDateTime":              export.formatDateTime,
		"join":                        strings.Join,
		"lower":                       strings.ToLower,
		"upper":                       strings.ToUpper,
		"sortHistory":                 export.sortHistory,
		"sortComments":                export.sortComments,
		"sortRelatedEvents":           export.sortRelatedEvents,
		"sortArtifacts":               export.sortArtifacts,
		"sortDetections":              export.sortDetections,
		"sortMetrics":                 export.sortMetrics,
		"sortAssistantMessages":       export.sortAssistantMessages,
		"sortAssistantSessionDetails": export.SortAssistantSessionDetails,
		"formatNumber":                export.formatNumber,
		"parseJSON":                   export.parseJSON,
		"toJSON":                      export.toJSON,
		"add":                         export.add,
		"stripEmoji":                  export.stripEmoji,
	})

	var err error
	export.templates, err = master.ParseGlob(export.templatePath + "/**/*.md")
	if err != nil {
		log.WithError(err).Error("Failed to parse templates during export cache refresh")
		return
	}

	log.WithField("templateNames", export.templates.DefinedTemplates()).Info("Loaded export templates")
}

func (export *Export) formatNumber(format string, language string, value interface{}) string {
	printer := message.NewPrinter(message.MatchLanguage(language))
	return printer.Sprintf(format, value)
}

func (export *Export) formatDateTime(format string, t *time.Time) string {
	return t.Format(format)
}

func (export *Export) getUserDetail(attr string, userId string) string {
	if user, exists := export.usersById[userId]; exists {
		switch strings.ToLower(attr) {
		case "email":
			return user.Email
		case "firstname":
			return user.FirstName
		case "lastname":
			return user.LastName
		case "note":
			return user.Note
		case "oidcstatus":
			return user.OidcStatus
		case "status":
			return user.Status
		case "searchusername":
			return user.SearchUsername
		case "roles":
			return strings.Join(user.Roles, ", ")
		}
	}
	return userId
}

func (export *Export) prepareKeyForTemplate(key string) string {
	return strings.ReplaceAll(key, ".", "_")
}

func (export *Export) parseJSON(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	var jsonBytes []byte
	switch v := data.(type) {
	case []byte:
		jsonBytes = v
	case string:
		jsonBytes = []byte(v)
	case json.RawMessage:
		jsonBytes = []byte(v)
	default:
		log.WithField("type", fmt.Sprintf("%T", data)).Warn("parseJSON received unexpected type")
		return result
	}

	if len(jsonBytes) == 0 {
		log.Debug("parseJSON received empty JSON bytes")
		return result
	}

	err := json.Unmarshal(jsonBytes, &result)
	if err != nil {
		log.WithError(err).WithField("json", string(jsonBytes)).Warn("Failed to parse JSON in template")
		return result
	}

	log.WithFields(log.Fields{
		"parsedKeys": len(result),
		"json":       string(jsonBytes),
	}).Debug("Successfully parsed JSON in template")

	return result
}

func (export *Export) toJSON(data interface{}) string {
	if data == nil {
		return ""
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.WithError(err).WithField("type", fmt.Sprintf("%T", data)).Warn("Failed to marshal data to JSON in template")
		return fmt.Sprintf("%v", data)
	}

	return string(jsonBytes)
}

func (export *Export) add(a, b int) int {
	return a + b
}

func (export *Export) stripEmoji(text string) string {
	// Remove emoji and other non-ASCII characters that don't render well in PDFs
	// This regex matches common emoji ranges
	emojiPattern := regexp.MustCompile(`[\x{1F600}-\x{1F64F}]|[\x{1F300}-\x{1F5FF}]|[\x{1F680}-\x{1F6FF}]|[\x{1F1E0}-\x{1F1FF}]|[\x{2600}-\x{26FF}]|[\x{2700}-\x{27BF}]|[\x{FE00}-\x{FE0F}]|[\x{1F900}-\x{1F9FF}]|[\x{1F018}-\x{1F270}]|[\x{238C}-\x{2454}]|[\x{20D0}-\x{20FF}]`)
	return emojiPattern.ReplaceAllString(text, "")
}

/* getParamsFromTemplate retrieves parameters from a template file.
 * It looks for lines containing specific prefixes and suffixes to extract
 * the parameters defined in the template.
 * It returns a slice of strings containing the parameters.
 *
 * @param filepath: The path to the template file
 * @param param:  Tag indicating that the line contains a single parameter (e.g., "pdf_param:")
 * @param params: Tag indicating that the line contains multiple parameters (e.g., "pdf_params:")
 */
func (export *Export) getParamsFromTemplate(filepath string, param string, params string) []string {
	if len(params) == 0 && len(param) == 0 {
		log.Error("No parameters specified for template parameter extraction")
		return []string{}
	}

	if len(filepath) == 0 {
		log.Error("No template filepath specified for parameter extraction")
		return []string{}
	}

	file, err := os.Open(filepath)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"templateFilepath":   filepath,
			"templateParamName":  param,
			"templateParamsName": params,
		}).Error("Failed to open template file to find parameters")
		return []string{}
	}

	if len(param) > 0 {
		param = "/* " + param
	}
	if len(params) > 0 {
		params = "/* " + params
	}

	args := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(params) > 0 && strings.Contains(line, params) && strings.Contains(line, "*/") {
			startIdx := strings.Index(line, params) + len(params)
			endIdx := startIdx + strings.Index(line[startIdx:], "*/")
			line = strings.TrimSpace(line[startIdx:endIdx])
			args = append(args, strings.Fields(line)...)
		} else if len(param) > 0 && strings.Contains(line, param) && strings.Contains(line, "*/") {
			startIdx := strings.Index(line, param) + len(param)
			endIdx := startIdx + strings.Index(line[startIdx:], "*/")
			line = strings.TrimSpace(line[startIdx:endIdx])
			args = append(args, line)
		}
	}
	return args
}

func (export *Export) getPdfExportParams(templatePath string, templateName string) []string {
	path := filepath.Join(templatePath, templateName)
	return export.getParamsFromTemplate(path, "pdf_param:", "pdf_params:")
}

func (export *Export) CleanupJob(job *model.Job) {
}

func (export *Export) GetDataEpoch() time.Time {
	return time.Now()
}

func (export *Export) queryEventData(query string, filter *model.Filter, metricLimit int, eventLimit int, results *model.EventSearchResults) (bool, error) {
	timezone := "UTC"
	if zone, ok := filter.Parameters["timezone"]; ok {
		timezone = zone.(string)
	}
	if filter.EndTime.IsZero() || filter.EndTime.Before(filter.BeginTime) {
		log.WithFields(log.Fields{
			"beginTime": filter.BeginTime,
			"endTime":   filter.EndTime,
			"timezone":  timezone,
		}).Info("Invalid time range for event query; defaulting to all time")
		filter.EndTime = time.Date(2999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	stdDateTimeFormat := "2006-01-02 3:04:05 PM"
	timerange := filter.BeginTime.Format(stdDateTimeFormat) + " - " + filter.EndTime.Format(stdDateTimeFormat)
	uri := fmt.Sprintf("/api/events/?query=%s&range=%s&format=%s&zone=%s&metricLimit=%d&eventLimit=%d",
		url.QueryEscape(query),
		url.QueryEscape(timerange),
		url.QueryEscape(stdDateTimeFormat),
		timezone,
		metricLimit,
		eventLimit,
	)

	exists, reqerr := export.agent.Client.SendAuthorizedObject("GET", uri, nil, results)
	if exists && reqerr == nil {
		for key, value := range results.Metrics {
			newKey := export.prepareKeyForTemplate(key)
			results.Metrics[newKey] = value
		}
	}

	return exists, reqerr
}

func (export *Export) addMetric(metrics []*model.EventMetric, keys []interface{}, value float64) []*model.EventMetric {
	for _, metric := range metrics {
		existingKeys := fmt.Sprintf("%v", metric.Keys)
		keysStr := fmt.Sprintf("%v", keys)

		if len(metric.Keys) == len(keys) && existingKeys == keysStr {
			metric.Value += value
			return metrics
		}
	}
	// If not found, add a new metric
	newMetric := &model.EventMetric{
		Keys:  keys,
		Value: value,
	}
	return append(metrics, newMetric)
}

func (export *Export) expandMetrics(metrics []*model.EventMetric) []*model.EventMetric {
	total := 0.0
	for _, metric := range metrics {
		total += metric.Value
	}
	return export.expandMetricsWithTotal(metrics, total)
}

func (export *Export) expandMetricsWithTotal(metrics []*model.EventMetric, actualTotal float64) []*model.EventMetric {
	for _, metric := range metrics {
		metric.Ratio = metric.Value / actualTotal
		metric.Percentage = metric.Ratio * 100.0
	}
	return metrics
}

func stripTrailingSlash(path string) string {
	if len(path) > 0 && path[len(path)-1] == '/' {
		return path[:len(path)-1]
	}
	return path
}

func (export *Export) getMetricLimit(job *model.Job) int {
	if value, valid := export.parseJobParameterInt(job, "metricLimit"); valid {
		return value
	}
	if export.exportMetricLimit > 0 {
		return export.exportMetricLimit
	}
	return DEFAULT_METRIC_LIMIT
}

func (export *Export) getEventLimit(job *model.Job) int {
	if value, valid := export.parseJobParameterInt(job, "eventLimit"); valid {
		return value
	}
	if export.exportEventLimit > 0 {
		return export.exportEventLimit
	}
	return DEFAULT_EVENT_LIMIT
}

func (export *Export) parseJobParameterInt(job *model.Job, paramName string) (int, bool) {
	if limit, exists := job.Filter.Parameters[paramName]; exists {
		if limitInt, ok := limit.(int); ok && limitInt > 0 {
			return limitInt, true
		}
		if limitStr, ok := limit.(string); ok && limitStr != "" {
			val, err := strconv.Atoi(limitStr)
			if err == nil {
				return val, true
			}
		}
		log.WithFields(log.Fields{
			"specifiedIntValue": limit,
			"jobId":             job.Id,
		}).Warn("Invalid integer job parameter")
	}
	return 0, false
}
