// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

const DEFAULT_GROUP_FETCH_LIMIT = 10
const DEFAULT_EVENT_FETCH_LIMIT = 100
const DEFAULT_RELATIVE_TIME_VALUE = 24
const DEFAULT_RELATIVE_TIME_UNIT = 30
const DEFAULT_SAFE_STRING_MAX_LENGTH = 100
const DEFAULT_CHART_LABEL_MAX_LENGTH = 35
const DEFAULT_CHART_LABEL_OTHER_LIMIT = 10
const DEFAULT_CHART_LABEL_FIELD_SEPARATOR = ", "

type ClientParameters struct {
	HuntingParams      HuntingParameters    `json:"hunt"`
	AlertingParams     AlertingParameters   `json:"alerts"`
	CasesParams        HuntingParameters    `json:"cases"`
	CaseParams         CaseParameters       `json:"case"`
	DashboardsParams   HuntingParameters    `json:"dashboards"`
	JobParams          HuntingParameters    `json:"job"`
	DetectionsParams   DetectionsParameters `json:"detections"`
	DetectionParams    DetectionParameters  `json:"detection"`
	DocsUrl            string               `json:"docsUrl"`
	CheatsheetUrl      string               `json:"cheatsheetUrl"`
	ReleaseNotesUrl    string               `json:"releaseNotesUrl"`
	GridParams         GridParameters       `json:"grid"`
	WebSocketTimeoutMs int                  `json:"webSocketTimeoutMs"`
	TipTimeoutMs       int                  `json:"tipTimeoutMs"`
	ApiTimeoutMs       int                  `json:"apiTimeoutMs"`
	CacheExpirationMs  int                  `json:"cacheExpirationMs"`
	InactiveTools      []string             `json:"inactiveTools"`
	Tools              []ClientTool         `json:"tools"`
	CasesEnabled       bool                 `json:"casesEnabled"`
	DetectionsEnabled  bool                 `json:"detectionsEnabled"`
	ExportNodeId       string               `json:"exportNodeId"`
	AssistantParams    AssistantParameters  `json:"assistant"`
}

func (config *ClientParameters) Verify() error {
	if err := config.HuntingParams.Verify(); err != nil {
		return err
	}
	if err := config.AlertingParams.Verify(); err != nil {
		return err
	}
	if err := config.CasesParams.Verify(); err != nil {
		return err
	}
	if err := config.DashboardsParams.Verify(); err != nil {
		return err
	}
	return config.JobParams.Verify()
}

type ClientTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Icon        string `json:"icon"`
	Link        string `json:"link"`
}

type HuntingQuery struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Query        string `json:"query"`
	ShowSubtitle bool   `json:"showSubtitle"`
}

type HuntingAction struct {
	Name                  string                 `json:"name"`
	Description           string                 `json:"description"`
	Icon                  string                 `json:"icon"`
	Link                  string                 `json:"link"`
	Links                 []string               `json:"links"`
	Fields                []string               `json:"fields"`
	Target                string                 `json:"target"`
	Background            bool                   `json:"background"`
	BackgroundSuccessLink string                 `json:"backgroundSuccessLink"`
	BackgroundFailureLink string                 `json:"backgroundFailureLink"`
	Method                string                 `json:"method"`
	Body                  string                 `json:"body"`
	Options               map[string]interface{} `json:"options"`
	Categories            []string               `json:"categories"`
	JSCall                string                 `json:"jsCall"`
}

type ToggleFilter struct {
	Name            string   `json:"name"`
	Filter          string   `json:"filter"`
	Enabled         bool     `json:"enabled"`
	Exclusive       bool     `json:"exclusive"`
	EnablesToggles  []string `json:"enablesToggles"`
	DisablesToggles []string `json:"disablesToggles"`
}

type HuntingParameters struct {
	GroupItemsPerPage            int                 `json:"groupItemsPerPage"`
	GroupFetchLimit              int                 `json:"groupFetchLimit"`
	EventItemsPerPage            int                 `json:"eventItemsPerPage"`
	EventFetchLimit              int                 `json:"eventFetchLimit"`
	RelativeTimeValue            int                 `json:"relativeTimeValue"`
	RelativeTimeUnit             int                 `json:"relativeTimeUnit"`
	MostRecentlyUsedLimit        int                 `json:"mostRecentlyUsedLimit"`
	EventFields                  map[string][]string `json:"eventFields"`
	SafeStringMaxLength          int                 `json:"safeStringMaxLength"`
	QueryBaseFilter              string              `json:"queryBaseFilter"`
	QueryToggleFilters           []*ToggleFilter     `json:"queryToggleFilters"`
	Queries                      []*HuntingQuery     `json:"queries"`
	Actions                      []*HuntingAction    `json:"actions"`
	Advanced                     bool                `json:"advanced"`
	AckEnabled                   bool                `json:"ackEnabled"`
	EscalateEnabled              bool                `json:"escalateEnabled"`
	EscalateRelatedEventsEnabled bool                `json:"escalateRelatedEventsEnabled"`
	ViewEnabled                  bool                `json:"viewEnabled"`
	CreateLink                   string              `json:"createLink"`
	ChartLabelMaxLength          int                 `json:"chartLabelMaxLength"`
	ChartLabelOtherLimit         int                 `json:"chartLabelOtherLimit"`
	ChartLabelFieldSeparator     string              `json:"chartLabelFieldSeparator"`
	AggregationActionsEnabled    bool                `json:"aggregationActionsEnabled"`
	DetectionEngineStatusQueries string              `json:"detectionEngineStatusQueries"`
}

func (params *HuntingParameters) Verify() error {
	var err error
	if params.GroupFetchLimit <= 0 {
		params.GroupFetchLimit = DEFAULT_GROUP_FETCH_LIMIT
	}
	if params.EventFetchLimit <= 0 {
		params.EventFetchLimit = DEFAULT_EVENT_FETCH_LIMIT
	}
	if params.RelativeTimeValue <= 0 {
		params.RelativeTimeValue = DEFAULT_RELATIVE_TIME_VALUE
	}
	if params.RelativeTimeUnit <= 0 {
		params.RelativeTimeUnit = DEFAULT_RELATIVE_TIME_UNIT
	}
	if params.MostRecentlyUsedLimit < 0 {
		params.MostRecentlyUsedLimit = 0
	}
	if params.SafeStringMaxLength <= 0 {
		params.SafeStringMaxLength = DEFAULT_SAFE_STRING_MAX_LENGTH
	}
	if params.ChartLabelMaxLength <= 0 {
		params.ChartLabelMaxLength = DEFAULT_CHART_LABEL_MAX_LENGTH
	}
	if params.ChartLabelOtherLimit <= 0 {
		params.ChartLabelOtherLimit = DEFAULT_CHART_LABEL_OTHER_LIMIT
	}
	if params.ChartLabelFieldSeparator == "" {
		params.ChartLabelFieldSeparator = DEFAULT_CHART_LABEL_FIELD_SEPARATOR
	}
	params.combineDeprecatedLinkIntoLinks()
	return err
}

func (params *HuntingParameters) combineDeprecatedLinkIntoLinks() {
	for _, action := range params.Actions {
		if len(action.Link) > 0 {
			action.Links = append(action.Links, action.Link)
			action.Link = ""
		}
	}
}

type AlertingParameters struct {
	HuntingParameters
	MaxBulkEscalateEvents int `json:"maxBulkEscalateEvents"`
}

type AssistantParameters struct {
	Enabled                bool                `json:"enabled"`
	InvestigationPrompt    string              `json:"investigationPrompt"`
	CompressContextPrompt  string              `json:"compressContextPrompt"`
	ThresholdColorRatioLow float64             `json:"thresholdColorRatioLow"`
	ThresholdColorRatioMed float64             `json:"thresholdColorRatioMed"`
	ThresholdColorRatioMax float64             `json:"thresholdColorRatioMax"`
	AvailableModels        []ModelParameters   `json:"availableModels"`
	AvailableAdapters      []AdapterParameters `json:"availableAdapters"`
}

type ModelParameters struct {
	ID                    string  `json:"id"`
	DisplayName           string  `json:"displayName"`
	ContextLimitSmall     int     `json:"contextLimitSmall"`
	ContextLimitLarge     int     `json:"contextLimitLarge"`
	CharsPerTokenEstimate float64 `json:"charsPerTokenEstimate"`
	LowBalanceColorAlert  int     `json:"lowBalanceColorAlert"`
	Origin                string  `json:"origin"`
	Adapter               string  `json:"adapter"`
	Enabled               bool    `json:"enabled"`

	IsAgentic        bool     `json:"isAgentic"`
	IsOrchestrator   bool     `json:"isOrchestrator"`
	CanDelegateTo    []string `json:"canDelegateTo"`
	AllowedTools     []string `json:"allowedTools"`
	AgentPrompt      string   `json:"agentPrompt"`
	AgentDescription string   `json:"agentDescription"`
}

// Selector returns the canonical client-facing selector for this model: its
// DisplayName, which is required configuration. There is deliberately no
// fallback — a model without a DisplayName is misconfigured and gets disabled
// at startup (see validateModelSelectors).
func (m *ModelParameters) Selector() string {
	return m.DisplayName
}

// LegacySelector returns the historical "id@adapter" selector form. It exists
// only so old stored sessions and browser-side settings still resolve
// (resolveModel pass 2); it is never a model's canonical selector.
func (m *ModelParameters) LegacySelector() string {
	return m.ID + "@" + m.Adapter
}

type AdapterParameters struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// Custom unmarshal to handle numeric or scientific-notation string fields
func (m *ModelParameters) UnmarshalJSON(data []byte) error {
	type Alias ModelParameters // Prevent recursion
	aux := struct {
		ContextLimitSmall    any `json:"contextLimitSmall"`
		ContextLimitLarge    any `json:"contextLimitLarge"`
		LowBalanceColorAlert any `json:"lowBalanceColorAlert"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	parseToInt := func(v any) (int, error) {
		switch val := v.(type) {
		case float64:
			return int(val), nil
		case string:
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return 0, err
			}
			return int(math.Round(f)), nil
		case nil:
			return 0, nil
		default:
			return 0, fmt.Errorf("unexpected type %T for numeric field", v)
		}
	}

	var err error
	if m.ContextLimitSmall, err = parseToInt(aux.ContextLimitSmall); err != nil {
		return fmt.Errorf("parsing contextLimitSmall: %w", err)
	}
	if m.ContextLimitLarge, err = parseToInt(aux.ContextLimitLarge); err != nil {
		return fmt.Errorf("parsing contextLimitLarge: %w", err)
	}
	if aux.LowBalanceColorAlert != nil {
		if m.LowBalanceColorAlert, err = parseToInt(aux.LowBalanceColorAlert); err != nil {
			return fmt.Errorf("parsing LowBalanceColorAlert: %w", err)
		}
	}

	return nil
}

type PresetParameters struct {
	Labels        []string `json:"labels"`
	CustomEnabled bool     `json:"customEnabled"`
}

type CaseParameters struct {
	MostRecentlyUsedLimit  int                         `json:"mostRecentlyUsedLimit"`
	RenderAbbreviatedCount int                         `json:"renderAbbreviatedCount"`
	AnalyzerNodeId         string                      `json:"analyzerNodeId"`
	Presets                map[string]PresetParameters `json:"presets"`
}

func (params *CaseParameters) Verify() error {
	var err error
	if params.MostRecentlyUsedLimit < 0 {
		params.MostRecentlyUsedLimit = 0
	}
	return err
}

type GridParameters struct {
	MaxUploadSize  uint64 `json:"maxUploadSize,omitempty"`
	StaleMetricsMs uint64 `json:"staleMetricsMs,omitempty"`
}

type DetectionsParameters struct {
	HuntingParameters
	Presets map[string]PresetParameters `json:"presets"`
}

type DetectionParameters struct {
	Presets                   map[string]PresetParameters `json:"presets"`
	SeverityTranslations      map[string]string           `json:"severityTranslations"`
	TemplateDetections        map[string]string           `json:"templateDetections"`
	ShowUnreviewedAiSummaries bool                        `json:"showUnreviewedAiSummaries"`
}

func (params *DetectionsParameters) Verify() error {
	err := params.HuntingParameters.Verify()

	return err
}

func (params *DetectionParameters) Verify() error {
	return nil
}
