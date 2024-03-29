// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

const DEFAULT_GROUP_FETCH_LIMIT = 10
const DEFAULT_EVENT_FETCH_LIMIT = 100
const DEFAULT_RELATIVE_TIME_VALUE = 24
const DEFAULT_RELATIVE_TIME_UNIT = 30
const DEFAULT_SAFE_STRING_MAX_LENGTH = 100
const DEFAULT_CHART_LABEL_MAX_LENGTH = 35
const DEFAULT_CHART_LABEL_OTHER_LIMIT = 10
const DEFAULT_CHART_LABEL_FIELD_SEPARATOR = ", "

type ClientParameters struct {
	HuntingParams       HuntingParameters   `json:"hunt"`
	AlertingParams      HuntingParameters   `json:"alerts"`
	CasesParams         HuntingParameters   `json:"cases"`
	CaseParams          CaseParameters      `json:"case"`
	DashboardsParams    HuntingParameters   `json:"dashboards"`
	JobParams           HuntingParameters   `json:"job"`
	DetectionsParams    DetectionParameters `json:"detections"`
	DetectionParams     DetectionParameters `json:"detection"`
	PlaybooksParams     HuntingParameters   `json:"playbooks"`
	DocsUrl             string              `json:"docsUrl"`
	CheatsheetUrl       string              `json:"cheatsheetUrl"`
	ReleaseNotesUrl     string              `json:"releaseNotesUrl"`
	GridParams          GridParameters      `json:"grid"`
	WebSocketTimeoutMs  int                 `json:"webSocketTimeoutMs"`
	TipTimeoutMs        int                 `json:"tipTimeoutMs"`
	ApiTimeoutMs        int                 `json:"apiTimeoutMs"`
	CacheExpirationMs   int                 `json:"cacheExpirationMs"`
	InactiveTools       []string            `json:"inactiveTools"`
	Tools               []ClientTool        `json:"tools"`
	CasesEnabled        bool                `json:"casesEnabled"`
	EnableReverseLookup bool                `json:"enableReverseLookup"`
	DetectionsEnabled   bool                `json:"detectionsEnabled"`
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

type DetectionParameters struct {
	HuntingParameters
	Presets              map[string]PresetParameters `json:"presets"`
	SeverityTranslations map[string]string           `json:"severityTranslations"`
}

func (params *DetectionParameters) Verify() error {
	err := params.HuntingParameters.Verify()

	return err

}
