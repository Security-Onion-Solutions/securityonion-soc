// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package config

const DEFAULT_GROUP_FETCH_LIMIT = 10
const DEFAULT_EVENT_FETCH_LIMIT = 100
const DEFAULT_RELATIVE_TIME_VALUE = 24
const DEFAULT_RELATIVE_TIME_UNIT = 30
const DEFAULT_MOST_RECENTLY_USED_LIMIT = 5

type ClientParameters struct {
	HuntingParams      HuntingParameters `json:"hunt"`
	AlertingParams     HuntingParameters `json:"alerts"`
	JobParams          HuntingParameters `json:"job"`
	DocsUrl            string            `json:"docsUrl"`
	CheatsheetUrl      string            `json:"cheatsheetUrl"`
	ReleaseNotesUrl    string            `json:"releaseNotesUrl"`
	GridParams         GridParameters    `json:"grid"`
	WebSocketTimeoutMs int               `json:"webSocketTimeoutMs"`
	TipTimeoutMs       int               `json:"tipTimeoutMs"`
	ApiTimeoutMs       int               `json:"apiTimeoutMs"`
	CacheExpirationMs  int               `json:"cacheExpirationMs"`
	InactiveTools      []string          `json:"inactiveTools"`
	Tools              []ClientTool      `json:"tools"`
}

func (config *ClientParameters) Verify() error {
	if err := config.HuntingParams.Verify(); err != nil {
		return err
	}
	if err := config.AlertingParams.Verify(); err != nil {
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
	Name        string `json:"name"`
	Description string `json:"description"`
	Query       string `json:"query"`
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
	GroupItemsPerPage     int                 `json:"groupItemsPerPage"`
	GroupFetchLimit       int                 `json:"groupFetchLimit"`
	EventItemsPerPage     int                 `json:"eventItemsPerPage"`
	EventFetchLimit       int                 `json:"eventFetchLimit"`
	RelativeTimeValue     int                 `json:"relativeTimeValue"`
	RelativeTimeUnit      int                 `json:"relativeTimeUnit"`
	MostRecentlyUsedLimit int                 `json:"mostRecentlyUsedLimit"`
	EventFields           map[string][]string `json:"eventFields"`
	QueryBaseFilter       string              `json:"queryBaseFilter"`
	QueryToggleFilters    []*ToggleFilter     `json:"queryToggleFilters"`
	Queries               []*HuntingQuery     `json:"queries"`
	Actions               []*HuntingAction    `json:"actions"`
	Advanced              bool                `json:"advanced"`
	AckEnabled            bool                `json:"ackEnabled"`
	EscalateEnabled       bool                `json:"escalateEnabled"`
}

type GridParameters struct {
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
	if params.MostRecentlyUsedLimit < 10 {
		params.MostRecentlyUsedLimit = DEFAULT_MOST_RECENTLY_USED_LIMIT
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
