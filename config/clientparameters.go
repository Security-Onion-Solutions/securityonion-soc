// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
	HuntingParams			HuntingParameters			`json:"hunt"`
	AlertingParams			HuntingParameters			`json:"alerts"`
}

func (config *ClientParameters) Verify() error {
	var err error
	err = config.HuntingParams.Verify()
	return err
}

type HuntingQuery struct {
	Name		string		`json:"name"`
	Description	string		`json:"description"`
	Query		string		`json:"query"`
}

type HuntingAction struct {
	Name		string		`json:"name"`
	Description	string		`json:"description"`
	Icon		string		`json:"icon"`
	Link		string		`json:"link"`
	Fields		[]string	`json:"fields"`
	Target		string		`json:"target"`
}

type HuntingParameters struct {
	GroupItemsPerPage      	int  					`json:"groupItemsPerPage"`
	GroupFetchLimit      	int  					`json:"groupFetchLimit"`
	EventItemsPerPage      	int  					`json:"eventItemsPerPage"`
	EventFetchLimit      	int       				`json:"eventFetchLimit"`
	RelativeTimeValue		int						`json:"relativeTimeValue"`
	RelativeTimeUnit		int						`json:"relativeTimeUnit"`
	MostRecentlyUsedLimit	int						`json:"mostRecentlyUsedLimit"`
	EventFields				map[string][]string		`json:"eventFields"`
	QueryPrefix				string					`json:"queryPrefix"`
	QuerySuffix				string					`json:"querySuffix"`
	Queries					[]HuntingQuery			`json:"queries"`
	Actions					[]HuntingAction			`json:"actions"`
	Advanced				bool					`json:"advanced"`
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
	return err
}

