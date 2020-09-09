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
const DEFAULT_DATE_RANGE_MINUTES = 1440
const DEFAULT_MOST_RECENTLY_USED_LIMIT = 5

type ClientParameters struct {
	HuntingParams			HuntingParameters			`json:"hunt"`
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
}

type HuntingParameters struct {
	GroupFetchLimit      	int  					`json:"groupFetchLimit"`
	EventFetchLimit      	int       				`json:"eventFetchLimit"`
	DateRangeMinutes		int						`json:"dateRangeMinutes"`
	MostRecentlyUsedLimit	int						`json:"mostRecentlyUsedLimit"`
	EventFields				map[string][]string		`json:"eventFields"`
	Queries					[]HuntingQuery			`json:"queries"`
	Actions					[]HuntingAction			`json:"actions"`
}

func (params *HuntingParameters) Verify() error {
  var err error
  if params.GroupFetchLimit <= 0 {
    params.GroupFetchLimit = DEFAULT_GROUP_FETCH_LIMIT
  }
  if params.EventFetchLimit <= 0 {
    params.EventFetchLimit = DEFAULT_EVENT_FETCH_LIMIT
	}
  if params.DateRangeMinutes <= 0 {
    params.DateRangeMinutes = DEFAULT_DATE_RANGE_MINUTES
  }
  if params.MostRecentlyUsedLimit <= 0 {
    params.MostRecentlyUsedLimit = DEFAULT_MOST_RECENTLY_USED_LIMIT
  }
	return err
}

