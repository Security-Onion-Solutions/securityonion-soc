// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
)

type EventResults struct {
	// The date and time when the search was submitted
	CreateTime time.Time `json:"createTime" example:"2024-12-04T19:54:33.519514906Z"`
	// The date and time when the search completed
	CompleteTime time.Time `json:"completeTime" example:"2024-12-04T19:54:33.822293482Z"`
	// The number of milliseconds it took to complete the search
	ElapsedMs int `json:"elapsedMs" example:"299"`
	// A list of errors that the search encountered. The presence of errors does not necessarily preclude the search from returning events."
	Errors []string `json:"errors" example:"all shards failed"`
}

func (results *EventResults) initEventResults() {
	results.CreateTime = time.Now()
	results.Errors = make([]string, 0)
}

func (results *EventResults) Complete() {
	results.CompleteTime = time.Now()
}

type EventSearchResults struct {
	EventResults
	// The search criteria used in to locate these search results
	Criteria *EventSearchCriteria `json:"criteria"`
	// The total number of matching events (not necessarily the total number returned)
	TotalEvents int `json:"totalEvents" example:"5109848"`
	// The events that matched the search criteria (limited to the specified eventLimit value, or the max result length as configured in the backend data server)
	Events []*EventRecord `json:"events"`
	// The collection of aggregated metrics associated with this search
	Metrics map[string]([]*EventMetric) `json:"metrics"`
}

func NewEventSearchResults() *EventSearchResults {
	results := &EventSearchResults{
		Events:  make([]*EventRecord, 0),
		Metrics: make(map[string]([]*EventMetric)),
	}
	results.initEventResults()
	return results
}

type SortCriteria struct {
	// The field to sort on
	Field string `example:"some_field_name"`
	// The direction of the sort: asc, desc
	Order string `example:"asc"`
}

type EventSearchCriteria struct {
	// The base query used to conduct the event search
	RawQuery string `json:"query" example:"(*) AND tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true | groupby rule.name event.module* event.severity_label rule.uuid"`
	// The date range to use for searching for matching events
	DateRange string `json:"dateRange" example:""`
	// The maximum number of metrics to limit in aggregate groups
	MetricLimit int `json:"metricLimit" example:"10"`
	// The maximum number of events to retrieve
	EventLimit int `json:"eventLimit" example:"100"`
	// The start of the search time range, in the requestor's timezone
	BeginTime time.Time `example:"2024-12-03T14:31:35-05:00"`
	// The end of the search time range, in the requestor's timezone
	EndTime time.Time `example:"2024-12-04T14:31:35-05:00"`
	// The UTC date and time when the search request was submitted
	CreateTime  time.Time       `example:"2024-12-04T19:31:42.73865332Z"`
	ParsedQuery *Query          `json:"-"`
	SortFields  []*SortCriteria `json:"-"`
	SearchAfter []interface{}   `json:"-"`
}

func (criteria *EventSearchCriteria) initSearchCriteria() {
	criteria.CreateTime = time.Now()
	criteria.ParsedQuery = NewQuery()
	criteria.EventLimit = 25
	criteria.MetricLimit = 10
}

func NewEventSearchCriteria() *EventSearchCriteria {
	criteria := &EventSearchCriteria{}
	criteria.initSearchCriteria()
	return criteria
}

func (criteria *EventSearchCriteria) Populate(query string, dateRange string, dateRangeFormat string, timezone string, metricLimit string, eventLimit string) (err error) {
	criteria.RawQuery = strings.Trim(query, " ")

	criteria.BeginTime, criteria.EndTime, err = util.ParseDateRange(dateRange, dateRangeFormat, timezone)

	if err == nil {
		criteria.MetricLimit, err = strconv.Atoi(metricLimit)
	}
	if err == nil {
		criteria.EventLimit, err = strconv.Atoi(eventLimit)
	}

	if err == nil {
		err = criteria.ParsedQuery.Parse(query)
	}

	return err
}

type EventMetric struct {
	// The field or fields (compound key) associated with this metric. Commonly referenced as "buckets".
	Keys []interface{} `json:"keys" example:"23.1.45.212,54.3.1.120"`
	// The computed metric value
	Value float64 `json:"value" example:"55"`

	// Calculated fields for reporting
	Ratio      float64
	Percentage float64
}

type EventRecord struct {
	// The source index of the event
	Source string `json:"source" example:"so:.ds-logs-zeek-so-2024.11.21-000017"`
	// The parsed event time
	Time time.Time `example:"2024-12-04T20:08:15.97Z"`
	// The event timestamp
	Timestamp string `json:"timestamp" example:"2024-12-04T20:08:15.970Z"`
	// The event's unique document ID
	Id string `json:"id" example:"ru5Jk5MB4OVrR03M8ee8"`
	// The type of event, often left blank
	Type string `json:"type" example:""`
	// The score of the event, often left 0
	Score float64 `json:"score" example:"0"`
	// The event data fields
	Payload map[string]interface{} `json:"payload" example:"@timestamp:2024-12-04T20:06:04.725Z,@version:1,client.ip:4.33.51.1,client.port:5544"`
	// The values used for the purposes of sorting across the returned event list
	Sort []interface{} `json:"sort" example:"0:33.32.12.56"`
}

type EventUpdateCriteria struct {
	EventSearchCriteria
	// Any scripts used in the event update
	UpdateScripts []string `json:"updateScripts" example:"<Painless Script Syntax>"`
	// Whether the update was performed asynchronously or not
	Asynchronous bool `json:"async" example:"false"`
}

func NewEventUpdateCriteria() *EventUpdateCriteria {
	criteria := &EventUpdateCriteria{}
	criteria.initSearchCriteria()
	return criteria
}

func (criteria *EventUpdateCriteria) AddUpdateScript(script string) {
	criteria.UpdateScripts = append(criteria.UpdateScripts, script)
}

type EventUpdateResults struct {
	EventResults
	// The criteria used for performing the update
	Criteria *EventUpdateCriteria `json:"criteria"`
	// The number of events that were updated
	UpdatedCount int `json:"updatedCount" example:"1"`
	// The number of events the were left unmodified
	UnchangedCount int `json:"unchangedCount" example:"0"`
}

func NewEventUpdateResults() *EventUpdateResults {
	results := &EventUpdateResults{}
	results.initEventResults()
	return results
}

func (results *EventUpdateResults) AddEventUpdateResults(newResults *EventUpdateResults) {
	results.UpdatedCount += newResults.UpdatedCount
	results.UnchangedCount += newResults.UnchangedCount
	results.ElapsedMs += newResults.ElapsedMs
}

type EventAckCriteria struct {
	// The search filter to utilize when searching for matching events to acknowledge.
	SearchFilter string `json:"searchFilter" example:"tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true | groupby rule.name event.module* event.severity_label rule.uuid"`
	// Optional event filters to further narrow down matching events to acknowledge. These are field:value pairs.
	EventFilter map[string]interface{} `json:"eventFilter" example:"event.module:sigma,rule.name:Security Onion - SOC Login Failure,rule.uuid:bf86ef21-41e6-417b-9a05-b9ea6bf28a38"`
	// The date range to use for searching for matching events
	DateRange string `json:"dateRange" example:"2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM"`
	// The date range format. If unsure how to use this then use the example value exactly as shown.
	DateRangeFormat string `json:"dateRangeFormat" example:"2006/01/02 3:04:05 PM"`
	// The timezone to use with the date range
	Timezone string `json:"timezone" example:"America/New_York"`
	// Whether the events have also been escalated to a case: true = escalated, false = has not been escalated
	Escalate bool `json:"escalate" example:"false"`
	// Whether to acknowledge or unacknowledge the events: true = acknowledge, false = unacknowledge
	Acknowledge bool `json:"acknowledge" example:"true"`
}

func NewEventAckCriteria() *EventAckCriteria {
	return &EventAckCriteria{}
}

type EventIndexResults struct {
	Success    bool   `json:"success"`
	DocumentId string `json:"id"`
}

func NewEventIndexResults() *EventIndexResults {
	results := &EventIndexResults{}
	return results
}

type EventScrollCriteria struct {
	RawQuery    string `json:"query"`
	BeginTime   time.Time
	EndTime     time.Time
	CreateTime  time.Time
	ParsedQuery *Query
	SortFields  []*SortCriteria
}

type EventScrollResults struct {
	EventResults
	Criteria    *EventScrollCriteria `json:"criteria"`
	TotalEvents int                  `json:"totalEvents"`
	Events      []*EventRecord       `json:"events"`
}

func NewEventScrollResults() *EventScrollResults {
	results := &EventScrollResults{
		Events: make([]*EventRecord, 0),
	}
	results.initEventResults()
	return results
}

func (criteria *EventScrollCriteria) initScrollCriteria() {
	criteria.CreateTime = time.Now()
	criteria.ParsedQuery = NewQuery()
}

func NewEventScrollCriteria() *EventScrollCriteria {
	criteria := &EventScrollCriteria{}
	criteria.initScrollCriteria()
	return criteria
}

func (criteria *EventScrollCriteria) Populate(query string, dateRange string, dateRangeFormat string, timezone string) error {
	var err error
	criteria.RawQuery = strings.Trim(query, " ")

	datePieces := strings.SplitN(dateRange, " - ", 2)

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.WithField("timezone", timezone).Info("Invalid timezone provided by client")
		loc, _ = time.LoadLocation("UTC")
	}

	if len(datePieces) == 2 {
		criteria.BeginTime, err = time.ParseInLocation(dateRangeFormat, strings.Trim(datePieces[0], " "), loc)

		if err == nil {
			criteria.EndTime, err = time.ParseInLocation(dateRangeFormat, strings.Trim(datePieces[1], " "), loc)
		}
	} else {
		criteria.EndTime = time.Now()
		criteria.BeginTime = criteria.EndTime.Add(time.Duration(-24) * time.Hour)
	}

	if err == nil {
		err = criteria.ParsedQuery.Parse(query)
	}

	return err
}

type EventMSearchCriteria struct {
	Index       string
	RawQuery    string
	ParsedQuery *Query
}

func NewEventMSearchCriteria() *EventMSearchCriteria {
	criteria := &EventMSearchCriteria{}
	criteria.ParsedQuery = NewQuery()

	return criteria
}

func (criteria *EventMSearchCriteria) Populate(index string, query string) error {
	criteria.Index = index

	criteria.RawQuery = strings.TrimSpace(query)
	err := criteria.ParsedQuery.Parse(query)

	return err
}

type EventMSearchResults struct {
	ElapsedMs int                   `json:"elapsedMs"`
	Responses []*EventSearchResults `json:"responses"`
}

func NewEventMSearchResults() *EventMSearchResults {
	results := &EventMSearchResults{
		Responses: make([]*EventSearchResults, 0),
	}

	return results
}
