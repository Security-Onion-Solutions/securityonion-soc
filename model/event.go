// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
)

type EventResults struct {
	CreateTime   time.Time `json:"createTime"`
	CompleteTime time.Time `json:"completeTime"`
	ElapsedMs    int       `json:"elapsedMs"`
	Errors       []string  `json:"errors"`
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
	Criteria    *EventSearchCriteria        `json:"criteria"`
	TotalEvents int                         `json:"totalEvents"`
	Events      []*EventRecord              `json:"events"`
	Metrics     map[string]([]*EventMetric) `json:"metrics"`
}

func NewEventSearchResults() *EventSearchResults {
	results := &EventSearchResults{
		Events:  make([]*EventRecord, 0, 0),
		Metrics: make(map[string]([]*EventMetric)),
	}
	results.initEventResults()
	return results
}

type SortCriteria struct {
	Field string
	Order string
}

type EventSearchCriteria struct {
	RawQuery    string `json:"query"`
	DateRange   string `json:"dateRange"`
	MetricLimit int    `json:"metricLimit"`
	EventLimit  int    `json:"eventLimit"`
	BeginTime   time.Time
	EndTime     time.Time
	CreateTime  time.Time
	ParsedQuery *Query
	SortFields  []*SortCriteria
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

func (criteria *EventSearchCriteria) Populate(query string, dateRange string, dateRangeFormat string, timezone string, metricLimit string, eventLimit string) error {
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
		criteria.DateRange = ""
		criteria.EndTime = time.Now()
		criteria.BeginTime = criteria.EndTime.Add(time.Duration(-24) * time.Hour)
	}

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
	Keys  []interface{} `json:"keys"`
	Value int           `json:"value"`
}

type EventRecord struct {
	Source    string `json:"source"`
	Time      time.Time
	Timestamp string                 `json:"timestamp"`
	Id        string                 `json:"id"`
	Type      string                 `json:"type"`
	Score     float64                `json:"score"`
	Payload   map[string]interface{} `json:"payload"`
}

type EventUpdateCriteria struct {
	EventSearchCriteria
	UpdateScripts []string `json:"updateScripts"`
	Asynchronous  bool     `json:"async"`
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
	Criteria       *EventUpdateCriteria `json:"criteria"`
	UpdatedCount   int                  `json:"updatedCount"`
	UnchangedCount int                  `json:"unchangedCount"`
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
	SearchFilter    string                 `json:"searchFilter"`
	EventFilter     map[string]interface{} `json:"eventFilter"`
	DateRange       string                 `json:"dateRange"`
	DateRangeFormat string                 `json:"dateRangeFormat"`
	Timezone        string                 `json:"timezone"`
	Escalate        bool                   `json:"escalate"`
	Acknowledge     bool                   `json:"acknowledge"`
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
