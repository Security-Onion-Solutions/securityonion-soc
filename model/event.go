// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
  "strconv"
  "strings"
  "time"
  "github.com/apex/log"
)

type EventAckCriteria struct {
  Event           map[string]interface{} `json:"event"`
  Escalate        bool              `json:"escalate"`
}

type EventSearchCriteria struct {
  RawQuery        string    	`json:"query"`
  DateRange       string      `json:"dateRange"`
  MetricLimit     int         `json:"metricLimit"`
  EventLimit      int         `json:"eventLimit"`
  BeginTime		    time.Time		
  EndTime			    time.Time		
  CreateTime      time.Time
  ParsedQuery     *Query
}

func NewEventSearchCriteria() *EventSearchCriteria {
  return &EventSearchCriteria{
    CreateTime: time.Now(),
    ParsedQuery: NewQuery(),
    EventLimit: 25,
    MetricLimit: 10,
  }
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
  Keys          []interface{}           `json:"keys"`
  Value         int                     `json:"value"`
}

type EventRecord struct {
  Source        string                  `json:"source"`
  Timestamp     string                  `json:"timestamp"`
  Id            string                  `json:"id"`
  Type          string                  `json:"type"`
  Score         float64                 `json:"score"`
  Payload       map[string]interface{}  `json:"payload"`
}

type EventSearchResults struct {
  Criteria		      *EventSearchCriteria	      `json:"criteria"`
  TotalEvents       int                         `json:"totalEvents"`
  Events            []*EventRecord              `json:"events"`
  Metrics           map[string]([]*EventMetric) `json:"metrics"`
  CreateTime	      time.Time			              `json:"createTime"`
  CompleteTime	    time.Time			              `json:"completeTime"`
  FetchElapsedMs    int                         `json:"fetchElapsedMs"`
}

func NewEventSearchResults() *EventSearchResults {
  return &EventSearchResults{
    CreateTime: time.Now(),
    Events: make([]*EventRecord, 0, 0),
    Metrics: make(map[string]([]*EventMetric)),
  }
}

func (results *EventSearchResults) Complete() {
  results.CompleteTime = time.Now()
}