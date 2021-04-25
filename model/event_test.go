// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
	"testing"
	"time"
)

func TestNewEventSearchCriteria(tester *testing.T) {
	event := NewEventSearchCriteria()
	if event.CreateTime.IsZero() {
		tester.Errorf("expected CreateTime to be auto populated")
	}
}

func TestNewEventUpdateCriteria(tester *testing.T) {
	event := NewEventUpdateCriteria()
	if event.CreateTime.IsZero() {
		tester.Errorf("expected CreateTime to be auto populated")
	}
}

func TestPopulateQueryTrim(tester *testing.T) {
	goodTime := "2006-05-07T14:15:59+01:00 - 2006-05-07T14:16:59+01:00"
	zone := "America/New_York"
	criteria := NewEventSearchCriteria()
	_ = criteria.Populate(" foo ", goodTime, time.RFC3339, zone, "10", "100")
	if criteria.RawQuery != "foo" {
		tester.Errorf("Expected empty query string")
	}
}

func TestPopulateBadInputTimes(tester *testing.T) {
	badTime := "2006-05-07"
	goodTime := "2006-05-07T14:15:59+01:00"
	zone := "America/New_York"
	criteria := NewEventSearchCriteria()
	err := criteria.Populate("foo", badTime+" - "+badTime, time.RFC3339, zone, "10", "100")
	if err == nil {
		tester.Errorf("expected error from bad time input")
	}
	err = criteria.Populate("foo", badTime+" - "+goodTime, time.RFC3339, zone, "10", "100")
	if err == nil {
		tester.Errorf("expected error from bad begin time input")
	}
	err = criteria.Populate("foo", goodTime+" - "+badTime, time.RFC3339, zone, "10", "100")
	if err == nil {
		tester.Errorf("expected error from bad end time input")
	}
	err = criteria.Populate("foo", goodTime+" - "+goodTime, time.RFC3339, zone, "30", "100")
	if err != nil {
		tester.Errorf("expected no error from good time input: %v", err)
	}
}

func TestLimits(tester *testing.T) {
	goodTime := "2006-05-07T14:15:59+01:00"
	criteria := NewEventSearchCriteria()
	_ = criteria.Populate("foo", goodTime+" - "+goodTime, time.RFC3339, "PST", "30", "100")
	if criteria.EventLimit != 100 {
		tester.Errorf("Incorrect event limit: %d", criteria.EventLimit)
	}
	if criteria.MetricLimit != 30 {
		tester.Errorf("Incorrect event limit: %d", criteria.MetricLimit)
	}
}

func TestNewEventSearchResult(tester *testing.T) {
	event := NewEventSearchResults()
	time.Sleep(1)
	event.Complete()
	if !event.CompleteTime.After(event.CreateTime) {
		tester.Errorf("expected CompleteTime to be newer than CreateTime")
	}
	if len(event.Errors) != 0 {
		tester.Errorf("expected no errors")
	}
}

func TestNewEventUpdateResult(tester *testing.T) {
	event := NewEventUpdateResults()
	time.Sleep(1)
	event.Complete()
	if !event.CompleteTime.After(event.CreateTime) {
		tester.Errorf("expected CompleteTime to be newer than CreateTime")
	}
	if len(event.Errors) != 0 {
		tester.Errorf("expected no errors")
	}
}
