// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
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

	"github.com/stretchr/testify/assert"
)

func TestNewEventSearchCriteria(tester *testing.T) {
	event := NewEventSearchCriteria()
	assert.NotZero(tester, event.CreateTime)
}

func TestNewEventUpdateCriteria(tester *testing.T) {
	event := NewEventUpdateCriteria()
	assert.NotZero(tester, event.CreateTime)
}

func TestPopulateQueryTrim(tester *testing.T) {
	goodTime := "2006-05-07T14:15:59+01:00 - 2006-05-07T14:16:59+01:00"
	zone := "America/New_York"
	criteria := NewEventSearchCriteria()
	_ = criteria.Populate(" foo ", goodTime, time.RFC3339, zone, "10", "100")
	assert.Equal(tester, "foo", criteria.RawQuery)
}

func TestPopulateBadInputTimes(tester *testing.T) {
	badTime := "2006-05-07"
	goodTime := "2006-05-07T14:15:59+01:00"
	zone := "America/New_York"
	criteria := NewEventSearchCriteria()
	err := criteria.Populate("foo", badTime+" - "+badTime, time.RFC3339, zone, "10", "100")
	assert.Error(tester, err, "expected error from bad start time and end time input")

	err = criteria.Populate("foo", badTime+" - "+goodTime, time.RFC3339, zone, "10", "100")
	assert.Error(tester, err, "expected error from bad start time input")

	err = criteria.Populate("foo", goodTime+" - "+badTime, time.RFC3339, zone, "10", "100")
	assert.Error(tester, err, "expected error from bad end time input")

	err = criteria.Populate("foo", goodTime+" - "+goodTime, time.RFC3339, zone, "30", "100")
	assert.NoError(tester, err, "expected no error from good time input")
}

func TestLimits(tester *testing.T) {
	goodTime := "2006-05-07T14:15:59+01:00"
	criteria := NewEventSearchCriteria()
	_ = criteria.Populate("foo", goodTime+" - "+goodTime, time.RFC3339, "PST", "30", "100")
	assert.Equal(tester, 100, criteria.EventLimit)
	assert.Equal(tester, 30, criteria.MetricLimit)
}

func TestNewEventSearchResult(tester *testing.T) {
	event := NewEventSearchResults()
	time.Sleep(1 * time.Nanosecond)
	event.Complete()
	assert.True(tester, event.CompleteTime.After(event.CreateTime), "expected CompleteTime to be newer than CreateTime")
	assert.Len(tester, event.Errors, 0)
}

func TestNewEventUpdateResult(tester *testing.T) {
	event := NewEventUpdateResults()
	time.Sleep(1 * time.Nanosecond)
	event.Complete()
	assert.True(tester, event.CompleteTime.After(event.CreateTime), "expected CompleteTime to be newer than CreateTime")
	assert.Len(tester, event.Errors, 0)
}
