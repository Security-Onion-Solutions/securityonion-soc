// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package thehive

import (
	"strconv"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestConvertFromTheHiveCase(tester *testing.T) {
	thehiveCase := NewTheHiveCase()
	thehiveCase.Title = "my title"
	thehiveCase.Description = "my description.\nline 2.\n"
	thehiveCase.Severity = 3
	thehiveCase.Id = 123
	thehiveCase.StartDate = 1601476801619
	thehiveCase.CreateDate = 1601476802619
	thehiveCase.EndDate = 1601476803619

	socCase, err := convertFromTheHiveCase(thehiveCase)
	assert.Nil(tester, err)
	assert.Equal(tester, thehiveCase.Title, socCase.Title)
	assert.Equal(tester, thehiveCase.Description, socCase.Description)
	assert.Equal(tester, "3", socCase.Severity)
	assert.Equal(tester, strconv.Itoa(thehiveCase.Id), socCase.Id)

	tm := socCase.CreateTime.Format(time.RFC3339)
	assert.Contains(tester, tm, ":40:02")

	tm = socCase.StartTime.Format(time.RFC3339)
	assert.Contains(tester, tm, ":40:01")

	tm = socCase.CompleteTime.Format(time.RFC3339)
	assert.Contains(tester, tm, ":40:03")
}

func TestConvertToTheHiveCase(tester *testing.T) {
	socCase := model.NewCase()
	socCase.Title = "my title"
	socCase.Description = "my description.\nline 2.\n"
	socCase.Severity = "low"
	socCase.Id = "my id"
	socCase.Template = "someTemplate"

	thehiveCase, err := convertToTheHiveCase(socCase)
	assert.Nil(tester, err)

	assert.Equal(tester, thehiveCase.Title, socCase.Title)
	assert.Equal(tester, thehiveCase.Description, socCase.Description)
	assert.Equal(tester, thehiveCase.Severity, 1)
	assert.Len(tester, thehiveCase.Tags, 1)
	assert.Equal(tester, thehiveCase.Template, socCase.Template)
}

func TestConvertSeverity(tester *testing.T) {
	assert.Equal(tester, 3, convertSeverity(""))
	assert.Equal(tester, 3, convertSeverity("unknown"))
	assert.Equal(tester, 1, convertSeverity("low"))
	assert.Equal(tester, 1, convertSeverity("Low"))
	assert.Equal(tester, 1, convertSeverity("1"))
	assert.Equal(tester, 2, convertSeverity("medium"))
	assert.Equal(tester, 2, convertSeverity("Medium"))
	assert.Equal(tester, 2, convertSeverity("2"))
	assert.Equal(tester, 3, convertSeverity("high"))
	assert.Equal(tester, 3, convertSeverity("High"))
	assert.Equal(tester, 3, convertSeverity("3"))
	assert.Equal(tester, 4, convertSeverity("critical"))
	assert.Equal(tester, 4, convertSeverity("4"))
	assert.Equal(tester, 4, convertSeverity("Critical"))
}
