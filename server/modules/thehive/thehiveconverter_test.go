// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
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
	assert.Equal(tester, thehiveCase.Severity, socCase.Severity)
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
	socCase.Severity = 3
	socCase.Id = "my id"
	socCase.Template = "someTemplate"

	thehiveCase, err := convertToTheHiveCase(socCase)
	assert.Nil(tester, err)

	assert.Equal(tester, thehiveCase.Title, socCase.Title)
	assert.Equal(tester, thehiveCase.Description, socCase.Description)
	assert.Equal(tester, thehiveCase.Severity, socCase.Severity)
	assert.Len(tester, thehiveCase.Tags, 1)
	assert.Equal(tester, thehiveCase.Template, socCase.Template)
}
