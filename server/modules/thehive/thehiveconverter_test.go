// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  if err != nil {
    tester.Errorf("unexpected convert error: %s", err)
  }

  if socCase.Title != thehiveCase.Title {
    tester.Errorf("expected title: %s, but got: %s", thehiveCase.Title, socCase.Title)
  }

  if socCase.Description != thehiveCase.Description {
    tester.Errorf("expected description: %s, but got: %s", thehiveCase.Description, socCase.Description)
  }

  if socCase.Severity != thehiveCase.Severity {
    tester.Errorf("expected severity: %d, but got: %d", thehiveCase.Severity, socCase.Severity)
  }

  if socCase.Id != strconv.Itoa(thehiveCase.Id) {
    tester.Errorf("expected id: %d, but got: %s", thehiveCase.Id, socCase.Id)
  }

  if socCase.CreateTime.Format(time.RFC3339) != "2020-09-30T10:40:02-04:00" {
    tester.Errorf("unexpected create time: %s", socCase.CreateTime.Format(time.RFC3339))
  }

  if socCase.StartTime.Format(time.RFC3339) != "2020-09-30T10:40:01-04:00" {
    tester.Errorf("unexpected start time: %s", socCase.StartTime.Format(time.RFC3339))
  }

  if socCase.CompleteTime.Format(time.RFC3339) != "2020-09-30T10:40:03-04:00" {
    tester.Errorf("unexpected complete time: %s", socCase.CompleteTime.Format(time.RFC3339))
  }
}

func TestConvertToTheHiveCase(tester *testing.T) {
  socCase := model.NewCase()
  socCase.Title = "my title"
  socCase.Description = "my description.\nline 2.\n"
  socCase.Severity = 3
  socCase.Id = "my id"
  socCase.Template = "someTemplate"

  thehiveCase, err := convertToTheHiveCase(socCase)
  if err != nil {
    tester.Errorf("unexpected convert error: %s", err)
  }

  if socCase.Title != thehiveCase.Title {
    tester.Errorf("expected title: %s, but got: %s", thehiveCase.Title, socCase.Title)
  }

  if socCase.Description != thehiveCase.Description {
    tester.Errorf("expected description: %s, but got: %s", thehiveCase.Description, socCase.Description)
  }

  if socCase.Severity != thehiveCase.Severity {
    tester.Errorf("expected severity: %d, but got: %d", thehiveCase.Severity, socCase.Severity)
  }

  if len(thehiveCase.Tags) != 1 {
    tester.Errorf("expected one tag, but got: %v", thehiveCase.Tags)
  }

  if socCase.Template != thehiveCase.Template {
    tester.Errorf("expected template: %s, but got: %s", thehiveCase.Template, socCase.Template)
  }
}
