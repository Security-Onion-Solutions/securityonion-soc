// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package config

import (
  "testing"
)

func TestVerifyClientParameters(tester *testing.T) {
  params := &ClientParameters{}
	err := params.Verify()
  if err != nil {
    tester.Errorf("expected no error")
  }
}

func TestVerifyHuntingParams(tester *testing.T) {
	params := &HuntingParameters{}
	err := params.Verify()
  if err != nil {
    tester.Errorf("expected no error")
  }
  if params.GroupFetchLimit != DEFAULT_GROUP_FETCH_LIMIT {
    tester.Errorf("expected GroupFetchLimit %d but got %d", DEFAULT_GROUP_FETCH_LIMIT, params.GroupFetchLimit)
  }
  if params.EventFetchLimit != DEFAULT_EVENT_FETCH_LIMIT {
    tester.Errorf("expected EventFetchLimit %d but got %d", DEFAULT_EVENT_FETCH_LIMIT, params.EventFetchLimit)
  }
  if params.RelativeTimeValue != DEFAULT_RELATIVE_TIME_VALUE {
    tester.Errorf("expected RelativeTimeValue %d but got %d", DEFAULT_RELATIVE_TIME_VALUE, params.RelativeTimeValue)
  }
  if params.RelativeTimeUnit != DEFAULT_RELATIVE_TIME_UNIT {
    tester.Errorf("expected RelativeTimeUnit %d but got %d", DEFAULT_RELATIVE_TIME_UNIT, params.RelativeTimeUnit)
  }
}
