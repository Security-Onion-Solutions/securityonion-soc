// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
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
	if params.WebSocketTimeoutMs != 0 {
		tester.Errorf("expected 0 but got %d", params.WebSocketTimeoutMs)
	}
	if params.TipTimeoutMs != 0 {
		tester.Errorf("expected 0 but got %d", params.TipTimeoutMs)
	}
	if params.ApiTimeoutMs != 0 {
		tester.Errorf("expected 0 but got %d", params.ApiTimeoutMs)
	}
	if params.CacheExpirationMs != 0 {
		tester.Errorf("expected 0 but got %d", params.CacheExpirationMs)
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

func TestCombineEmptyDeprecatedLinkIntoEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()
	if len(action.Links) != 0 {
		tester.Errorf("expected empty links list but got %d", len(action.Links))
	}
}

func TestCombineDeprecatedLinkIntoEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()
	if len(action.Links) != 0 {
		tester.Errorf("expected empty links list but got %d", len(action.Links))
	}

	action.Link = "test"
	params.combineDeprecatedLinkIntoLinks()
	if len(action.Links) != 1 {
		tester.Errorf("expected single item in links list but got %d", len(action.Links))
	}
	if len(action.Link) != 0 {
		tester.Errorf("expected empty link but got %d", len(action.Link))
	}
}

func TestCombineDeprecatedLinkIntoNonEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()

	action.Link = "test"
	action.Links = append(action.Links, "new-item")
	params.combineDeprecatedLinkIntoLinks()
	if len(action.Links) != 2 {
		tester.Errorf("expected 2 items in links list but got %d", len(action.Links))
	}
	if len(action.Link) != 0 {
		tester.Errorf("expected empty link but got %d", len(action.Link))
	}
}
