// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyClientParameters(tester *testing.T) {
	params := &ClientParameters{}
	err := params.Verify()
	assert.Nil(tester, err)
	assert.Zero(tester, params.WebSocketTimeoutMs)
	assert.Zero(tester, params.TipTimeoutMs)
	assert.Zero(tester, params.ApiTimeoutMs)
	assert.Zero(tester, params.CacheExpirationMs)
	assert.False(tester, params.CasesEnabled)
	verifyInitialHuntingParams(tester, &params.HuntingParams)
	verifyInitialHuntingParams(tester, &params.AlertingParams)
	verifyInitialHuntingParams(tester, &params.CasesParams)
	verifyInitialHuntingParams(tester, &params.DashboardsParams)
}

func TestVerifyHuntingParams(tester *testing.T) {
	params := &HuntingParameters{}
	err := params.Verify()
	assert.Nil(tester, err)
	verifyInitialHuntingParams(tester, params)
}

func verifyInitialHuntingParams(tester *testing.T, params *HuntingParameters) {
	assert.Equal(tester, DEFAULT_GROUP_FETCH_LIMIT, params.GroupFetchLimit)
	assert.Equal(tester, DEFAULT_EVENT_FETCH_LIMIT, params.EventFetchLimit)
	assert.Equal(tester, DEFAULT_RELATIVE_TIME_VALUE, params.RelativeTimeValue)
	assert.Equal(tester, DEFAULT_RELATIVE_TIME_UNIT, params.RelativeTimeUnit)
	assert.Equal(tester, DEFAULT_CHART_LABEL_MAX_LENGTH, params.ChartLabelMaxLength)
	assert.Equal(tester, DEFAULT_CHART_LABEL_OTHER_LIMIT, params.ChartLabelOtherLimit)
	assert.Equal(tester, DEFAULT_CHART_LABEL_FIELD_SEPARATOR, params.ChartLabelFieldSeparator)
	assert.Equal(tester, 0, params.MostRecentlyUsedLimit)
	assert.Equal(tester, false, params.EscalateRelatedEventsEnabled)
	assert.Equal(tester, false, params.EscalateEnabled)
	assert.Equal(tester, false, params.AggregationActionsEnabled)
}

func TestCombineEmptyDeprecatedLinkIntoEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()
	assert.Len(tester, action.Links, 0)
}

func TestCombineDeprecatedLinkIntoEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()
	assert.Len(tester, action.Links, 0)

	action.Link = "test"
	params.combineDeprecatedLinkIntoLinks()
	assert.Len(tester, action.Links, 1)
	assert.Len(tester, action.Link, 0)
}

func TestCombineDeprecatedLinkIntoNonEmptyLinks(tester *testing.T) {
	action := &HuntingAction{}
	params := &HuntingParameters{}
	params.Actions = append(params.Actions, action)
	params.combineDeprecatedLinkIntoLinks()

	action.Link = "test"
	action.Links = append(action.Links, "new-item")
	params.combineDeprecatedLinkIntoLinks()
	assert.Len(tester, action.Links, 2)
	assert.Len(tester, action.Link, 0)
}

func TestVerifyCaseParams(tester *testing.T) {
	params := &CaseParameters{}
	params.MostRecentlyUsedLimit = -1
	err := params.Verify()
	assert.Nil(tester, err)
	assert.Equal(tester, params.MostRecentlyUsedLimit, 0)
}
