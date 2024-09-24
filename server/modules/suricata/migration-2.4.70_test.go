// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestM2470ReadStateFile(t *testing.T) {
	tests := []struct {
		Name          string
		Contents      string
		ShouldMigrate bool
		Error         error
	}{
		{
			Name:          "Hasn't Run Yet",
			Contents:      "0",
			ShouldMigrate: true,
			Error:         nil,
		},
		{
			Name:          "Has Run",
			Contents:      "1",
			ShouldMigrate: false,
			Error:         nil,
		},
		{
			Name:          "Invalid Contents",
			Contents:      "2",
			ShouldMigrate: false,
			Error:         fmt.Errorf("unexpected state file content: 2"),
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			iom := mock.NewMockIOManager(ctrl)
			iom.EXPECT().ReadFile(idstoolsYaml).Return([]byte(test.Contents), nil)

			e := &SuricataEngine{
				IOManager: iom,
			}

			shouldMigrate, err := e.m2470ReadStateFile(idstoolsYaml)
			assert.Equal(t, test.ShouldMigrate, shouldMigrate)
			assert.Equal(t, test.Error, err)
		})
	}
}

func TestM2470WriteStateFileSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().WriteFile("stateFile", []byte("1"), fs.FileMode(0644)).Return(nil)

	e := &SuricataEngine{
		IOManager: iom,
	}

	err := e.m2470WriteStateFileSuccess("stateFile")
	assert.NoError(t, err)
}

func TestM2470LoadEnabledDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(idstoolsYaml).Return([]byte(`{ "idstools": { "sids": {"enabled": ["1", "2", "3"], "disabled": ["4", "5", "6"]} }}`), nil)

	e := &SuricataEngine{
		IOManager: iom,
	}

	enabled, disabled, err := e.m2470LoadEnabledDisabled()
	assert.NoError(t, err)

	assert.Equal(t, []string{"1", "2", "3"}, enabled)
	assert.Equal(t, []string{"4", "5", "6"}, disabled)

	iom.EXPECT().ReadFile(idstoolsYaml).Return([]byte(`{}`), nil)

	enabled, disabled, err = e.m2470LoadEnabledDisabled()
	assert.NoError(t, err)

	assert.Equal(t, 0, len(enabled))
	assert.Equal(t, 0, len(disabled))

	iom.EXPECT().ReadFile(idstoolsYaml).Return([]byte(`{ "idstools": {}}`), nil)

	enabled, disabled, err = e.m2470LoadEnabledDisabled()
	assert.NoError(t, err)

	assert.Equal(t, 0, len(enabled))
	assert.Equal(t, 0, len(disabled))
}

func TestM2470ApplyList(t *testing.T) {
	tests := []struct {
		Name    string
		List    []string
		Detects map[string]*model.Detection
		Sids    map[string]struct{}
	}{
		{
			Name: "Single SID",
			List: []string{"1"},
			Detects: map[string]*model.Detection{
				"1": {
					PublicID: "1",
				},
			},
			Sids: map[string]struct{}{
				"1": {},
			},
		},
		{
			Name: "Multiple SIDs",
			List: []string{"1", "3", "5"},
			Detects: map[string]*model.Detection{
				"1": {},
				"2": {},
				"3": {},
				"4": {},
				"5": {},
			},
			Sids: map[string]struct{}{
				"1": {},
				"3": {},
				"5": {},
			},
		},
		{
			Name: "Single Regex",
			List: []string{`re:10\d`},
			Detects: map[string]*model.Detection{
				"108": {
					Content: "108",
				},
				"109": {
					Content: "109",
				},
				"110": {
					Content: "110",
				},
				"111": {
					Content: "111",
				},
			},
			Sids: map[string]struct{}{
				"108": {},
				"109": {},
			},
		},
		{
			Name: "Multiple Regex",
			List: []string{`re:10\d`, `re:11`},
			Detects: map[string]*model.Detection{
				"108": {
					Content: "108",
				},
				"109": {
					Content: "109",
				},
				"110": {
					Content: "110",
				},
				"111": {
					Content: "111",
				},
				"120": {
					Content: "120",
				},
				"121": {
					Content: "121",
				},
			},
			Sids: map[string]struct{}{
				"108": {},
				"109": {},
				"110": {},
				"111": {},
			},
		},
		{
			Name: "Mixed",
			List: []string{"1", "2", `re:10\d`},
			Detects: map[string]*model.Detection{
				"1": {},
				"108": {
					Content: "108",
				},
				"109": {
					Content: "109",
				},
				"110": {
					Content: "110",
				},
				"111": {
					Content: "111",
				},
				"120": {
					Content: "120",
				},
				"121": {
					Content: "121",
				},
			},
			Sids: map[string]struct{}{
				"1":   {},
				"108": {},
				"109": {},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			e := &SuricataEngine{}

			sids, err := e.m2470ApplyList(test.List, test.Detects)
			assert.NoError(t, err)

			assert.Equal(t, test.Sids, sids)
		})
	}
}

func TestM2470ToggleEnabled(t *testing.T) {
	tests := []struct {
		Name    string
		Detects map[string]*model.Detection
		Set     map[string]struct{}
		Enable  bool
	}{
		{
			Name: "Enable",
			Detects: map[string]*model.Detection{
				"1": {},
				"2": {},
				"3": {},
			},
			Set: map[string]struct{}{
				"1": {},
				"3": {},
			},
			Enable: true,
		},
		{
			Name: "Disable",
			Detects: map[string]*model.Detection{
				"1": {IsEnabled: true},
				"2": {IsEnabled: true},
				"3": {IsEnabled: true},
			},
			Set: map[string]struct{}{
				"1": {},
				"3": {},
			},
			Enable: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			e := &SuricataEngine{}

			e.m2470ToggleEnabled(test.Detects, test.Set, test.Enable)

			modified := []string{}
			for pid, det := range test.Detects {
				if det.IsEnabled == test.Enable {
					modified = append(modified, pid)
				}
			}

			list := []string{}
			for pid := range test.Set {
				list = append(list, pid)
			}

			sort.Strings(modified)
			sort.Strings(list)

			assert.Equal(t, list, modified)
		})
	}
}

func TestM2470LoadOverrides(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(sidsYaml).Return([]byte(`{ "2013030": [ "suppress": {"gen_id": 1, "track": "by_src", "ip": "10.10.3.0/24"} ]}`), nil) // success
	iom.EXPECT().ReadFile(sidsYaml).Return(nil, errors.New("bad"))                                                                              // bad error
	iom.EXPECT().ReadFile(sidsYaml).Return(nil, fs.ErrNotExist)                                                                                 // good error

	e := &SuricataEngine{
		IOManager: iom,
	}

	// file is present and contains data
	overrides, err := e.m2470LoadOverrides()
	assert.NoError(t, err)

	assert.Equal(t, 1, len(overrides))
	assert.Equal(t, 1, len(overrides["2013030"]))
	assert.Equal(t, overrides["2013030"][0], &model.Override{
		Type:      model.OverrideTypeSuppress,
		IsEnabled: true,
		OverrideParameters: model.OverrideParameters{
			GenID: util.Ptr(1),
			Track: util.Ptr("by_src"),
			IP:    util.Ptr("10.10.3.0/24"),
		},
	})

	// error opening the file
	overrides, err = e.m2470LoadOverrides()
	assert.Error(t, err)
	assert.Equal(t, 0, len(overrides))

	// file does not exist, no error expected
	overrides, err = e.m2470LoadOverrides()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(overrides))
}

func TestM2470ApplyOverrides(t *testing.T) {
	detects := map[string]*model.Detection{
		"1": {},
		"2": {},
	}
	overrides := map[string][]*model.Override{
		"1": {
			{
				Type: model.OverrideTypeSuppress,
				OverrideParameters: model.OverrideParameters{
					GenID: util.Ptr(1),
					Track: util.Ptr("by_src"),
					IP:    util.Ptr("10.10.3.0/24"),
				},
			},
		},
	}

	e := &SuricataEngine{}

	e.m2470ApplyOverrides(detects, overrides)

	assert.Equal(t, 2, len(detects))
	assert.NotZero(t, detects["1"].Overrides[0].CreatedAt)
	assert.NotZero(t, detects["1"].Overrides[0].UpdatedAt)

	then := detects["1"].Overrides[0].CreatedAt
	assert.Equal(t, detects["1"].Overrides, []*model.Override{
		{
			Type:      model.OverrideTypeSuppress,
			IsEnabled: true,
			CreatedAt: then,
			UpdatedAt: then,
			OverrideParameters: model.OverrideParameters{
				GenID: util.Ptr(1),
				Track: util.Ptr("by_src"),
				IP:    util.Ptr("10.10.3.0/24"),
			},
		},
	})
}
