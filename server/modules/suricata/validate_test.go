// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/assert"
)

func TestParseSuricata(t *testing.T) {
	table := []struct {
		Name   string
		Input  string
		Output *SuricataRule
		Error  *string
	}{
		{
			Name:  "Minimal Rule",
			Input: `a b source port <> destination port ()`,
			Output: &SuricataRule{
				Action:      "a",
				Protocol:    "b",
				Source:      "source port",
				Direction:   "<>",
				Destination: "destination port",
				Options:     []*RuleOption{},
			},
		},
		{
			Name:  "Bad Direction",
			Input: `a b source port <- destination port ()`,
			Error: util.Ptr("invalid direction, must be '<>' or '->', got <-"),
		},
		{
			Name:  "Unnecessary Suffix",
			Input: `a b source port <> destination port () x`,
			Error: util.Ptr("invalid rule, expected end of rule, got 2 more bytes"),
		},
		{
			Name:  "Escaped Option",
			Input: `a b source port <> destination port (msg:"\\\"";)`,
			Output: &SuricataRule{
				Action:      "a",
				Protocol:    "b",
				Source:      "source port",
				Direction:   "<>",
				Destination: "destination port",
				Options: []*RuleOption{
					{Name: "msg", Value: util.Ptr(`"\\\""`)},
				},
			},
		},
		{
			Name:  "Real rule",
			Input: `alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)`,
			Output: &SuricataRule{
				Action:      "alert",
				Protocol:    "http",
				Source:      "any any",
				Direction:   "->",
				Destination: "any any",
				Options: []*RuleOption{
					{Name: "msg", Value: util.Ptr(`"GPL ATTACK_RESPONSE id check returned root"`)},
					{Name: "content", Value: util.Ptr(`"uid=0|28|root|29|"`)},
					{Name: "classtype", Value: util.Ptr("bad-unknown")},
					{Name: "sid", Value: util.Ptr("2100498")},
					{Name: "rev", Value: util.Ptr("7")},
					{Name: "metadata", Value: util.Ptr("created_at 2010_09_23, updated_at 2010_09_23")},
				},
			},
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rule, err := ParseSuricataRule(test.Input)
			if test.Error != nil {
				assert.Nil(t, rule)
				assert.Equal(t, *test.Error, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.Output, rule)
			}
		})
	}
}

func TestSuricataRule(t *testing.T) {
	input := `a b source port <> destination port (msg:"\\\""; noalert; sid:12345; rev: "9"; ) 	`

	rule, err := ParseSuricataRule(input)
	assert.NoError(t, err)

	rule2, err := ParseSuricataRule(rule.String())
	assert.NoError(t, err)

	assert.Equal(t, rule, rule2)

	opt, ok := rule.GetOption("msg")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, `"\\\""`, *opt)

	opt, ok = rule.GetOption("sid")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, "12345", *opt)

	opt, ok = rule.GetOption("rev")
	assert.True(t, ok)
	assert.NotNil(t, opt)
	assert.Equal(t, `"9"`, *opt)

	opt, ok = rule.GetOption("NoAlErT")
	assert.True(t, ok)
	assert.Nil(t, opt)

	opt, ok = rule.GetOption("notfound")
	assert.False(t, ok)
	assert.Nil(t, opt)
}

func TestDuplicateDetection(t *testing.T) {
	det := &model.Detection{
		Engine:      model.EngineNameSuricata,
		Language:    model.SigLangSuricata,
		Content:     `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Fake Antivirus Download ws.exe"; flow:established,to_server; content:"GET"; http_method; content:"/install/ws.exe"; http_uri; nocase; reference:url,doc.emergingthreats.net/2010051; classtype:trojan-activity; sid:2010051; rev:4;)`,
		IsCommunity: true,
		Ruleset:     "somewhere",
		Author:      "Dade Murphy",
		Severity:    model.SeverityUnknown,
		License:     "BSD",
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	ctrl := gomock.NewController(t)
	mUser := mock.NewMockUserstore(ctrl)
	mUser.EXPECT().GetUserById(ctx, "myRequestorId").Return(&model.User{
		FirstName: "Dade",
		LastName:  "Murphy",
	}, nil)

	mDetect := mock.NewMockDetectionstore(ctrl)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(&model.Detection{}, nil)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(nil, nil)

	eng := SuricataEngine{
		srv: &server.Server{
			Userstore:      mUser,
			Detectionstore: mDetect,
		},
		isRunning: true,
	}

	_ = eng.ExtractDetails(det)

	dupe, err := eng.DuplicateDetection(ctx, det)

	assert.NoError(t, err)
	assert.NotNil(t, dupe)

	// expected differences
	assert.NotEqual(t, det.Title, dupe.Title)
	assert.Equal(t, det.Title, dupe.Title[:len(dupe.Title)-len(" (copy)")])
	assert.NotEqual(t, det.PublicID, dupe.PublicID)
	assert.NotEmpty(t, dupe.PublicID)
	assert.NotEqual(t, det.IsCommunity, dupe.IsCommunity)
	assert.NotEqual(t, det.Ruleset, dupe.Ruleset)

	// expected similarities
	assert.Equal(t, det.Severity, dupe.Severity)
	assert.Equal(t, "Dade Murphy", dupe.Author)
	assert.Equal(t, det.Category, dupe.Category)
	assert.Equal(t, det.Description, dupe.Description)
	assert.Equal(t, det.Engine, dupe.Engine)
	assert.Equal(t, det.Language, dupe.Language)

	// always empty after duplication
	assert.False(t, det.IsEnabled)
	assert.False(t, det.IsReporting)
	assert.False(t, dupe.IsEnabled)
	assert.False(t, dupe.IsCommunity)
	assert.Equal(t, det.License, dupe.License)
	assert.Empty(t, dupe.Overrides)
	assert.Empty(t, dupe.Tags)
}

func TestGenerateUnusedPublicId(t *testing.T) {
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	mDetect := mock.NewMockDetectionstore(ctrl)
	mDetect.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(&model.Detection{}, nil).Times(10)

	eng := SuricataEngine{
		srv: &server.Server{
			Detectionstore: mDetect,
		},
		isRunning: true,
	}

	id, err := eng.generateUnusedPublicId(ctx)

	assert.Empty(t, id)
	assert.Error(t, err)
	assert.Equal(t, "unable to generate a unique publicId", err.Error())
}

func TestUpdateForDuplication(t *testing.T) {
	publicId := "2"

	tests := []struct {
		Name            string
		Input           string
		OptionsBefore   int
		OptionsAfter    int
		ExpectedOptions []*RuleOption
	}{
		{
			Name:          "Normal Options",
			Input:         `alert any any <> any any (msg:"test"; sid:1; rev:1;)`,
			OptionsBefore: 3,
			OptionsAfter:  3,
			ExpectedOptions: []*RuleOption{
				{Name: "msg", Value: util.Ptr("test (copy)")},
				{Name: "sid", Value: util.Ptr(publicId)},
				{Name: "rev", Value: util.Ptr("1")},
			},
		},
		{
			Name:          "Present but Empty Options",
			Input:         `alert any any <> any any (msg; sid; rev;)`,
			OptionsBefore: 3,
			OptionsAfter:  3,
			ExpectedOptions: []*RuleOption{
				{Name: "msg", Value: util.Ptr("(copy)")},
				{Name: "sid", Value: util.Ptr(publicId)},
				{Name: "rev", Value: nil},
			},
		},
		{
			Name:          "Missing Options",
			Input:         `alert any any <> any any (rev;)`,
			OptionsBefore: 1,
			OptionsAfter:  3,
			ExpectedOptions: []*RuleOption{
				{Name: "msg", Value: util.Ptr("(copy)")},
				{Name: "sid", Value: util.Ptr(publicId)},
				{Name: "rev", Value: nil},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			rule, err := ParseSuricataRule(test.Input)
			assert.NoError(t, err)
			assert.NotNil(t, rule)

			assert.Equal(t, test.OptionsBefore, len(rule.Options))

			rule.UpdateForDuplication(publicId)

			assert.Equal(t, test.OptionsAfter, len(rule.Options))

			for _, exOpt := range test.ExpectedOptions {
				opt, ok := rule.GetOption(exOpt.Name)
				assert.True(t, ok)
				if exOpt.Value != nil {
					assert.NotNil(t, opt)
					assert.Equal(t, *exOpt.Value, *opt)
				} else {
					assert.Nil(t, opt)
				}
			}
		})
	}

	// rule, err = ParseSuricataRule(`alert any any <> any any (rev:1;)`)
	// assert.NoError(t, err)
	// assert.NotNil(t, rule)
	//
	// assert.Equal(t, len(rule.Options), 1)
	// rev, ok = rule.GetOption("rev")
	// assert.True(t, ok)
	// assert.NotNil(t, rev)
	// assert.Equal(t, "1", *rev)
	//
	// sid, ok = rule.GetOption("sid")
	// assert.False(t, ok)
	// assert.Nil(t, sid)
	//
	// msg, ok = rule.GetOption("msg")
	// assert.False(t, ok)
	// assert.Nil(t, msg)
	//
	// rule.UpdateForDuplication("1")
	//
	// assert.Equal(t, len(rule.Options), 3)
	//
	// sid, ok = rule.GetOption("sid")
	// assert.True(t, ok)
	// assert.NotNil(t, sid)
	// assert.Equal(t, "1", *sid)
	//
	// msg, ok = rule.GetOption("msg")
	// assert.True(t, ok)
	// assert.NotNil(t, msg)
	// assert.Equal(t, "(copy)", *msg)
	//
	// rev, ok = rule.GetOption("rev")
	// assert.True(t, ok)
	// assert.NotNil(t, rev)
	// assert.Equal(t, "1", *rev)
}
