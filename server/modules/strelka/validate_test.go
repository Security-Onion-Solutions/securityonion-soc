// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMetaSet(t *testing.T) {
	t.Parallel()

	meta := Metadata{}
	assert.True(t, meta.IsEmpty())

	meta.Set("author", "John Doe")

	assert.Equal(t, "John Doe", *meta.Author)
	assert.False(t, meta.IsEmpty())

	meta.Author = nil

	assert.True(t, meta.IsEmpty())

	meta.Set("date", "2023-12-27")
	meta.Set("version", "1.0")
	meta.Set("reference", "http://somewhere.invalid")
	meta.Set("description", "Example Rule")
	meta.Set("my_identifier_1", "Some string data")

	assert.Nil(t, meta.Author)
	assert.Equal(t, "2023-12-27", *meta.Date)
	assert.Equal(t, "1.0", *meta.Version)
	assert.Equal(t, "http://somewhere.invalid", *meta.Reference)
	assert.Equal(t, "Example Rule", *meta.Description)
	assert.Equal(t, "Some string data", meta.Rest["my_identifier_1"])
	assert.False(t, meta.IsEmpty())
}

func TestValidate(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name string
		Rule *YaraRule
		Err  *string
	}{
		{
			Name: "Minimally Valid Rule",
			Rule: &YaraRule{
				Identifier: "ExampleRule",
				Condition:  "false",
			},
		},
		{
			Name: "Missing Identifier",
			Rule: &YaraRule{
				Condition: "false",
			},
			Err: util.Ptr("missing required fields: identifier"),
		},
		{
			Name: "Missing Condition",
			Rule: &YaraRule{
				Identifier: "ExampleRule",
			},
			Err: util.Ptr("missing required fields: condition"),
		},
		{
			Name: "Missing Multiple Fields",
			Rule: &YaraRule{},
			Err:  util.Ptr("missing required fields: identifier, condition"),
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			err := test.Rule.Validate()
			if test.Err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, *test.Err, err.Error())
			}
		})
	}
}

func TestDuplicateDetection(t *testing.T) {
	det := &model.Detection{
		Engine:   model.EngineNameStrelka,
		Language: model.SigLangYara,
		Content: `rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi); Didier Stevens"

	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
		$asn1_84		= { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

	condition:
		$asn1 at 0 or $asn1_84 at 0
}`,
		IsCommunity: true,
		Ruleset:     "somewhere",
		Author:      "David Levinson",
		Severity:    model.SeverityUnknown,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	ctrl := gomock.NewController(t)
	mUser := mock.NewMockUserstore(ctrl)
	mUser.EXPECT().GetUserById(ctx, "myRequestorId").Return(&model.User{
		FirstName: "David",
		LastName:  "Levinson",
	}, nil)

	eng := StrelkaEngine{
		srv: &server.Server{
			Userstore: mUser,
		},
		isRunning: true,
	}

	_ = eng.ExtractDetails(det)

	dupe, err := eng.DuplicateDetection(ctx, det)

	assert.NoError(t, err)
	assert.NotNil(t, dupe)

	// expected differences
	assert.NotEqual(t, det.Title, dupe.Title)
	assert.Equal(t, det.Title, dupe.Title[:len(dupe.Title)-len("_copy")])
	assert.NotEqual(t, det.PublicID, dupe.PublicID)
	assert.NotEmpty(t, dupe.PublicID)
	assert.NotEqual(t, det.IsCommunity, dupe.IsCommunity)
	assert.NotEqual(t, det.Ruleset, dupe.Ruleset)

	// expected similarities
	assert.Equal(t, det.Severity, dupe.Severity)
	assert.Equal(t, det.Author, dupe.Author)
	assert.Equal(t, det.Category, dupe.Category)
	assert.Equal(t, det.Description, dupe.Description)
	assert.Equal(t, det.Engine, dupe.Engine)
	assert.Equal(t, det.Language, dupe.Language)

	// always empty after duplication
	assert.False(t, det.IsEnabled)
	assert.False(t, det.IsReporting)
	assert.Equal(t, dupe.License, model.LicenseUnknown)
	assert.Empty(t, dupe.Overrides)
	assert.Empty(t, dupe.Tags)
}
