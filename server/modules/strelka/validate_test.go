// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"fmt"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
)

const BasicRule = `rule ExampleRule
{
	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const BasicRuleWMeta = `import "pe"

rule MetadataExample {
	meta:
		author = "John Doe"
		date = "2023-12-27"
		version = "1.0"
		reference = "http://somewhere.invalid"
		description = "Example Rule"
		my_identifier_1 = "Some string data"
		mY_iDeNtIfIeR_2 = 24
		MY_IDENTIFIER_3 = true

	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const NormalizedBasicRuleWMeta = `import "pe"

rule MetadataExample {
	meta:
		author = "John Doe"
		date = "2023-12-27"
		version = "1.0"
		reference = "http://somewhere.invalid"
		description = "Example Rule"
		my_identifier_1 = "Some string data"
		my_identifier_2 = 24
		my_identifier_3 = true

	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const RegexRule = `rule RegExpExample1
{
	strings:
		$re1 = /md5: [0-9a-fA-F]{32}/
		$re2 = /state: (on|off)/

	condition:
		$re1 and $re2
}`

const ImportRule = `import "pe"

rule Test
{
    strings:
        $a = "some string"

    condition:
        $a and pe.entry_point == 0x1000
}`

const UnexpectedHeader = `rule ExampleRule
{
	extra:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const RuleWithComments = `rule ExampleRule
{
	/*
		Multiline comment
	*/
	strings:
		$my_text_string = "text here"
		// $my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const NoIdentifier = `rule {}`

const BadMeta = `rule ExampleRule
{
	meta:
		copyrighted
		author = "Some Guy"
}`

const WeirdRule = `import "pe"

rule ExampleRule : FILE
{` + "\r\n" + `
strings:
$my_text_string = "text here"
$my_hex_string = { E2 34 A1 C8 23 FB }
$badslashes = "\\var\\www\\html\\"
$multilinehex = {
46 DC EA D3 17 FE 45 D8 09 23
EB 97 E4 95 64 10 D4 CD B2 C2
}
condition : // comment
$my_text_string or $my_hex_string
}`

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

func TestParseRule(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name          string
		Input         string
		ExpectedRules []*YaraRule
		ExpectedError *string
	}{
		{
			Name:  "Basic Rule",
			Input: BasicRule,
			ExpectedRules: []*YaraRule{
				{
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
						`$my_hex_string = { E2 34 A1 C8 23 FB }`,
					},
					Condition: `$my_text_string or $my_hex_string`,
				},
			},
		},
		{
			Name:  "Basic Rule With Metadata",
			Input: BasicRuleWMeta,
			ExpectedRules: []*YaraRule{
				{
					Imports: []string{
						"pe",
					},
					Identifier: "MetadataExample",
					Meta: Metadata{
						Author:      util.Ptr(`"John Doe"`),
						Date:        util.Ptr(`"2023-12-27"`),
						Version:     util.Ptr(`"1.0"`),
						Reference:   util.Ptr(`"http://somewhere.invalid"`),
						Description: util.Ptr(`"Example Rule"`),
						Rest: map[string]string{
							"my_identifier_1": "\"Some string data\"",
							"my_identifier_2": "24",
							"my_identifier_3": "true",
						},
					},
					Strings: []string{
						"$my_text_string = \"text here\"",
						"$my_hex_string = { E2 34 A1 C8 23 FB }",
					},
					Condition: "$my_text_string or $my_hex_string",
				},
			},
		},
		{
			Name:  "Rule With Regex",
			Input: RegexRule,
			ExpectedRules: []*YaraRule{
				{
					Identifier: "RegExpExample1",
					Strings: []string{
						"$re1 = /md5: [0-9a-fA-F]{32}/",
						"$re2 = /state: (on|off)/",
					},
					Condition: "$re1 and $re2",
				},
			},
		},
		{
			Name:  "Rule With Import",
			Input: ImportRule,
			ExpectedRules: []*YaraRule{
				{
					Imports: []string{
						"pe",
					},
					Identifier: "Test",
					Strings: []string{
						`$a = "some string"`,
					},
					Condition: `$a and pe.entry_point == 0x1000`,
				},
			},
		},
		{
			Name:          "Rule With Unexpected Header",
			Input:         UnexpectedHeader,
			ExpectedError: util.Ptr(`unexpected header at 26: extra`),
		},
		{
			Name:  "Basic Rule With Comments",
			Input: RuleWithComments,
			ExpectedRules: []*YaraRule{
				{
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
					},
					Condition: `$my_text_string or $my_hex_string`,
				},
			},
		},
		{
			Name:  "Multiple Rules",
			Input: ImportRule + "\n\n" + BasicRule,
			ExpectedRules: []*YaraRule{
				{
					Imports: []string{
						"pe",
					},
					Identifier: "Test",
					Strings: []string{
						`$a = "some string"`,
					},
					Condition: `$a and pe.entry_point == 0x1000`,
				},
				{
					Imports: []string{
						"pe",
					},
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
						`$my_hex_string = { E2 34 A1 C8 23 FB }`,
					},
					Condition: `$my_text_string or $my_hex_string`,
				},
			},
		},
		{
			Name:  "Rule With Oddities",
			Input: WeirdRule,
			ExpectedRules: []*YaraRule{
				{
					Imports: []string{
						"pe",
					},
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
						`$my_hex_string = { E2 34 A1 C8 23 FB }`,
						`$badslashes = "\\var\\www\\html\\"`,
						`$multilinehex = {`,
						`46 DC EA D3 17 FE 45 D8 09 23`,
						`EB 97 E4 95 64 10 D4 CD B2 C2`,
						`}`,
					},
					Condition: `$my_text_string or $my_hex_string`,
				},
			},
		},
		{
			Name:          "Missing Identifier",
			Input:         NoIdentifier,
			ExpectedError: util.Ptr("expected rule identifier at 5"),
		},
		{
			Name:          "Invalid Metadata",
			Input:         BadMeta,
			ExpectedError: util.Ptr("invalid meta line at 39: copyrighted"),
		},
		{
			Name:          "Unexpected End Of Rule",
			Input:         BasicRule[:len(BasicRule)-1],
			ExpectedError: util.Ptr("unexpected end of rule"),
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rules, err := ParseYaraRules([]byte(test.Input))
			if test.ExpectedError == nil {
				assert.NoError(t, err)
				assert.NotNil(t, rules)

				assert.Equal(t, test.ExpectedRules, rules)
			} else {
				assert.Error(t, err)
				assert.Equal(t, *test.ExpectedError, err.Error())

				assert.Empty(t, rules)
			}
		})
	}
}

func TestRuleString(t *testing.T) {
	rules, err := ParseYaraRules([]byte(BasicRuleWMeta))
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)

	raw := rules[0].String()
	fmt.Println(raw)
	assert.Equal(t, NormalizedBasicRuleWMeta, raw)
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
