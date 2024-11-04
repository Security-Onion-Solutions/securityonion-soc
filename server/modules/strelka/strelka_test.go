// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const simpleRule = `rule dummy {
	condition:
	  false
}`

const MyBasicRule = `rule ExampleRule
{
	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const BasicRule = `rule ExampleRule
{
	strings:
		$text_string = "text here"
		$hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$text_string or $hex_string
}`

const MyBasic_Rule = `rule Example Rule
{
	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const DeniedRule = `rule DenyRule
{
	strings:
		$text_string = "text here"
		$hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$text_string or $hex_string
}`

const BasicRuleWMeta = `import "pe"

private rule MetadataExample {
	meta:
		author = "John Doe"
		date = "2023-12-27"
		version = "1.0"
		reference = "http://somewhere.invalid"
		description = "Example Rule"
		my_identifier_1 = "Some string data"
		mY_iDeNtIfIeR_2 = "24"
		MY_IDENTIFIER_3 = "true"

	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const NormalizedBasicRuleWMeta = `import "pe"

private rule MetadataExample {
	meta:
		author = "John Doe"
		date = "2023-12-27"
		version = "1.0"
		reference = "http://somewhere.invalid"
		description = "Example Rule"
		my_identifier_1 = "Some string data"
		my_identifier_2 = "24"
		my_identifier_3 = "true"

	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

const RegexRule = `rule RegExpExample1
{
	strings:
		$my_re1 = /md5: [0-9a-fA-F]{32}/
		$my_re2 = /state: (on|off)/

	condition:
		$my_re1 and $my_re2
}`

const ImportRule = `import "pe"

rule myTest
{
    strings:
        $a = "some string"

    condition:
        $a and pe.entry_point == 0x1000
}`

const UnexpectedHeader = `rule ExampleRule
{
	extra:
		$text_string = "text here"
		$hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$text_string or $hex_string
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

const problematicRule = `rule my_Methodology_Contains_Shortcut_OtherURIhandlers
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Noisy rule for .URL shortcuts containing unique URI handlers"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 35
    date = "27.09.2019"
  strings:
    $file = "URL="
    $filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*) and not $filenegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}`

const ExtractableRule = `import "pe"

rule ExtractableRule {
	meta:
		id = "2050327"

	strings:
		$my_text_string = "text here"
		$my_hex_string = { E2 34 A1 C8 23 FB }

	condition:
		$my_text_string or $my_hex_string
}`

func TestStrelkaModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewStrelkaEngine(srv)

	assert.Implements(t, (*module.Module)(nil), mod)
	assert.Implements(t, (*server.DetectionEngine)(nil), mod)

	err := mod.Init(nil)
	assert.NoError(t, err)

	mod.showAiSummaries = false

	err = mod.Start()
	assert.NoError(t, err)

	assert.True(t, mod.IsRunning())

	err = mod.Stop()
	assert.NoError(t, err)

	assert.Equal(t, 1, len(srv.DetectionEngines))
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameStrelka])
}

func TestCheckAutoEnabledYaraRule(t *testing.T) {
	e := &StrelkaEngine{
		autoEnabledYaraRules: []string{"securityonion-yara"},
	}

	tests := []struct {
		name     string
		ruleset  string
		expected bool
	}{
		{"securityonion-yara rule, rule enabled", "securityonion-yara", true},
		{"securityonion-YARA rule upper case, rule enabled", "securityonion-YARA", true},
		{"securityonion-fake rule, rule not enabled", "securityonion-fake", false},
		{"no ruleset, rule not enabled", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := &model.Detection{
				Ruleset: tt.ruleset,
			}
			checkRulesetEnabled(e, det)
			assert.Equal(t, tt.expected, det.IsEnabled)
		})
	}
}

func TestSyncStrelka(t *testing.T) {
	table := []struct {
		Name           string
		InitMock       func(*servermock.MockDetectionstore, *mock.MockIOManager)
		ExpectedErr    error
		ExpectedErrMap map[string]string
	}{
		{
			Name: "Enable Simple Rules",
			InitMock: func(mockDetStore *servermock.MockDetectionstore, iom *mock.MockIOManager) {
				mockDetStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					"1": {
						PublicID:  "1",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
					"2": {
						PublicID:  "2",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
				}, nil)

				iom.EXPECT().ReadDir("yaraRulesFolder").Return(nil, nil)

				iom.EXPECT().WriteFile(gomock.Any(), []byte(simpleRule), fs.FileMode(0644)).Return(nil).MaxTimes(2)

				iom.EXPECT().ExecCommand(gomock.Cond(func(c any) bool {
					cmd := c.(*exec.Cmd)

					if !strings.HasSuffix(cmd.Path, "python3") {
						return false
					}

					if slices.Equal(cmd.Args, []string{"compileYaraPythonScriptPath", "yaraRulesFolder"}) {
						return false
					}

					return true
				})).Return([]byte{}, 0, time.Duration(0), nil)
			},
		},
	}

	ctx := context.Background()

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockDetStore := servermock.NewMockDetectionstore(ctrl)
			iom := mock.NewMockIOManager(ctrl)

			mod := NewStrelkaEngine(&server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
				Detectionstore:   mockDetStore,
			})
			mod.isRunning = true
			mod.srv.DetectionEngines[model.EngineNameSuricata] = mod
			mod.IOManager = iom

			mod.compileYaraPythonScriptPath = "compileYaraPythonScriptPath"
			mod.yaraRulesFolder = "yaraRulesFolder"

			test.InitMock(mockDetStore, iom)

			errMap, err := mod.SyncLocalDetections(ctx, nil)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)
		})
	}
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
			Input: MyBasicRule,
			ExpectedRules: []*YaraRule{
				{
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
						`$my_hex_string = { E2 34 A1 C8 23 FB }`,
					},
					Condition: `$my_text_string or $my_hex_string`,
					Src:       MyBasicRule,
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
					IsPrivate:  true,
					Identifier: "MetadataExample",
					Meta: Metadata{
						Author:      util.Ptr("John Doe"),
						Date:        util.Ptr("2023-12-27"),
						Version:     util.Ptr("1.0"),
						Reference:   util.Ptr("http://somewhere.invalid"),
						Description: util.Ptr("Example Rule"),
						Rest: map[string]string{
							"my_identifier_1": "Some string data",
							"my_identifier_2": "24",
							"my_identifier_3": "true",
						},
					},
					Strings: []string{
						"$my_text_string = \"text here\"",
						"$my_hex_string = { E2 34 A1 C8 23 FB }",
					},
					Condition: "$my_text_string or $my_hex_string",
					Src:       BasicRuleWMeta,
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
						"$my_re1 = /md5: [0-9a-fA-F]{32}/",
						"$my_re2 = /state: (on|off)/",
					},
					Condition: "$my_re1 and $my_re2",
					Src:       RegexRule,
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
					Identifier: "myTest",
					Strings: []string{
						`$a = "some string"`,
					},
					Condition: `$a and pe.entry_point == 0x1000`,
					Src:       ImportRule,
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
					Src:       RuleWithComments,
				},
			},
		},
		{
			Name:  "Multiple Rules",
			Input: ImportRule + "\n\n" + MyBasicRule,
			ExpectedRules: []*YaraRule{
				{
					Imports: []string{
						"pe",
					},
					Identifier: "myTest",
					Strings: []string{
						`$a = "some string"`,
					},
					Condition: `$a and pe.entry_point == 0x1000`,
					Src:       ImportRule,
				},
				{
					Identifier: "ExampleRule",
					Strings: []string{
						`$my_text_string = "text here"`,
						`$my_hex_string = { E2 34 A1 C8 23 FB }`,
					},
					Condition: `$my_text_string or $my_hex_string`,
					Src:       MyBasicRule,
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
					Src:       WeirdRule,
				},
			},
		},
		{
			Name:  "Problematic Rule",
			Input: problematicRule,
			ExpectedRules: []*YaraRule{
				{
					Identifier: "my_Methodology_Contains_Shortcut_OtherURIhandlers",
					Meta: Metadata{
						Author:      util.Ptr("@itsreallynick (Nick Carr)"),
						Date:        util.Ptr("27.09.2019"),
						Reference:   util.Ptr("https://twitter.com/cglyer/status/1176184798248919044"),
						Description: util.Ptr("Detects possible shortcut usage for .URL persistence"),
						Rest: map[string]string{
							"score": "35",
						},
					},
					Strings: []string{
						`$file = "URL="`,
						`$filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase`,
						`$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"`,
						`$url_explicit = "[InternetShortcut]" nocase`,
					},
					Condition: `$file and any of ($url*) and not $filenegate and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE and filesize < 30KB`,
					Src:       problematicRule,
				},
			},
		},
		{
			Name:          "Missing Identifier",
			Input:         NoIdentifier,
			ExpectedError: util.Ptr("unexpected character in rule identifier around 5"),
		},
		{
			Name:          "Invalid Metadata",
			Input:         BadMeta,
			ExpectedError: util.Ptr("invalid meta line at 39: copyrighted"),
		},
		{
			Name:          "Unexpected End Of Rule",
			Input:         MyBasicRule[:len(MyBasicRule)-1],
			ExpectedError: util.Ptr("unexpected end of rule"),
		},
		{
			Name:          "Space in Identifier",
			Input:         MyBasic_Rule,
			ExpectedError: util.Ptr("unexpected character in rule identifier around 18"),
		},
	}

	e := &StrelkaEngine{}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rules, err := e.parseYaraRules([]byte(test.Input))
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

func TestExtractDetails(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name             string
		Input            string
		ExpectedTitle    string
		ExpectedPublicID string
		ExpectedSeverity model.Severity
	}{
		{
			Name:             "Simple Extraction",
			Input:            ExtractableRule,
			ExpectedTitle:    "ExtractableRule",
			ExpectedPublicID: "ExtractableRule",
			ExpectedSeverity: model.SeverityUnknown,
		},
		{
			Name:             "No Extracted Values",
			Input:            simpleRule,
			ExpectedTitle:    "dummy",
			ExpectedPublicID: "dummy",
			ExpectedSeverity: model.SeverityUnknown,
		},
	}

	eng := &StrelkaEngine{}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			detect := &model.Detection{
				Content: test.Input,
			}

			err := eng.ExtractDetails(detect)
			assert.NoError(t, err)

			assert.Equal(t, test.ExpectedTitle, detect.Title)
			assert.Equal(t, test.ExpectedPublicID, detect.PublicID)
			assert.Equal(t, test.ExpectedSeverity, detect.Severity)
		})
	}
}

func TestToDetection(t *testing.T) {
	e := &StrelkaEngine{}

	expected := &model.Detection{
		Engine:      model.EngineNameStrelka,
		Language:    model.SigLangYara,
		PublicID:    "MetadataExample",
		Author:      "John Doe",
		Title:       "MetadataExample",
		Description: "Example Rule",
		Content:     BasicRuleWMeta,
		Severity:    model.SeverityUnknown,
		IsCommunity: true,
		Ruleset:     "ruleset",
		License:     "license",
	}

	rules, err := e.parseYaraRules([]byte(BasicRuleWMeta))
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
	assert.Equal(t, 1, len(rules))

	det := rules[0].ToDetection("license", "ruleset", true)
	assert.Equal(t, expected, det)
}

func TestAddMissingImports(t *testing.T) {
	tests := []struct {
		Name            string
		Input           *YaraRule
		FileImports     map[string]*regexp.Regexp
		ExpectedSrc     string
		ExpectedImports []string
	}{
		{
			Name:  "No Imports",
			Input: &YaraRule{},
			FileImports: map[string]*regexp.Regexp{
				"pe": buildImportChecker("pe"),
			},
			ExpectedSrc:     "",
			ExpectedImports: nil,
		},
		{
			Name: "No Missing Imports",
			Input: &YaraRule{
				Imports: []string{
					"pe",
				},
				Src: "import \"pe\"\nrule Test {\ncondition:\npe.imphash() == \"1234\"\n}",
			},
			FileImports: map[string]*regexp.Regexp{
				"pe": buildImportChecker("pe"),
			},
			ExpectedSrc:     "import \"pe\"\nrule Test {\ncondition:\npe.imphash() == \"1234\"\n}",
			ExpectedImports: []string{"pe"},
		},
		{
			Name: "Missing pe Import",
			Input: &YaraRule{
				Src: "rule Test {\ncondition:\npe.imphash() == \"1234\"\n}",
			},
			FileImports: map[string]*regexp.Regexp{
				"pe": buildImportChecker("pe"),
			},
			ExpectedSrc:     "import \"pe\"\n\nrule Test {\ncondition:\npe.imphash() == \"1234\"\n}",
			ExpectedImports: []string{"pe"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			addMissingImports(test.Input, test.FileImports)

			assert.Equal(t, test.ExpectedSrc, test.Input.Src)
			assert.Equal(t, test.ExpectedImports, test.Input.Imports)
		})
	}
}

func TestGetCompilationResult(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsn := `{
		"timestamp": "2021-08-26T15:00:00Z",
		"success": ["ca978112-ca1b-4dca-bac2-31b39a23dc4d", "3e23e816-0039-494a-b389-4f6564e1b134"],
		"failure": ["2e7d2c03-a950-4ae2-a5ec-f5b5356885a5", "18ac3e73-43f0-4689-8c51-0e93f9352611"],
		"compiled_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
}`

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return([]byte(jsn), nil)

	eng := &StrelkaEngine{
		yaraRulesFolder: "/opt/so/conf/strelka/rules",
		IOManager:       iom,
	}

	report, err := eng.getCompilationReport()
	assert.NoError(t, err)

	assert.Equal(t, "2021-08-26T15:00:00Z", report.Timestamp)
	assert.Equal(t, []string{"ca978112-ca1b-4dca-bac2-31b39a23dc4d", "3e23e816-0039-494a-b389-4f6564e1b134"}, report.Success)
	assert.Equal(t, []string{"2e7d2c03-a950-4ae2-a5ec-f5b5356885a5", "18ac3e73-43f0-4689-8c51-0e93f9352611"}, report.Failure)
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", report.CompiledRulesHash)
}

func TestGetDeployed(t *testing.T) {
	report := &model.CompilationReport{
		Success: []string{"a", "b"},
		Failure: []string{"c", "d"},
	}

	publicIds := getDeployed(report)
	assert.Equal(t, []string{"a", "b", "c", "d"}, publicIds)
}

func TestVerifyCompiledHash(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil).Times(3)
	iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return(nil, os.ErrNotExist).Times(2)

	eng := &StrelkaEngine{
		IOManager:       iom,
		yaraRulesFolder: "/opt/so/conf/strelka/rules",
	}

	// a successful match
	err := eng.verifyCompiledHash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	assert.NoError(t, err)

	// an unsuccessful match
	err = eng.verifyCompiledHash("a bad hash that'll never match")
	assert.Error(t, err)

	// a missing hash and a present file
	err = eng.verifyCompiledHash("")
	assert.Error(t, err)

	// a hash but a missing file
	err = eng.verifyCompiledHash("no file, no way this'll match")
	assert.Error(t, err)

	// edge case where there's no compiled rules because there's no enabled rules,
	// no hash is only allowed if the file is explicitly missing
	err = eng.verifyCompiledHash("")
	assert.NoError(t, err)
}

func TestIntegrityCheck(t *testing.T) {
	tests := []struct {
		Name     string
		InitMock func(*mock.MockIOManager, *servermock.MockDetectionstore)
		DbnE     []string
		EbnD     []string
		ExpError error
	}{
		{
			Name: "No Rules",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return(nil, os.ErrNotExist)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, opts ...model.GetAllOption) (map[string]*model.Detection, error) {
					expected := []string{
						`query AND so_detection.engine:"strelka"`,
						`query AND so_detection.isEnabled:"true"`,
					}

					for i, opt := range opts {
						value := opt("query", "so_")
						assert.Equal(t, expected[i], value)
					}

					return map[string]*model.Detection{}, nil
				})
			},
			DbnE: []string{},
			EbnD: []string{},
		},
		{
			Name: "Bad Compilation Report Hash",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "bad hash",
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)
			},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Compilation Report Failures",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					Failure:           []string{"MyYARARule1", "MyYARARule2", "MyYARARule3", "MyYARARule4", "MyYARARule5", "MyYARARule6"},
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)
			},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "1 Deployed, 0 Enabled",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					Success:           []string{"MyYARARule"},
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil)
			},
			DbnE:     []string{"MyYARARule"},
			EbnD:     []string{},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "0 Deployed, 1 Enabled",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					"MyYARARule": {},
				}, nil)
			},
			DbnE:     []string{},
			EbnD:     []string{"MyYARARule"},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Mix and Match Fail",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					Success:           []string{"MyYARARule", "MyOtherYARARule"},
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					"MyYARARule":     {},
					"AThirdYARARule": {},
				}, nil)
			},
			DbnE:     []string{"MyOtherYARARule"},
			EbnD:     []string{"AThirdYARARule"},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Mix and Match Fail",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) {
				report := model.CompilationReport{
					CompiledRulesHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					Success:           []string{"MyYARARule", "MyOtherYARARule"},
				}

				jsonReport, _ := json.Marshal(report)
				iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return(jsonReport, nil)

				iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					"MyYARARule":      {},
					"MyOtherYARARule": {},
				}, nil)
			},
			DbnE: []string{},
			EbnD: []string{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			detStore := servermock.NewMockDetectionstore(ctrl)
			iom := mock.NewMockIOManager(ctrl)
			test.InitMock(iom, detStore)

			e := &StrelkaEngine{
				srv: &server.Server{
					Detectionstore: detStore,
				},
				IOManager: iom,
			}

			DbnE, EbnD, err := e.IntegrityCheck(false, nil)

			if test.ExpError != nil {
				assert.Error(t, err)
				assert.Equal(t, err, test.ExpError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.DbnE, DbnE)
			assert.Equal(t, test.EbnD, EbnD)
		})
	}
}

func TestSyncWriteNoReadFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "123").Return(nil, errors.New("Object not found"))

	wnr := util.Ptr("123")

	eng := &StrelkaEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		writeNoRead: wnr,
	}

	logger := log.WithField("detectionEngine", "test-strelka")

	err := eng.Sync(logger, false)
	assert.Equal(t, detections.ErrSyncFailed, err)
	assert.Equal(t, wnr, eng.writeNoRead)
}

func TestSyncIncrementalNoChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	eng := &StrelkaEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		isRunning:   true,
		reposFolder: "repos",
		rulesRepos: []*model.RuleRepo{
			{
				Repo:      "https://github.com/user/repo",
				Community: true,
			},
		},
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: false,
	}

	logger := log.WithField("detectionEngine", "test-strelka")

	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(false, false, false)
	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return([]byte(`{"timestamp": "now", "success": ["publicId"], "failure": [], "compiled_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`), nil) // getCompilationReport
	iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)                                                                                                                                  // verifyCompiledHash
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		"publicId": nil,
	}, nil)

	err := eng.Sync(logger, false)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
}

func TestSyncChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)

	eng := &StrelkaEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		isRunning:   true,
		reposFolder: "repos",
		rulesRepos: []*model.RuleRepo{
			{
				Repo:      "https://github.com/user/repo",
				Community: true,
			},
		},
		autoEnabledYaraRules:        []string{"repo"},
		yaraRulesFolder:             "yaraRulesFolder",
		compileYaraPythonScriptPath: "compile_yara.py",
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: false,
	}

	logger := log.WithField("detectionEngine", "test-strelka")

	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(true, false, false)
	// Sync
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		"dummy": {
			Auditable: model.Auditable{
				Id:         "abc",
				CreateTime: util.Ptr(time.Now()),
			},
			PublicID:  "dummy",
			IsEnabled: true,
		},
		"delete": {
			Auditable: model.Auditable{
				Id: "deleteme",
			},
			PublicID: "delete",
		},
	}, nil)
	iom.EXPECT().WalkDir("repos/repo", gomock.Any()).DoAndReturn(func(path string, walkFn fs.WalkDirFunc) error {
		files := []fs.DirEntry{
			&handmock.MockDirEntry{
				Filename: "rule1.yar",
			},
			&handmock.MockDirEntry{
				Filename: "rule2.yar",
			},
		}

		for _, f := range files {
			err := walkFn(f.Name(), f, nil)
			assert.NoError(t, err)
		}
		return nil
	})
	iom.EXPECT().ReadFile("rule1.yar").Return([]byte(simpleRule), nil)
	iom.EXPECT().ReadFile("rule2.yar").Return([]byte(MyBasicRule), nil)
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil).Times(3)
	bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: "id",
			}
			item.OnSuccess(ctx, item, resp)
		}

		workItems = append(workItems, item)

		return nil
	}).Times(3)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditm, nil)
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("document"), "index", nil).Times(3)
	auditm.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: "id",
			}
			item.OnSuccess(ctx, item, resp)
		}

		auditItems = append(auditItems, item)

		return nil
	}).Times(3)
	auditm.EXPECT().Close(gomock.Any()).Return(nil)
	auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
	// syncDetections
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"dummy": {
			Auditable: model.Auditable{
				Id:         "abc",
				CreateTime: util.Ptr(time.Now()),
			},
			PublicID:  "dummy",
			IsEnabled: true,
		},
		"ExampleRule": {
			Auditable: model.Auditable{
				Id:         "new",
				CreateTime: util.Ptr(time.Now()),
			},
			PublicID: "ExampleRule",
		},
	}, nil)
	iom.EXPECT().ReadDir("yaraRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "pre-existing-rule.compiled",
		},
	}, nil)
	iom.EXPECT().DeleteFile("yaraRulesFolder/pre-existing-rule.compiled").Return(nil)
	iom.EXPECT().WriteFile("yaraRulesFolder/dummy.yar", gomock.Any(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("yaraRulesFolder/ExampleRule.yar", gomock.Any(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().ExecCommand(gomock.Any()).DoAndReturn(func(cmd *exec.Cmd) ([]byte, int, time.Duration, error) {
		assert.Contains(t, cmd.Args, "python3")
		assert.Len(t, cmd.Args, 3)
		assert.Equal(t, "python3", cmd.Args[0])
		assert.Equal(t, "compile_yara.py", cmd.Args[1])
		assert.Equal(t, "yaraRulesFolder", cmd.Args[2])
		return []byte("Compiled Successfully"), 0, time.Duration(time.Second), nil
	})
	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadFile("/opt/so/state/detections_yara_compilation-total.log").Return([]byte(`{"timestamp": "now", "success": ["dummy", "ExampleRule"], "failure": [], "compiled_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`), nil) // getCompilationReport
	iom.EXPECT().ReadFile("/opt/so/saltstack/local/salt/strelka/rules/compiled/rules.compiled").Return([]byte("abc"), nil)                                                                                                                                              // verifyCompiledHash
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		"dummy":       nil,
		"ExampleRule": nil,
	}, nil)

	err := eng.Sync(logger, true)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)

	assert.Len(t, workItems, 3)
	assert.Len(t, auditItems, 3)

	workActions := lo.Map(workItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.Action
	})

	auditActions := lo.Map(auditItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.Action
	})

	assert.Equal(t, []string{"update", "create", "delete"}, workActions)
	assert.Equal(t, []string{"create", "create", "create"}, auditActions)

	workDocIds := lo.Map(workItems, func(item esutil.BulkIndexerItem, _ int) string {
		return item.DocumentID
	})

	assert.Equal(t, []string{"abc", "", "deleteme"}, workDocIds) // update has an id, create does not, delete does
}

func TestLoadAndMergeAuxiliaryData(t *testing.T) {
	tests := []struct {
		Name              string
		PublicId          string
		Content           string
		ExpectedAiFields  bool
		ExpectedAiSummary string
		ExpectedReviewed  bool
		ExpectedStale     bool
	}{
		{
			Name:             "No Auxiliary Data",
			PublicId:         "Webshell_FOPO_Obfuscation_APT_ON_Nov17_1",
			ExpectedAiFields: false,
		},
		{
			Name:              "Data, Unreviewed",
			PublicId:          "Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256",
			Content:           "no-alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256",
			ExpectedReviewed:  false,
			ExpectedStale:     true,
		},
		{
			Name:              "Data, Reviewed",
			PublicId:          "_root_040_zip_Folder_deploy",
			Content:           "alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for _root_040_zip_Folder_deploy",
			ExpectedReviewed:  true,
		},
	}

	e := StrelkaEngine{
		showAiSummaries: true,
	}
	err := e.LoadAuxiliaryData([]*model.AiSummary{
		{
			PublicId:     "_root_040_zip_Folder_deploy",
			Summary:      "Summary for _root_040_zip_Folder_deploy",
			Reviewed:     true,
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
		},
		{
			PublicId:     "Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256",
			Summary:      "Summary for Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256",
			Reviewed:     false,
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
		},
	})
	assert.NoError(t, err)

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			det := &model.Detection{
				PublicID: test.PublicId,
				Content:  test.Content,
			}

			e.showAiSummaries = true
			err := e.MergeAuxiliaryData(det)
			assert.NoError(t, err)
			if test.ExpectedAiFields {
				assert.NotNil(t, det.AiFields)
				assert.Equal(t, test.ExpectedAiSummary, det.AiSummary)
				assert.Equal(t, test.ExpectedReviewed, det.AiSummaryReviewed)
				assert.Equal(t, test.ExpectedStale, det.IsAiSummaryStale)
			} else {
				assert.Nil(t, det.AiFields)
			}

			e.showAiSummaries = false
			det.AiFields = nil

			err = e.MergeAuxiliaryData(det)
			assert.NoError(t, err)
			assert.Nil(t, det.AiFields)
		})
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		Name          string
		Input         string
		ExpectedError string
	}{
		{
			Name:  "Valid Rule",
			Input: MyBasicRule,
		},
		{
			Name:          "Empty Rule",
			Input:         "",
			ExpectedError: "expected exactly 1 rule, got 0",
		},
		{
			Name:          "Empty Rule",
			Input:         MyBasicRule + "\n" + MyBasicRule,
			ExpectedError: "expected exactly 1 rule, got 2",
		},
		{
			Name:          "Missing ID",
			Input:         strings.ReplaceAll(MyBasicRule, "ExampleRule", ""),
			ExpectedError: "unexpected character in rule identifier around 6",
		},
	}

	e := &StrelkaEngine{}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			_, err := e.ValidateRule(test.Input)
			if test.ExpectedError != "" {
				assert.Error(t, err)
				assert.Equal(t, test.ExpectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
