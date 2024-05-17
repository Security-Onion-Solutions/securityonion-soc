package strelka

import (
	"context"
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
	"github.com/security-onion-solutions/securityonion-soc/server/modules/strelka/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/tj/assert"
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
			InitMock: func(mockDetStore *servermock.MockDetectionstore, mio *mock.MockIOManager) {
				mockDetStore.EXPECT().Query(gomock.Any(), gomock.Any(), gomock.Any()).Return([]interface{}{
					&model.Detection{
						PublicID:  "1",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
					&model.Detection{
						PublicID:  "2",
						Engine:    model.EngineNameStrelka,
						Content:   simpleRule,
						IsEnabled: true,
					},
				}, nil)

				mio.EXPECT().ReadDir("yaraRulesFolder").Return(nil, nil)

				mio.EXPECT().WriteFile(gomock.Any(), []byte(simpleRule), fs.FileMode(0644)).Return(nil).MaxTimes(2)

				mio.EXPECT().ExecCommand(gomock.Cond(func(c any) bool {
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
			mio := mock.NewMockIOManager(ctrl)

			mod := NewStrelkaEngine(&server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
				Detectionstore:   mockDetStore,
			})
			mod.isRunning = true
			mod.srv.DetectionEngines[model.EngineNameSuricata] = mod
			mod.IOManager = mio

			mod.compileYaraPythonScriptPath = "compileYaraPythonScriptPath"
			mod.yaraRulesFolder = "yaraRulesFolder"

			test.InitMock(mockDetStore, mio)

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
			Input:         MyBasicRule[:len(MyBasicRule)-1],
			ExpectedError: util.Ptr("unexpected end of rule"),
		},
		{
			Name: "Filter Out",
			// BasicRule doesn't match either filter and will be left out,
			// DeniedRule will be filtered out by the denyRegex.
			Input:         BasicRule + "\n\n" + DeniedRule,
			ExpectedRules: []*YaraRule{},
		},
	}

	e := &StrelkaEngine{
		allowRegex: regexp.MustCompile("my"),
		denyRegex:  regexp.MustCompile("Deny"), // case sensitive
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rules, err := e.parseYaraRules([]byte(test.Input), true)
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
	e := &StrelkaEngine{}
	e.allowRegex = regexp.MustCompile("thing not in rule")
	e.denyRegex = regexp.MustCompile("Metadata Example")

	rules, err := e.parseYaraRules([]byte(BasicRuleWMeta), false)
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)
	assert.Equal(t, 1, len(rules))

	raw := rules[0].String()
	assert.Equal(t, NormalizedBasicRuleWMeta, raw)
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
			ExpectedPublicID: "2050327",
			ExpectedSeverity: model.SeverityUnknown,
		},
		{
			Name:             "No Extracted Values",
			Input:            simpleRule,
			ExpectedTitle:    "dummy",
			ExpectedPublicID: "b5a2c962-5061-4366-aa27-2ffac6d9744a",
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
		PublicID:    "7669eb89-c61c-446e-aaff-12b2c0994dea",
		Author:      "John Doe",
		Title:       "MetadataExample",
		Description: "Example Rule",
		Content:     NormalizedBasicRuleWMeta,
		Severity:    model.SeverityUnknown,
		IsCommunity: true,
		Ruleset:     "ruleset",
		License:     "license",
	}

	rules, err := e.parseYaraRules([]byte(BasicRuleWMeta), false)
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

	mio := mock.NewMockIOManager(ctrl)
	mio.EXPECT().ReadFile("/opt/sensoroni/logs/detections_yara_compilation-total.log").Return([]byte(jsn), nil)

	eng := &StrelkaEngine{
		IOManager:       mio,
		yaraRulesFolder: "/opt/so/conf/strelka/rules",
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
	assert.Equal(t, []string{"ca978112-ca1b-4dca-bac2-31b39a23dc4d",
		"3e23e816-0039-494a-b389-4f6564e1b134",
		"2e7d2c03-a950-4ae2-a5ec-f5b5356885a5",
		"18ac3e73-43f0-4689-8c51-0e93f9352611"}, publicIds)
}

func TestVerifyCompiledHash(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mio := mock.NewMockIOManager(ctrl)
	mio.EXPECT().ReadFile("/opt/so/conf/strelka/rules/rules.compiled").Return([]byte("abc"), nil).Times(3)
	mio.EXPECT().ReadFile("/opt/so/conf/strelka/rules/rules.compiled").Return(nil, os.ErrNotExist).Times(2)

	eng := &StrelkaEngine{
		IOManager:       mio,
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
