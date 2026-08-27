// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/handmock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	SimpleRuleSID    = "10000"
	SimpleRule       = `alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)`
	SimpleRule2      = `alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000; rev:7; metadata:created_at 2010_09_23, updated_at 2025_05_03;)`
	FlowbitsRuleASID = "50000"
	FlowbitsRuleA    = `alert http any any -> any any ( msg:"RULE A"; flow: established,to_server; http.method; content:"POST"; http.content_type; content:"x-www-form-urlencoded"; flowbits: set, test; sid:50000;)`
	FlowbitsRuleBSID = "60000"
	FlowbitsRuleB    = `alert http any any -> any any (msg:"RULE B"; flowbits: isset, test; flow: established,to_client; content:"uid=0"; sid:60000;)`
	IgnoredSIDRange  = "1100000-1101000\n"
	IgnoredSID       = "1100001"
)

func emptySettings() []*model.Setting {
	return []*model.Setting{
		{Id: "idstools.rules.local__rules"},
		{Id: "idstools.sids.enabled"},
		{Id: "idstools.sids.disabled"},
		{Id: "idstools.sids.modify"},
		{Id: "suricata.thresholding.sids__yaml"},
		{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges"},
	}
}

func TestSuricataModule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().DoesTemplateExist(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

	srv := &server.Server{
		DetectionEngines: sync.Map{}, // map[model.EngineName]server.DetectionEngine{},
		Detectionstore:   detStore,
	}
	mod := NewSuricataEngine(srv)

	assert.Implements(t, (*module.Module)(nil), mod)
	assert.Implements(t, (*server.DetectionEngine)(nil), mod)

	// Provide minimal config with empty rulesetSources array
	cfg := map[string]interface{}{
		"rulesetSources": []interface{}{},
	}
	err := mod.Init(cfg)
	assert.NoError(t, err)

	mod.showAiSummaries = false

	err = mod.Start()
	assert.NoError(t, err)

	assert.True(t, mod.IsRunning())

	err = mod.Stop()
	assert.NoError(t, err)

	count := 0
	srv.DetectionEngines.Range(func(k, v interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 1, count)

	m, ok := srv.DetectionEngines.Load(model.EngineNameSuricata)
	assert.True(t, ok)
	assert.Same(t, mod, m)
}

func TestSettingByID(t *testing.T) {
	allSettings := []*model.Setting{
		{Id: "1", Value: "one"},
		{Id: "2", Value: "two"},
		{Id: "3", Value: "three"},
	}
	byId := map[string]*model.Setting{
		"1": allSettings[0],
		"2": allSettings[1],
		"3": allSettings[2],
	}

	table := []struct {
		Name          string
		SettingID     string
		ExpectedValue *string
	}{
		{Name: "Get 1", SettingID: "1", ExpectedValue: util.Ptr("one")},
		{Name: "Get 2", SettingID: "2", ExpectedValue: util.Ptr("two")},
		{Name: "Get 3", SettingID: "3", ExpectedValue: util.Ptr("three")},
		{Name: "Get 4", SettingID: "4", ExpectedValue: nil},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			value := settingByID(allSettings, test.SettingID)
			if test.ExpectedValue == nil {
				assert.Nil(t, value)
			} else {
				assert.Equal(t, *test.ExpectedValue, value.Value)
				assert.Same(t, value, byId[test.SettingID])
			}
		})
	}
}

func TestReadFingerprint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	content := " fingerprint\n\t"

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("file").Return([]byte(content), nil)

	e := &SuricataEngine{
		srv:       &server.Server{},
		IOManager: iom,
	}

	fingerprint, ok, err := e.readFingerprint("file")

	assert.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, fingerprint)
	assert.Equal(t, "fingerprint", *fingerprint)
}

func TestReadFingerprintDoesNotExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("file").Return(nil, os.ErrNotExist)

	e := &SuricataEngine{
		srv:       &server.Server{},
		IOManager: iom,
	}

	fingerprint, ok, err := e.readFingerprint("file")

	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, fingerprint)
}

func TestReadFingerprintError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("file").Return(nil, errors.New("error"))

	e := &SuricataEngine{
		srv:       &server.Server{},
		IOManager: iom,
	}

	fingerprint, ok, err := e.readFingerprint("file")

	assert.Error(t, err)
	assert.False(t, ok)
	assert.Nil(t, fingerprint)
}

func TestExtractSID(t *testing.T) {
	table := []struct {
		Name   string
		Input  string
		Output *string
	}{
		{Name: "Simple SID", Input: "sid:10000;", Output: util.Ptr("10000")},
		{Name: "Empty SID", Input: "sid: ;", Output: util.Ptr("")},
		{Name: "Capital SID", Input: "SID:10000;", Output: util.Ptr("10000")},
		{Name: "UUID SID", Input: "sid: 82ca7105-9001-40b7-a8cc-4eaebaf17815;", Output: util.Ptr("82ca7105-9001-40b7-a8cc-4eaebaf17815")},
		{Name: "No SID", Input: "nid: 10000", Output: nil},
		{Name: "Single-Quoted SID", Input: "sid: '10000';", Output: util.Ptr("10000")},
		{Name: "Double-Quoted SID", Input: `sid:"10000";`, Output: util.Ptr("10000")},
		{Name: "Single-Quoted Empty SID", Input: "sid:'';", Output: util.Ptr("")},
		{Name: "Double-Quoted Empty SID", Input: `sid: "";`, Output: util.Ptr("")},
		{Name: "Multiple SIDs", Input: "sid: 10000; sid: 10001;", Output: nil},
		{Name: "Sample Rule", Input: SimpleRule, Output: util.Ptr(SimpleRuleSID)},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			output := extractSID(test.Input)
			assert.Equal(t, test.Output, output)
		})
	}
}

func TestIndexRules(t *testing.T) {
	lines := []string{
		`90000 this that`,
		`10000 "flowbits" "noalert; flowbits"`,
		`alert http any any -> any any (msg:"FILE pdf detected"; filemagic:"PDF document"; filestore; sid:1100000; rev:1;)`,
		`#alert smtp any any -> any any (msg:"FILE pdf detected"; filemagic:"PDF document"; filestore; sid:1100001; rev:1;)`,
		`# An unrelated comment`,
		`a83ba97b-a8e8-4258-be1b-022aff230e6e "flowbits" "noalert; flowbits"`,
		` # 23220e49-7229-43a1-92d5-d68e46d27105 "flowbits" "noalert; flowbits"`,
		`e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5 that this`,
	}

	output := indexRules(lines, true)

	assert.Equal(t, 1, len(output))
	assert.Contains(t, output, "1100000")
	assert.Equal(t, output["1100000"], 2)
}

func TestValidate(t *testing.T) {
	table := []struct {
		Name        string
		Input       string
		ExpectedErr string
	}{
		{
			Name:  "Valid Rule",
			Input: SimpleRule,
		},
		{
			Name:  "Valid Rule with Flowbits",
			Input: FlowbitsRuleA,
		},
		{
			Name:  "Valid Rule with Escaped Quotes",
			Input: `alert http any any -> any any (msg:"This rule has \"escaped quotes\""; sid: 200000;)`,
		},
		{
			Name:        "Invalid Direction",
			Input:       `alert http any any <-> any any (msg:"This rule has an invalid direction";)`,
			ExpectedErr: "invalid direction, must be '<>', '->', or '=>', got <->",
		},
		{
			Name:        "Unexpected Suffix",
			Input:       SimpleRule + "x",
			ExpectedErr: "invalid rule, expected end of rule, got 1 more bytes",
		},
		{
			Name:        "Unexpected End of Rule",
			Input:       "x",
			ExpectedErr: "invalid rule, unexpected end of rule",
		},
		{
			Name:  "Parentheses in Unquoted Option",
			Input: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ADWARE_PUP WinSoftware.com Spyware User-Agent (WinSoftware)\\"; flow:to_server,established; http.user_agent; content:"WinSoftware"; nocase; depth:11; reference:url,research.sunbelt-software.com/threatdisplay.aspx?name=WinSoftware%20Corporation%2c%20Inc.%20(v)&threatid=90037; reference:url,doc.emergingthreats.net/2003527; classtype:pup-activity; sid:2003527; rev:12; metadata:attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, former_category ADWARE_PUP, signature_severity Minor, tag Spyware_User_Agent, updated_at 2020_10_13;)`,
		},
		{
			Name:  "Unescaped Double Quote in PCRE Option",
			Input: `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET PHISHING Common Unhidebody Function Observed in Phishing Landing"; flow:established,to_client; file.data; content:"function unhideBody()"; nocase; fast_pattern; content:"var bodyElems = document.getElementsByTagName(|22|body|22|)|3b|"; nocase; content:"bodyElems[0].style.visibility =|20 22|visible|22 3b|"; nocase; distance:0; content:"onload=|22|unhideBody()|22|"; content:"method="; nocase; pcre:"/^["']?post/Ri"; classtype:social-engineering; sid:2029732; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, created_at 2020_03_24, deployment Perimeter, signature_severity Minor, tag Phishing, updated_at 2020_03_24;)`,
		},
		{
			Name:  "Accidental Whitespace",
			Input: SimpleRule + "\n",
		},
		{
			Name:  "Excessive Whitespace",
			Input: "\n\n" + SimpleRule + "\n\n",
		},
		{
			Name:        "Rule w/ Comment",
			Input:       "# This rule does X, Y, and Z\n" + SimpleRule,
			ExpectedErr: "suricata rules must be a single line",
		},
		{
			Name:        "Multiple Rules",
			Input:       FlowbitsRuleA + "\n" + FlowbitsRuleB,
			ExpectedErr: "suricata rules must be a single line",
		},
		{
			Name:        "Multiple Rules, One Line",
			Input:       FlowbitsRuleA + " " + FlowbitsRuleB,
			ExpectedErr: "invalid rule, expected end of rule, got 126 more bytes",
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			mod := NewSuricataEngine(&server.Server{})

			_, err := mod.ValidateRule(test.Input)
			if test.ExpectedErr == "" {
				assert.NoError(t, err)

				// this rule seems valid, attempt to parse, serialize, re-parse
				parsed, err := ParseSuricataRule(test.Input)
				assert.NoError(t, err)

				_, err = ParseSuricataRule(parsed.String())
				assert.NoError(t, err)
			} else {
				assert.Equal(t, test.ExpectedErr, err.Error())
			}
		})
	}
}

func TestParse(t *testing.T) {
	ruleset := "ruleset"

	table := []struct {
		Name               string
		Lines              []string
		ExpectedDetections []*model.Detection
		ExpectedError      *string
	}{
		{
			Name: "Sunny Day Path with Edge Cases",
			Lines: []string{
				"# Comment",
				SimpleRule,
				"",
				`# alert  http any any  <>   any any (metadata:signature_severity   Informational; sid: "20000"; msg:"a \\\"tricky\"\;\\ msg";)`,
				" # " + FlowbitsRuleA,
				FlowbitsRuleB,
			},
			ExpectedDetections: []*model.Detection{
				{
					Author:        ruleset,
					PublicID:      SimpleRuleSID,
					Title:         `GPL ATTACK_RESPONSE id check returned root`,
					Category:      `GPL ATTACK_RESPONSE`,
					Severity:      model.SeverityUnknown,
					Content:       SimpleRule,
					IsEnabled:     true,
					Engine:        model.EngineNameSuricata,
					Language:      model.SigLangSuricata,
					Ruleset:       ruleset,
					License:       "Unknown",
					SourceCreated: util.Ptr(time.Date(2010, 9, 23, 0, 0, 0, 0, time.UTC)),
					SourceUpdated: util.Ptr(time.Date(2010, 9, 23, 0, 0, 0, 0, time.UTC)),
				},
				{
					Author:   ruleset,
					PublicID: "20000",
					Title:    `a \"tricky";\ msg`,
					Category: ``,
					Severity: model.SeverityInformational,
					Content:  `alert  http any any  <>   any any (metadata:signature_severity   Informational; sid: "20000"; msg:"a \\\"tricky\"\;\\ msg";)`,
					Engine:   model.EngineNameSuricata,
					Language: model.SigLangSuricata,
					Ruleset:  ruleset,
					License:  "Unknown",
				},
				{
					Author:   ruleset,
					PublicID: FlowbitsRuleASID,
					Title:    "RULE A",
					Severity: model.SeverityUnknown,
					Content:  FlowbitsRuleA,
					Engine:   model.EngineNameSuricata,
					Language: model.SigLangSuricata,
					Ruleset:  ruleset,
					License:  "Unknown",
				},
				{
					Author:    ruleset,
					PublicID:  FlowbitsRuleBSID,
					Title:     "RULE B",
					Severity:  model.SeverityUnknown,
					Content:   FlowbitsRuleB,
					IsEnabled: true,
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Ruleset:   ruleset,
					License:   "Unknown",
				},
			},
		},
		{
			Name: "Transactional Rule",
			Lines: []string{
				`alert http any any => any any (msg:"transactional"; sid:1;)`,
			},
			ExpectedDetections: []*model.Detection{
				{
					Author:    ruleset,
					PublicID:  "1",
					Title:     "transactional",
					Severity:  model.SeverityUnknown,
					Content:   `alert http any any => any any (msg:"transactional"; sid:1;)`,
					IsEnabled: true,
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Ruleset:   ruleset,
					License:   "Unknown",
				},
			},
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			data := strings.Join(test.Lines, "\n")

			detections, err := ParseSuricataRules(context.Background(), data, ruleset)
			if test.ExpectedError == nil {
				assert.NoError(t, err)
				assert.Equal(t, test.ExpectedDetections, detections)
			} else {
				assert.Equal(t, *test.ExpectedError, err.Error())
				assert.Empty(t, detections)
			}
		})
	}
}

func TestExtractDetails(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name             string
		Input            string
		ExpectedErr      *string
		ExpectedTitle    string
		ExpectedPublicID string
		ExpectedSeverity model.Severity
	}{
		{
			Name:             "Simple Extraction",
			Input:            `alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE ScarCruft TA409 Domain in TLS SNI (nav .offlinedocument .site)"; flow:established,to_server; tls.sni; bsize:24; content:"nav.offlinedocument.site"; fast_pattern; reference:url,www.sentinelone.com/labs/a-glimpse-into-future-scarcruft-campaigns-attackers-gather-strategic-intelligence-and-target-cybersecurity-professionals/; classtype:trojan-activity; sid:2050327; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2024_01_22, deployment Perimeter, performance_impact Low, confidence Medium, signature_severity Major, tag ScarCruft, tag TA409, updated_at 2024_01_22;)`,
			ExpectedTitle:    "ET MALWARE ScarCruft TA409 Domain in TLS SNI (nav .offlinedocument .site)",
			ExpectedPublicID: "2050327",
			ExpectedSeverity: model.SeverityHigh,
		},
		{
			Name:        "Missing Public Id",
			Input:       `alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:established,to_server; tls.sni; bsize:24; content:"nav.offlinedocument.site"; fast_pattern; reference:url,www.sentinelone.com/labs/a-glimpse-into-future-scarcruft-campaigns-attackers-gather-strategic-intelligence-and-target-cybersecurity-professionals/; classtype:trojan-activity; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2024_01_22, deployment Perimeter, performance_impact Low, confidence Medium, tag ScarCruft, tag TA409, updated_at 2024_01_22;)`,
			ExpectedErr: util.Ptr("rule does not contain a public Id"),
		},
		{
			Name:             "Minimal Extraction",
			Input:            `alert any any <> any any (msg:"Required";sid:10000;)`,
			ExpectedTitle:    "Required",
			ExpectedPublicID: "10000",
			ExpectedSeverity: model.SeverityUnknown,
		},
	}

	eng := &SuricataEngine{}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			detect := &model.Detection{
				Content: test.Input,
			}

			err := eng.ExtractDetails(detect)
			if test.ExpectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, *test.ExpectedErr, err.Error())
			}

			assert.Equal(t, test.ExpectedTitle, detect.Title)
			assert.Equal(t, test.ExpectedPublicID, detect.PublicID)
			assert.Equal(t, test.ExpectedSeverity, detect.Severity)
		})
	}
}

func TestCheckForMigrations(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ReadDir("/opt/so/conf/soc/migrations/").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "suricata-migration-2.4.70",
		},
		&handmock.MockDirEntry{
			Filename: "etc",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "not-a-migration",
		},
	}, nil)

	m2470 := 0
	m2471 := 0

	e := &SuricataEngine{
		migrations: map[string]func(string) error{
			"2.4.70": func(string) error {
				m2470++

				return nil
			},
			"2.4.71": func(string) error {
				// shouldn't be called
				m2471++

				return nil
			},
		},
		IOManager: iom,
	}

	e.checkForMigrations()

	assert.Equal(t, m2470, 1)
	assert.Equal(t, m2471, 0)
	assert.False(t, e.EngineState.MigrationFailure)
	assert.False(t, e.EngineState.Migrating)
}

func TestIntegrityCheck(t *testing.T) {
	// the configstore only needs to specify disabled and modify
	tests := []struct {
		Name     string
		InitMock func(*mock.MockIOManager, *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore)
		DbnE     []string
		EbnD     []string
		ExpError error
	}{
		{
			Name: "No Rules",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte{}, nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(func(ctx context.Context, opts ...model.GetAllOption) (map[string]*model.Detection, error) {
					expected := []string{
						`query AND so_detection.engine:"suricata"`,
					}

					for i, opt := range opts {
						value := opt("query", "so_")
						assert.Equal(t, expected[i], value)
					}

					return map[string]*model.Detection{}, nil
				})

				return server.NewMemConfigStore(emptySettings())
			},
			DbnE: []string{},
			EbnD: []string{},
		},
		{
			Name: "1 Deployed, 0 Enabled",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).Return(map[string]*model.Detection{
					SimpleRuleSID: {PublicID: SimpleRuleSID, IsEnabled: false, Content: SimpleRule},
				}, nil)

				return server.NewMemConfigStore(emptySettings())
			},
			DbnE:     []string{SimpleRuleSID},
			EbnD:     []string{},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "0 Deployed, 1 Enabled",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte{}, nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).Return(map[string]*model.Detection{
					SimpleRuleSID: {PublicID: SimpleRuleSID, IsEnabled: true, Content: SimpleRule},
				}, nil)

				return server.NewMemConfigStore(emptySettings())
			},
			DbnE:     []string{},
			EbnD:     []string{SimpleRuleSID},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Deployed As Disabled",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA+"\n"+IgnoredSID), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).Return(map[string]*model.Detection{
					SimpleRuleSID:    {PublicID: SimpleRuleSID, IsEnabled: false, Content: SimpleRule},
					FlowbitsRuleASID: {PublicID: FlowbitsRuleASID, IsEnabled: false, Content: FlowbitsRuleA},
				}, nil)

				return server.NewMemConfigStore([]*model.Setting{
					{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges", Value: IgnoredSIDRange},
				})
			},
			DbnE:     []string{SimpleRuleSID, FlowbitsRuleASID}, // Both rules are deployed but not enabled
			EbnD:     []string{},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Mix and Match Fail",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).Return(map[string]*model.Detection{
					SimpleRuleSID:    {PublicID: SimpleRuleSID, IsEnabled: true, Content: SimpleRule},
					FlowbitsRuleASID: {PublicID: FlowbitsRuleASID, IsEnabled: false, Content: FlowbitsRuleA}, // This should be excluded from deployed
					FlowbitsRuleBSID: {PublicID: FlowbitsRuleBSID, IsEnabled: true, Content: FlowbitsRuleB},
				}, nil)

				return server.NewMemConfigStore(emptySettings())
			},
			DbnE:     []string{},
			EbnD:     []string{FlowbitsRuleBSID},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Mix and Match Success",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil) // FlowbitsRuleB should not be deployed since it's disabled isset rule

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Times(2).Return(map[string]*model.Detection{
					SimpleRuleSID:    {PublicID: SimpleRuleSID, IsEnabled: true, Content: SimpleRule},
					FlowbitsRuleASID: {PublicID: FlowbitsRuleASID, IsEnabled: true, Content: FlowbitsRuleA},
					FlowbitsRuleBSID: {PublicID: FlowbitsRuleBSID, IsEnabled: false, Content: FlowbitsRuleB},
				}, nil)

				return server.NewMemConfigStore([]*model.Setting{
					{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges"},
				})
			},
			DbnE:     []string{}, // FlowbitsRuleB should be excluded from deployed count now
			EbnD:     []string{},
			ExpError: nil, // Should pass now because disabled flowbits rules are excluded
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			detStore := servermock.NewMockDetectionstore(ctrl)
			iom := mock.NewMockIOManager(ctrl)
			cfgStore := test.InitMock(iom, detStore)

			// Initialize flowbitResolver to track flowbit dependencies
			flowbitResolver := NewFlowbitResolver(&nidsLogger{log.WithField("test", "integrity")})

			e := &SuricataEngine{
				srv: &server.Server{
					Configstore:    cfgStore,
					Detectionstore: detStore,
					Context:        context.Background(),
				},
				allRulesFile:    "allrules",
				IOManager:       iom,
				flowbitResolver: flowbitResolver,
				flowbitRequired: make(map[string]*FlowbitDependency),
			}

			// Resolve flowbit dependencies based on detections
			// This needs to happen before IntegrityCheck
			allDetections, _ := detStore.GetAllDetections(e.srv.Context, model.WithEngine(model.EngineNameSuricata))
			if len(allDetections) > 0 {
				// Convert map to slice for flowbit resolution
				detSlice := make([]*model.Detection, 0, len(allDetections))
				for _, det := range allDetections {
					detSlice = append(detSlice, det)
				}
				e.flowbitRequired = e.flowbitResolver.ResolveFlowbitDependencies(detSlice)
			}

			DbnE, EbnD, err := e.IntegrityCheck(false, nil)

			if test.ExpError != nil {
				assert.Error(t, err)
				assert.Equal(t, err, test.ExpError)
			} else {
				assert.NoError(t, err)
			}

			assert.ElementsMatch(t, test.DbnE, DbnE)
			assert.ElementsMatch(t, test.EbnD, EbnD)
		})
	}
}

func TestSyncWriteNoReadFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "123").Return(nil, errors.New("Object not found"))

	wnr := util.Ptr("123")

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		writeNoRead: wnr,
	}

	logger := log.WithField("detectionEngine", "test-suricata")

	err := eng.Sync(logger, false)
	assert.Equal(t, detections.ErrSyncFailed, err)
	assert.Equal(t, wnr, eng.writeNoRead)
}

func TestSyncRecoversFromPanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "123").DoAndReturn(func(ctx context.Context, publicId string) (*model.Detection, error) {
		panic("test panic")
	})

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		writeNoRead: util.Ptr("123"),
	}

	logger := log.WithField("detectionEngine", "test-suricata")

	var err error
	assert.NotPanics(t, func() {
		err = eng.Sync(logger, false)
	})
	assert.NoError(t, err)
}

func TestSyncIncrementalNoChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges"},
	})

	migrationChecked := false
	checkMigration := func() {
		migrationChecked = true
	}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Configstore:    cfgStore,
			Context:        context.Background(),
		},
		isRunning:           true,
		allRulesFile:        "allRulesFile",
		thresholdFile:       "/opt/sensoroni/nids/threshold.conf",
		checkMigrationsOnce: sync.OnceFunc(checkMigration),
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:         iom,
		showAiSummaries:   false,
		autoUpdateEnabled: true,
		rulesetSources:    []*RulesetSource{}, // Empty rulesets
	}

	logger := &nidsLogger{log.WithField("detectionEngine", "test-suricata")}

	// Initialize RulesetManager with empty sources
	eng.rulesetManager = NewRulesetManager(iom, logger)
	// Initialize FlowbitResolver
	eng.flowbitResolver = NewFlowbitResolver(logger)

	// Mock RulesetManager behavior - no rulesets configured, so no files to sync
	// The sync will initialize RulesetManager with empty config and proceed

	// Mock the new unified Sync behavior with empty rulesets
	// Allow multiple calls to GetAllDetections (used by applyUserState and IntegrityCheck)
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil).AnyTimes()

	// Mock BulkIndexer for updateDetectionStore (even with no detections, it still creates indexer)
	bim := servermock.NewMockBulkIndexer(ctrl)
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	// 1. Write empty all rules file
	iom.EXPECT().WriteFile("allRulesFile", gomock.Nil(), fs.FileMode(0644)).Return(nil)
	// 2. Write empty threshold file
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// 3. Write state file
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// 4. IntegrityCheck - read the empty rules file
	iom.EXPECT().ReadFile("allRulesFile").Return([]byte(""), nil)

	err := eng.Sync(logger.Entry, false)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
	assert.True(t, migrationChecked)
}

func TestSyncDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Config:         &config.ServerConfig{},
		},
		isRunning:         true,
		IOManager:         iom,
		showAiSummaries:   true,
		autoUpdateEnabled: false,
	}

	logger := log.WithField("detectionEngine", "test-suricata")

	err := eng.Sync(logger, false)
	assert.NoError(t, err)

	assert.False(t, eng.EngineState.Syncing)
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
}

// TestSyncIntegrityCheckWithNoRulesets verifies that the integrity check correctly detects
// mismatches between enabled rules in Elasticsearch and deployed rules when no rulesets
// are configured. This tests the scenario where ES has existing rules but no ruleset
// sources are providing rules during sync.
func TestSyncIntegrityCheckWithNoRulesets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges"},
	})

	migrationChecked := false
	checkMigration := func() {
		migrationChecked = true
	}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Configstore:    cfgStore,
			Context:        ctx,
		},
		isRunning:           true,
		checkMigrationsOnce: sync.OnceFunc(checkMigration),
		allRulesFile:        "allRulesFile",
		thresholdFile:       "/opt/sensoroni/nids/threshold.conf",
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		disableRegex:      []*regexp.Regexp{regexp.MustCompile(".")}, // Disable all rules by regex filter
		IOManager:         iom,
		showAiSummaries:   false,
		autoUpdateEnabled: true,
		rulesetSources:    []*RulesetSource{}, // Empty rulesets
	}

	logger := &nidsLogger{log.WithField("detectionEngine", "test-suricata")}

	// Initialize RulesetManager with empty sources
	eng.rulesetManager = NewRulesetManager(iom, logger)
	// Initialize FlowbitResolver
	eng.flowbitResolver = NewFlowbitResolver(logger)

	// Simulate an existing enabled rule in ES that should be disabled by the regex filter
	existingRule := &model.Detection{
		Auditable: model.Auditable{
			Id: "abc",
		},
		PublicID:      SimpleRuleSID,
		IsEnabled:     true,
		Content:       SimpleRule,
		Ruleset:       "existing-rule",
		IsCommunity:   false,
		SourceCreated: util.Ptr(time.Date(2010, 9, 23, 0, 0, 0, 0, time.UTC)),
		SourceUpdated: util.Ptr(time.Date(2010, 9, 23, 0, 0, 0, 0, time.UTC)),
	}

	// Mock GetAllDetections to return the existing rule - this simulates existing data in ES
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: existingRule,
	}, nil).AnyTimes()

	// BulkIndexer is created even when no rules are processed
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	// The existing rule will be disabled by the regex filter, so it needs to be updated in ES
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, "", nil).AnyTimes()
	bim.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// File writes: all rules file (empty since rule is disabled), threshold file, state file
	iom.EXPECT().WriteFile("allRulesFile", gomock.Nil(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck - empty rules file since all rules disabled
	iom.EXPECT().ReadFile("allRulesFile").Return([]byte(""), nil)

	err := eng.Sync(logger.Entry, true)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	// The integrity check will fail because we have an enabled rule in ES but no deployed rules
	assert.True(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
	assert.True(t, migrationChecked)

	// This test verifies that integrity check correctly detects mismatches
	// between enabled rules in ES and deployed rules when no rulesets are configured
}

func TestSyncStateFileNoCommunity(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	migrationChecked := false
	checkMigration := func() {
		migrationChecked = true
	}

	ctx := context.Background()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{Id: "soc.config.server.modules.suricataengine.ignoredSidRanges"},
	})

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Configstore:    cfgStore,
			Context:        ctx,
		},
		isRunning:           true,
		allRulesFile:        "allRulesFile",
		thresholdFile:       "/opt/sensoroni/nids/threshold.conf",
		checkMigrationsOnce: sync.OnceFunc(checkMigration),
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:         iom,
		showAiSummaries:   false,
		autoUpdateEnabled: true,
		rulesetSources:    []*RulesetSource{}, // Empty rulesets
	}

	logger := &nidsLogger{log.WithField("detectionEngine", "test-suricata")}

	// Initialize RulesetManager with empty sources
	eng.rulesetManager = NewRulesetManager(iom, logger)
	// Initialize FlowbitResolver
	eng.flowbitResolver = NewFlowbitResolver(logger)

	// In the new unified architecture, this error condition doesn't exist in the same way
	// The new sync approach doesn't have the same "state file no community" concept
	// Instead, it will succeed with empty rulesets and no community rules
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil).AnyTimes()

	// Mock BulkIndexer
	bim := servermock.NewMockBulkIndexer(ctrl)
	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	// File writes for empty sync
	iom.EXPECT().WriteFile("allRulesFile", gomock.Nil(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadFile("allRulesFile").Return([]byte(""), nil)

	err := eng.Sync(logger.Entry, true)
	// In the new architecture, this succeeds rather than returning ErrStateFileNoCommunity
	assert.NoError(t, err)

	// migration should be checked even with no community rules
	assert.True(t, migrationChecked)
}

func TestApplyFilters(t *testing.T) {
	tests := []struct {
		Name             string
		EnableRegex      []*regexp.Regexp
		DisableRegex     []*regexp.Regexp
		Detection        *model.Detection
		ExpStatus        bool
		ExpFilterApplied bool
	}{
		{
			Name:             "No Filters, Disabled",
			Detection:        &model.Detection{},
			ExpStatus:        false,
			ExpFilterApplied: false,
		},
		{
			Name: "No Filters, Enabled",
			Detection: &model.Detection{
				IsEnabled: true,
			},
			ExpStatus:        true,
			ExpFilterApplied: false,
		},
		{
			Name:         "Unmodified, Disabled",
			EnableRegex:  toRegex(`alert`),
			DisableRegex: toRegex(`drop`),
			Detection: &model.Detection{
				Content: "Hello World",
			},
			ExpStatus:        false,
			ExpFilterApplied: false,
		},
		{
			Name:         "Unmodified, Enabled",
			EnableRegex:  toRegex(`alert`),
			DisableRegex: toRegex(`drop`),
			Detection: &model.Detection{
				Content:   "Hello World",
				IsEnabled: true,
			},
			ExpStatus:        true,
			ExpFilterApplied: false,
		},
		{
			Name:         "From Disabled to Enabled",
			EnableRegex:  toRegex(`alert`),
			DisableRegex: toRegex(`drop`),
			Detection: &model.Detection{
				Content:   "alert",
				IsEnabled: false,
			},
			ExpStatus:        true,
			ExpFilterApplied: true,
		},
		{
			Name:         "From Enabled to Disabled",
			EnableRegex:  toRegex(`alert`),
			DisableRegex: toRegex(`drop`),
			Detection: &model.Detection{
				Content:   "drop",
				IsEnabled: true,
			},
			ExpStatus:        false,
			ExpFilterApplied: true,
		},
		{
			Name:         "Prioritize EnableRegex",
			EnableRegex:  toRegex(`alert`),
			DisableRegex: toRegex(`alert`),
			Detection: &model.Detection{
				Content: "alert",
			},
			ExpStatus:        true,
			ExpFilterApplied: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			eng := &SuricataEngine{
				enableRegex:  test.EnableRegex,
				disableRegex: test.DisableRegex,
			}

			applied, err := eng.ApplyFilters(test.Detection)

			assert.NoError(t, err) // Error is always nil
			assert.Equal(t, test.ExpFilterApplied, applied)
			assert.Equal(t, test.ExpStatus, test.Detection.IsEnabled)
		})
	}
}

func toRegex(s ...string) []*regexp.Regexp {
	r := make([]*regexp.Regexp, len(s))

	for i, v := range s {
		r[i] = regexp.MustCompile(v)
	}

	return r
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
			PublicId:         "100000",
			Content:          "alert",
			ExpectedAiFields: false,
		},
		{
			Name:              "Data, Unreviewed",
			PublicId:          "100002",
			Content:           "no-alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 100002",
			ExpectedReviewed:  false,
			ExpectedStale:     true,
		},
		{
			Name:              "Data, Reviewed",
			PublicId:          "100001",
			Content:           "alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 100001",
			ExpectedReviewed:  true,
		},
	}

	e := SuricataEngine{
		showAiSummaries: true,
	}
	err := e.LoadAuxiliaryData([]*model.AiSummary{
		{
			PublicId:     "100001",
			Summary:      "Summary for 100001",
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
			Reviewed:     true,
		},
		{
			PublicId:     "100002",
			Summary:      "Summary for 100002",
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
			Reviewed:     false,
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

func TestRangeContains(t *testing.T) {
	tests := []struct {
		Name    string
		Range   Range
		Value   uint64
		InRange bool
	}{
		{
			Name:    "In Normal Range",
			Range:   Range{LowerLimit: 10, UpperLimit: 20},
			Value:   15,
			InRange: true,
		},
		{
			Name:  "Below Normal Range",
			Range: Range{LowerLimit: 20, UpperLimit: 25},
			Value: 5,
		},
		{
			Name:  "Above Normal Range",
			Range: Range{LowerLimit: 5, UpperLimit: 10},
			Value: 25,
		},
		{
			Name:    "Match Lower Limit",
			Range:   Range{LowerLimit: 10, UpperLimit: 20},
			Value:   10,
			InRange: true,
		},
		{
			Name:    "Match Upper Limit",
			Range:   Range{LowerLimit: 10, UpperLimit: 20},
			Value:   20,
			InRange: true,
		},
		{
			Name:    "Inside Single-Value Range",
			Range:   Range{LowerLimit: 10, UpperLimit: 10},
			Value:   10,
			InRange: true,
		},
		{
			Name:  "Outside Single-Value Range",
			Range: Range{LowerLimit: 20, UpperLimit: 20},
			Value: 10,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			assert.Equal(t, test.InRange, test.Range.Contains(test.Value))
		})
	}
}

func TestParseRanges(t *testing.T) {
	tests := []struct {
		Name           string
		Input          string
		ExpectedRanges []Range
	}{
		{
			Name:           "Empty",
			Input:          "",
			ExpectedRanges: []Range{},
		},
		{
			Name:  "Single Range",
			Input: "1100000-1101000\n",
			ExpectedRanges: []Range{
				{LowerLimit: 1100000, UpperLimit: 1101000},
			},
		},
		{
			Name:  "Multiple Ranges",
			Input: "1100000-1101000\n1102000-1103000\n1104000-1105000\n",
			ExpectedRanges: []Range{
				{LowerLimit: 1100000, UpperLimit: 1101000},
				{LowerLimit: 1102000, UpperLimit: 1103000},
				{LowerLimit: 1104000, UpperLimit: 1105000},
			},
		},
		{
			Name:  "Blank Lines",
			Input: "1100000-1101000\n\n1102000-1103000\n\n1104000-1105000\n",
			ExpectedRanges: []Range{
				{LowerLimit: 1100000, UpperLimit: 1101000},
				{LowerLimit: 1102000, UpperLimit: 1103000},
				{LowerLimit: 1104000, UpperLimit: 1105000},
			},
		},
		{
			Name:  "Inverse Range",
			Input: "1000000-1100000\n1101000-1100000\n1200000-1300000",
			ExpectedRanges: []Range{
				{LowerLimit: 1000000, UpperLimit: 1100000},
				{LowerLimit: 1200000, UpperLimit: 1300000},
			},
		},
		{
			Name:  "Overlapping Ranges",
			Input: "1000000-1100000\n900000-1200000\n",
			ExpectedRanges: []Range{
				{LowerLimit: 1000000, UpperLimit: 1100000},
				{LowerLimit: 900000, UpperLimit: 1200000},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ranges := parseIgnoredSidRanges(test.Input)
			assert.Equal(t, test.ExpectedRanges, ranges)
		})
	}
}

func TestFilterOutSIDsInRanges(t *testing.T) {
	tests := []struct {
		Name         string
		Sids         []string
		Ranges       []Range
		FilteredSids []string
	}{
		{
			Name: "Filter Nothing Out",
			Sids: []string{"100000", "100001", "100002"},
			Ranges: []Range{
				{LowerLimit: 1100000, UpperLimit: 1101000},
			},
			FilteredSids: []string{"100000", "100001", "100002"},
		},
		{
			Name: "Filter Everything Out",
			Sids: []string{"100000", "100001", "100002"},
			Ranges: []Range{
				{LowerLimit: 100000, UpperLimit: 100002},
			},
			FilteredSids: []string{},
		},
		{
			Name: "Filter Some Out",
			Sids: []string{"100000", "100001", "100002"},
			Ranges: []Range{
				{LowerLimit: 100000, UpperLimit: 100001},
			},
			FilteredSids: []string{"100002"},
		},
		{
			Name: "Filter Some Out (Multiple Ranges)",
			Sids: []string{"100000", "100001", "100002", "100003", "100004"},
			Ranges: []Range{
				{LowerLimit: 100000, UpperLimit: 100001},
				{LowerLimit: 100003, UpperLimit: 100004},
			},
			FilteredSids: []string{"100002"},
		},
		{
			Name: "Filter Out Bad SIDs",
			Sids: []string{"100000", "100001", "100002", "bad", "100003"},
			Ranges: []Range{
				{LowerLimit: 100000, UpperLimit: 100001},
			},
			FilteredSids: []string{"100002", "100003"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			filtered := filterOutSIDsInRanges(test.Sids, test.Ranges)
			assert.Equal(t, test.FilteredSids, filtered)
		})
	}
}

func TestApplyStatusRegexes(t *testing.T) {
	tests := []struct {
		Name           string
		EnableRegex    []*regexp.Regexp
		DisableRegex   []*regexp.Regexp
		Input          *model.Detection
		ExpectedResult bool
		ExpectedStatus bool
	}{
		{
			Name:           "No Regexes",
			EnableRegex:    nil,
			DisableRegex:   nil,
			Input:          &model.Detection{IsEnabled: true},
			ExpectedResult: false,
			ExpectedStatus: true,
		},
		{
			Name:           "Regexes Don't Apply (Start Disabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{Content: "Hello World"},
			ExpectedResult: false,
			ExpectedStatus: false,
		},
		{
			Name:           "Regexes Don't Apply (Start Enabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{IsEnabled: true, Content: "Hello World"},
			ExpectedResult: false,
			ExpectedStatus: true,
		},
		{
			Name:           "Regexes Apply But Do Not Alter (Start Disabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{Content: "drop: something"},
			ExpectedResult: false,
			ExpectedStatus: false,
		},
		{
			Name:           "Regexes Apply But Do Not Alter (Start Enabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{IsEnabled: true, Content: "alert: something"},
			ExpectedResult: false,
			ExpectedStatus: true,
		},
		{
			Name:           "Regexes Apply and Alter (Start Disabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{Content: "alert: something"},
			ExpectedResult: true,
			ExpectedStatus: true,
		},
		{
			Name:           "Regexes Apply and Alter (Start Enabled)",
			EnableRegex:    []*regexp.Regexp{regexp.MustCompile("alert")},
			DisableRegex:   []*regexp.Regexp{regexp.MustCompile("drop")},
			Input:          &model.Detection{IsEnabled: true, Content: "drop: something"},
			ExpectedResult: true,
			ExpectedStatus: false,
		},
	}

	e := SuricataEngine{}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			e.enableRegex = test.EnableRegex
			e.disableRegex = test.DisableRegex

			result := e.applyStatusRegexes(test.Input)

			assert.Equal(t, test.ExpectedResult, result)
			assert.Equal(t, test.ExpectedStatus, test.Input.IsEnabled)
		})
	}
}

// ==========================
// New Methods Tests (from refactor)
// ==========================

// Test RegenerateRuleFiles method
func TestRegenerateRuleFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	logger := &nidsLogger{log.WithField("test", "RegenerateRuleFiles")}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		IOManager:       iom,
		allRulesFile:    "/opt/rules/all.rules",
		thresholdFile:   "/opt/sensoroni/nids/threshold.conf",
		isRunning:       true,
		flowbitResolver: NewFlowbitResolver(logger),
		flowbitRequired: make(map[string]*FlowbitDependency),
	}

	// Test with enabled and disabled detections
	changedDetections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Ruleset:   "test",
		},
		{
			PublicID:  "1002",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 2\"; sid:1002;)",
			IsEnabled: false, // Should not be included in output
			Ruleset:   "test",
		},
	}

	// Mock getting all detections from ES (called by getAllSuricataDetections in RegenerateRuleFiles)
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": changedDetections[0],
		"1002": changedDetections[1],
	}, nil)

	// Mock writing the all rules file (should contain comment header and enabled rule)
	expectedContent := "# Ruleset: test\nalert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)\n\n"
	iom.EXPECT().WriteFile("/opt/rules/all.rules", []byte(expectedContent), fs.FileMode(0644)).Return(nil)

	// Mock writing threshold file
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).Return(nil)

	errMap, err := eng.RegenerateRuleFiles(ctx, changedDetections)

	assert.NoError(t, err)
	assert.Empty(t, errMap)
}

// Test RegenerateRuleFiles with write error
func TestRegenerateRuleFilesWriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	logger := &nidsLogger{log.WithField("test", "RegenerateRuleFilesWriteError")}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		IOManager:       iom,
		allRulesFile:    "/opt/rules/all.rules",
		thresholdFile:   "/opt/sensoroni/nids/threshold.conf",
		isRunning:       true,
		flowbitResolver: NewFlowbitResolver(logger),
		flowbitRequired: make(map[string]*FlowbitDependency),
	}

	changedDetections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
		},
	}

	// Mock getting all detections
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": changedDetections[0],
	}, nil)

	// Mock write failure
	iom.EXPECT().WriteFile("/opt/rules/all.rules", gomock.Any(), fs.FileMode(0644)).Return(errors.New("write failed"))

	errMap, err := eng.RegenerateRuleFiles(ctx, changedDetections)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write failed")
	assert.NotEmpty(t, errMap)
	assert.Contains(t, errMap, "write_rules")
}

// Test RegenerateRuleFiles with threshold write error
func TestRegenerateRuleFilesThresholdWriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	logger := &nidsLogger{log.WithField("test", "RegenerateRuleFilesThresholdWriteError")}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		IOManager:       iom,
		allRulesFile:    "/opt/rules/all.rules",
		thresholdFile:   "/opt/sensoroni/nids/threshold.conf",
		isRunning:       true,
		flowbitResolver: NewFlowbitResolver(logger),
		flowbitRequired: make(map[string]*FlowbitDependency),
	}

	changedDetections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
		},
	}

	// Mock getting all detections
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": changedDetections[0],
	}, nil)

	// Mock successful rules file write
	iom.EXPECT().WriteFile("/opt/rules/all.rules", gomock.Any(), fs.FileMode(0644)).Return(nil)

	// Mock threshold file write failure
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).Return(errors.New("threshold write failed"))

	errMap, err := eng.RegenerateRuleFiles(ctx, changedDetections)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threshold write failed")
	assert.NotEmpty(t, errMap)
	assert.Contains(t, errMap, "write_threshold")
}

// Test applyUserState method
func TestApplyUserState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		isRunning: true,
	}

	// Create test detections
	detections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Ruleset:   "community",
		},
		{
			PublicID:  "1002",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 2\"; sid:1002;)",
			IsEnabled: true,
			Ruleset:   "custom",
		},
	}

	// Mock getting existing detections with user modifications
	existingDetections := map[string]*model.Detection{
		"1001": {
			PublicID:    "1001",
			IsEnabled:   false, // User disabled this rule
			IsCommunity: false,
			Ruleset:     "community",
		},
	}

	detStore.EXPECT().GetAllDetections(ctx,
		gomock.Any(), // EngineNameSuricata filter
	).Return(existingDetections, nil)

	err := eng.applyUserState(ctx, detections)

	assert.NoError(t, err)
	// First detection should inherit user's disabled state
	assert.False(t, detections[0].IsEnabled)
	// Second detection should remain unchanged
	assert.True(t, detections[1].IsEnabled)
}

// An empty store read with a state file present must abort the sync, not
// redeploy every rule at its vendor default.
func TestApplyUserStateEmptyStoreGuard(t *testing.T) {
	newParsedRules := func() []*model.Detection {
		return []*model.Detection{
			{
				PublicID:  "1001",
				Content:   `alert tcp any any -> any any (msg:"Test Rule 1"; sid:1001;)`,
				IsEnabled: true, // vendor default
				Ruleset:   "ETOPEN",
			},
		}
	}

	tests := []struct {
		Name          string
		StateFile     []byte
		StateFileErr  error
		ExpectedErr   error
		ExpectEnabled bool
	}{
		{
			Name:          "State File Present, Empty Store Aborts Sync",
			StateFile:     []byte("1753304832"),
			ExpectedErr:   detections.ErrStateFileNoCommunity,
			ExpectEnabled: true, // untouched, sync aborted
		},
		{
			Name:          "No State File Is A First Import",
			StateFileErr:  os.ErrNotExist,
			ExpectedErr:   nil,
			ExpectEnabled: true,
		},
		{
			Name:          "Unreadable State File Aborts Sync",
			StateFileErr:  errors.New("permission denied"),
			ExpectedErr:   detections.ErrStateFileNoCommunity,
			ExpectEnabled: true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := context.Background()
			detStore := servermock.NewMockDetectionstore(ctrl)
			iom := mock.NewMockIOManager(ctrl)

			eng := &SuricataEngine{
				srv: &server.Server{
					Detectionstore: detStore,
					Context:        ctx,
				},
				IOManager: iom,
				SyncSchedulerParams: detections.SyncSchedulerParams{
					StateFilePath: "stateFilePath",
				},
				isRunning: true,
			}

			// the silently-empty read
			detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{}, nil)
			iom.EXPECT().ReadFile("stateFilePath").Return(test.StateFile, test.StateFileErr)

			parsed := newParsedRules()
			err := eng.applyUserState(ctx, parsed)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectEnabled, parsed[0].IsEnabled)
		})
	}
}

// A populated store must not read the state file.
func TestApplyUserStateGuardSkippedWhenStorePopulated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		IOManager: iom,
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		isRunning: true,
	}

	parsed := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   `alert tcp any any -> any any (msg:"Test Rule 1"; sid:1001;)`,
			IsEnabled: true,
			Ruleset:   "ETOPEN",
		},
	}

	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(map[string]*model.Detection{
		"1001": {PublicID: "1001", IsEnabled: false, Ruleset: "ETOPEN"},
	}, nil)
	// no iom.ReadFile expectation: the guard must short-circuit

	err := eng.applyUserState(ctx, parsed)

	assert.NoError(t, err)
	assert.False(t, parsed[0].IsEnabled, "user's disabled state should be applied")
}

// Test writeAllRulesFile method
func TestWriteAllRulesFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		IOManager:    iom,
		allRulesFile: "/opt/rules/all.rules",
	}

	detections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Ruleset:   "test",
		},
		{
			PublicID:  "1002",
			Content:   "# alert tcp any any -> any any (msg:\"Test Rule 2\"; sid:1002;)",
			IsEnabled: false, // Disabled rule should not be included
			Ruleset:   "test",
		},
		{
			PublicID:  "1003",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 3\"; sid:1003;)",
			IsEnabled: true,
			Ruleset:   "test",
		},
	}

	// Expected content should include comment header and only enabled rules
	expectedContent := "# Ruleset: test\nalert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)\nalert tcp any any -> any any (msg:\"Test Rule 3\"; sid:1003;)\n\n"

	iom.EXPECT().WriteFile("/opt/rules/all.rules", []byte(expectedContent), fs.FileMode(0644)).Return(nil)

	err := eng.writeAllRulesFile(detections)

	assert.NoError(t, err)
}

// Test writeThresholdFile method
func TestWriteThresholdFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		IOManager:     iom,
		thresholdFile: "/opt/sensoroni/nids/threshold.conf",
	}

	detections := []*model.Detection{
		{
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Overrides: []*model.Override{
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("limit"),
						Track:         util.Ptr("by_src"),
						Count:         util.Ptr(5),
						Seconds:       util.Ptr(60),
					},
				},
			},
		},
		{
			PublicID:  "1002",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 2\"; sid:1002;)",
			IsEnabled: false, // Disabled, no overrides
		},
	}

	// Mock writing threshold file - should only include enabled rule's threshold
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).DoAndReturn(
		func(path string, content []byte, perm fs.FileMode) error {
			// Verify the content contains threshold for enabled rule with correct parameters
			contentStr := string(content)
			assert.Contains(t, contentStr, "gen_id 1, sig_id 1001", "Should include rule 1001")

			// Verify that the actual override parameters are used, not hardcoded values
			assert.Contains(t, contentStr, "type limit", "Should use ThresholdType from override (limit, not threshold)")
			assert.Contains(t, contentStr, "track by_src", "Should use Track from override")
			assert.Contains(t, contentStr, "count 5", "Should use Count from override (5, not 1)")
			assert.Contains(t, contentStr, "seconds 60", "Should use Seconds from override")

			// Full line verification
			assert.Contains(t, contentStr, "threshold gen_id 1, sig_id 1001, type limit, track by_src, count 5, seconds 60",
				"Complete threshold line should use all override parameters")

			assert.NotContains(t, contentStr, "sig_id 1002", "Disabled rule's threshold should not be included")
			return nil
		})

	err := eng.writeThresholdFile(detections)

	assert.NoError(t, err)
}

// Test writeThresholdFile with multiple override types
func TestWriteThresholdFileMultipleTypes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		IOManager:     iom,
		thresholdFile: "/opt/sensoroni/nids/threshold.conf",
	}

	// Note: Override validation happens at creation time in model.Override.Validate()
	// These test cases use valid data that would pass validation
	detections := []*model.Detection{
		{
			PublicID:  "2001",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 1\"; sid:2001;)",
			IsEnabled: true,
			Overrides: []*model.Override{
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("both"),
						Track:         util.Ptr("by_dst"),
						Count:         util.Ptr(10),
						Seconds:       util.Ptr(120),
					},
				},
			},
		},
		{
			PublicID:  "2002",
			Content:   "alert tcp any any -> any any (msg:\"Test Rule 2\"; sid:2002;)",
			IsEnabled: true,
			Overrides: []*model.Override{
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						Track: util.Ptr("by_src"),
						IP:    util.Ptr("192.168.1.0/24"),
					},
				},
			},
		},
	}

	// Mock writing threshold file
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).DoAndReturn(
		func(path string, content []byte, perm fs.FileMode) error {
			contentStr := string(content)

			// Test rule 2001 with "both" type and custom values
			assert.Contains(t, contentStr, "threshold gen_id 1, sig_id 2001, type both, track by_dst, count 10, seconds 120",
				"Should use all custom threshold parameters")

			// Test rule 2002 with suppress type
			assert.Contains(t, contentStr, "suppress gen_id 1, sig_id 2002, track by_src, ip 192.168.1.0/24",
				"Should create suppress line with track and IP")

			return nil
		})

	err := eng.writeThresholdFile(detections)
	assert.NoError(t, err)
}

// Test writeThresholdFile returns error for overrides with nil fields
func TestWriteThresholdFileNilOverrideFields(t *testing.T) {
	eng := &SuricataEngine{
		thresholdFile: "/opt/sensoroni/nids/threshold.conf",
	}

	tests := []struct {
		name      string
		detection *model.Detection
		errMsg    string
	}{
		{
			name: "nil Track in suppress",
			detection: &model.Detection{
				PublicID: "1001",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeSuppress,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Track: nil,
							IP:    util.Ptr("192.168.1.0/24"),
						},
					},
				},
			},
			errMsg: "invalid suppress override for SID 1001",
		},
		{
			name: "nil IP in suppress",
			detection: &model.Detection{
				PublicID: "1002",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeSuppress,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Track: util.Ptr("by_src"),
							IP:    nil,
						},
					},
				},
			},
			errMsg: "invalid suppress override for SID 1002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eng.writeThresholdFile([]*model.Detection{tt.detection})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// Test that writeThresholdFile produces byte-identical output regardless of the
// order of the input detections or the order of overrides within a detection.
// The real caller derives the slice from a Go map (non-deterministic iteration),
// so any sensitivity to input order produces a churning threshold.conf.
func TestWriteThresholdFileDeterministicOrder(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		IOManager:     iom,
		thresholdFile: "/opt/sensoroni/nids/threshold.conf",
	}

	// Two detections, each with two enabled overrides, plus a third
	// detection with one override. Mixed SIDs and mixed override types
	// so a stable sort has something to do on both axes.
	makeDetections := func() []*model.Detection {
		return []*model.Detection{
			{
				PublicID:  "3000",
				IsEnabled: true,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeSuppress,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Track: util.Ptr("by_src"),
							IP:    util.Ptr("10.0.0.1"),
						},
					},
					{
						Type:      model.OverrideTypeThreshold,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(5),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
			{
				PublicID:  "1000",
				IsEnabled: true,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeThreshold,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							ThresholdType: util.Ptr("both"),
							Track:         util.Ptr("by_dst"),
							Count:         util.Ptr(10),
							Seconds:       util.Ptr(120),
						},
					},
					{
						Type:      model.OverrideTypeSuppress,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Track: util.Ptr("by_dst"),
							IP:    util.Ptr("192.168.1.0/24"),
						},
					},
				},
			},
			{
				PublicID:  "2000",
				IsEnabled: true,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeSuppress,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Track: util.Ptr("by_src"),
							IP:    util.Ptr("172.16.0.0/12"),
						},
					},
				},
			},
		}
	}

	var captured [][]byte
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).
		DoAndReturn(func(_ string, content []byte, _ fs.FileMode) error {
			buf := make([]byte, len(content))
			copy(buf, content)
			captured = append(captured, buf)
			return nil
		}).Times(2)

	// First write: detections in original order.
	first := makeDetections()
	assert.NoError(t, eng.writeThresholdFile(first))

	// Second write: same detections, but reversed at both levels. The
	// real caller iterates a map, so any input permutation must produce
	// the same file content.
	second := makeDetections()
	for i, j := 0, len(second)-1; i < j; i, j = i+1, j-1 {
		second[i], second[j] = second[j], second[i]
	}
	for _, det := range second {
		for i, j := 0, len(det.Overrides)-1; i < j; i, j = i+1, j-1 {
			det.Overrides[i], det.Overrides[j] = det.Overrides[j], det.Overrides[i]
		}
	}
	assert.NoError(t, eng.writeThresholdFile(second))

	assert.Equal(t, 2, len(captured), "expected two captured writes")
	assert.Equal(t, string(captured[0]), string(captured[1]),
		"threshold.conf must be byte-identical regardless of detection/override input order")
}

// Test that multiple overrides of the same type on a single SID — distinguished
// only by their inner fields — also emit in a stable order. The sort key must
// disambiguate within a Type bucket, not just between Types.
func TestWriteThresholdFileSameSIDSameTypeDifferentFields(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	eng := &SuricataEngine{
		IOManager:     iom,
		thresholdFile: "/opt/sensoroni/nids/threshold.conf",
	}

	// One SID, multiple threshold overrides differing only by inner fields,
	// plus multiple suppress overrides differing only by IP/Track.
	makeDetection := func() *model.Detection {
		return &model.Detection{
			PublicID:  "5000",
			IsEnabled: true,
			Overrides: []*model.Override{
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("threshold"),
						Track:         util.Ptr("by_src"),
						Count:         util.Ptr(20),
						Seconds:       util.Ptr(60),
					},
				},
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						Track: util.Ptr("by_dst"),
						IP:    util.Ptr("10.0.0.5"),
					},
				},
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("limit"),
						Track:         util.Ptr("by_src"),
						Count:         util.Ptr(5),
						Seconds:       util.Ptr(60),
					},
				},
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						Track: util.Ptr("by_src"),
						IP:    util.Ptr("10.0.0.1"),
					},
				},
				{
					Type:      model.OverrideTypeThreshold,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						ThresholdType: util.Ptr("both"),
						Track:         util.Ptr("by_dst"),
						Count:         util.Ptr(10),
						Seconds:       util.Ptr(120),
					},
				},
				{
					Type:      model.OverrideTypeSuppress,
					IsEnabled: true,
					OverrideParameters: model.OverrideParameters{
						Track: util.Ptr("by_src"),
						IP:    util.Ptr("192.168.1.0/24"),
					},
				},
			},
		}
	}

	var captured [][]byte
	iom.EXPECT().WriteFile("/opt/sensoroni/nids/threshold.conf", gomock.Any(), fs.FileMode(0644)).
		DoAndReturn(func(_ string, content []byte, _ fs.FileMode) error {
			buf := make([]byte, len(content))
			copy(buf, content)
			captured = append(captured, buf)
			return nil
		}).Times(2)

	first := makeDetection()
	assert.NoError(t, eng.writeThresholdFile([]*model.Detection{first}))

	second := makeDetection()
	for i, j := 0, len(second.Overrides)-1; i < j; i, j = i+1, j-1 {
		second.Overrides[i], second.Overrides[j] = second.Overrides[j], second.Overrides[i]
	}
	assert.NoError(t, eng.writeThresholdFile([]*model.Detection{second}))

	assert.Equal(t, 2, len(captured), "expected two captured writes")
	assert.Equal(t, string(captured[0]), string(captured[1]),
		"threshold.conf must be byte-identical when same-type overrides differ only by inner fields")

	// Sanity check: every override produced exactly one line.
	contentStr := string(captured[0])
	assert.Equal(t, 3, strings.Count(contentStr, "threshold gen_id 1, sig_id 5000"),
		"all three threshold overrides should appear")
	assert.Equal(t, 3, strings.Count(contentStr, "suppress gen_id 1, sig_id 5000"),
		"all three suppress overrides should appear")
}

// Test hasDetectionChanged method
func TestHasDetectionChanged(t *testing.T) {
	eng := &SuricataEngine{}

	tests := []struct {
		name     string
		existing *model.Detection
		new      *model.Detection
		expected bool
	}{
		{
			name: "No change",
			existing: &model.Detection{
				PublicID:  "1001",
				Content:   "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
				IsEnabled: true,
				Title:     "Test Rule",
			},
			new: &model.Detection{
				PublicID:  "1001",
				Content:   "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
				IsEnabled: true,
				Title:     "Test Rule",
			},
			expected: false,
		},
		{
			name: "Content changed",
			existing: &model.Detection{
				PublicID:  "1001",
				Content:   "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
				IsEnabled: true,
			},
			new: &model.Detection{
				PublicID:  "1001",
				Content:   "alert tcp any any -> any any (msg:\"Modified\"; sid:1001;)",
				IsEnabled: true,
			},
			expected: true,
		},
		{
			name: "Title changed",
			existing: &model.Detection{
				PublicID: "1001",
				Content:  "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
				Title:    "Old Title",
			},
			new: &model.Detection{
				PublicID: "1001",
				Content:  "alert tcp any any -> any any (msg:\"Test\"; sid:1001;)",
				Title:    "New Title",
			},
			expected: true,
		},
		{
			name: "Severity changed",
			existing: &model.Detection{
				PublicID: "1001",
				Severity: model.SeverityMedium,
			},
			new: &model.Detection{
				PublicID: "1001",
				Severity: model.SeverityHigh,
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := eng.hasDetectionChanged(test.existing, test.new)
			assert.Equal(t, test.expected, result)
		})
	}
}

// Test updateDetectionStore method - comprehensive test following ElastAlert/Strelka patterns
func TestUpdateDetectionStore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		failAfterConsecutiveErrorCount: 10,
	}

	// Track bulk indexer items for assertions
	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// New/updated detections to sync
	detections := []*model.Detection{
		{
			Auditable: model.Auditable{
				Id: "existing-1001",
			},
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Updated Rule 1\"; sid:1001;)",
			IsEnabled: true,
			Ruleset:   "community",
		},
		{
			Auditable: model.Auditable{
				Id: "new-1002",
			},
			PublicID:  "1002",
			Content:   "alert tcp any any -> any any (msg:\"New Rule 2\"; sid:1002;)",
			IsEnabled: true,
			Ruleset:   "community",
		},
	}

	// Existing detections in ES - includes one that will be deleted
	existingDetections := map[string]*model.Detection{
		"1001": {
			Auditable: model.Auditable{
				Id: "existing-1001",
			},
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Old Rule 1\"; sid:1001;)", // Changed
			IsEnabled: false,
			Ruleset:   "community",
		},
		"9999": {
			Auditable: model.Auditable{
				Id: "to-delete-9999",
			},
			PublicID:  "9999",
			Content:   "alert tcp any any -> any any (msg:\"To Delete\"; sid:9999;)",
			IsEnabled: true,
			Ruleset:   "community", // Same ruleset with DeleteUnreferenced
		},
	}

	// Configure rulesets - community has DeleteUnreferenced=true
	configuredRulesets := map[string]*RulesetSource{
		"community": {
			Name:               "community",
			DeleteUnreferenced: true,
		},
	}

	rulesetResults := make(map[string]*RulesetSyncResult)

	// Mock getting existing detections
	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(existingDetections, nil)

	// Mock creating bulk indexer for work items
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(bim, nil)

	// Mock document conversions - update, create, and delete
	detStore.EXPECT().ConvertObjectToDocument(ctx, "detection",
		gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil).Times(3)

	// Mock bulk.Add with OnSuccess callback invocation (following ElastAlert/Strelka pattern)
	bim.EXPECT().Add(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: item.DocumentID,
			}
			item.OnSuccess(ctx, item, resp)
		}
		workItems = append(workItems, item)
		return nil
	}).Times(3) // update + create + delete

	bim.EXPECT().Close(ctx).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{NumAdded: 3}).AnyTimes()

	// Mock creating bulk indexer for audit items
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(auditm, nil)

	// Mock audit document conversions
	detStore.EXPECT().ConvertObjectToDocument(ctx, "detection",
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("audit-doc"), "audit-index", nil).Times(3)

	// Mock audit bulk.Add with OnSuccess callback
	auditm.EXPECT().Add(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: "audit-id",
			}
			item.OnSuccess(ctx, item, resp)
		}
		auditItems = append(auditItems, item)
		return nil
	}).Times(3)

	auditm.EXPECT().Close(ctx).Return(nil)
	auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	err := eng.updateDetectionStore(ctx, detections, configuredRulesets, rulesetResults)

	assert.NoError(t, err)

	// Verify work items
	assert.Len(t, workItems, 3)
	workActions := make([]string, len(workItems))
	for i, item := range workItems {
		workActions[i] = item.Action
	}
	assert.Contains(t, workActions, "update")
	assert.Contains(t, workActions, "create")
	assert.Contains(t, workActions, "delete")

	// Verify audit items
	assert.Len(t, auditItems, 3)
	for _, item := range auditItems {
		assert.Equal(t, "create", item.Action)
	}
}

// TestUpdateDetectionStore_RulesetRemoved tests deletion when a ruleset is removed from config
func TestUpdateDetectionStore_RulesetRemoved(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		failAfterConsecutiveErrorCount: 10,
	}

	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// No new detections - empty sync
	detections := []*model.Detection{}

	// Existing detection from a ruleset that's no longer configured
	existingDetections := map[string]*model.Detection{
		"9999": {
			Auditable: model.Auditable{
				Id: "orphaned-9999",
			},
			PublicID:  "9999",
			Content:   "alert tcp any any -> any any (msg:\"Orphaned Rule\"; sid:9999;)",
			IsEnabled: true,
			Ruleset:   "removed-ruleset", // This ruleset is NOT in configuredRulesets
		},
	}

	// Only "community" is configured - "removed-ruleset" is gone
	configuredRulesets := map[string]*RulesetSource{
		"community": {
			Name:               "community",
			DeleteUnreferenced: false, // Doesn't matter for removed rulesets
		},
	}

	rulesetResults := make(map[string]*RulesetSyncResult)

	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(existingDetections, nil)
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(bim, nil)

	// Delete conversion for the orphaned rule
	detStore.EXPECT().ConvertObjectToDocument(ctx, "detection",
		gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil)

	bim.EXPECT().Add(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			resp := esutil.BulkIndexerResponseItem{
				DocumentID: item.DocumentID,
			}
			item.OnSuccess(ctx, item, resp)
		}
		workItems = append(workItems, item)
		return nil
	})

	bim.EXPECT().Close(ctx).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	// Audit indexer for the delete
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(auditm, nil)
	detStore.EXPECT().ConvertObjectToDocument(ctx, "detection",
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("audit-doc"), "audit-index", nil)

	auditm.EXPECT().Add(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.OnSuccess != nil {
			item.OnSuccess(ctx, item, esutil.BulkIndexerResponseItem{DocumentID: "audit-id"})
		}
		auditItems = append(auditItems, item)
		return nil
	})

	auditm.EXPECT().Close(ctx).Return(nil)
	auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	err := eng.updateDetectionStore(ctx, detections, configuredRulesets, rulesetResults)

	assert.NoError(t, err)
	assert.Len(t, workItems, 1)
	assert.Equal(t, "delete", workItems[0].Action)
	assert.Len(t, auditItems, 1)
}

// TestUpdateDetectionStore_PreserveUnreferenced tests that rules are preserved when DeleteUnreferenced=false
func TestUpdateDetectionStore_PreserveUnreferenced(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		failAfterConsecutiveErrorCount: 10,
	}

	workItems := []esutil.BulkIndexerItem{}

	// No new detections
	detections := []*model.Detection{}

	// Existing detection that's not in the new sync
	existingDetections := map[string]*model.Detection{
		"9999": {
			Auditable: model.Auditable{
				Id: "preserve-9999",
			},
			PublicID:  "9999",
			Content:   "alert tcp any any -> any any (msg:\"Preserved Rule\"; sid:9999;)",
			IsEnabled: true,
			Ruleset:   "community",
		},
	}

	// DeleteUnreferenced=false means we keep unreferenced rules
	configuredRulesets := map[string]*RulesetSource{
		"community": {
			Name:               "community",
			DeleteUnreferenced: false,
		},
	}

	rulesetResults := make(map[string]*RulesetSyncResult)

	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(existingDetections, nil)
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(bim, nil)

	// No Add calls expected - rule should be preserved
	bim.EXPECT().Add(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		workItems = append(workItems, item)
		return nil
	}).Times(0) // Explicitly expect no calls

	bim.EXPECT().Close(ctx).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	err := eng.updateDetectionStore(ctx, detections, configuredRulesets, rulesetResults)

	assert.NoError(t, err)
	assert.Len(t, workItems, 0, "No items should be added when preserving unreferenced rules")
}

// TestUpdateDetectionStore_UnchangedDetection tests the path where a detection exists but hasn't changed
func TestUpdateDetectionStore_UnchangedDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	detStore := servermock.NewMockDetectionstore(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Context:        ctx,
		},
		failAfterConsecutiveErrorCount: 10,
	}

	// Detection that matches existing - no changes
	detections := []*model.Detection{
		{
			Auditable: model.Auditable{Id: "existing-1001"},
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Same Rule\"; sid:1001;)",
			Title:     "Same Rule",
			IsEnabled: true,
			Ruleset:   "community",
		},
	}

	// Existing detection is identical
	existingDetections := map[string]*model.Detection{
		"1001": {
			Auditable: model.Auditable{Id: "existing-1001"},
			PublicID:  "1001",
			Content:   "alert tcp any any -> any any (msg:\"Same Rule\"; sid:1001;)",
			Title:     "Same Rule",
			IsEnabled: true,
			Ruleset:   "community",
		},
	}

	configuredRulesets := map[string]*RulesetSource{
		"community": {Name: "community"},
	}

	detStore.EXPECT().GetAllDetections(ctx, gomock.Any()).Return(existingDetections, nil)
	detStore.EXPECT().BuildBulkIndexer(ctx, gomock.Any()).Return(bim, nil)

	// ConvertObjectToDocument still called but Add should NOT be called (no changes)
	detStore.EXPECT().ConvertObjectToDocument(ctx, "detection",
		gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil)

	// No Add calls - detection is unchanged
	bim.EXPECT().Close(ctx).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{}).AnyTimes()

	err := eng.updateDetectionStore(ctx, detections, configuredRulesets, map[string]*RulesetSyncResult{})

	assert.NoError(t, err)
}

// Test handleSyncError method
// Note: This function is only called when an error has occurred during sync.
// All call sites check if err != nil before calling, so nil is not a valid input.
func TestHandleSyncError(t *testing.T) {
	t.Run("Without notification", func(t *testing.T) {
		eng := &SuricataEngine{
			EngineState: model.EngineState{},
			notify:      false,
		}

		logger := log.WithField("test", "handleSyncError")

		// Test that handleSyncError always returns detections.ErrSyncFailed
		result := eng.handleSyncError(errors.New("sync failed"), "Test sync failure", logger)

		assert.Error(t, result)
		assert.Equal(t, "failed to sync community rules", result.Error())
	})

	t.Run("With notification", func(t *testing.T) {
		// Create a minimal Host - Broadcast iterates over connections which will be empty
		host := web.NewHost("127.0.0.1:0", "/tmp", 1000, "test", nil)

		eng := &SuricataEngine{
			EngineState: model.EngineState{},
			srv: &server.Server{
				Host: host,
			},
			notify: true,
		}

		logger := log.WithField("test", "handleSyncError_notify")

		// Test that handleSyncError broadcasts when notify is true
		result := eng.handleSyncError(errors.New("sync failed"), "Test sync failure", logger)

		assert.Error(t, result)
		assert.Equal(t, "failed to sync community rules", result.Error())
	})
}

// ==========================
// Quick Win Coverage Tests
// ==========================

// Test partitionDetectionsBySID method
func TestPartitionDetectionsBySID(t *testing.T) {
	eng := &SuricataEngine{}

	tests := []struct {
		name               string
		detections         []*model.Detection
		rulesetName        string
		existingSeen       map[string]string
		expectedUnique     int
		expectedDuplicates int
	}{
		{
			name:               "Empty input",
			detections:         []*model.Detection{},
			rulesetName:        "test",
			existingSeen:       map[string]string{},
			expectedUnique:     0,
			expectedDuplicates: 0,
		},
		{
			name: "All unique",
			detections: []*model.Detection{
				{PublicID: "1001"},
				{PublicID: "1002"},
				{PublicID: "1003"},
			},
			rulesetName:        "test",
			existingSeen:       map[string]string{},
			expectedUnique:     3,
			expectedDuplicates: 0,
		},
		{
			name: "All duplicates",
			detections: []*model.Detection{
				{PublicID: "1001"},
				{PublicID: "1002"},
			},
			rulesetName: "ruleset-b",
			existingSeen: map[string]string{
				"1001": "ruleset-a",
				"1002": "ruleset-a",
			},
			expectedUnique:     0,
			expectedDuplicates: 2,
		},
		{
			name: "Mixed unique and duplicates",
			detections: []*model.Detection{
				{PublicID: "1001"}, // duplicate
				{PublicID: "1002"}, // unique
				{PublicID: "1003"}, // duplicate
				{PublicID: "1004"}, // unique
			},
			rulesetName: "ruleset-b",
			existingSeen: map[string]string{
				"1001": "ruleset-a",
				"1003": "ruleset-a",
			},
			expectedUnique:     2,
			expectedDuplicates: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]string)
			for k, v := range tt.existingSeen {
				seen[k] = v
			}
			duplicates := make(map[string]DuplicateInfo)

			unique := eng.partitionDetectionsBySID(tt.detections, tt.rulesetName, seen, duplicates)

			assert.Equal(t, tt.expectedUnique, len(unique))
			assert.Equal(t, tt.expectedDuplicates, len(duplicates))

			// Verify duplicate info is correct
			for sid, info := range duplicates {
				assert.Equal(t, tt.rulesetName, info.SkippedRuleset)
				assert.Equal(t, tt.existingSeen[sid], info.KeptRuleset)
			}
		})
	}
}

// Test validateRulesetNames method
func TestValidateRulesetNames(t *testing.T) {
	tests := []struct {
		name        string
		sources     []*RulesetSource
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty sources",
			sources:     []*RulesetSource{},
			expectError: false,
		},
		{
			name: "Single source",
			sources: []*RulesetSource{
				{Name: "etopen"},
			},
			expectError: false,
		},
		{
			name: "Multiple unique sources",
			sources: []*RulesetSource{
				{Name: "etopen"},
				{Name: "etpro"},
				{Name: "custom"},
			},
			expectError: false,
		},
		{
			name: "Duplicate names",
			sources: []*RulesetSource{
				{Name: "etopen"},
				{Name: "etopen"},
			},
			expectError: true,
			errorMsg:    "duplicate ruleset name 'etopen'",
		},
		{
			name: "Duplicate in middle",
			sources: []*RulesetSource{
				{Name: "first"},
				{Name: "second"},
				{Name: "first"},
			},
			expectError: true,
			errorMsg:    "duplicate ruleset name 'first'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &SuricataEngine{
				rulesetSources: tt.sources,
			}

			err := eng.validateRulesetNames()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test mergeRulesetResults method
func TestMergeRulesetResults(t *testing.T) {
	eng := &SuricataEngine{}

	t.Run("Empty results", func(t *testing.T) {
		results := map[string]*RulesetSyncResult{}

		merged := eng.mergeRulesetResults(results)

		assert.NotNil(t, merged)
		assert.Empty(t, merged.Detections)
		assert.Empty(t, merged.Duplicates)
		assert.Empty(t, merged.Stats)
	})

	t.Run("Single ruleset no duplicates", func(t *testing.T) {
		results := map[string]*RulesetSyncResult{
			"etopen": {
				Detections: []*model.Detection{
					{PublicID: "1001"},
					{PublicID: "1002"},
				},
			},
		}

		merged := eng.mergeRulesetResults(results)

		assert.Len(t, merged.Detections, 2)
		assert.Empty(t, merged.Duplicates)
		assert.Equal(t, 2, merged.Stats["etopen"])
	})

	t.Run("Multiple rulesets with duplicates", func(t *testing.T) {
		results := map[string]*RulesetSyncResult{
			"etopen": {
				Detections: []*model.Detection{
					{PublicID: "1001"},
					{PublicID: "1002"},
				},
			},
			"etpro": {
				Detections: []*model.Detection{
					{PublicID: "1001"}, // duplicate
					{PublicID: "1003"},
				},
			},
		}

		merged := eng.mergeRulesetResults(results)

		assert.Len(t, merged.Detections, 3) // 1001, 1002, 1003
		assert.Len(t, merged.Duplicates, 1) // 1001 is duplicate
		assert.Contains(t, merged.Duplicates, "1001")
		assert.Equal(t, "etopen", merged.Duplicates["1001"].KeptRuleset)
		assert.Equal(t, "etpro", merged.Duplicates["1001"].SkippedRuleset)
	})

	t.Run("Deterministic ordering by ruleset name", func(t *testing.T) {
		// 'aaa' comes before 'zzz' alphabetically
		results := map[string]*RulesetSyncResult{
			"zzz-ruleset": {
				Detections: []*model.Detection{
					{PublicID: "1001"},
				},
			},
			"aaa-ruleset": {
				Detections: []*model.Detection{
					{PublicID: "1001"}, // same SID - aaa should win because it's processed first
				},
			},
		}

		merged := eng.mergeRulesetResults(results)

		assert.Len(t, merged.Detections, 1)
		assert.Len(t, merged.Duplicates, 1)
		// aaa-ruleset is processed first (alphabetically), so zzz-ruleset's 1001 is the duplicate
		assert.Equal(t, "aaa-ruleset", merged.Duplicates["1001"].KeptRuleset)
		assert.Equal(t, "zzz-ruleset", merged.Duplicates["1001"].SkippedRuleset)
	})
}

// Test generateConfigFingerprint method
func TestGenerateConfigFingerprint(t *testing.T) {
	t.Run("Empty config", func(t *testing.T) {
		eng := &SuricataEngine{
			srv:            &server.Server{},
			rulesetSources: []*RulesetSource{},
			enableRegex:    []*regexp.Regexp{},
			disableRegex:   []*regexp.Regexp{},
		}

		fingerprint := eng.generateConfigFingerprint()

		assert.NotEmpty(t, fingerprint)
		assert.Len(t, fingerprint, 64) // SHA256 hex = 64 chars
	})

	t.Run("With ruleset sources", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
			rulesetSources: []*RulesetSource{
				{Name: "etopen", SourceType: "url", SourcePath: "https://example.com"},
			},
			enableRegex:  []*regexp.Regexp{},
			disableRegex: []*regexp.Regexp{},
		}

		fingerprint := eng.generateConfigFingerprint()

		assert.NotEmpty(t, fingerprint)
		assert.Len(t, fingerprint, 64)
	})

	t.Run("With exclude files", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
			rulesetSources: []*RulesetSource{
				{
					Name:         "etopen",
					SourceType:   "url",
					SourcePath:   "https://example.com",
					ExcludeFiles: []string{"botcc*", "deleted*"},
				},
			},
			enableRegex:  []*regexp.Regexp{},
			disableRegex: []*regexp.Regexp{},
		}

		fingerprint := eng.generateConfigFingerprint()

		assert.NotEmpty(t, fingerprint)
		assert.Len(t, fingerprint, 64)
	})

	t.Run("With regex patterns", func(t *testing.T) {
		eng := &SuricataEngine{
			srv:            &server.Server{},
			rulesetSources: []*RulesetSource{},
			enableRegex:    []*regexp.Regexp{regexp.MustCompile("ET MALWARE"), regexp.MustCompile("ET TROJAN")},
			disableRegex:   []*regexp.Regexp{regexp.MustCompile("ET INFO")},
		}

		fingerprint := eng.generateConfigFingerprint()

		assert.NotEmpty(t, fingerprint)
		assert.Len(t, fingerprint, 64)
	})

	t.Run("Different configs produce different fingerprints", func(t *testing.T) {
		eng1 := &SuricataEngine{
			srv:            &server.Server{},
			rulesetSources: []*RulesetSource{{Name: "etopen"}},
			enableRegex:    []*regexp.Regexp{},
			disableRegex:   []*regexp.Regexp{},
		}

		eng2 := &SuricataEngine{
			srv:            &server.Server{},
			rulesetSources: []*RulesetSource{{Name: "etpro"}},
			enableRegex:    []*regexp.Regexp{},
			disableRegex:   []*regexp.Regexp{},
		}

		fp1 := eng1.generateConfigFingerprint()
		fp2 := eng2.generateConfigFingerprint()

		assert.NotEqual(t, fp1, fp2)
	})

	t.Run("Same config produces same fingerprint", func(t *testing.T) {
		eng := &SuricataEngine{
			srv:            &server.Server{},
			rulesetSources: []*RulesetSource{{Name: "etopen"}},
			enableRegex:    []*regexp.Regexp{},
			disableRegex:   []*regexp.Regexp{},
		}

		fp1 := eng.generateConfigFingerprint()
		fp2 := eng.generateConfigFingerprint()

		assert.Equal(t, fp1, fp2)
	})

	t.Run("Ruleset order does not affect fingerprint", func(t *testing.T) {
		eng1 := &SuricataEngine{
			srv: &server.Server{},
			rulesetSources: []*RulesetSource{
				{Name: "aaa"},
				{Name: "zzz"},
			},
			enableRegex:  []*regexp.Regexp{},
			disableRegex: []*regexp.Regexp{},
		}

		eng2 := &SuricataEngine{
			srv: &server.Server{},
			rulesetSources: []*RulesetSource{
				{Name: "zzz"},
				{Name: "aaa"},
			},
			enableRegex:  []*regexp.Regexp{},
			disableRegex: []*regexp.Regexp{},
		}

		fp1 := eng1.generateConfigFingerprint()
		fp2 := eng2.generateConfigFingerprint()

		assert.Equal(t, fp1, fp2, "fingerprint should be order-independent")
	})
}

// Test writeAllRulesFile additional coverage
func TestWriteAllRulesFileAdditionalCoverage(t *testing.T) {
	t.Run("Skip PendingDelete detections", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				assert.NotContains(t, content, "pending-delete-rule")
				assert.Contains(t, content, "active-rule")
				return nil
			})

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{PublicID: "1001", Content: "alert tcp any any -> any any (msg:\"active-rule\"; sid:1001;)", IsEnabled: true, Ruleset: "test"},
			{PublicID: "1002", Content: "alert tcp any any -> any any (msg:\"pending-delete-rule\"; sid:1002;)", IsEnabled: true, PendingDelete: true, Ruleset: "test"},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})

	t.Run("Include disabled rules needed for flowbits with noalert", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				// Should include the disabled rule
				assert.Contains(t, content, "flowbit-setter")
				// Should have noalert added
				assert.Contains(t, content, "noalert")
				// Should have the explanatory comment
				assert.Contains(t, content, "AUTO-ENABLED")
				assert.Contains(t, content, "flowbit: evil")
				return nil
			})

		eng := &SuricataEngine{
			IOManager:    iom,
			allRulesFile: "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{
				"1001": {
					FlowbitName: "evil",
					Reason:      "required for flowbit dependency",
					RequiredBy:  []string{"1002"},
				},
			},
		}

		detections := []*model.Detection{
			{PublicID: "1001", Content: "alert tcp any any -> any any (msg:\"flowbit-setter\"; flowbits:set,evil; sid:1001;)", IsEnabled: false, Ruleset: "test"},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})

	t.Run("Modify override with literal string replacement", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				assert.Contains(t, content, `content:"88:98:30`)
				assert.NotContains(t, content, `content:"67:98:30`)
				return nil
			})

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "903200005",
				Content:   `alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"SSLBL: Malicious SSL certificate detected (Shylock C&C)"; tls_cert_fingerprint; content:"67:98:30:81:90:fb:07:05:36:af:19:02:3a:e8:9b:a4:bd:54:e9:b6"; sid:903200005; rev:1;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`content:"67:98:30`),
							Value: util.Ptr(`content:"88:98:30`),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})

	t.Run("Modify override with regex pattern", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				assert.Contains(t, content, "seconds 3600")
				assert.NotContains(t, content, "seconds 60")
				return nil
			})

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "1001",
				Content:   `alert http any any -> any any (msg:"Test"; threshold:type limit,track by_src,count 1,seconds 60; sid:1001;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`seconds \d+`),
							Value: util.Ptr("seconds 3600"),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})

	t.Run("Modify override skipped when disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				assert.Contains(t, content, `content:"67:98:30`)
				assert.NotContains(t, content, `content:"88:98:30`)
				return nil
			})

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "903200005",
				Content:   `alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"SSLBL: Malicious SSL certificate detected (Shylock C&C)"; tls_cert_fingerprint; content:"67:98:30:81:90:fb:07:05:36:af:19:02:3a:e8:9b:a4:bd:54:e9:b6"; sid:903200005; rev:1;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: false,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`content:"67:98:30`),
							Value: util.Ptr(`content:"88:98:30`),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})

	t.Run("Modify override with invalid regex returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "1001",
				Content:   `alert tcp any any -> any any (msg:"Test"; sid:1001;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`[invalid`),
							Value: util.Ptr("replacement"),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid modify override regex")
		assert.Contains(t, err.Error(), "SID 1001")
	})

	t.Run("Modify override with Python-style backreference returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "1001",
				Content:   `alert tcp any any -> any any (msg:"Test"; sid:1001;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`(alert)(.*)`),
							Value: util.Ptr(`drop\2`),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported backreference")
		assert.Contains(t, err.Error(), "SID 1001")
	})

	t.Run("Modify override with PCRE containing backslash sequences succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().WriteFile(gomock.Any(), gomock.Any(), os.FileMode(0644)).DoAndReturn(
			func(path string, data []byte, perm os.FileMode) error {
				content := string(data)
				assert.Contains(t, content, `pcre:"/[^\1]/"`)
				return nil
			})

		eng := &SuricataEngine{
			IOManager:       iom,
			allRulesFile:    "/test/all.rules",
			flowbitRequired: map[string]*FlowbitDependency{},
		}

		detections := []*model.Detection{
			{
				PublicID:  "1001",
				Content:   `alert tcp any any -> any any (msg:"Test"; pcre:"/test/"; sid:1001;)`,
				IsEnabled: true,
				Ruleset:   "test",
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: true,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(`pcre:"/test/"`),
							Value: util.Ptr(`pcre:"/[^\1]/"`),
						},
					},
				},
			},
		}

		err := eng.writeAllRulesFile(detections)
		assert.NoError(t, err)
	})
}

// Test buildConfiguredRulesetsMap method
func TestBuildConfiguredRulesetsMap(t *testing.T) {
	t.Run("Nil rulesetManager", func(t *testing.T) {
		eng := &SuricataEngine{
			rulesetManager: nil,
		}

		result := eng.buildConfiguredRulesetsMap()

		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("Empty sources", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "buildConfiguredRulesetsMap")}

		rm := NewRulesetManager(iom, logger)

		eng := &SuricataEngine{
			rulesetManager: rm,
		}

		result := eng.buildConfiguredRulesetsMap()

		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("Only enabled sources included", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		logger := &nidsLogger{log.WithField("test", "buildConfiguredRulesetsMap")}

		enabledSource := &RulesetSource{
			Name:    "enabled-source",
			Enabled: util.Ptr(true),
		}
		disabledSource := &RulesetSource{
			Name:    "disabled-source",
			Enabled: util.Ptr(false),
		}
		nilEnabledSource := &RulesetSource{
			Name:    "nil-enabled-source",
			Enabled: nil,
		}

		rm := NewRulesetManager(iom, logger, enabledSource, disabledSource, nilEnabledSource)

		eng := &SuricataEngine{
			rulesetManager: rm,
		}

		result := eng.buildConfiguredRulesetsMap()

		assert.Len(t, result, 1)
		assert.Contains(t, result, "enabled-source")
		assert.NotContains(t, result, "disabled-source")
		assert.NotContains(t, result, "nil-enabled-source")
	})
}

// Test parseIgnoredSidRanges additional coverage
func TestParseIgnoredSidRangesAdditionalCoverage(t *testing.T) {
	t.Run("Invalid upper limit", func(t *testing.T) {
		result := parseIgnoredSidRanges("1000-abc")

		assert.Empty(t, result)
	})

	t.Run("Invalid lower limit", func(t *testing.T) {
		result := parseIgnoredSidRanges("abc-2000")

		assert.Empty(t, result)
	})

	t.Run("Lower greater than upper", func(t *testing.T) {
		result := parseIgnoredSidRanges("2000-1000")

		assert.Empty(t, result)
	})

	t.Run("Invalid format no dash", func(t *testing.T) {
		result := parseIgnoredSidRanges("1000")

		assert.Empty(t, result)
	})

	t.Run("Valid range", func(t *testing.T) {
		result := parseIgnoredSidRanges("1000-2000")

		assert.Len(t, result, 1)
		assert.Equal(t, uint64(1000), result[0].LowerLimit)
		assert.Equal(t, uint64(2000), result[0].UpperLimit)
	})

	t.Run("Multiple ranges with some invalid", func(t *testing.T) {
		result := parseIgnoredSidRanges("1000-2000\nabc-def\n3000-4000")

		assert.Len(t, result, 2)
	})

	t.Run("Empty lines ignored", func(t *testing.T) {
		result := parseIgnoredSidRanges("1000-2000\n\n\n3000-4000")

		assert.Len(t, result, 2)
	})
}

// Test DuplicateDetection error paths
func TestDuplicateDetectionErrors(t *testing.T) {
	t.Run("ParseSuricataRule error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mDetect := servermock.NewMockDetectionstore(ctrl)
		mDetect.EXPECT().GetDetectionByPublicId(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

		eng := &SuricataEngine{
			srv: &server.Server{
				Detectionstore: mDetect,
			},
			isRunning: true,
		}

		ctx := context.Background()
		det := &model.Detection{
			Content: "invalid rule content", // Not a valid suricata rule
		}

		result, err := eng.DuplicateDetection(ctx, det)

		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("GetUserById error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mDetect := servermock.NewMockDetectionstore(ctrl)
		mDetect.EXPECT().GetDetectionByPublicId(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

		mUser := servermock.NewMockUserstore(ctrl)
		mUser.EXPECT().GetUserById(gomock.Any(), "test-user").Return(nil, errors.New("user not found"))

		eng := &SuricataEngine{
			srv: &server.Server{
				Detectionstore: mDetect,
				Userstore:      mUser,
			},
			isRunning: true,
		}

		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
		det := &model.Detection{
			Content: `alert tcp any any -> any any (msg:"Test Rule"; sid:1001; rev:1;)`,
		}

		result, err := eng.DuplicateDetection(ctx, det)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

// Test checkForMigrations additional coverage
func TestCheckForMigrationsAdditionalCoverage(t *testing.T) {
	t.Run("ReadDir error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return(nil, errors.New("directory not found"))

		eng := &SuricataEngine{
			srv:       &server.Server{},
			IOManager: iom,
		}

		// Should not panic, just log error
		assert.NotPanics(t, func() {
			eng.checkForMigrations()
		})
	})

	t.Run("No migrations found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return([]fs.DirEntry{}, nil)

		eng := &SuricataEngine{
			srv:       &server.Server{},
			IOManager: iom,
		}

		assert.NotPanics(t, func() {
			eng.checkForMigrations()
		})
	})

	t.Run("Migration function not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		// Create a mock DirEntry
		mockEntry := &mockDirEntry{name: "suricata-migration-9.9.99", isDir: false}
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return([]fs.DirEntry{mockEntry}, nil)

		eng := &SuricataEngine{
			srv:        &server.Server{},
			IOManager:  iom,
			migrations: map[string]func(string) error{}, // empty migrations map
		}

		assert.NotPanics(t, func() {
			eng.checkForMigrations()
		})
	})

	t.Run("Migration function returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		mockEntry := &mockDirEntry{name: "suricata-migration-9.9.99", isDir: false}
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return([]fs.DirEntry{mockEntry}, nil)

		eng := &SuricataEngine{
			srv:       &server.Server{},
			IOManager: iom,
			migrations: map[string]func(string) error{
				"9.9.99": func(state string) error {
					return errors.New("migration failed")
				},
			},
		}

		eng.checkForMigrations()

		assert.True(t, eng.EngineState.MigrationFailure)
	})

	t.Run("Skip directories", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		dirEntry := &mockDirEntry{name: "suricata-migration-1.0.0", isDir: true}
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return([]fs.DirEntry{dirEntry}, nil)

		eng := &SuricataEngine{
			srv:        &server.Server{},
			IOManager:  iom,
			migrations: map[string]func(string) error{},
		}

		assert.NotPanics(t, func() {
			eng.checkForMigrations()
		})
	})

	t.Run("Skip non-matching files", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		fileEntry := &mockDirEntry{name: "other-file.txt", isDir: false}
		iom.EXPECT().ReadDir(DEFAULT_MIGRATIONS_DIR).Return([]fs.DirEntry{fileEntry}, nil)

		eng := &SuricataEngine{
			srv:        &server.Server{},
			IOManager:  iom,
			migrations: map[string]func(string) error{},
		}

		assert.NotPanics(t, func() {
			eng.checkForMigrations()
		})
	})
}

// Test ExtractDetails additional coverage
func TestExtractDetailsAdditionalCoverage(t *testing.T) {
	t.Run("Rule without SID", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
		}

		det := &model.Detection{
			Content: `alert tcp any any -> any any (msg:"No SID Rule";)`,
		}

		err := eng.ExtractDetails(det)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public Id")
	})

	t.Run("Rule without msg gets default title", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
		}

		det := &model.Detection{
			Content: `alert tcp any any -> any any (sid:1001;)`,
		}

		err := eng.ExtractDetails(det)

		assert.NoError(t, err)
		assert.Contains(t, det.Title, "Detection title not yet provided")
	})

	t.Run("Invalid created_at date", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
		}

		det := &model.Detection{
			Content: `alert tcp any any -> any any (msg:"Test"; sid:1001; metadata:created_at invalid_date;)`,
		}

		err := eng.ExtractDetails(det)

		assert.NoError(t, err)
		assert.Nil(t, det.SourceCreated) // Should be nil due to parse error
	})

	t.Run("Invalid updated_at date", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
		}

		det := &model.Detection{
			Content: `alert tcp any any -> any any (msg:"Test"; sid:1001; metadata:updated_at not-a-date;)`,
		}

		err := eng.ExtractDetails(det)

		assert.NoError(t, err)
		assert.Nil(t, det.SourceUpdated) // Should be nil due to parse error
	})

	t.Run("Invalid rule content", func(t *testing.T) {
		eng := &SuricataEngine{
			srv: &server.Server{},
		}

		det := &model.Detection{
			Content: `not a valid rule`,
		}

		err := eng.ExtractDetails(det)

		assert.Error(t, err)
	})
}

// Test hasConfigChanged method
func TestHasConfigChanged(t *testing.T) {
	t.Run("No previous fingerprint file", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(gomock.Any()).Return(nil, os.ErrNotExist)

		eng := &SuricataEngine{
			srv:                   &server.Server{},
			IOManager:             iom,
			configFingerprintFile: "/test/fingerprint",
			rulesetSources:        []*RulesetSource{},
		}

		changed, err := eng.hasConfigChanged()
		assert.NoError(t, err)
		assert.True(t, changed)
	})

	t.Run("Fingerprint differs", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(gomock.Any()).Return([]byte("different_fingerprint"), nil)

		eng := &SuricataEngine{
			srv:                   &server.Server{},
			IOManager:             iom,
			configFingerprintFile: "/test/fingerprint",
			rulesetSources:        []*RulesetSource{},
		}

		changed, err := eng.hasConfigChanged()
		assert.NoError(t, err)
		assert.True(t, changed)
	})

	t.Run("Read error (non-NotExist)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(gomock.Any()).Return(nil, errors.New("permission denied"))

		eng := &SuricataEngine{
			srv:                   &server.Server{},
			IOManager:             iom,
			configFingerprintFile: "/test/fingerprint",
			rulesetSources:        []*RulesetSource{},
		}

		changed, err := eng.hasConfigChanged()
		assert.NoError(t, err)
		assert.True(t, changed) // Assumes changed on error
	})

	t.Run("Fingerprint matches - no change", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)

		eng := &SuricataEngine{
			srv:                   &server.Server{},
			IOManager:             iom,
			configFingerprintFile: "/test/fingerprint",
			rulesetSources:        []*RulesetSource{},
			enableRegex:           []*regexp.Regexp{},
			disableRegex:          []*regexp.Regexp{},
		}

		// Get the actual fingerprint that will be generated
		expectedFingerprint := eng.generateConfigFingerprint()

		// Mock returns the same fingerprint
		iom.EXPECT().ReadFile("/test/fingerprint").Return([]byte(expectedFingerprint), nil)

		changed, err := eng.hasConfigChanged()
		assert.NoError(t, err)
		assert.False(t, changed, "should return false when fingerprints match")
	})
}
