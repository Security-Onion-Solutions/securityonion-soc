// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"sort"
	"strings"
	"sync"
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
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	SimpleRuleSID    = "10000"
	SimpleRule       = `alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)`
	FlowbitsRuleASID = "50000"
	FlowbitsRuleA    = `alert http any any -> any any ( msg:"RULE A"; flow: established,to_server; http.method; content:"POST"; http.content_type; content:"x-www-form-urlencoded"; flowbits: set, test; sid:50000;)`
	FlowbitsRuleBSID = "60000"
	FlowbitsRuleB    = `alert http any any -> any any (msg:"RULE B"; flowbits: isset, test; flow: established,to_client; content:"uid=0"; sid:60000;)`
)

func emptySettings() []*model.Setting {
	return []*model.Setting{
		{Id: "idstools.rules.local__rules"},
		{Id: "idstools.sids.enabled"},
		{Id: "idstools.sids.disabled"},
		{Id: "idstools.sids.modify"},
		{Id: "suricata.thresholding.sids__yaml"},
	}
}

func TestSuricataModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewSuricataEngine(srv)

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
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameSuricata])
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

func TestReadAndHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	content := "content"

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile("file").Return([]byte(content), nil)

	e := &SuricataEngine{
		srv:       &server.Server{},
		IOManager: iom,
	}

	fileContent, sha256Hash, err := e.readAndHash("file")

	assert.NoError(t, err)
	assert.Equal(t, content, fileContent)
	assert.Equal(t, "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73", sha256Hash)
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

func TestIndexLocal(t *testing.T) {
	lines := []string{
		"sid: 10000;",
		" ",
		"# sid: 20000;",
		"sid: 30000;",
		"# 40000", // note: extractSID won't find anything here
		"50000",
	}

	output := indexLocal(lines)
	assert.Equal(t, 3, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, output["10000"], 0)
	assert.Contains(t, output, "20000")
	assert.Equal(t, output["20000"], 2)
	assert.Contains(t, output, "30000")
	assert.Equal(t, output["30000"], 3)
	assert.NotContains(t, output, "40000")
	assert.NotContains(t, output, "50000")
}

func TestIndexEnabled(t *testing.T) {
	lines := []string{
		"10000",
		" ",
		"# 20000   ",
		"30000 ",
		"#   40000", // note: extractSID won't find anything here
		"   50000",
		" not a number ",
		"#  24adee9b-6010-46ed-9c4a-9cb7a9c972a1",
	}

	output := indexEnabled(lines, false)

	assert.Equal(t, 7, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, output["10000"], 0)
	assert.Contains(t, output, "20000")
	assert.Equal(t, output["20000"], 2)
	assert.Contains(t, output, "30000")
	assert.Equal(t, output["30000"], 3)
	assert.Contains(t, output, "40000")
	assert.Equal(t, output["40000"], 4)
	assert.Contains(t, output, "50000")
	assert.Equal(t, output["50000"], 5)
	assert.Contains(t, output, "not a number")
	assert.Equal(t, output["not a number"], 6)
	assert.Contains(t, output, "24adee9b-6010-46ed-9c4a-9cb7a9c972a1")
	assert.Equal(t, output["24adee9b-6010-46ed-9c4a-9cb7a9c972a1"], 7)

	output = indexEnabled(lines, true)
	assert.Equal(t, 4, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, output["10000"], 0)
	assert.NotContains(t, output, "20000")
	assert.Contains(t, output, "30000")
	assert.Equal(t, output["30000"], 3)
	assert.NotContains(t, output, "40000")
	assert.Contains(t, output, "50000")
	assert.Equal(t, output["50000"], 5)
	assert.Contains(t, output, "not a number")
	assert.Equal(t, output["not a number"], 6)
	assert.NotContains(t, output, "24adee9b-6010-46ed-9c4a-9cb7a9c972a1")
}

func TestIndexModify(t *testing.T) {
	lines := []string{
		`90000 this that`,
		`10000 "flowbits" "noalert; flowbits"`,
		`# 20000 "flowbits" "noalert; flowbits"`,
		`30000 "flowbits" "noalert; flowbits" # we'll turn this on later`,
		`# An unrelated comment`,
		`a83ba97b-a8e8-4258-be1b-022aff230e6e "flowbits" "noalert; flowbits"`,
		`e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5 that this`,
	}

	output := indexModify(lines, false, false)

	assert.Equal(t, 7, len(output))
	assert.Contains(t, output, "90000")
	assert.Equal(t, 0, output["90000"])
	assert.Contains(t, output, "10000")
	assert.Equal(t, 1, output["10000"])
	assert.Contains(t, output, "20000")
	assert.Equal(t, 2, output["20000"])
	assert.Contains(t, output, "a83ba97b-a8e8-4258-be1b-022aff230e6e")
	assert.Equal(t, 5, output["a83ba97b-a8e8-4258-be1b-022aff230e6e"])
	assert.Contains(t, output, "90000")
	assert.Equal(t, 0, output["90000"])
	assert.Contains(t, output, "30000")
	assert.Equal(t, 3, output["30000"])
	assert.Contains(t, output, "e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5")
	assert.Equal(t, 6, output["e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5"])

	output = indexModify(lines, true, false)

	assert.Equal(t, 5, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, 1, output["10000"])
	assert.Contains(t, output, "a83ba97b-a8e8-4258-be1b-022aff230e6e")
	assert.Equal(t, 5, output["a83ba97b-a8e8-4258-be1b-022aff230e6e"])
	assert.Contains(t, output, "90000")
	assert.Equal(t, 0, output["90000"])
	assert.Contains(t, output, "30000")
	assert.Equal(t, 3, output["30000"])
	assert.Contains(t, output, "e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5")
	assert.Equal(t, 6, output["e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5"])

	output = indexModify(lines, false, true)

	assert.Equal(t, 4, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, 1, output["10000"])
	assert.Contains(t, output, "20000")
	assert.Equal(t, 2, output["20000"])
	assert.Contains(t, output, "a83ba97b-a8e8-4258-be1b-022aff230e6e")
	assert.Equal(t, 5, output["a83ba97b-a8e8-4258-be1b-022aff230e6e"])
	assert.Contains(t, output, "30000")
	assert.Equal(t, 3, output["30000"])

	output = indexModify(lines, true, true)

	assert.Equal(t, 3, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, 1, output["10000"])
	assert.Contains(t, output, "30000")
	assert.Equal(t, 3, output["30000"])
	assert.Contains(t, output, "a83ba97b-a8e8-4258-be1b-022aff230e6e")
	assert.Equal(t, 5, output["a83ba97b-a8e8-4258-be1b-022aff230e6e"])
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
			Input: `alert http any any -> any any (msg:"This rule has \"escaped quotes\"";)`,
		},
		{
			Name:        "Invalid Direction",
			Input:       `alert http any any <-> any any (msg:"This rule has an invalid direction";)`,
			ExpectedErr: "invalid direction, must be '<>' or '->', got <->",
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
					Author:    ruleset,
					PublicID:  SimpleRuleSID,
					Title:     `GPL ATTACK_RESPONSE id check returned root`,
					Category:  `GPL ATTACK_RESPONSE`,
					Severity:  model.SeverityUnknown,
					Content:   SimpleRule,
					IsEnabled: true,
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Ruleset:   ruleset,
					License:   "Unknown",
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
	}

	mod := NewSuricataEngine(&server.Server{})

	mod.isRunning = true

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			data := strings.Join(test.Lines, "\n")

			detections, err := mod.ParseRules(data, ruleset)
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

func TestSyncLocalSuricata(t *testing.T) {
	table := []struct {
		Name             string
		InitialSettings  []*model.Setting
		Detections       []*model.Detection // Content (Valid Rule), PublicID, IsEnabled
		ExpectedSettings map[string]string
		ExpectedErr      error
		ExpectedErrMap   map[string]string
	}{
		{
			Name:            "Enable New Simple Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "Disable New Simple Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      "",
				"idstools.sids.enabled":            "",
				"idstools.sids.disabled":           SimpleRuleSID,
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name: "Enable Existing Simple Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: SimpleRule},
				{Id: "idstools.sids.enabled", Value: "# " + SimpleRuleSID},
				{Id: "idstools.sids.disabled", Value: SimpleRuleSID},
				{Id: "idstools.sids.modify"},
				{Id: "suricata.thresholding.sids__yaml"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name: "Disable Existing Simple Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: SimpleRule},
				{Id: "idstools.sids.enabled", Value: SimpleRuleSID},
				{Id: "idstools.sids.disabled", Value: "# " + SimpleRuleSID},
				{Id: "idstools.sids.modify"},
				{Id: "suricata.thresholding.sids__yaml"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      "",
				"idstools.sids.enabled":            "",
				"idstools.sids.disabled":           SimpleRuleSID,
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "Enable New Flowbits Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleASID,
					Content:   FlowbitsRuleA,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      FlowbitsRuleA,
				"idstools.sids.enabled":            FlowbitsRuleASID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "Disable New Flowbits Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleASID,
					Content:   FlowbitsRuleA,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      FlowbitsRuleA,
				"idstools.sids.enabled":            FlowbitsRuleASID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             FlowbitsRuleASID + ` "flowbits" "noalert; flowbits"`,
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name: "Enable Existing Flowbits Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: FlowbitsRuleB},
				{Id: "idstools.sids.enabled", Value: FlowbitsRuleBSID},
				{Id: "idstools.sids.disabled", Value: ""},
				{Id: "idstools.sids.modify", Value: FlowbitsRuleBSID + ` "flowbits" "noalert; flowbits"`},
				{Id: "suricata.thresholding.sids__yaml"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleBSID,
					Content:   FlowbitsRuleB,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      FlowbitsRuleB,
				"idstools.sids.enabled":            FlowbitsRuleBSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name: "Disable Existing Flowbits Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: FlowbitsRuleB},
				{Id: "idstools.sids.enabled", Value: FlowbitsRuleBSID},
				{Id: "idstools.sids.disabled", Value: "# " + FlowbitsRuleBSID},
				{Id: "idstools.sids.modify", Value: ""},
				{Id: "suricata.thresholding.sids__yaml"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleBSID,
					Content:   FlowbitsRuleB,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      FlowbitsRuleB,
				"idstools.sids.enabled":            FlowbitsRuleBSID,
				"idstools.sids.disabled":           "# " + FlowbitsRuleBSID,
				"idstools.sids.modify":             FlowbitsRuleBSID + ` "flowbits" "noalert; flowbits"`,
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "Completely Invalid Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  "0",
					Content:   "x",
					IsEnabled: true,
				},
			},
			ExpectedErrMap: map[string]string{
				"0": "unable to parse rule; reason=invalid rule, unexpected end of rule",
			},
		},
		{
			Name:            "Rule Missing SID",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  "0",
					Content:   `alert http any any -> any any (msg:"This rule doesn't have a SID";)`, // missing closing paren
					IsEnabled: true,
				},
			},
			ExpectedErrMap: map[string]string{
				"0": `rule does not contain a SID; rule=alert http any any -> any any (msg:"This rule doesn't have a SID";)`,
			},
		},
		{
			Name:            "Thresholding (Modify)",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Overrides: []*model.Override{
						{
							Type:      model.OverrideTypeModify,
							IsEnabled: true,
							OverrideParameters: model.OverrideParameters{
								Regex: util.Ptr("rev:7;"),
								Value: util.Ptr("rev:8;"),
							},
						},
					},
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             SimpleRuleSID + ` "rev:7;" "rev:8;"`,
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "Thresholding (Suppress)",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Overrides: []*model.Override{
						{
							Type:      model.OverrideTypeSuppress,
							IsEnabled: true,
							OverrideParameters: model.OverrideParameters{
								Track: util.Ptr("by_src"),
								IP:    util.Ptr("0.0.0.0"),
							},
						},
					},
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "\"10000\":\n    - suppress:\n        gen_id: 1\n        track: by_src\n        ip: 0.0.0.0\n",
			},
		},
		{
			Name:            "Thresholding (Threshold)",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
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
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "\"10000\":\n    - threshold:\n        gen_id: 1\n        type: limit\n        track: by_src\n        count: 5\n        seconds: 60\n",
			},
		},
	}

	ctx := context.Background()

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			mCfgStore := server.NewMemConfigStore(test.InitialSettings)
			mod := NewSuricataEngine(&server.Server{
				Configstore:      mCfgStore,
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
			})
			mod.srv.DetectionEngines[model.EngineNameSuricata] = mod

			mod.isRunning = true

			errMap, err := mod.SyncLocalDetections(ctx, test.Detections)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)

			set, err := mCfgStore.GetSettings(ctx, true)
			assert.NoError(t, err, "GetSettings should not return an error")

			for id, expectedValue := range test.ExpectedSettings {
				setting := settingByID(set, id)
				assert.NotNil(t, setting, "Setting %s", id)
				assert.Equal(t, expectedValue, setting.Value, "Setting %s", id)
			}
		})
	}
}

func TestSyncCommunitySuricata(t *testing.T) {
	ctrl := gomock.NewController(t)

	table := []struct {
		Name             string
		InitialSettings  []*model.Setting
		Detections       []*model.Detection // Content (Valid Rule), PublicID, IsEnabled
		ChangedByUser    bool
		InitMock         func(*servermock.MockDetectionstore)
		ExpectedSettings map[string]string
		ExpectedErr      error
		ExpectedErrMap   map[string]string
	}{
		{
			Name:            "Non-User Update Community Simple Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					Auditable:   model.Auditable{Id: "1"},
					PublicID:    SimpleRuleSID,
					Content:     SimpleRule,
					IsEnabled:   true,
					IsCommunity: true,
				},
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				bim := servermock.NewMockBulkIndexer(ctrl)
				auditm := servermock.NewMockBulkIndexer(ctrl)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil)
				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil)
				bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				bim.EXPECT().Close(gomock.Any()).Return(nil)
				bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})

				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditm, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), util.Ptr("id"), util.Ptr("create")).Return([]byte("document"), "index", nil)
				auditm.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				auditm.EXPECT().Close(gomock.Any()).Return(nil)
				auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
			},
			ExpectedSettings: map[string]string{
				"idstools.sids.enabled":            "",
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name:            "User Update Community Simple Rule",
			InitialSettings: emptySettings(),
			Detections: []*model.Detection{
				{
					Auditable:   model.Auditable{Id: "1"},
					PublicID:    SimpleRuleSID,
					Content:     SimpleRule,
					IsEnabled:   true,
					IsCommunity: true,
				},
			},
			ChangedByUser: true,
			InitMock: func(detStore *servermock.MockDetectionstore) {
				bim := servermock.NewMockBulkIndexer(ctrl)
				auditm := servermock.NewMockBulkIndexer(ctrl)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil)
				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil)
				bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				bim.EXPECT().Close(gomock.Any()).Return(nil)
				bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})

				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditm, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), util.Ptr("id"), util.Ptr("create")).Return([]byte("document"), "index", nil)
				auditm.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				auditm.EXPECT().Close(gomock.Any()).Return(nil)
				auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
			},
			ExpectedSettings: map[string]string{
				"idstools.sids.enabled":            SimpleRuleSID,
				"idstools.sids.disabled":           "",
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
		{
			Name: "update existing community rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: SimpleRule},
				{Id: "idstools.sids.enabled"},
				{Id: "idstools.sids.disabled"},
				{Id: "idstools.sids.modify"},
				{Id: "suricata.thresholding.sids__yaml"},
			},
			Detections: []*model.Detection{
				{
					Auditable:   model.Auditable{Id: "1"},
					PublicID:    SimpleRuleSID,
					Content:     SimpleRule,
					IsEnabled:   false,
					IsCommunity: true,
				},
			},
			ChangedByUser: true,
			InitMock: func(detStore *servermock.MockDetectionstore) {
				bim := servermock.NewMockBulkIndexer(ctrl)
				auditm := servermock.NewMockBulkIndexer(ctrl)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					SimpleRuleSID: {
						Auditable:   model.Auditable{Id: "1"},
						PublicID:    SimpleRuleSID,
						Content:     SimpleRule,
						IsEnabled:   true,
						IsCommunity: true,
					},
				}, nil)
				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), nil, nil).Return([]byte("document"), "index", nil)
				bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				bim.EXPECT().Close(gomock.Any()).Return(nil)
				bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})

				detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditm, nil)
				detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), util.Ptr("id"), util.Ptr("update")).Return([]byte("document"), "index", nil)
				auditm.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
					if item.OnSuccess != nil {
						resp := esutil.BulkIndexerResponseItem{
							DocumentID: "id",
						}
						item.OnSuccess(context.Background(), item, resp)
					}
					return nil
				})
				auditm.EXPECT().Close(gomock.Any()).Return(nil)
				auditm.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules":      SimpleRule,
				"idstools.sids.enabled":            "",
				"idstools.sids.disabled":           SimpleRuleSID,
				"idstools.sids.modify":             "",
				"suricata.thresholding.sids__yaml": "{}\n",
			},
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			detStore := servermock.NewMockDetectionstore(ctrl)
			test.InitMock(detStore)

			mCfgStore := server.NewMemConfigStore(test.InitialSettings)
			mod := NewSuricataEngine(&server.Server{
				Configstore:      mCfgStore,
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
				Detectionstore:   detStore,
			})
			mod.srv.DetectionEngines[model.EngineNameSuricata] = mod

			mod.isRunning = true

			ctx := web.MarkChangedByUser(context.Background(), test.ChangedByUser)

			errMap, err := mod.syncCommunityDetections(ctx, nil, test.Detections, false, test.InitialSettings)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)

			for _, det := range test.Detections {
				assert.NotEmpty(t, det.Id)
			}

			set, err := mCfgStore.GetSettings(ctx, true)
			assert.NoError(t, err, "GetSettings should not return an error")

			for id, expectedValue := range test.ExpectedSettings {
				setting := settingByID(set, id)
				assert.NotNil(t, setting, "Setting %s", id)
				assert.Equal(t, expectedValue, setting.Value, "Setting %s", id)
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

func TestConslidateEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		Rules        []string
		Disabled     []string
		ExpectedSIDs []string
	}{
		{
			Name:         "Empty",
			Rules:        []string{},
			Disabled:     []string{},
			ExpectedSIDs: []string{},
		},
		{
			Name:         "No Disabled",
			Rules:        []string{"10000", "20000", "30000", "40000", "50000"},
			Disabled:     []string{},
			ExpectedSIDs: []string{"10000", "20000", "30000", "40000", "50000"},
		},
		{
			Name:         "No Enabled",
			Rules:        []string{},
			Disabled:     []string{"10000", "20000", "30000", "40000", "50000"},
			ExpectedSIDs: []string{},
		},
		{
			Name:         "Some Enabled, Some Disabled",
			Rules:        []string{"10000", "20000", "30000", "40000", "50000"},
			Disabled:     []string{"20000", "40000", "60000"},
			ExpectedSIDs: []string{"10000", "30000", "50000"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			rulesIndex := map[string]int{}
			for _, rule := range test.Rules {
				rulesIndex[rule] = 0
			}

			disabledIndex := map[string]int{}
			for _, rule := range test.Disabled {
				disabledIndex[rule] = 0
			}

			deployed := consolidateEnabled(rulesIndex, disabledIndex)

			sort.Strings(deployed)
			sort.Strings(test.ExpectedSIDs)

			assert.Equal(t, test.ExpectedSIDs, deployed)
		})
	}
}

func TestUpdateLocal(t *testing.T) {
	localLines := []string{
		"100000",
		"200000",
		"300000",
	}

	localIndex := map[string]int{
		"100000": 0,
		"200000": 1,
		"300000": 2,
	}

	sid := "400000"

	det := &model.Detection{
		IsEnabled: true,
		Content:   sid,
	}

	// is enabled, not present
	localLines = updateLocal(localLines, localIndex, sid, false, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "400000", localLines[3])
	assert.Equal(t, 4, len(localIndex))
	assert.Equal(t, 3, localIndex["400000"])

	det.Content = "400000!"

	// no flowbits
	// is enabled, present, different content
	localLines = updateLocal(localLines, localIndex, sid, false, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "400000!", localLines[3])
	assert.Equal(t, 4, len(localIndex))
	assert.Equal(t, 3, localIndex["400000"])

	det.IsEnabled = false

	// is disabled, present, should be removed
	localLines = updateLocal(localLines, localIndex, sid, false, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "", localLines[3])
	assert.Equal(t, 3, len(localIndex))
	assert.NotContains(t, localIndex, "400000")

	// is disabled, not present, no change
	localLines = updateLocal(localLines, localIndex, sid, false, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "", localLines[3])
	assert.Equal(t, 3, len(localIndex))
	assert.NotContains(t, localIndex, "400000")

	// reset
	localLines = localLines[:3]
	det.Content = "400000"

	// again, but with Flowbits
	// is enabled, not present
	localLines = updateLocal(localLines, localIndex, sid, true, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "400000", localLines[3])
	assert.Equal(t, 4, len(localIndex))
	assert.Equal(t, 3, localIndex["400000"])

	det.Content = "400000!"

	// is enabled, present, different content
	localLines = updateLocal(localLines, localIndex, sid, true, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "400000!", localLines[3])
	assert.Equal(t, 4, len(localIndex))
	assert.Equal(t, 3, localIndex["400000"])

	det.IsEnabled = false

	// is disabled, present, should be NOT removed because Flowbits
	localLines = updateLocal(localLines, localIndex, sid, true, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "400000!", localLines[3])
	assert.Equal(t, 4, len(localIndex))
	assert.Contains(t, localIndex, "400000")

	det.PendingDelete = true

	// PendingDelete should remove it regardless the rest of the state
	localLines = updateLocal(localLines, localIndex, sid, true, det)

	assert.Equal(t, 4, len(localLines))
	assert.Equal(t, "", localLines[3])
	assert.Equal(t, 3, len(localIndex))
	assert.NotContains(t, localIndex, "400000")
}

func TestUpdateEnabled(t *testing.T) {
	enableLines := []string{}
	enableIndex := map[string]int{}

	sid := "12345"
	det := &model.Detection{
		PublicID:  sid,
		IsEnabled: false,
	}

	// no flowbits
	// disabled, no change
	enableLines = updateEnabled(enableLines, enableIndex, sid, false, det)

	assert.Equal(t, 0, len(enableLines))
	assert.Equal(t, 0, len(enableIndex))

	det.IsEnabled = true

	// enabled
	enableLines = updateEnabled(enableLines, enableIndex, sid, false, det)

	assert.Equal(t, 1, len(enableLines))
	assert.Equal(t, sid, enableLines[0])
	assert.Equal(t, 1, len(enableIndex))
	assert.Equal(t, 0, enableIndex[sid])

	det.IsEnabled = false

	// disabled, remove entry
	enableLines = updateEnabled(enableLines, enableIndex, sid, false, det)

	assert.Equal(t, 1, len(enableLines))
	assert.Equal(t, "", enableLines[0])
	assert.Equal(t, 0, len(enableIndex))
	assert.NotContains(t, enableIndex, sid)

	det.IsEnabled = true

	// enabled, restore entry
	enableLines = updateEnabled(enableLines, enableIndex, sid, false, det)

	assert.Equal(t, 2, len(enableLines))
	assert.Equal(t, sid, enableLines[1])
	assert.Equal(t, 1, len(enableIndex))
	assert.Equal(t, 1, enableIndex[sid])

	det.PendingDelete = true

	// pending delete
	enableLines = updateEnabled(enableLines, enableIndex, sid, false, det)

	assert.Equal(t, 2, len(enableLines))
	assert.Equal(t, "", enableLines[1])
	assert.Equal(t, 0, len(enableIndex))
	assert.NotContains(t, enableIndex, sid)

	// reset for flowbits
	enableLines = []string{}
	enableIndex = map[string]int{}

	det.IsEnabled = true
	det.PendingDelete = false

	// with flowbits
	// enabled
	enableLines = updateEnabled(enableLines, enableIndex, sid, true, det)

	assert.Equal(t, 1, len(enableLines))
	assert.Equal(t, sid, enableLines[0])
	assert.Equal(t, 1, len(enableIndex))
	assert.Equal(t, 0, enableIndex[sid])

	det.IsEnabled = true

	// disabled
	enableLines = updateEnabled(enableLines, enableIndex, sid, true, det)

	assert.Equal(t, 1, len(enableLines))
	assert.Equal(t, sid, enableLines[0])
	assert.Equal(t, 1, len(enableIndex))
	assert.Equal(t, 0, enableIndex[sid])
}

func TestUpdateModify(t *testing.T) {
	modifyLines := []string{}
	modifyIndex := map[string]int{}

	sid := "12345"

	det := &model.Detection{
		PublicID:  sid,
		IsEnabled: true,
	}

	// enabled, no override
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 0, len(modifyLines))
	assert.Equal(t, 0, len(modifyIndex))

	det.IsEnabled = false

	// disabled, no override
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 0, len(modifyLines))
	assert.Equal(t, 0, len(modifyIndex))

	det.Overrides = []*model.Override{
		{
			Type: model.OverrideTypeModify,
			OverrideParameters: model.OverrideParameters{
				Regex: util.Ptr("A"),
				Value: util.Ptr("B"),
			},
			IsEnabled: true,
		},
	}

	// disabled, with override
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 0, len(modifyLines))
	assert.Equal(t, 0, len(modifyIndex))

	det.IsEnabled = true

	// enabled, with override
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, `12345 "A" "B"`, modifyLines[0])
	assert.Equal(t, 1, len(modifyIndex))
	assert.Equal(t, 0, modifyIndex["12345"])

	det.Overrides[0].Value = util.Ptr(`"C"`)

	// enabled, with override, new contents
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, `12345 "A" "\"C\""`, modifyLines[0])
	assert.Equal(t, 1, len(modifyIndex))
	assert.Equal(t, 0, modifyIndex["12345"])

	det.Overrides[0].IsEnabled = false

	// enabled, with disabled override
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, ``, modifyLines[0])
	assert.Equal(t, 0, len(modifyIndex))
	assert.NotContains(t, modifyIndex, "12345")

	// put it back so we can take it out...
	det.Overrides[0].IsEnabled = true
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)
	assert.Equal(t, 2, len(modifyLines))
	assert.Equal(t, `12345 "A" "\"C\""`, modifyLines[1])
	assert.Equal(t, 1, len(modifyIndex))
	assert.Equal(t, 1, modifyIndex["12345"])

	det.PendingDelete = true

	// PendingDelete, remove it regardless the rest of state
	modifyLines = updateModify(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 2, len(modifyLines))
	assert.Equal(t, ``, modifyLines[1])
	assert.Equal(t, 0, len(modifyIndex))
	assert.NotContains(t, modifyIndex, "12345")
}

func TestUpdateDisabled(t *testing.T) {
	disableLines := []string{}
	disableIndex := map[string]int{}

	sid := "12345"
	det := &model.Detection{
		PublicID:  sid,
		IsEnabled: true,
	}

	// no flowbits
	// enabled, no change
	disableLines = updateDisabled(disableLines, disableIndex, sid, false, det)

	assert.Equal(t, 0, len(disableLines))
	assert.Equal(t, 0, len(disableIndex))

	det.IsEnabled = false

	// disabled
	disableLines = updateDisabled(disableLines, disableIndex, sid, false, det)

	assert.Equal(t, 1, len(disableLines))
	assert.Equal(t, sid, disableLines[0])
	assert.Equal(t, 1, len(disableIndex))
	assert.Equal(t, 0, disableIndex[sid])

	det.IsEnabled = true

	// enabled, remove disabled entry
	disableLines = updateDisabled(disableLines, disableIndex, sid, false, det)

	assert.Equal(t, 1, len(disableLines))
	assert.Equal(t, "", disableLines[0])
	assert.Equal(t, 0, len(disableIndex))
	assert.NotContains(t, disableIndex, sid)

	det.IsEnabled = false

	// disabled
	disableLines = updateDisabled(disableLines, disableIndex, sid, false, det)

	assert.Equal(t, 2, len(disableLines))
	assert.Equal(t, sid, disableLines[1])
	assert.Equal(t, 1, len(disableIndex))
	assert.Equal(t, 1, disableIndex[sid])

	det.PendingDelete = true

	// pending delete
	disableLines = updateDisabled(disableLines, disableIndex, sid, false, det)

	assert.Equal(t, 2, len(disableLines))
	assert.Equal(t, "", disableLines[1])
	assert.Equal(t, 0, len(disableIndex))
	assert.NotContains(t, disableIndex, sid)

	// reset for flowbits
	disableLines = []string{}
	disableIndex = map[string]int{}

	det.IsEnabled = false
	det.PendingDelete = false

	// with flowbits
	// disabled
	disableLines = updateDisabled(disableLines, disableIndex, sid, true, det)

	assert.Equal(t, 0, len(disableLines))
	assert.Equal(t, 0, len(disableIndex))

	det.IsEnabled = true

	// enabled
	disableLines = updateDisabled(disableLines, disableIndex, sid, true, det)

	assert.Equal(t, 0, len(disableLines))
	assert.Equal(t, 0, len(disableIndex))
}

func TestUpdateModifyForDisabledFlowbits(t *testing.T) {
	modifyLines := []string{}
	modifyIndex := map[string]int{}

	sid := "12345"
	det := &model.Detection{
		PublicID: sid,
	}

	// not present, add
	modifyLines = updateModifyForDisabledFlowbits(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, sid+" "+modifyFromTo, modifyLines[0])
	assert.Equal(t, 1, len(modifyIndex))
	assert.Equal(t, 0, modifyIndex[sid])

	// present, don't add
	modifyLines = updateModifyForDisabledFlowbits(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, sid+" "+modifyFromTo, modifyLines[0])
	assert.Equal(t, 1, len(modifyIndex))
	assert.Equal(t, 0, modifyIndex[sid])

	det.PendingDelete = true

	// pending delete, remove
	modifyLines = updateModifyForDisabledFlowbits(modifyLines, modifyIndex, sid, det)

	assert.Equal(t, 1, len(modifyLines))
	assert.Equal(t, "", modifyLines[0])
	assert.Equal(t, 0, len(modifyIndex))
}

func TestUpdateThreshold(t *testing.T) {
	thresholdIndex := map[string][]*model.Override{}
	genId := 1
	sid := "12345"
	det := &model.Detection{
		PublicID: sid,
	}

	// no overrides, no change
	updateThreshold(thresholdIndex, genId, det)

	assert.Equal(t, 0, len(thresholdIndex))

	det.Overrides = []*model.Override{
		{
			IsEnabled: true,
			Type:      model.OverrideTypeThreshold,
			OverrideParameters: model.OverrideParameters{
				ThresholdType: util.Ptr("limit"),
				Track:         util.Ptr("by_src"),
				Count:         util.Ptr(5),
				Seconds:       util.Ptr(60),
			},
		},
		{
			IsEnabled: true,
			Type:      model.OverrideTypeSuppress,
			OverrideParameters: model.OverrideParameters{
				Track: util.Ptr("by_dest"),
				IP:    util.Ptr("127.0.0.1"),
			},
		},
		{
			IsEnabled: true,
			Type:      model.OverrideTypeModify,
			OverrideParameters: model.OverrideParameters{
				Regex: util.Ptr("A"),
				Value: util.Ptr("B"),
			},
		},
	}

	// add two
	updateThreshold(thresholdIndex, genId, det)

	assert.Equal(t, 1, len(thresholdIndex))
	assert.Equal(t, 2, len(thresholdIndex["12345"]))
	assert.Equal(t, &model.Override{
		IsEnabled: true,
		Type:      model.OverrideTypeThreshold,
		OverrideParameters: model.OverrideParameters{
			GenID:         util.Ptr(genId),
			ThresholdType: util.Ptr("limit"),
			Track:         util.Ptr("by_src"),
			Count:         util.Ptr(5),
			Seconds:       util.Ptr(60),
		},
	}, thresholdIndex["12345"][0])
	assert.Equal(t, &model.Override{
		IsEnabled: true,
		Type:      model.OverrideTypeSuppress,
		OverrideParameters: model.OverrideParameters{
			GenID: util.Ptr(genId),
			Track: util.Ptr("by_dest"),
			IP:    util.Ptr("127.0.0.1"),
		},
	}, thresholdIndex[sid][1])

	// update
	det.Overrides = []*model.Override{
		{
			IsEnabled: true,
			Type:      model.OverrideTypeSuppress,
			OverrideParameters: model.OverrideParameters{
				Track: util.Ptr("by_src"),
				IP:    util.Ptr("0.0.0.0"),
			},
		},
	}

	// add two
	updateThreshold(thresholdIndex, genId, det)

	assert.Equal(t, 1, len(thresholdIndex))
	assert.Equal(t, 1, len(thresholdIndex["12345"]))
	assert.Equal(t, &model.Override{
		IsEnabled: true,
		Type:      model.OverrideTypeSuppress,
		OverrideParameters: model.OverrideParameters{
			GenID: util.Ptr(genId),
			Track: util.Ptr("by_src"),
			IP:    util.Ptr("0.0.0.0"),
		},
	}, thresholdIndex["12345"][0])

	det.PendingDelete = true

	updateThreshold(thresholdIndex, genId, det)

	assert.Equal(t, 0, len(thresholdIndex))
}

func TestRemoveFromIndex(t *testing.T) {
	localLines := []string{
		"100000",
		"200000",
		"300000",
	}

	localIndex := map[string]int{
		"100000": 0,
		"200000": 1,
		"300000": 2,
	}

	// remove non-existent entry, no change
	removeFromIndex(localLines, localIndex, "500000")

	assert.Equal(t, []string{
		"100000",
		"200000",
		"300000",
	}, localLines)
	assert.Equal(t, map[string]int{
		"100000": 0,
		"200000": 1,
		"300000": 2,
	}, localIndex)

	// remove existing entry
	removeFromIndex(localLines, localIndex, "200000")

	assert.Equal(t, []string{
		"100000",
		"",
		"300000",
	}, localLines)
	assert.Equal(t, map[string]int{
		"100000": 0,
		"300000": 2,
	}, localIndex)
}

func TestReadCustomRulesets(t *testing.T) {
	tests := []struct {
		Name          string
		Rulesets      []*model.CustomRuleset
		InitMock      func(io *mock.MockIOManager)
		ExpDetections []*model.Detection
		ExpError      string
	}{
		{
			Name:          "Empty",
			Rulesets:      []*model.CustomRuleset{},
			ExpDetections: []*model.Detection{},
		},
		{
			Name: "Simple File",
			Rulesets: []*model.CustomRuleset{
				{
					Community: true,
					License:   "DRL",
					File:      "testdata/simple.rules",
					Ruleset:   "ruleset",
				},
			},
			InitMock: func(io *mock.MockIOManager) {
				io.EXPECT().ReadFile("testdata/simple.rules").Return([]byte(SimpleRule), nil)
			},
			ExpDetections: []*model.Detection{
				{
					PublicID: SimpleRuleSID,

					Title:       "GPL ATTACK_RESPONSE id check returned root",
					Severity:    model.SeverityUnknown,
					Author:      "ruleset",
					Category:    "GPL ATTACK_RESPONSE",
					Content:     "alert http any any -> any any (msg:\"GPL ATTACK_RESPONSE id check returned root\"; content:\"uid=0|28|root|29|\"; classtype:bad-unknown; sid:10000; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)",
					IsEnabled:   true,
					IsCommunity: true,
					Engine:      model.EngineNameSuricata,
					Language:    model.SigLangSuricata,
					Ruleset:     "ruleset",
					License:     "DRL",
				},
			},
		},
		{
			Name: "Simple URL",
			Rulesets: []*model.CustomRuleset{
				{
					Community:  true,
					License:    "DRL",
					Url:        "x",
					TargetFile: "target.file",
					Ruleset:    "ruleset",
				},
			},
			InitMock: func(io *mock.MockIOManager) {
				io.EXPECT().ReadFile("/nsm/rules/detect-suricata/custom_temp/target.file").Return([]byte(SimpleRule), nil)
			},
			ExpDetections: []*model.Detection{
				{
					PublicID: SimpleRuleSID,

					Title:       "GPL ATTACK_RESPONSE id check returned root",
					Severity:    model.SeverityUnknown,
					Author:      "ruleset",
					Category:    "GPL ATTACK_RESPONSE",
					Content:     "alert http any any -> any any (msg:\"GPL ATTACK_RESPONSE id check returned root\"; content:\"uid=0|28|root|29|\"; classtype:bad-unknown; sid:10000; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)",
					IsEnabled:   true,
					IsCommunity: true,
					Engine:      model.EngineNameSuricata,
					Language:    model.SigLangSuricata,
					Ruleset:     "ruleset",
					License:     "DRL",
				},
			},
		},
		{
			Name: "Bad File, Good Url",
			Rulesets: []*model.CustomRuleset{
				{
					Community:  true,
					License:    "DRL",
					Url:        "x",
					TargetFile: "target.file",
					Ruleset:    "ruleset",
				},
				{
					Community: true,
					License:   "DRL",
					File:      "testdata/simple.rules",
					Ruleset:   "ruleset",
				},
			},
			InitMock: func(io *mock.MockIOManager) {
				io.EXPECT().ReadFile("/nsm/rules/detect-suricata/custom_temp/target.file").Return([]byte(SimpleRule), nil)
				io.EXPECT().ReadFile("testdata/simple.rules").Return(nil, errors.New("bad file"))
			},
			ExpError: "bad file",
		},
		{
			Name: "Bad Url, Good File",
			Rulesets: []*model.CustomRuleset{
				{
					Community: true,
					License:   "DRL",
					File:      "testdata/simple.rules",
					Ruleset:   "ruleset",
				},
				{
					Community:  true,
					License:    "DRL",
					Url:        "x",
					TargetFile: "target.file",
					Ruleset:    "ruleset",
				},
			},
			InitMock: func(io *mock.MockIOManager) {
				io.EXPECT().ReadFile("testdata/simple.rules").Return([]byte(SimpleRule), nil)
				io.EXPECT().ReadFile("/nsm/rules/detect-suricata/custom_temp/target.file").Return(nil, errors.New("bad file"))
			},
			ExpError: "bad file",
		},
		{
			Name: "Bad Custom Ruleset",
			Rulesets: []*model.CustomRuleset{
				{},
			},
			ExpError: "invalid custom ruleset",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			io := mock.NewMockIOManager(ctrl)

			e := &SuricataEngine{
				customRulesets: test.Rulesets,
				IOManager:      io,
				isRunning:      true,
			}

			if test.InitMock != nil {
				test.InitMock(io)
			}

			detects, err := e.ReadCustomRulesets()

			if test.ExpError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpError)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, test.ExpDetections, detects)
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

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, opts ...model.GetAllOption) (map[string]*model.Detection, error) {
					expected := []string{
						`query AND so_detection.engine:"suricata"`,
						`query AND so_detection.isEnabled:"true"`,
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

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil)

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

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					SimpleRuleSID: {},
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
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{}, nil)

				return server.NewMemConfigStore([]*model.Setting{
					{Id: "idstools.sids.disabled", Value: SimpleRuleSID},
					{Id: "idstools.sids.modify", Value: FlowbitsRuleASID + " " + modifyFromTo},
				})
			},
			DbnE: []string{},
			EbnD: []string{},
		},
		{
			Name: "Mix and Match Fail",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					SimpleRuleSID:    {},
					FlowbitsRuleBSID: {},
				}, nil)

				return server.NewMemConfigStore(emptySettings())
			},
			DbnE:     []string{FlowbitsRuleASID},
			EbnD:     []string{FlowbitsRuleBSID},
			ExpError: detections.ErrIntCheckFailed,
		},
		{
			Name: "Mix and Match Success",
			InitMock: func(iom *mock.MockIOManager, detStore *servermock.MockDetectionstore) (cfgStore *server.MemConfigStore) {
				iom.EXPECT().ReadFile("allrules").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA+"\n"+FlowbitsRuleB), nil)

				detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
					SimpleRuleSID:    {},
					FlowbitsRuleASID: {},
				}, nil)

				return server.NewMemConfigStore([]*model.Setting{
					{Id: "idstools.sids.disabled"},
					{Id: "idstools.sids.modify", Value: FlowbitsRuleBSID + " " + modifyFromTo},
				})
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
			cfgStore := test.InitMock(iom, detStore)

			e := &SuricataEngine{
				srv: &server.Server{
					Configstore:    cfgStore,
					Detectionstore: detStore,
				},
				allRulesFile: "allrules",
				IOManager:    iom,
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

func TestSyncIncrementalNoChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{Id: "idstools.rules.local__rules"},
		{Id: "idstools.sids.enabled"},
		{Id: "idstools.sids.disabled"},
		{Id: "idstools.sids.modify"},
		{Id: "suricata.thresholding.sids__yaml"},
	})

	migrationChecked := false
	checkMigration := func() {
		migrationChecked = true
	}

	eng := &SuricataEngine{
		srv: &server.Server{
			Detectionstore: detStore,
			Configstore:    cfgStore,
		},
		isRunning:            true,
		communityRulesFile:   "communityRulesFile",
		rulesFingerprintFile: "rulesFingerprintFile",
		checkMigrationsOnce:  sync.OnceFunc(checkMigration),
		allRulesFile:         "allRulesFile",
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: true,
		aiRepoUrl:       "aiRepoUrl",
		aiRepoBranch:    "aiRepoBranch",
		aiRepoPath:      "aiRepoPath",
	}

	logger := log.WithField("detectionEngine", "test-suricata")

	// RefreshAiSummaries
	iom.EXPECT().ReadDir("aiRepoPath").Return([]fs.DirEntry{}, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "aiRepoPath/aiRepoUrl", "aiRepoUrl", util.Ptr("aiRepoBranch")).Return(nil)
	iom.EXPECT().ReadFile("aiRepoPath/aiRepoUrl/detections-ai/suricata_summaries.yaml").Return([]byte("{}"), nil)
	// readAndHash
	iom.EXPECT().ReadFile("communityRulesFile").Return([]byte(SimpleRule), nil)
	// readFingerprint
	iom.EXPECT().ReadFile("rulesFingerprintFile").Return([]byte("2a4374cf63736ccbaf7a58aedf2282cb21afebf82120e29e4cbcc459516852f2"), nil)
	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadFile("allRulesFile").Return([]byte(SimpleRule), nil)
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		"10000": nil,
	}, nil)

	err := eng.Sync(logger, false)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
	assert.True(t, migrationChecked)
}

func TestSyncChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{Id: "idstools.rules.local__rules", Value: FlowbitsRuleA},
		{Id: "idstools.sids.enabled", Value: SimpleRuleSID + "\n99999"},
		{Id: "idstools.sids.disabled"},
		{Id: "idstools.sids.modify", Value: FlowbitsRuleASID + " " + modifyFromTo}, // used to be disabled, will be enabled
		{Id: "suricata.thresholding.sids__yaml"},
		{Id: "idstools.config.ruleset", Value: "repo"},
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
		isRunning:            true,
		communityRulesFile:   "communityRulesFile",
		rulesFingerprintFile: "rulesFingerprintFile",
		checkMigrationsOnce:  sync.OnceFunc(checkMigration),
		allRulesFile:         "allRulesFile",
		SyncSchedulerParams: detections.SyncSchedulerParams{
			StateFilePath: "stateFilePath",
		},
		IntegrityCheckerData: detections.IntegrityCheckerData{
			IsRunning: true,
		},
		IOManager:       iom,
		showAiSummaries: true,
		aiRepoUrl:       "aiRepoUrl",
		aiRepoBranch:    "aiRepoBranch",
		aiRepoPath:      "aiRepoPath",
	}

	logger := log.WithField("detectionEngine", "test-suricata")

	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// RefreshAiSummaries
	iom.EXPECT().ReadDir("aiRepoPath").Return([]fs.DirEntry{}, nil)
	iom.EXPECT().CloneRepo(gomock.Any(), "aiRepoPath/aiRepoUrl", "aiRepoUrl", util.Ptr("aiRepoBranch")).Return(nil)
	iom.EXPECT().ReadFile("aiRepoPath/aiRepoUrl/detections-ai/suricata_summaries.yaml").Return([]byte("{}"), nil)
	// readAndHash
	iom.EXPECT().ReadFile("communityRulesFile").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil)
	// syncCommunityDetections
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: {
			Auditable: model.Auditable{
				Id:         "abc",
				CreateTime: util.Ptr(time.Now()),
			},
			IsEnabled: true,
		},
		"99999": {
			Auditable: model.Auditable{
				Id: "deleteme",
			},
		}, // to be deleted
	}, nil)
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
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), gomock.Any(), util.Ptr("id"), gomock.Any()).Return([]byte("document"), "index", nil).Times(3)
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

	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	iom.EXPECT().WriteFile("rulesFingerprintFile", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadFile("allRulesFile").Return([]byte(SimpleRule+"\n"+FlowbitsRuleA), nil)
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		"10000": nil,
		"50000": nil,
	}, nil)

	err := eng.Sync(logger, true)
	assert.NoError(t, err)

	assert.True(t, eng.EngineState.Syncing) // stays true until the SyncScheduler resets it
	assert.False(t, eng.EngineState.IntegrityFailure)
	assert.False(t, eng.EngineState.Migrating)
	assert.False(t, eng.EngineState.MigrationFailure)
	assert.False(t, eng.EngineState.Importing)
	assert.False(t, eng.EngineState.SyncFailure)
	assert.True(t, migrationChecked)

	allSettings, err := cfgStore.GetSettings(ctx, true)
	assert.NoError(t, err)

	enabled := settingByID(allSettings, "idstools.sids.enabled")
	assert.NotNil(t, enabled)
	assert.Equal(t, SimpleRuleSID, enabled.Value)

	disabled := settingByID(allSettings, "idstools.sids.disabled")
	assert.NotNil(t, disabled)
	assert.Equal(t, "", disabled.Value)

	modify := settingByID(allSettings, "idstools.sids.modify")
	assert.NotNil(t, modify)
	assert.Equal(t, "", modify.Value)

	threshold := settingByID(allSettings, "suricata.thresholding.sids__yaml")
	assert.NotNil(t, threshold)
	assert.Equal(t, "{}\n", threshold.Value)

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

func TestApplyFilters(t *testing.T) {
	tests := []struct {
		Name             string
		EnableRegex      []*regexp.Regexp
		DisableRegex     []*regexp.Regexp
		Detection        *model.Detection
		ExpStatus        bool
		ExpFilterApplied bool
		ExpError         string
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

			if test.ExpError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpError)
			} else {
				assert.NoError(t, err)
			}

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
