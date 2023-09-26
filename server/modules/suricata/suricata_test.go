package suricata

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/stretchr/testify/assert"
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
	assert.Nil(t, err)

	err = mod.Start()
	assert.Nil(t, err)

	err = mod.Stop()
	assert.Nil(t, err)

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

	output := indexEnabled(lines)

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
}

func TestIndexModify(t *testing.T) {
	lines := []string{
		`90000 this that`,
		`10000 "flowbits" "noalert; flowbits"`,
		`# 20000 "flowbits" "noalert; flowbits"`,
		`30000 "flowbits" "noalert; flowbits" # we'll turn this on later`,
		`# An unrelated comment`,
		`a83ba97b-a8e8-4258-be1b-022aff230e6e "flowbits" "noalert; flowbits"`,
		` # 23220e49-7229-43a1-92d5-d68e46d27105 "flowbits" "noalert; flowbits"`,
		`e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5 that this`,
	}

	// Reminder: We only care about the lines that the API has added,
	// if a line doesn't end with suricataModifyFromTo (`"flowbits" "noalert; flowbits"`)
	// then it's a line we don't want to touch.

	output := indexModify(lines)

	assert.Equal(t, 4, len(output))
	assert.Contains(t, output, "10000")
	assert.Equal(t, output["10000"], 1)
	assert.Contains(t, output, "20000")
	assert.Equal(t, output["20000"], 2)
	assert.Contains(t, output, "a83ba97b-a8e8-4258-be1b-022aff230e6e")
	assert.Equal(t, output["a83ba97b-a8e8-4258-be1b-022aff230e6e"], 5)
	assert.Contains(t, output, "23220e49-7229-43a1-92d5-d68e46d27105")
	assert.Equal(t, output["23220e49-7229-43a1-92d5-d68e46d27105"], 6)
	assert.NotContains(t, output, "90000")
	assert.NotContains(t, output, "30000")
	assert.NotContains(t, output, "e4bd794a-8156-4fcc-b6a9-9fb2c9ecadc5")
}

func TestValidate(t *testing.T) {
	table := []struct {
		Name        string
		Input       string
		ExpectedErr *string
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
			ExpectedErr: util.Ptr("invalid direction, must be '<>' or '->', got <->"),
		},
		{
			Name:        "Unexpected Suffix",
			Input:       SimpleRule + "x",
			ExpectedErr: util.Ptr("invalid rule, expected end of rule, got 1 more bytes"),
		},
		{
			Name:        "Unexpected End of Rule",
			Input:       "x",
			ExpectedErr: util.Ptr("invalid rule, unexpected end of rule"),
		},
	}

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			mod := NewSuricataEngine(&server.Server{})

			_, err := mod.ValidateRule(test.Input)
			if test.ExpectedErr == nil {
				assert.NoError(t, err)

				// this rule seems valid, attempt to parse, serialize, re-parse
				parsed, err := ParseSuricataRule(test.Input)
				assert.NoError(t, err)

				_, err = ParseSuricataRule(parsed.String())
				assert.NoError(t, err)
			} else {
				assert.Equal(t, *test.ExpectedErr, err.Error())
			}
		})
	}
}

func TestSyncSuricata(t *testing.T) {
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
				"idstools.rules.local__rules": "\n" + SimpleRule,
				"idstools.sids.enabled":       "\n" + SimpleRuleSID,
				"idstools.sids.disabled":      "\n# " + SimpleRuleSID,
				"idstools.sids.modify":        "",
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
				"idstools.rules.local__rules": "\n" + SimpleRule,
				"idstools.sids.enabled":       "\n# " + SimpleRuleSID,
				"idstools.sids.disabled":      "\n" + SimpleRuleSID,
				"idstools.sids.modify":        "",
			},
		},
		{
			Name: "Enable Existing Simple Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: SimpleRule},
				{Id: "idstools.sids.enabled", Value: "# " + SimpleRuleSID},
				{Id: "idstools.sids.disabled", Value: SimpleRuleSID},
				{Id: "idstools.sids.modify"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules": SimpleRule,
				"idstools.sids.enabled":       SimpleRuleSID,
				"idstools.sids.disabled":      "# " + SimpleRuleSID,
				"idstools.sids.modify":        "",
			},
		},
		{
			Name: "Disable Existing Simple Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: SimpleRule},
				{Id: "idstools.sids.enabled", Value: SimpleRuleSID},
				{Id: "idstools.sids.disabled", Value: "# " + SimpleRuleSID},
				{Id: "idstools.sids.modify"},
			},
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules": SimpleRule,
				"idstools.sids.enabled":       "# " + SimpleRuleSID,
				"idstools.sids.disabled":      SimpleRuleSID,
				"idstools.sids.modify":        "",
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
				"idstools.rules.local__rules": "\n" + FlowbitsRuleA,
				"idstools.sids.enabled":       "\n" + FlowbitsRuleASID,
				"idstools.sids.disabled":      "",
				"idstools.sids.modify":        "",
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
				"idstools.rules.local__rules": "\n" + FlowbitsRuleA,
				"idstools.sids.enabled":       "\n" + FlowbitsRuleASID,
				"idstools.sids.disabled":      "",
				"idstools.sids.modify":        "\n" + FlowbitsRuleASID + ` "flowbits" "noalert; flowbits"`,
			},
		},
		{
			Name: "Enable Existing Flowbits Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: FlowbitsRuleB},
				{Id: "idstools.sids.enabled", Value: FlowbitsRuleBSID},
				{Id: "idstools.sids.disabled", Value: ""},
				{Id: "idstools.sids.modify", Value: FlowbitsRuleBSID + ` "flowbits" "noalert; flowbits"`},
			},
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleBSID,
					Content:   FlowbitsRuleB,
					IsEnabled: true,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules": FlowbitsRuleB,
				"idstools.sids.enabled":       FlowbitsRuleBSID,
				"idstools.sids.disabled":      "",
				"idstools.sids.modify":        "",
			},
		},
		{
			Name: "Disable Existing Flowbits Rule",
			InitialSettings: []*model.Setting{
				{Id: "idstools.rules.local__rules", Value: FlowbitsRuleB},
				{Id: "idstools.sids.enabled", Value: FlowbitsRuleBSID},
				{Id: "idstools.sids.disabled", Value: "# " + FlowbitsRuleBSID},
				{Id: "idstools.sids.modify", Value: ""},
			},
			Detections: []*model.Detection{
				{
					PublicID:  FlowbitsRuleBSID,
					Content:   FlowbitsRuleB,
					IsEnabled: false,
				},
			},
			ExpectedSettings: map[string]string{
				"idstools.rules.local__rules": FlowbitsRuleB,
				"idstools.sids.enabled":       FlowbitsRuleBSID,
				"idstools.sids.disabled":      "# " + FlowbitsRuleBSID,
				"idstools.sids.modify":        "\n" + FlowbitsRuleBSID + ` "flowbits" "noalert; flowbits"`,
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

			errMap, err := mod.SyncDetections(ctx, test.Detections)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)

			set, err := mCfgStore.GetSettings(ctx)
			assert.NoError(t, err, "GetSettings should not return an error")

			for id, expectedValue := range test.ExpectedSettings {
				setting := settingByID(set, id)
				assert.NotNil(t, setting, "Setting %s", id)
				assert.Equal(t, expectedValue, setting.Value, "Setting %s", id)
			}
		})
	}
}
