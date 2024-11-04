// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
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
	"gopkg.in/yaml.v3"
)

func TestCheckAutoEnabledSigmaRule(t *testing.T) {
	e := &ElastAlertEngine{
		autoEnabledSigmaRules: []string{"securityonion-resources+high", "core+critical"},
	}

	tests := []struct {
		name     string
		ruleset  string
		severity model.Severity
		expected bool
	}{
		{"securityonion-resources rule with high severity, rule enabled", "securityonion-resources", model.SeverityHigh, true},
		{"securityonion-resources rule with high severity upper case, rule enabled", "securityonion-RESOURCES", model.SeverityHigh, true},
		{"core rule with critical severity, rule enabled", "core", model.SeverityCritical, true},
		{"core rule with high severity, rule not enabled", "core", model.SeverityHigh, false},
		{"empty ruleset, high severity, rule not enabled", "", model.SeverityHigh, false},
		{"core ruleset, empty severity, rule not enabled", "core", "", false},
		{"empty ruleset, empty severity, rule not enabled", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := &model.Detection{
				Ruleset:  tt.ruleset,
				Severity: tt.severity,
			}
			checkRulesetEnabled(e, det)
			assert.Equal(t, tt.expected, det.IsEnabled)
		})
	}
}

func TestElastAlertModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewElastAlertEngine(srv)

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
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameElastAlert])
}

func TestParseSigmaPackages(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name     string
		Input    []string
		Expected []string
	}{
		{
			Name:     "Simple Sunny Day Path",
			Input:    []string{"core"},
			Expected: []string{"core"},
		},
		{
			Name:     "Multiple Packages",
			Input:    []string{"core+", "emerging_threats"},
			Expected: []string{"core+", "emerging_threats_addon"},
		},
		{
			Name:     "Rename (all => all_rules)",
			Input:    []string{"all"},
			Expected: []string{"all_rules"},
		},
		{
			Name:     "Rename (emerging_threats_addon => emerging_threats)",
			Input:    []string{"emerging_threats"},
			Expected: []string{"emerging_threats_addon"},
		},
		{
			Name:     "Normalize",
			Input:    []string{"CoRe++"},
			Expected: []string{"core++"},
		},
		{
			Name:     "Account For Nesting Packages",
			Input:    []string{"core", "core+", "core++", "all_rules", "emerging_threats"},
			Expected: []string{"all_rules"},
		},
	}

	for _, tt := range table {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			engine := ElastAlertEngine{}

			engine.parseSigmaPackages(tt.Input)

			sort.Strings(engine.sigmaRulePackages)
			sort.Strings(tt.Expected)

			assert.Equal(t, tt.Expected, engine.sigmaRulePackages)
		})
	}
}

func TestTimeFrame(t *testing.T) {
	tf := TimeFrame{}

	tf.SetWeeks(1)
	assert.Equal(t, 1, *tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetDays(1)
	assert.Nil(t, tf.Weeks)
	assert.Equal(t, 1, *tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetHours(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Equal(t, 1, *tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetMinutes(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Equal(t, 1, *tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetSeconds(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Equal(t, 1, *tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetMilliseconds(1)
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Equal(t, 1, *tf.Milliseconds)
	assert.Nil(t, tf.Schedule)

	tf.SetSchedule("0 0 0 * * *")
	assert.Nil(t, tf.Weeks)
	assert.Nil(t, tf.Days)
	assert.Nil(t, tf.Hours)
	assert.Nil(t, tf.Minutes)
	assert.Nil(t, tf.Seconds)
	assert.Nil(t, tf.Milliseconds)
	assert.Equal(t, "0 0 0 * * *", *tf.Schedule)

	tf.Schedule = nil // everything is now nil

	yml, err := yaml.Marshal(tf)
	assert.NoError(t, err)
	assert.Equal(t, "0\n", string(yml))

	err = yaml.Unmarshal(yml, &tf)
	assert.NoError(t, err)
	assert.Empty(t, tf)

	tf.SetWeeks(1)

	yml, err = yaml.Marshal(tf)
	assert.NoError(t, err)
	assert.Equal(t, "weeks: 1\n", string(yml))

	err = yaml.Unmarshal(yml, &tf)
	assert.NoError(t, err)
	assert.Equal(t, 1, *tf.Weeks)
}

func TestCheckSigmaPipelines(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	e := &ElastAlertEngine{
		sigmaPipelineFinal:            "/opt/sensoroni/sigma_final_pipeline.yaml",
		sigmaPipelineSO:               "/opt/sensoroni/sigma_so_pipeline.yaml",
		sigmaPipelinesFingerprintFile: "/opt/sensoroni/fingerprints/sigma.pipelines.fingerprint",
		IOManager:                     iom,
	}

	testList := []struct {
		name           string
		setupMock      func()
		expectedChange bool
		expectedHash   string
		expectedErr    error
	}{
		{
			name: "No changes in pipelines",
			setupMock: func() {
				// Setup the hash values to be the same
				iom.EXPECT().ReadFile("/opt/sensoroni/sigma_final_pipeline.yaml").Return([]byte("data"), nil)
				iom.EXPECT().ReadFile("/opt/sensoroni/sigma_so_pipeline.yaml").Return([]byte("data"), nil)
				hash := "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7-3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
				iom.EXPECT().ReadFile("/opt/sensoroni/fingerprints/sigma.pipelines.fingerprint").Return([]byte(hash), nil)
			},
			expectedChange: false,
			expectedHash:   "",
			expectedErr:    nil,
		},
		{
			name: "Changes detected in pipelines",
			setupMock: func() {
				// Setup the hash values to be different
				iom.EXPECT().ReadFile("/opt/sensoroni/sigma_final_pipeline.yaml").Return([]byte("data1"), nil)
				iom.EXPECT().ReadFile("/opt/sensoroni/sigma_so_pipeline.yaml").Return([]byte("data2"), nil)
				hash := "7c563a27ed29beba2a5e9fd515c0b4435065d7c90af52b29a7f96f1ba2f00d7b-6d8758d5149c097c5131dd1355b7b8891b2b207384ff8f66a650537c3d2ffd6f"
				iom.EXPECT().ReadFile("/opt/sensoroni/fingerprints/sigma.pipelines.fingerprint").Return([]byte(hash), nil)
			},
			expectedChange: true,
			expectedHash:   "5b41362bc82b7f3d56edc5a306db22105707d01ff4819e26faef9724a2d406c9-d98cf53e0c8b77c14a96358d5b69584225b4bb9026423cbc2f7b0161894c402c",
			expectedErr:    nil,
		},
		{
			name: "Error reading final pipeline file",
			setupMock: func() {
				iom.EXPECT().ReadFile("/opt/sensoroni/sigma_final_pipeline.yaml").Return(nil, errors.New("file read error"))
			},
			expectedChange: false,
			expectedHash:   "",
			expectedErr:    fmt.Errorf("error hashing file /opt/sensoroni/sigma_final_pipeline.yaml: file read error"),
		},
	}

	for _, tt := range testList {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			regenNeeded, updatedHash, err := e.checkSigmaPipelines()
			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedChange, regenNeeded)
				assert.Equal(t, tt.expectedHash, updatedHash)
			}
		})
	}
}

func TestSigmaToElastAlertSunnyDay(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	engine := ElastAlertEngine{
		IOManager:          iom,
		additionalAlerters: []string{"email", "slack"},
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content:  `{"detection": {"condition": "*"}}`,
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
		Overrides: []*model.Override{
			{
				Type:      model.OverrideTypeCustomFilter,
				IsEnabled: true,
				OverrideParameters: model.OverrideParameters{
					CustomFilter: util.Ptr(`{"this": ["that"]}`),
				},
			},
		},
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	// No license
	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert:
    - modules.so.securityonion-es.SecurityOnionESAlerter
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
realert:
    seconds: 0
type: any
filter:
    - eql: <eql>
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestSigmaToElastAlertSunnyDayLicensed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	engine := ElastAlertEngine{
		IOManager:               iom,
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content:  "totally good sigma",
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	// License
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert:
    - modules.so.securityonion-es.SecurityOnionESAlerter
    - email
    - slack
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
type: any
realert:
    seconds: 0
filter:
    - eql: <eql>
foo: bar
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestSigmaToElastAlertCustomNotificationLicensed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	config := make(map[string]interface{})
	config["MyAlerters"] = "post2"
	config["MyParams"] = "foo: car"

	engine := ElastAlertEngine{
		IOManager:               iom,
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
		customAlerters:          &config,
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content: `
title: Test Detection
id: 00000000-0000-0000-0000-000000000000
logsource:
    product: linux
    service: auth
detection:
    selection:
        event.outcome: failure
        process.name: sshd
        tags|contains: so-grid-node
    filter:
        system.auth.ssh.method: '*'
    condition: selection and not filter
tags:
- so.alerters.MyAlerters
- so.params.MyParams
`,
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	// License
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert:
    - modules.so.securityonion-es.SecurityOnionESAlerter
    - post2
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
type: any
realert:
    seconds: 0
filter:
    - eql: <eql>
foo: car
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestSigmaToElastAlertCustomNotificationUnlicensed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	config := make(map[string]interface{})
	config["MyAlerters"] = "post2"
	config["MyParams"] = "foo: car"

	engine := ElastAlertEngine{
		IOManager:               iom,
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
		customAlerters:          &config,
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content: `
title: Test Detection
id: 00000000-0000-0000-0000-000000000000
logsource:
    product: linux
    service: auth
detection:
    selection:
        event.outcome: failure
        process.name: sshd
        tags|contains: so-grid-node
    filter:
        system.auth.ssh.method: '*'
    condition: selection and not filter
tags:
- so.alerters.MyAlerters
- so.params.MyParams
`,
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert:
    - modules.so.securityonion-es.SecurityOnionESAlerter
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
type: any
realert:
    seconds: 0
filter:
    - eql: <eql>
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestSigmaToElastAlertNotificationOnlyLicensed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	engine := ElastAlertEngine{
		IOManager:               iom,
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content: `
title: Test Detection
id: 00000000-0000-0000-0000-000000000000
logsource:
    product: linux
    service: auth
detection:
    selection:
        event.outcome: failure
        process.name: sshd
        tags|contains: so-grid-node
    filter:
        system.auth.ssh.method: '*'
    condition: selection and not filter
tags:
- so.notification
`,
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	// License
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert:
    - email
    - slack
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
type: any
realert:
    seconds: 0
filter:
    - eql: <eql>
foo: bar
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestSigmaToElastAlertNotificationOnlyUnlicensed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("<eql>"), 0, time.Duration(0), nil)

	engine := ElastAlertEngine{
		IOManager:               iom,
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
	}

	det := &model.Detection{
		PublicID: "00000000-0000-0000-0000-000000000000",
		Content: `
title: Test Detection
id: 00000000-0000-0000-0000-000000000000
logsource:
    product: linux
    service: auth
detection:
    selection:
        event.outcome: failure
        process.name: sshd
        tags|contains: so-grid-node
    filter:
        system.auth.ssh.method: '*'
    condition: selection and not filter
tags:
- so.notification
`,
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	wrappedRule, err := engine.wrapRule(det, query)
	assert.NoError(t, err)

	expected := `detection_title: Test Detection
detection_public_id: 00000000-0000-0000-0000-000000000000
event.module: sigma
event.dataset: sigma.alert
event.severity: 4
sigma_level: high
alert: []
index: .ds-logs-*
name: Test Detection -- 00000000-0000-0000-0000-000000000000
type: any
realert:
    seconds: 0
filter:
    - eql: <eql>
is_enabled: False
`
	assert.YAMLEq(t, expected, wrappedRule)
}

func TestAdditionalAlertersSev0(t *testing.T) {
	engine := ElastAlertEngine{
		additionalAlerters:      []string{"email", "slack"},
		additionalAlerterParams: "foo: bar",
	}

	for sev := range 6 {
		alerters, params := engine.getAdditionalAlerters(sev)
		assert.Equal(t, []string{"email", "slack"}, alerters)
		assert.Equal(t, "foo: bar", params)
	}
}

func TestAdditionalAlertersSev0Sev3(t *testing.T) {
	engine := ElastAlertEngine{
		additionalAlerters:          []string{"email", "slack"},
		additionalAlerterParams:     "foo: bar",
		mediumSeverityAlerters:      []string{"teams"},
		mediumSeverityAlerterParams: "foo: boo",
	}

	for sev := range 6 {
		alerters, params := engine.getAdditionalAlerters(sev)
		if sev < 3 {
			assert.Equal(t, []string{"email", "slack"}, alerters)
			assert.Equal(t, "foo: bar", params)
		} else {
			assert.Equal(t, []string{"teams"}, alerters)
			assert.Equal(t, "foo: boo", params)
		}
	}
}

func TestAdditionalAlertersSev0Sev5(t *testing.T) {
	engine := ElastAlertEngine{
		additionalAlerters:            []string{"email", "slack"},
		additionalAlerterParams:       "foo: bar",
		criticalSeverityAlerters:      []string{"teams"},
		criticalSeverityAlerterParams: "foo: boo",
	}

	for sev := range 6 {
		alerters, params := engine.getAdditionalAlerters(sev)
		if sev < 5 {
			assert.Equal(t, []string{"email", "slack"}, alerters)
			assert.Equal(t, "foo: bar", params)
		} else {
			assert.Equal(t, []string{"teams"}, alerters)
			assert.Equal(t, "foo: boo", params)
		}
	}
}

func TestSigmaToElastAlertError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)

	iom.EXPECT().ExecCommand(gomock.Cond(func(x any) bool {
		cmd := x.(*exec.Cmd)

		if !strings.HasSuffix(cmd.Path, "sigma") {
			return false
		}

		if !slices.Contains(cmd.Args, "convert") {
			return false
		}

		if cmd.Stdin == nil {
			return false
		}

		return true
	})).Return([]byte("Error: something went wrong"), 1, time.Duration(0), errors.New("non-zero return"))

	engine := ElastAlertEngine{
		IOManager: iom,
	}

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "00000000-0000-0000-0000-000000000000",
		},
		Content:  "totally good sigma",
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	query, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.Empty(t, query)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "problem with sigma cli")
}

func TestParseZipRules(t *testing.T) {
	t.Parallel()

	data := `title: Always Alert
id: 00000000-0000-0000-0000-00000000
status: experimental
description: Always Alerts
author: Corey Ogburn
date: 2023/11/03
modified: 2023/11/03
logsource:
    product: windows
detection:
    filter:
        event.module: zeek
    condition: filter
level: high
`

	buf := bytes.NewBuffer([]byte{})

	writer := zip.NewWriter(buf)
	aa, err := writer.Create("rules/always_alert.yml")
	assert.NoError(t, err)

	_, err = aa.Write([]byte(data))
	assert.NoError(t, err)

	bad, err := writer.Create("rules/bad.yml")
	assert.NoError(t, err)

	_, err = bad.Write([]byte("bad data"))
	assert.NoError(t, err)

	denied, err := writer.Create("rules/deny.yml")
	assert.NoError(t, err)

	_, err = denied.Write([]byte("deny"))
	assert.NoError(t, err)

	allowThenDeny, err := writer.Create("rules/eventually_deny.yml")
	assert.NoError(t, err)

	_, err = allowThenDeny.Write([]byte("00000000-0000-0000-0000-00000000 deny"))
	assert.NoError(t, err)

	matchesNeither, err := writer.Create("rules/not_allowed.yml")
	assert.NoError(t, err)

	_, err = matchesNeither.Write([]byte("123"))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	pkgZips := map[string][]byte{
		"all_rules": buf.Bytes(),
	}

	engine := ElastAlertEngine{
		isRunning:         true,
		sigmaRulePackages: []string{"all_rules"},
	}

	expected := &model.Detection{
		Author:      "Corey Ogburn",
		PublicID:    "00000000-0000-0000-0000-00000000",
		Title:       "Always Alert",
		Severity:    model.SeverityHigh,
		Content:     data,
		Description: "Always Alerts",
		Product:     "windows",
		IsCommunity: true,
		Engine:      model.EngineNameElastAlert,
		Language:    model.SigLangSigma,
		Ruleset:     "all_rules",
		License:     model.LicenseDRL,
	}

	dets, errMap := engine.parseZipRules(pkgZips)
	assert.NotNil(t, errMap)
	assert.Error(t, errMap["rules/bad.yml"])
	assert.Len(t, dets, 1)
	assert.Equal(t, expected, dets[0])
}

func TestParseRepoRules(t *testing.T) {
	t.Parallel()

	data := `title: Security Onion - SOC Login Failure
id: bf86ef21-41e6-417b-9a05-b9ea6bf28a38
status: experimental
description: Detects when a user fails to login to the Security Onion Console (Web UI). Review associated logs for target username and source IP.
author: Security Onion Solutions
date: 2024/03/06
logsource:
    product: kratos
    service: audit
detection:
    selection:
        msg: Encountered self-service login error.
    condition: selection
falsepositives:
    - none
level: high
license: Elastic-2.0
`

	repos := []*detections.RepoOnDisk{
		{
			Repo: &model.RuleRepo{
				Repo:      "github.com/repo-user/repo-path",
				License:   "DRL",
				Community: true,
			},
			Path: "repo-path",
		},
	}

	iom := mock.NewMockIOManager(gomock.NewController(t))
	iom.EXPECT().WalkDir(gomock.Eq("repo-path"), gomock.Any()).DoAndReturn(func(path string, fn fs.WalkDirFunc) error {
		return fn("rules/so_soc_failed_login.yml", &handmock.MockDirEntry{
			Filename: "so_soc_failed_login.yml",
		}, nil)
	})
	iom.EXPECT().ReadFile(gomock.Eq("rules/so_soc_failed_login.yml")).Return([]byte(data), nil)

	engine := ElastAlertEngine{
		isRunning: true,
		IOManager: iom,
	}

	expected := &model.Detection{
		Author:      "Security Onion Solutions",
		PublicID:    "bf86ef21-41e6-417b-9a05-b9ea6bf28a38",
		Title:       "Security Onion - SOC Login Failure",
		Severity:    model.SeverityHigh,
		Content:     data,
		Description: "Detects when a user fails to login to the Security Onion Console (Web UI). Review associated logs for target username and source IP.",
		IsCommunity: true,
		Product:     "kratos",
		Service:     "audit",
		Engine:      model.EngineNameElastAlert,
		Language:    model.SigLangSigma,
		Ruleset:     "repo-path",
		License:     model.LicenseDRL,
	}

	dets, errMap := engine.parseRepoRules(repos)
	assert.Nil(t, errMap)
	assert.Len(t, dets, 1)
	assert.Equal(t, expected, dets[0])
}

func TestDownloadSigmaPackages(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	body := "data"

	for i := 0; i < 5; i++ {
		// can't use mock's Times(x) because the first response's body
		// closing will result in remaining requests getting 0 data
		iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}, nil)
	}

	iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusNotFound,
	}, nil)

	pkgs := []string{"core", "core+", "core++", "emerging_threats_addon", "all_rules", "fake"}

	engine := ElastAlertEngine{
		sigmaRulePackages:            pkgs,
		sigmaPackageDownloadTemplate: "localhost:3000/%s.zip",
		IOManager:                    iom,
	}

	pkgZips, errMap := engine.downloadSigmaPackages()
	assert.NotNil(t, errMap)
	assert.Error(t, errMap["fake"])
	assert.Len(t, pkgZips, len(pkgs)-1)

	for _, pkg := range pkgs[:len(pkgs)-1] {
		assert.Equal(t, []byte(body), pkgZips[pkg])
	}
}

func TestLoadSigmaPackagesFromDisks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	airgapBasePath := "/nsm/rules/detect-sigma/rulesets/"

	// List of packages to be loaded from disk
	pkgs := []string{"core", "core+", "core++", "emerging_threats_addon", "all_rules", "fake"}

	// Setting up mocks for each expected file read, except for the "fake" package to simulate an error
	for _, pkg := range pkgs[:len(pkgs)-1] {
		expectedFilePath := airgapBasePath + "sigma_" + pkg + ".zip"
		iom.EXPECT().ReadFile(expectedFilePath).Return([]byte("mocked data for "+pkg), nil)
	}

	// Simulating an error for the 'fake' package
	fakeFilePath := airgapBasePath + "sigma_fake.zip"
	iom.EXPECT().ReadFile(fakeFilePath).Return(nil, errors.New("file not found"))

	engine := ElastAlertEngine{
		sigmaRulePackages: pkgs,
		airgapBasePath:    airgapBasePath,
		IOManager:         iom,
	}

	zipData, errMap := engine.loadSigmaPackagesFromDisk()

	// Assertions
	assert.NotNil(t, errMap, "Expected error map to not be nil")
	assert.Error(t, errMap["fake"], "Expected an error for 'fake' package")
	assert.Nil(t, errMap["core"], "No error expected for 'core' package")
	assert.Len(t, zipData, len(pkgs)-1, "Expect one less entry in zipData due to the 'fake' package error")

	// Verify that the content for each successful load is as expected
	for _, pkg := range pkgs[:len(pkgs)-1] {
		expectedContent := []byte("mocked data for " + pkg)
		assert.Equal(t, expectedContent, zipData[pkg], "Expect the content to match the mocked content for package: "+pkg)
	}
}

const (
	SimpleRuleSID = "bcc6f179-11cd-4111-a9a6-0fab68515cf7"
	SimpleRule    = `title: Griffon Malware Attack Pattern
id: bcc6f179-11cd-4111-a9a6-0fab68515cf7
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
	SimpleRuleNoId = `title: Griffon Malware Attack Pattern
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
	SimpleRuleNoExtract = `title: Required
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely`
	SimpleRule2SID = "19aa1142-94dc-43ef-af58-9b31406dcdc9"
	SimpleRule2    = `title: Griffon Malware Attack Pattern
id: 19aa1142-94dc-43ef-af58-9b31406dcdc9
status: experimental
description: Detects process execution patterns related to Griffon malware as reported by Kaspersky
references:
  - https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
  - attack.execution
  - detection.emerging_threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\local\temp\'
      - '//b /e:jscript'
      - '.txt'
  condition: selection
falsepositives:
  - Unlikely
level: critical`
)

func TestSyncElastAlert(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name           string
		Detections     []*model.Detection
		InitMock       func(*ElastAlertEngine, *mock.MockIOManager)
		ExpectedErr    error
		ExpectedErrMap map[string]string
	}{
		{
			Name: "Enable New Simple Rule",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Title:     "TEST",
					Severity:  model.SeverityMedium,
				},
			},
			InitMock: func(mod *ElastAlertEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{}, nil)
				// sigmaToElastAlert
				m.EXPECT().ExecCommand(gomock.Any()).Return([]byte("[sigma rule]"), 0, time.Duration(0), nil)
				// WriteFile when enabling
				m.EXPECT().WriteFile(SimpleRuleSID+".yml", []byte("detection_title: TEST\ndetection_public_id: "+SimpleRuleSID+"\nevent.module: sigma\nevent.dataset: sigma.alert\nevent.severity: 3\nsigma_level: medium\nalert:\n    - modules.so.securityonion-es.SecurityOnionESAlerter\nindex: .ds-logs-*\nname: TEST -- "+SimpleRuleSID+"\nrealert:\n    seconds: 0\ntype: any\nfilter:\n    - eql: '[sigma rule]'\n"), fs.FileMode(0644)).Return(nil)
			},
		},
		{
			Name: "Disable Simple Rule",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					IsEnabled: false,
				},
			},
			InitMock: func(mod *ElastAlertEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				filename := SimpleRuleSID + ".yml"
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{
					&handmock.MockDirEntry{
						Filename: filename,
					},
					&handmock.MockDirEntry{
						Filename: "ignored_dir",
						Dir:      true,
					},
					&handmock.MockDirEntry{
						Filename: "ignored.txt",
					},
				}, nil)
				// DeleteFile when disabling
				m.EXPECT().DeleteFile(filename).Return(nil)
			},
		},
		{
			Name: "Enable Rule w/Override",
			Detections: []*model.Detection{
				{
					PublicID:  SimpleRuleSID,
					Content:   SimpleRule,
					IsEnabled: true,
					Title:     "TEST",
					Severity:  model.SeverityMedium,
					Overrides: []*model.Override{
						{
							Type:      model.OverrideTypeCustomFilter,
							IsEnabled: false,
							OverrideParameters: model.OverrideParameters{
								CustomFilter: util.Ptr(`sofilter_users:
	user.name: SA_ITOPS
sofilter_hosts:
	host.name|contains:
		- devops
		- sysadmin`),
							},
						},
					},
				},
			},
			InitMock: func(mod *ElastAlertEngine, m *mock.MockIOManager) {
				// IndexExistingRules
				m.EXPECT().ReadDir(mod.elastAlertRulesFolder).Return([]fs.DirEntry{}, nil)
				// sigmaToElastAlert
				m.EXPECT().ExecCommand(gomock.Any()).Return([]byte(`any where process.command_line:"*\\local\\temp\\*" and process.command_line:"*//b /e:jscript*" and process.command_line:"*.txt*"`), 0, time.Duration(0), nil)
				// WriteFile when enabling
				m.EXPECT().WriteFile(SimpleRuleSID+".yml", []byte("detection_title: TEST\ndetection_public_id: "+SimpleRuleSID+"\nevent.module: sigma\nevent.dataset: sigma.alert\nevent.severity: 3\nsigma_level: medium\nalert:\n    - modules.so.securityonion-es.SecurityOnionESAlerter\nindex: .ds-logs-*\nname: TEST -- "+SimpleRuleSID+"\nrealert:\n    seconds: 0\ntype: any\nfilter:\n    - eql: any where process.command_line:\"*\\\\local\\\\temp\\\\*\" and process.command_line:\"*//b /e:jscript*\" and process.command_line:\"*.txt*\"\n"), fs.FileMode(0644)).Return(nil)
			},
		},
	}

	ctx := context.Background()

	for _, test := range table {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := mock.NewMockIOManager(ctrl)

			mod := NewElastAlertEngine(&server.Server{
				DetectionEngines: map[model.EngineName]server.DetectionEngine{},
			})

			mod.IOManager = mockIO
			mod.srv.DetectionEngines[model.EngineNameElastAlert] = mod

			if test.InitMock != nil {
				test.InitMock(mod, mockIO)
			}

			errMap, err := mod.SyncLocalDetections(ctx, test.Detections)

			assert.Equal(t, test.ExpectedErr, err)
			assert.Equal(t, test.ExpectedErrMap, errMap)
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
			Input:            SimpleRule,
			ExpectedTitle:    "Griffon Malware Attack Pattern",
			ExpectedPublicID: SimpleRuleSID,
			ExpectedSeverity: model.SeverityCritical,
		},
		{
			Name:        "No Public Id",
			Input:       SimpleRuleNoId,
			ExpectedErr: util.Ptr("missing required fields: id"),
		},
		{
			Name:             "Minimal Extracted Values, No Error",
			Input:            SimpleRuleNoExtract,
			ExpectedTitle:    "Required",
			ExpectedPublicID: "00000000-0000-0000-0000-000000000000",
			ExpectedSeverity: model.SeverityUnknown,
		},
	}

	eng := &ElastAlertEngine{}

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

func TestGetDeployedPublicIds(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	path := "path"

	iom.EXPECT().ReadDir(path).Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "00000000-0000-0000-0000-000000000000.yml",
		},
		&handmock.MockDirEntry{
			Filename: "11111111-1111-1111-1111-111111111111.yaml",
		},
		&handmock.MockDirEntry{
			Filename: "ignored_dir",
			Dir:      true,
		},
		&handmock.MockDirEntry{
			Filename: "ignored.txt",
		},
	}, nil)

	eng := &ElastAlertEngine{
		elastAlertRulesFolder: path,
		IOManager:             iom,
	}

	ids, err := eng.getDeployedPublicIds()
	assert.NoError(t, err)

	assert.Len(t, ids, 2)
	assert.Contains(t, ids, "00000000-0000-0000-0000-000000000000")
	assert.Contains(t, ids, "11111111-1111-1111-1111-111111111111")
}

func TestSyncWriteNoReadFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "123").Return(nil, errors.New("Object not found"))

	wnr := util.Ptr("123")

	eng := &ElastAlertEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		writeNoRead: wnr,
	}

	logger := log.WithField("detectionEngine", "test-elastalert")

	err := eng.Sync(logger, false)
	assert.Equal(t, detections.ErrSyncFailed, err)
	assert.Equal(t, wnr, eng.writeNoRead)
}

func TestSyncIncrementalNoChanges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	buf := bytes.NewBuffer([]byte{})

	writer := zip.NewWriter(buf)
	sr, err := writer.Create("rules/simple_rule.yml")
	assert.NoError(t, err)

	_, err = sr.Write([]byte(SimpleRule))
	assert.NoError(t, err)

	assert.NoError(t, writer.Close())

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)

	eng := &ElastAlertEngine{
		srv: &server.Server{
			Detectionstore: detStore,
		},
		isRunning:                     true,
		sigmaPipelineFinal:            "sigmaPipelineFinal",
		sigmaPipelineSO:               "sigmaPipelineSO",
		sigmaPipelinesFingerprintFile: "sigmaPipelinesFingerprintFile",
		sigmaRulePackages:             []string{"core+"},
		sigmaPackageDownloadTemplate:  "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_%s.zip",
		reposFolder:                   "repos",
		rulesFingerprintFile:          "rulesFingerprintFile",
		elastAlertRulesFolder:         "elastAlertRulesFolder",
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

	logger := log.WithField("detectionEngine", "test-elastalert")

	// checkSigmaPipelines
	iom.EXPECT().ReadFile("sigmaPipelineFinal").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelineSO").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelinesFingerprintFile").Return([]byte("3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7-3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"), nil)
	// downloadSigmaPackages
	iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(buf),
	}, nil)
	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(false, false, false)
	// check for changes before sync
	iom.EXPECT().ReadFile("rulesFingerprintFile").Return([]byte(`{"core+": "c6OTI9nTQxGEeeNkSZZB9+OESMNvfMXrb+XLtMiVhf0="}`), nil)
	// WriteStateFile
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
	}, nil) // getDeployedPublicIds
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: nil,
	}, nil)

	err = eng.Sync(logger, false)
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

	buf := bytes.NewBuffer([]byte{})

	writer := zip.NewWriter(buf)
	sr, err := writer.Create("rules/simple_rule.yml")
	assert.NoError(t, err)

	_, err = sr.Write([]byte(SimpleRule))
	assert.NoError(t, err)

	assert.NoError(t, writer.Close())

	detStore := servermock.NewMockDetectionstore(ctrl)
	iom := mock.NewMockIOManager(ctrl)
	bim := servermock.NewMockBulkIndexer(ctrl)
	auditm := servermock.NewMockBulkIndexer(ctrl)

	eng := &ElastAlertEngine{
		srv: &server.Server{
			Context:        context.Background(),
			Detectionstore: detStore,
		},
		isRunning:                     true,
		sigmaPipelineFinal:            "sigmaPipelineFinal",
		sigmaPipelineSO:               "sigmaPipelineSO",
		sigmaPipelinesFingerprintFile: "sigmaPipelinesFingerprintFile",
		sigmaRulePackages:             []string{"core+"},
		sigmaPackageDownloadTemplate:  "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_%s.zip",
		reposFolder:                   "repos",
		rulesFingerprintFile:          "rulesFingerprintFile",
		elastAlertRulesFolder:         "elastAlertRulesFolder",
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

	logger := log.WithField("detectionEngine", "test-elastalert")

	workItems := []esutil.BulkIndexerItem{}
	auditItems := []esutil.BulkIndexerItem{}

	// checkSigmaPipelines
	iom.EXPECT().ReadFile("sigmaPipelineFinal").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelineSO").Return([]byte("data"), nil)
	iom.EXPECT().ReadFile("sigmaPipelinesFingerprintFile").Return([]byte("a different hash"), nil)
	// downloadSigmaPackages
	iom.EXPECT().MakeRequest(gomock.Any()).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(buf),
	}, nil)
	// UpdateRepos
	iom.EXPECT().ReadDir("repos").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: "repo",
			Dir:      true,
		},
	}, nil)
	iom.EXPECT().PullRepo(gomock.Any(), "repos/repo", nil).Return(false, false, false)
	// parseRepoRules
	iom.EXPECT().WalkDir("repos/repo", gomock.Any()).DoAndReturn(func(path string, fn fs.WalkDirFunc) error {
		files := []fs.DirEntry{
			&handmock.MockDirEntry{
				Filename: "rules/123.yml",
			},
			&handmock.MockDirEntry{
				Filename: "rules/456.yml",
			},
		}

		for _, file := range files {
			err := fn(file.Name(), file, nil)
			assert.NoError(t, err)
		}

		return nil
	})
	iom.EXPECT().ReadFile("rules/123.yml").Return([]byte(SimpleRule), nil)
	iom.EXPECT().ReadFile("rules/456.yml").Return([]byte(SimpleRule2), nil)
	// syncCommunityDetections
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
		&handmock.MockDirEntry{
			Filename: "00000000-0000-0000-0000-000000000000.yml",
		},
	}, nil) // IndexExistingRules
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: {
			Auditable: model.Auditable{
				Id:         "abc",
				CreateTime: util.Ptr(time.Now()),
			},
			PublicID:  SimpleRuleSID,
			IsEnabled: true,
		},
		"00000000-0000-0000-0000-000000000000": {
			Auditable: model.Auditable{
				Id: "deleteme",
			},
			PublicID: "00000000-0000-0000-0000-000000000000",
		},
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
	iom.EXPECT().DeleteFile("elastAlertRulesFolder/00000000-0000-0000-0000-000000000000.yml").Return(nil)
	bim.EXPECT().Close(gomock.Any()).Return(nil)
	bim.EXPECT().Stats().Return(esutil.BulkIndexerStats{})
	iom.EXPECT().ExecCommand(gomock.Any()).Return([]byte("\n[query]"), 0, time.Duration(time.Second), nil) // sigmaToElastAlert
	iom.EXPECT().WriteFile("elastAlertRulesFolder/bcc6f179-11cd-4111-a9a6-0fab68515cf7.yml", gomock.Any(), fs.FileMode(0644)).Return(nil)
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
	// SyncLocalDetections
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRule2SID: {
			PublicID: SimpleRule2SID,
		},
	}, nil)
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRule2SID + ".yml",
		},
	}, nil) // IndexExistingRules
	iom.EXPECT().DeleteFile("elastAlertRulesFolder/" + SimpleRule2SID + ".yml").Return(nil)
	iom.EXPECT().WriteFile("stateFilePath", gomock.Any(), fs.FileMode(0644)).Return(nil)        // WriteStateFile
	iom.EXPECT().WriteFile("rulesFingerprintFile", gomock.Any(), fs.FileMode(0644)).Return(nil) // WriteFingerprintFile
	// regenNeeded
	iom.EXPECT().WriteFile("sigmaPipelinesFingerprintFile", gomock.Any(), fs.FileMode(0644)).Return(nil)
	// IntegrityCheck
	iom.EXPECT().ReadDir("elastAlertRulesFolder").Return([]fs.DirEntry{
		&handmock.MockDirEntry{
			Filename: SimpleRuleSID + ".yml",
		},
	}, nil) // getDeployedPublicIds
	detStore.EXPECT().GetAllDetections(gomock.Any(), gomock.Any()).Return(map[string]*model.Detection{
		SimpleRuleSID: nil,
	}, nil)

	err = eng.Sync(logger, true)
	assert.NoError(t, err)

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
			PublicId:         "bd82a1a6-7bac-401e-afcf-5adf07c0c035",
			ExpectedAiFields: false,
		},
		{
			Name:              "Data, Unreviewed",
			PublicId:          "67ee455d-099f-4048-b021-43bb91af9298",
			Content:           "alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 67ee455d-099f-4048-b021-43bb91af9298",
			ExpectedReviewed:  false,
			ExpectedStale:     false,
		},
		{
			Name:              "Data, Reviewed",
			PublicId:          "83b3a29f-3009-4884-86c6-b6c3973788fa",
			Content:           "no-alert",
			ExpectedAiFields:  true,
			ExpectedAiSummary: "Summary for 83b3a29f-3009-4884-86c6-b6c3973788fa",
			ExpectedReviewed:  true,
			ExpectedStale:     true,
		},
	}

	e := ElastAlertEngine{
		showAiSummaries: true,
	}
	err := e.LoadAuxiliaryData([]*model.AiSummary{
		{
			PublicId:     "83b3a29f-3009-4884-86c6-b6c3973788fa",
			Summary:      "Summary for 83b3a29f-3009-4884-86c6-b6c3973788fa",
			Reviewed:     true,
			RuleBodyHash: "7ed21143076d0cca420653d4345baa2f",
		},
		{
			PublicId:     "67ee455d-099f-4048-b021-43bb91af9298",
			Summary:      "Summary for 67ee455d-099f-4048-b021-43bb91af9298",
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
