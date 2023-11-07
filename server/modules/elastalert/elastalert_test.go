// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
)

func TestElastAlertModule(t *testing.T) {
	srv := &server.Server{
		DetectionEngines: map[model.EngineName]server.DetectionEngine{},
	}
	mod := NewElastAlertEngine(srv)

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
	assert.Same(t, mod, srv.DetectionEngines[model.EngineNameElastAlert])
}

func TestParseSigmaPackages(t *testing.T) {
	t.Parallel()

	table := []struct {
		Name     string
		Input    string
		Expected []string
	}{
		{
			Name:     "Simple Sunny Day Path",
			Input:    "core",
			Expected: []string{"core"},
		},
		{
			Name:     "Multiple Packages",
			Input:    "core+\nemerging_threats",
			Expected: []string{"core+", "emerging_threats_addon"},
		},
		{
			Name:     "Rename (all => all_rules)",
			Input:    "all",
			Expected: []string{"all_rules"},
		},
		{
			Name:     "Rename (emerging_threats_addon => emerging_threats)",
			Input:    "emerging_threats",
			Expected: []string{"emerging_threats_addon"},
		},
		{
			Name:     "Normalize",
			Input:    "CoRe++\n",
			Expected: []string{"core++"},
		},
		{
			Name:     "Account For Nesting Packages",
			Input:    "core\ncore+\ncore++\nall_rules\nemerging_threats",
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

func TestSigmaToElastAlertSunnyDay(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<eql>"))

		callCount++
	}))
	defer srv.Close()

	engine := ElastAlertEngine{
		sigconverterUrl:       srv.URL,
		sigmaConversionTarget: "eql",
	}

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "00000000-0000-0000-0000-000000000000",
		},
		Content:  "totally good sigma",
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	wrappedRule, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.NoError(t, err)

	expected := `play_title: Test Detection
play_id: 00000000-0000-0000-0000-000000000000
event.module: elastalert
event.dataset: elastalert.alert
event.severity: 4
rule.category: TBD
sigma_level: high
alert:
    - modules.so.playbook-es.PlaybookESAlerter
index: .ds-logs-*
name: Test Detection - 00000000-0000-0000-0000-000000000000
type: any
filter:
    - eql: <eql>
play_url: play_url
kibana_pivot: kibana_pivot
soc_pivot: soc_pivot
`
	assert.YAMLEq(t, expected, wrappedRule)
	assert.Equal(t, 1, callCount)
}

func TestSigmaToElastAlertError(t *testing.T) {
	callCount := 0
	msg := "something went wrong"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Error: " + msg))

		callCount++
	}))
	defer srv.Close()

	engine := ElastAlertEngine{
		sigconverterUrl:       srv.URL,
		sigmaConversionTarget: "eql",
	}

	det := &model.Detection{
		Auditable: model.Auditable{
			Id: "00000000-0000-0000-0000-000000000000",
		},
		Content:  "totally good sigma",
		Title:    "Test Detection",
		Severity: model.SeverityHigh,
	}

	wrappedRule, err := engine.sigmaToElastAlert(context.Background(), det)
	assert.Equal(t, "", wrappedRule)
	assert.Error(t, err)
	assert.ErrorContains(t, err, msg)
}

func TestParseRules(t *testing.T) {
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
       event.module: "zeek"
    condition: "filter"
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

	err = writer.Close()
	assert.NoError(t, err)

	pkgZips := map[string][]byte{
		"all_rules": buf.Bytes(),
	}

	engine := ElastAlertEngine{}

	expected := &model.Detection{
		PublicID:    "00000000-0000-0000-0000-00000000",
		Title:       "Always Alert",
		Severity:    model.SeverityHigh,
		Content:     data,
		IsCommunity: true,
		Engine:      model.EngineNameElastAlert,
	}

	dets, errMap := engine.parseRules(pkgZips)
	assert.NotNil(t, errMap)
	assert.Error(t, errMap["rules/bad.yml"])
	assert.Len(t, dets, 1)
	assert.Equal(t, expected, dets[0])
}

func TestDownloadSigmaPackages(t *testing.T) {
	t.Parallel()

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.RequestURI == "/fake.zip" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))

	}))
	defer srv.Close()

	pkgs := []string{"core", "core+", "core++", "emerging_threats_addon", "all_rules", "fake"}

	engine := ElastAlertEngine{
		sigmaRulePackages:            pkgs,
		sigmaPackageDownloadTemplate: srv.URL + "/%s.zip",
	}

	pkgZips, errMap := engine.downloadSigmaPackages(context.Background())
	assert.NotNil(t, errMap)
	assert.Error(t, errMap["fake"])
	assert.Len(t, pkgZips, len(pkgs)-1)

	for _, pkg := range pkgs[:len(pkgs)-1] {
		assert.Equal(t, []byte("data"), pkgZips[pkg])
	}

	assert.Equal(t, len(pkgs), callCount)
}
