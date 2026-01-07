// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/stretchr/testify/assert"
)

func TestDetectionOverrideValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name          string
		Detect        *Detection
		ExpectedError *string
	}{
		{
			Name: "Valid Suricata Detection",
			Detect: &Detection{
				Engine: EngineNameSuricata,
			},
		},
		{
			Name: "Valid ElastAlert Detection",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
			},
		},
		{
			Name: "Valid Strelka Detection",
			Detect: &Detection{
				Engine: EngineNameStrelka,
			},
		},
		{
			Name: "Invalid Detection Engine",
			Detect: &Detection{
				Engine: "invalid",
			},
			ExpectedError: util.Ptr("unsupported engine"),
		},
		{
			Name: "Valid Suricata Override",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeModify,
						OverrideParameters: OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("0.0.0.0"),
							Track: util.Ptr("by_src"),
						},
					},
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
		},
		{
			Name: "Invalid Suricata Modify Override (Missing)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type:               OverrideTypeModify,
						OverrideParameters: OverrideParameters{},
					},
				},
			},
			ExpectedError: util.Ptr("missing required parameter(s)"),
		},
		{
			Name: "Invalid Suricata Modify Override (Extra)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeModify,
						OverrideParameters: OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
							Count: util.Ptr(1),
						},
					},
				},
			},
			ExpectedError: util.Ptr("unnecessary fields in override"),
		},
		{
			Name: "Invalid Suricata Modify Override (Invalid Regex)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeModify,
						OverrideParameters: OverrideParameters{
							Regex: util.Ptr("[invalid"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid regex pattern"),
		},
		{
			Name: "Invalid Suricata Suppress Override (Missing)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type:               OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{},
					},
				},
			},
			ExpectedError: util.Ptr("missing required parameter(s)"),
		},
		{
			Name: "Invalid Suricata Suppress Override (Extra)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("0.0.0.0"),
							Track: util.Ptr("by_src"),
							Count: util.Ptr(1),
						},
					},
				},
			},
			ExpectedError: util.Ptr("unnecessary fields in override"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Missing)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type:               OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{},
					},
				},
			},
			ExpectedError: util.Ptr("missing required parameter(s)"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Extra)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(60),
							Regex:         util.Ptr(".*"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("unnecessary fields in override"),
		},
		// Suppress validation tests
		{
			Name: "Invalid Suricata Suppress Override (Invalid Track - by_both)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("192.168.1.1/32"),
							Track: util.Ptr("by_both"), // by_both is only valid for threshold
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid track value"),
		},
		{
			Name: "Invalid Suricata Suppress Override (Invalid Track - garbage)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("192.168.1.1/32"),
							Track: util.Ptr("invalid"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid track value"),
		},
		{
			Name: "Invalid Suricata Suppress Override (Invalid IP - malformed)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("not-an-ip"),
							Track: util.Ptr("by_src"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid IP address"),
		},
		{
			Name: "Invalid Suricata Suppress Override (Invalid IP - bad CIDR)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("192.168.1.0/99"),
							Track: util.Ptr("by_src"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid CIDR"),
		},
		{
			Name: "Valid Suricata Suppress Override (Plain IP)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("192.168.1.1"),
							Track: util.Ptr("by_src"),
						},
					},
				},
			},
		},
		{
			Name: "Valid Suricata Suppress Override (CIDR)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("192.168.1.0/24"),
							Track: util.Ptr("by_dst"),
						},
					},
				},
			},
		},
		{
			Name: "Valid Suricata Suppress Override (Variable)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("$HOME_NET"),
							Track: util.Ptr("by_either"),
						},
					},
				},
			},
		},
		{
			Name: "Valid Suricata Suppress Override (Bracketed List)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
						OverrideParameters: OverrideParameters{
							IP:    util.Ptr("[192.168.1.1,10.0.0.0/8]"),
							Track: util.Ptr("by_src"),
						},
					},
				},
			},
		},
		// Threshold validation tests
		{
			Name: "Invalid Suricata Threshold Override (Invalid ThresholdType)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("suppress"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid thresholdType value"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Invalid Track - by_either)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_either"), // by_either is only valid for suppress
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid track value"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Count zero)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(0),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid count value"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Count negative)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(-1),
							Seconds:       util.Ptr(60),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid count value"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Seconds zero)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(0),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid seconds value"),
		},
		{
			Name: "Invalid Suricata Threshold Override (Seconds negative)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("limit"),
							Track:         util.Ptr("by_src"),
							Count:         util.Ptr(1),
							Seconds:       util.Ptr(-60),
						},
					},
				},
			},
			ExpectedError: util.Ptr("invalid seconds value"),
		},
		{
			Name: "Valid Suricata Threshold Override (by_both track)",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{
						Type: OverrideTypeThreshold,
						OverrideParameters: OverrideParameters{
							ThresholdType: util.Ptr("both"),
							Track:         util.Ptr("by_both"),
							Count:         util.Ptr(5),
							Seconds:       util.Ptr(120),
						},
					},
				},
			},
		},
		{
			Name: "Valid ElastAlert Override",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
				Overrides: []*Override{
					{
						Type: OverrideTypeCustomFilter,
						OverrideParameters: OverrideParameters{
							CustomFilter: util.Ptr("k: v"),
						},
					},
				},
			},
		},
		{
			Name: "Invalid ElastAlert Custom Filter (Missing)",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
				Overrides: []*Override{
					{
						Type:               OverrideTypeCustomFilter,
						OverrideParameters: OverrideParameters{},
					},
				},
			},
			ExpectedError: util.Ptr("missing required parameter(s)"),
		},
		{
			Name: "Invalid ElastAlert CustomFilter (Extra)",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
				Overrides: []*Override{
					{
						Type: OverrideTypeCustomFilter,
						OverrideParameters: OverrideParameters{
							CustomFilter: util.Ptr("k: v"),
							Count:        util.Ptr(1),
						},
					},
				},
			},
			ExpectedError: util.Ptr("unnecessary fields in override"),
		},
		{
			Name: "Invalid ElastAlert CustomFilter (Bad YAML)",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
				Overrides: []*Override{
					{
						Type: OverrideTypeCustomFilter,
						OverrideParameters: OverrideParameters{
							CustomFilter: util.Ptr("not valid yaml"),
						},
					},
				},
			},
			ExpectedError: util.Ptr("custom filter override has invalid YAML"),
		},
		{
			Name: "Invalid ElastAlert Override Type",
			Detect: &Detection{
				Engine: EngineNameElastAlert,
				Overrides: []*Override{
					{
						Type: OverrideTypeSuppress,
					},
				},
			},
			ExpectedError: util.Ptr("invalid override type"),
		},
		{
			Name: "Invalid Strelka Override Type",
			Detect: &Detection{
				Engine: EngineNameStrelka,
				Overrides: []*Override{
					{
						Type: OverrideTypeModify,
					},
				},
			},
			ExpectedError: util.Ptr("invalid override type"),
		},
		{
			Name: "Invalid Override Type",
			Detect: &Detection{
				Engine: EngineNameSuricata,
				Overrides: []*Override{
					{},
				},
			},
			ExpectedError: util.Ptr("override type is required"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			err := test.Detect.Validate()
			if test.ExpectedError != nil {
				assert.Contains(t, err.Error(), *test.ExpectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOverrideEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name     string
		Engine   EngineName
		One      *Override
		Two      *Override
		Expected bool
	}{
		{
			Name:     "Both Nil",
			Expected: true,
		},
		{
			Name:   "One Nil",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".*"),
					Value: util.Ptr("test"),
				},
			},
		},
		{
			Name:   "Unequal Meta",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".*"),
					Value: util.Ptr("test"),
				},
			},
			Two: &Override{
				Type: OverrideTypeSuppress,
				OverrideParameters: OverrideParameters{
					IP:    util.Ptr("0.0.0.0"),
					Track: util.Ptr("by_src"),
				},
			},
			Expected: false,
		},
		{
			Name:   "Equal Modify",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".*"),
					Value: util.Ptr("test"),
				},
			},
			Two: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".*"),
					Value: util.Ptr("test"),
				},
			},
			Expected: true,
		},
		{
			Name:   "Unequal Modify",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".+"),
					Value: util.Ptr("Hello World"),
				},
			},
			Two: &Override{
				Type: OverrideTypeModify,
				OverrideParameters: OverrideParameters{
					Regex: util.Ptr(".*"),
					Value: util.Ptr("test"),
				},
			},
		},
		{
			Name:   "Equal Suppress",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeSuppress,
				OverrideParameters: OverrideParameters{
					IP:    util.Ptr("0.0.0.0"),
					Track: util.Ptr("by_src"),
				},
			},
			Two: &Override{
				Type: OverrideTypeSuppress,
				OverrideParameters: OverrideParameters{
					IP:    util.Ptr("0.0.0.0"),
					Track: util.Ptr("by_src"),
				},
			},
			Expected: true,
		},
		{
			Name:   "Equal Suppress",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeSuppress,
				OverrideParameters: OverrideParameters{
					IP:    util.Ptr("0.0.0.0"),
					Track: util.Ptr("by_src"),
				},
			},
			Two: &Override{
				Type: OverrideTypeSuppress,
				OverrideParameters: OverrideParameters{
					IP:    util.Ptr("127.0.0.1"),
					Track: util.Ptr("by_either"),
				},
			},
		},
		{
			Name:   "Equal Threshold",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeThreshold,
				OverrideParameters: OverrideParameters{
					ThresholdType: util.Ptr("limit"),
					Track:         util.Ptr("by_src"),
					Count:         util.Ptr(3),
					Seconds:       util.Ptr(60),
				},
			},
			Two: &Override{
				Type: OverrideTypeThreshold,
				OverrideParameters: OverrideParameters{
					ThresholdType: util.Ptr("limit"),
					Track:         util.Ptr("by_src"),
					Count:         util.Ptr(3),
					Seconds:       util.Ptr(60),
				},
			},
			Expected: true,
		},
		{
			Name:   "Unequal Threshold",
			Engine: EngineNameSuricata,
			One: &Override{
				Type: OverrideTypeThreshold,
				OverrideParameters: OverrideParameters{
					ThresholdType: util.Ptr("both"),
					Track:         util.Ptr("by_src"),
					Count:         util.Ptr(1),
					Seconds:       util.Ptr(180),
				},
			},
			Two: &Override{
				Type: OverrideTypeThreshold,
				OverrideParameters: OverrideParameters{
					ThresholdType: util.Ptr("limit"),
					Track:         util.Ptr("by_dst"),
					Count:         util.Ptr(3),
					Seconds:       util.Ptr(60),
				},
			},
		},
		{
			Name:   "Equal Custom Filter",
			Engine: EngineNameElastAlert,
			One: &Override{
				Type: OverrideTypeCustomFilter,
				OverrideParameters: OverrideParameters{
					CustomFilter: util.Ptr("k: v"),
				},
			},
			Two: &Override{
				Type: OverrideTypeCustomFilter,
				OverrideParameters: OverrideParameters{
					CustomFilter: util.Ptr("k: v"),
				},
			},
			Expected: true,
		},
		{
			Name:   "Unequal Custom Filter",
			Engine: EngineNameElastAlert,
			One: &Override{
				Type: OverrideTypeCustomFilter,
				OverrideParameters: OverrideParameters{
					CustomFilter: util.Ptr("k: v"),
				},
			},
			Two: &Override{
				Type: OverrideTypeCustomFilter,
				OverrideParameters: OverrideParameters{
					CustomFilter: util.Ptr("k2: v2"),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			if test.One != nil {
				err := test.One.Validate(test.Engine)
				assert.NoError(t, err)
			}

			if test.Two != nil {
				err := test.Two.Validate(test.Engine)
				assert.NoError(t, err)
			}

			actual := test.One.Equal(test.Two)
			assert.Equal(t, test.Expected, actual)

			actual = test.Two.Equal(test.One)
			assert.Equal(t, test.Expected, actual)
		})
	}
}
