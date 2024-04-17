package model

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/tj/assert"
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
							GenID: util.Ptr(1),
						},
					},
				},
			},
			ExpectedError: util.Ptr("unnecessary fields in override"),
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
							GenID: util.Ptr(1),
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
							GenID:        util.Ptr(1),
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
