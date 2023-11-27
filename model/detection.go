// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"strings"
	"time"
)

type ScanType string
type SigLanguage string
type Severity string
type IDType string
type EngineName string
type OverrideType string

const (
	ScanTypeFiles           ScanType = "files"
	ScanTypePackets         ScanType = "packets"
	ScanTypePacketsAndFiles ScanType = "files,packets"
	ScanTypeElastic         ScanType = "elastic"

	SigLangElastic  SigLanguage = "elastic"  // yaml
	SigLangSigma    SigLanguage = "sigma"    // yaml
	SigLangSuricata SigLanguage = "suricata" // action, header, options
	SigLangYara     SigLanguage = "yara"
	SigLangZeek     SigLanguage = "zeek"

	SeverityUnknown       Severity = "unknown"
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"

	IDTypeUUID IDType = "uuid"
	IDTypeSID  IDType = "sid"

	EngineNameSuricata   EngineName = "suricata"
	EngineNameYara       EngineName = "yara"
	EngineNameElastAlert EngineName = "elastalert"

	OverrideTypeSuppress     OverrideType = "suppress"
	OverrideTypeThreshold    OverrideType = "threshold"
	OverrideTypeModify       OverrideType = "modify"
	OverrideTypeCustomFilter OverrideType = "customFilter"
)

var (
	EnginesByName = map[EngineName]*DetectionEngine{
		EngineNameSuricata: {
			Name:        string(EngineNameSuricata),
			IDType:      IDTypeSID,
			ScanType:    ScanTypePackets,
			SigLanguage: SigLangSuricata,
		},
		EngineNameYara: {
			Name:        string(EngineNameYara),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeFiles,
			SigLanguage: SigLangYara,
		},
		EngineNameElastAlert: {
			Name:        string(EngineNameElastAlert),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeElastic,
			SigLanguage: SigLangElastic,
		},
	}

	ErrUnsupportedEngine = errors.New("unsupported engine")
)

type DetectionEngine struct {
	Name        string      `json:"name"`
	IDType      IDType      `json:"idType"`
	ScanType    ScanType    `json:"scanType"`
	SigLanguage SigLanguage `json:"sigLanguage"`
}

type Detection struct {
	Auditable
	PublicID    string      `json:"publicId"`
	Title       string      `json:"title"`
	Severity    Severity    `json:"severity"`
	Author      string      `json:"author"`
	Description string      `json:"description"`
	Content     string      `json:"content"`
	IsEnabled   bool        `json:"isEnabled"`
	IsReporting bool        `json:"isReporting"`
	IsCommunity bool        `json:"isCommunity"`
	Note        string      `json:"note"`
	Engine      EngineName  `json:"engine"`
	Overrides   []*Override `json:"overrides"` // Tuning
}

// Note: JSON tags are used when storing the object in ElasticSearch,
// YAML tags are used when storing the object in a YAML config file (Suricata).

type Override struct {
	Type               OverrideType `json:"type" yaml:"type"`
	IsEnabled          bool         `json:"isEnabled" yaml:"-"`
	CreatedAt          time.Time    `json:"createdAt" yaml:"-"`
	UpdatedAt          time.Time    `json:"updatedAt" yaml:"-"`
	OverrideParameters `yaml:",inline"`
}

type OverrideParameters struct {
	// suricata
	Regex         *string `json:"regex,omitempty" yaml:"regex,omitempty"`                 // modify
	Value         *string `json:"value,omitempty" yaml:"value,omitempty"`                 // modify
	GenID         *int    `json:"-" yaml:"genId,omitempty"`                               // suppress, threshold
	ThresholdType *string `json:"thresholdType,omitempty" yaml:"thresholdType,omitempty"` // threshold
	Track         *string `json:"track,omitempty" yaml:"track,omitempty"`                 // suppress, threshold
	IP            *string `json:"ip,omitempty" yaml:"ip,omitempty"`                       // suppress
	Count         *int    `json:"count,omitempty" yaml:"count,omitempty"`                 // threshold
	Seconds       *int    `json:"seconds,omitempty" yaml:"seconds,omitempty"`             // threshold

	// elastalert
	CustomFilter *string `json:"customFilter,omitempty" yaml:"customFilter,omitempty"` // modify
}

func (o Override) MarshalYAML() (interface{}, error) {
	out := map[string]*OverrideParameters{
		string(o.Type): &o.OverrideParameters,
	}

	return out, nil
}

func (o *Override) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m map[string]*OverrideParameters
	if err := unmarshal(&m); err != nil {
		return err
	}

	for k, v := range m {
		o.Type = OverrideType(k)
		o.IsEnabled = true
		o.OverrideParameters = *v
	}

	return nil
}

func (detect *Detection) Validate() error {
	detect.Engine = EngineName(strings.ToLower(string(detect.Engine)))
	_, engIsSupported := EnginesByName[detect.Engine]
	if !engIsSupported {
		return ErrUnsupportedEngine
	}

	customs := 0

	for _, o := range detect.Overrides {
		if err := o.Validate(detect.Engine); err != nil {
			return err
		}

		if o.Type == OverrideTypeCustomFilter {
			customs++
		}
	}

	if detect.Engine == EngineNameElastAlert && customs > 1 {
		return errors.New("only one custom filter override is allowed per ElastAlert detection")
	}

	return nil
}

func (o *Override) Validate(engine EngineName) error {
	if o.Type == "" {
		return errors.New("override type is required")
	}

	if engine == EngineNameSuricata {
		switch o.Type {
		case OverrideTypeModify:
			if o.Regex == nil || o.Value == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.GenID != nil ||
				o.ThresholdType != nil ||
				o.Track != nil ||
				o.Count != nil ||
				o.Seconds != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}
		case OverrideTypeSuppress:
			if o.Value == nil || o.Track == nil || o.Count == nil || o.Seconds == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.GenID != nil ||
				o.ThresholdType != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}
		case OverrideTypeThreshold:
			if o.ThresholdType == nil || o.Track == nil || o.Count == nil || o.Seconds == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.GenID != nil ||
				o.CustomFilter != nil {
				return errors.New("unnecessary fields in override")
			}
		}

	} else if engine == EngineNameElastAlert {
		switch o.Type {
		case OverrideTypeCustomFilter:
			if o.CustomFilter == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.GenID != nil ||
				o.ThresholdType != nil ||
				o.Track != nil ||
				o.Count != nil ||
				o.Seconds != nil {
				return errors.New("unnecessary fields in override")
			}
		}
	}

	return nil
}
