// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"
	"gopkg.in/yaml.v3"
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

	SigLangSigma    SigLanguage = "sigma"    // yaml
	SigLangSuricata SigLanguage = "suricata" // action, header, options
	SigLangYara     SigLanguage = "yara"     // meta, strings, condition

	SeverityUnknown       Severity = "unknown"
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"

	IDTypeUUID IDType = "uuid"
	IDTypeSID  IDType = "sid"

	EngineNameSuricata   EngineName = "suricata"
	EngineNameStrelka    EngineName = "strelka"
	EngineNameElastAlert EngineName = "elastalert"

	OverrideTypeSuppress     OverrideType = "suppress"
	OverrideTypeThreshold    OverrideType = "threshold"
	OverrideTypeModify       OverrideType = "modify"
	OverrideTypeCustomFilter OverrideType = "customFilter"

	LicenseDRL        = "DRL"
	LicenseCommercial = "Commercial"
	LicenseBSD        = "BSD"
	LicenseUnknown    = "Unknown"
)

var (
	EnginesByName = map[EngineName]*DetectionEngine{
		EngineNameSuricata: {
			Name:        string(EngineNameSuricata),
			IDType:      IDTypeSID,
			ScanType:    ScanTypePackets,
			SigLanguage: SigLangSuricata,
		},
		EngineNameStrelka: {
			Name:        string(EngineNameStrelka),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeFiles,
			SigLanguage: SigLangYara,
		},
		EngineNameElastAlert: {
			Name:        string(EngineNameElastAlert),
			IDType:      IDTypeUUID,
			ScanType:    ScanTypeElastic,
			SigLanguage: SigLangSigma,
		},
	}

	SupportedLanguages = map[SigLanguage]struct{}{
		SigLangSigma:    {},
		SigLangSuricata: {},
		SigLangYara:     {},
	}

	ErrUnsupportedEngine   = errors.New("unsupported engine")
	ErrInvalidOverrideType = errors.New("invalid override type")
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
	Category    string      `json:"category,omitempty"`
	Description string      `json:"description"`
	Content     string      `json:"content"`
	IsEnabled   bool        `json:"isEnabled"`
	IsReporting bool        `json:"isReporting"`
	IsCommunity bool        `json:"isCommunity"`
	Engine      EngineName  `json:"engine"`
	Language    SigLanguage `json:"language"`
	Overrides   []*Override `json:"overrides"` // Tuning
	Tags        []string    `json:"tags"`
	Ruleset     string      `json:"ruleset"`
	License     string      `json:"license"`

	// these are transient fields, not stored in the database
	PendingDelete bool `json:"-"`
	PersistChange bool `json:"-"`

	// elastalert - sigma only
	Product string `json:"product,omitempty"`
	Service string `json:"service,omitempty"`

	// AI Description fields
	*AiFields `json:",omitempty"`
}

type AiFields struct {
	AiSummary         string `json:"aiSummary"`
	AiSummaryReviewed bool   `json:"aiSummaryReviewed"`
	IsAiSummaryStale  bool   `json:"isSummaryStale"`
}

type DetectionComment struct {
	Auditable
	DetectionId string `json:"detectionId"`
	Value       string `json:"value"`
}

// Note: JSON tags are used when storing the object in ElasticSearch,
// YAML tags are used when storing the object in a YAML config file (Suricata).

type Override struct {
	Type               OverrideType `json:"type" yaml:"type"`
	IsEnabled          bool         `json:"isEnabled" yaml:"-"`
	Note               string       `json:"note" yaml:"-"`
	CreatedAt          time.Time    `json:"createdAt" yaml:"-"`
	UpdatedAt          time.Time    `json:"updatedAt" yaml:"-"`
	OverrideParameters `yaml:",inline"`
}

type OverrideParameters struct {
	// suricata
	Regex         *string `json:"regex,omitempty" yaml:"regex,omitempty"`        // modify
	Value         *string `json:"value,omitempty" yaml:"value,omitempty"`        // modify
	GenID         *int    `json:"-" yaml:"gen_id,omitempty"`                     // suppress, threshold
	ThresholdType *string `json:"thresholdType,omitempty" yaml:"type,omitempty"` // threshold
	Track         *string `json:"track,omitempty" yaml:"track,omitempty"`        // suppress, threshold
	IP            *string `json:"ip,omitempty" yaml:"ip,omitempty"`              // suppress
	Count         *int    `json:"count,omitempty" yaml:"count,omitempty"`        // threshold
	Seconds       *int    `json:"seconds,omitempty" yaml:"seconds,omitempty"`    // threshold

	// elastalert
	CustomFilter *string `json:"customFilter,omitempty" yaml:"-"` // customFilter
}

type OverrideNoteUpdate struct {
	Note string `json:"note"`
}

func (o Override) PrepareForSigma() (map[string]interface{}, error) {
	if o.CustomFilter == nil || !o.IsEnabled {
		return map[string]interface{}{}, nil
	}

	mid := map[string]interface{}{}
	out := map[string]interface{}{}

	filter := util.TabsToSpaces(*o.CustomFilter, 2)

	err := yaml.Unmarshal([]byte(filter), mid)

	for k, v := range mid {
		// does the property begin with sofilter?
		if !strings.HasPrefix(k, "sofilter") {
			// does the object already contain a property with the sofilter prefix?
			_, exists := out["sofilter_"+k]
			if exists {
				// keep appending numbers until there's no collision
				for i := 0; ; i++ {
					num := strconv.Itoa(i)
					_, exists = out["sofilter_"+k+num]
					if !exists {
						out["sofilter_"+k+num] = v
						break
					}
				}
			} else {
				// the property doesn't begin with sofilter, but adding it isn't a collsion
				out["sofilter_"+k] = v
			}
		} else {
			// the property begins with sofilter
			out[k] = v
		}
	}

	return out, err
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

	for _, o := range detect.Overrides {
		if err := o.Validate(detect.Engine); err != nil {
			return err
		}
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
			if o.IP == nil || o.Track == nil {
				return errors.New("missing required parameter(s)")
			}

			if o.Regex != nil ||
				o.Value != nil ||
				o.GenID != nil ||
				o.ThresholdType != nil ||
				o.Count != nil ||
				o.Seconds != nil ||
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

			*o.CustomFilter = util.TabsToSpaces(*o.CustomFilter, 2)
			fauxDoc := map[string]interface{}{}

			err := yaml.Unmarshal([]byte(*o.CustomFilter), fauxDoc)
			if err != nil {
				return fmt.Errorf("custom filter override has invalid YAML: %w", err)
			}
		default:
			return ErrInvalidOverrideType
		}
	} else {
		return ErrInvalidOverrideType
	}

	return nil
}

func (o *Override) Equal(other *Override) bool {
	if o == nil && other == nil {
		return true
	}

	if (o == nil || other == nil) ||
		(o.Type != other.Type) ||
		(o.IsEnabled != other.IsEnabled) ||
		(o.CreatedAt != other.CreatedAt) ||
		(o.UpdatedAt != other.UpdatedAt) {
		return false
	}

	result := false

	switch o.Type {
	case OverrideTypeSuppress:
		result = util.ComparePtrs(o.IP, other.IP) &&
			util.ComparePtrs(o.Track, other.Track)
	case OverrideTypeThreshold:
		result = util.ComparePtrs(o.ThresholdType, other.ThresholdType) &&
			util.ComparePtrs(o.Track, other.Track) &&
			util.ComparePtrs(o.Count, other.Count) &&
			util.ComparePtrs(o.Seconds, other.Seconds)
	case OverrideTypeModify:
		result = util.ComparePtrs(o.Regex, other.Regex) &&
			util.ComparePtrs(o.Value, other.Value)
	case OverrideTypeCustomFilter:
		result = util.ComparePtrs(o.CustomFilter, other.CustomFilter)
	}

	return result
}

type AuditInfo struct {
	DocId     string
	Op        string
	Detection *Detection
}

type AiSummary struct {
	PublicId     string
	Reviewed     bool   `yaml:"Reviewed"`
	Summary      string `yaml:"Summary"`
	RuleBodyHash string `yaml:"Rule-Body-Hash"`
}
