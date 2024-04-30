// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"gopkg.in/yaml.v3"
)

type SigmaStatus string

const (
	SigmaStatusStable       SigmaStatus = "stable"
	SigmaStatusTest         SigmaStatus = "test"
	SigmaStatusExperimental SigmaStatus = "experimental"
	SigmaStatusDeprecated   SigmaStatus = "deprecated"
	SigmaStatusUnsupported  SigmaStatus = "unsupported"
)

type SigmaLevel string

const (
	SigmaLevelUnknown       SigmaLevel = "unknown"
	SigmaLevelInformational SigmaLevel = "informational"
	SigmaLevelLow           SigmaLevel = "low"
	SigmaLevelMedium        SigmaLevel = "medium"
	SigmaLevelHigh          SigmaLevel = "high"
	SigmaLevelCritical      SigmaLevel = "critical"
)

type RelatedRuleType string

const (
	RelatedRuleTypeDerived   RelatedRuleType = "derived"
	RelatedRuleTypeObsoletes RelatedRuleType = "obsoletes"
	RelatedRuleTypeMerged    RelatedRuleType = "merged"
	RelatedRuleTypeRenamed   RelatedRuleType = "renamed"
	RelatedRuleTypeSimilar   RelatedRuleType = "similar"
)

type SigmaRule struct {
	Title          string                 `yaml:"title"`
	ID             *string                `yaml:"id"`
	LogSource      LogSource              `yaml:"logsource"`
	Detection      SigmaDetection         `yaml:"detection"`
	Status         *SigmaStatus           `yaml:"status"`
	Description    *string                `yaml:"description"`
	License        *string                `yaml:"license"`
	Reference      []string               `yaml:"reference"`
	Related        []*RelatedRule         `yaml:"related"`
	Author         *string                `yaml:"author"`
	Date           *string                `yaml:"date"`
	Modified       *string                `yaml:"modified"`
	Fields         []string               `yaml:"fields"`
	FalsePositives OneOrMore[string]      `yaml:"falsepositives"`
	Level          *SigmaLevel            `yaml:"level"`
	Rest           map[string]interface{} `yaml:",inline"`
}

type LogSource struct {
	Category   *string `yaml:"category"`
	Product    *string `yaml:"product"`
	Service    *string `yaml:"service"`
	Definition *string `yaml:"definition"`
}

type SigmaDetection struct {
	Condition OneOrMore[string]      `yaml:"condition"`
	Rest      map[string]interface{} `yaml:",inline"`
}

type RelatedRule struct {
	ID   string          `yaml:"id"`
	Type RelatedRuleType `yaml:"type"`
}

func ParseElastAlertRule(data []byte) (*SigmaRule, error) {
	rule := &SigmaRule{}

	err := yaml.Unmarshal(data, rule)
	if err != nil {
		return nil, err
	}

	err = rule.Validate()
	if err != nil {
		return nil, err
	}

	return rule, nil
}

func (e *SigmaRule) Validate() error {
	// check required fields
	requiredFields := []string{}

	if len(e.Title) == 0 {
		requiredFields = append(requiredFields, "title")
	}

	if e.LogSource == (LogSource{}) {
		requiredFields = append(requiredFields, "logsource")
	}

	if len(e.Detection.Condition.Values) == 0 && e.Detection.Condition.Value == "" {
		requiredFields = append(requiredFields, "detection.condition")
	}

	if len(requiredFields) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(requiredFields, ", "))
	}

	return nil
}

func (r *SigmaRule) ToDetection(content string, ruleset string, license string, isCommunity bool) *model.Detection {
	id := r.Title

	if r.ID != nil {
		id = *r.ID
	}

	sev := model.SeverityUnknown

	if r.Level != nil {
		switch strings.ToLower(string(*r.Level)) {
		case "informational":
			sev = model.SeverityInformational
		case "low":
			sev = model.SeverityLow
		case "medium":
			sev = model.SeverityMedium
		case "high":
			sev = model.SeverityHigh
		case "critical":
			sev = model.SeverityCritical
		}
	}

	det := &model.Detection{
		Author:      socAuthor,
		Engine:      model.EngineNameElastAlert,
		PublicID:    id,
		Title:       r.Title,
		Severity:    sev,
		Content:     content,
		IsCommunity: isCommunity,
		Language:    model.SigLangSigma,
		Ruleset:     ruleset,
		License:     license,
	}

	if r.Description != nil {
		det.Description = *r.Description
	}

	if r.LogSource.Category != nil && *r.LogSource.Category != "" {
		det.Category = *r.LogSource.Category
	}

	if r.LogSource.Product != nil && *r.LogSource.Product != "" {
		det.Product = *r.LogSource.Product
	}

	if r.LogSource.Service != nil && *r.LogSource.Service != "" {
		det.Service = *r.LogSource.Service
	}

	return det
}
