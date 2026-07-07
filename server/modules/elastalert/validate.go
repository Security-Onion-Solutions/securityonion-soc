// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
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

type SigmaCorrelationType string

const (
	SigmaCorrelationEventCount      SigmaCorrelationType = "event_count"
	SigmaCorrelationValueCount      SigmaCorrelationType = "value_count"
	SigmaCorrelationTemporal        SigmaCorrelationType = "temporal"
	SigmaCorrelationTemporalOrdered SigmaCorrelationType = "temporal_ordered"
)

type SigmaCorrelation struct {
	Type      SigmaCorrelationType   `yaml:"type"`
	Rules     OneOrMore[string]      `yaml:"rules,omitempty"`
	GroupBy   []string               `yaml:"group-by,omitempty"`
	Timespan  *string                `yaml:"timespan,omitempty"`
	Condition map[string]int         `yaml:"condition,omitempty"`
	Field     *string                `yaml:"field,omitempty"`
	Rest      map[string]interface{} `yaml:",inline"`
}

func (c *SigmaCorrelation) HasRequiredFields() bool {
	return c.Type != "" && c.Rules.HasValue() && c.Timespan != nil
}

type SigmaRule struct {
	Title          string                 `yaml:"title"`
	Name           string                 `yaml:"name,omitempty"`
	ID             *string                `yaml:"id"`
	RuleType       string                 `yaml:"type,omitempty"`
	Related        []*RelatedRule         `yaml:"related,omitempty"`
	Status         *SigmaStatus           `yaml:"status"`
	Description    *string                `yaml:"description,omitempty"`
	References     []string               `yaml:"references,omitempty"`
	Author         *string                `yaml:"author,omitempty"`
	Date           *string                `yaml:"date"`
	Modified       *string                `yaml:"modified,omitempty"`
	Tags           []string               `yaml:"tags,omitempty"`
	LogSource      LogSource              `yaml:"logsource"`
	Detection      SigmaDetection         `yaml:"detection"`
	Correlation    *SigmaCorrelation      `yaml:"correlation,omitempty"`
	Fields         []string               `yaml:"fields,omitempty"`
	FalsePositives OneOrMore[string]      `yaml:"falsepositives,omitempty"`
	Level          *SigmaLevel            `yaml:"level"`
	License        *string                `yaml:"license,omitempty"`
	Rest           map[string]interface{} `yaml:",inline"`
	OriginalSource string                 `yaml:"-"`
}

type LogSource struct {
	Category   *string `yaml:"category,omitempty"`
	Product    *string `yaml:"product,omitempty"`
	Service    *string `yaml:"service,omitempty"`
	Definition *string `yaml:"definition,omitempty"`
}

type SigmaDetection struct {
	Rest      map[string]interface{} `yaml:",inline"`
	Condition OneOrMore[string]      `yaml:"condition"`
}

// Custom marshaller for MarshalYAML to ensure that Condition is the ordered correctly
func (s SigmaDetection) MarshalYAML() (interface{}, error) {
	node := yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{},
	}

	// Add other fields from Rest
	for key, value := range s.Rest {
		keyNode := yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: key,
		}
		valueNode := yaml.Node{}
		if err := valueNode.Encode(value); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &keyNode, &valueNode)
	}

	// Add Condition field last
	conditionKeyNode := yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "condition",
	}
	conditionValueNode := yaml.Node{}
	if err := conditionValueNode.Encode(s.Condition); err != nil {
		return nil, err
	}
	node.Content = append(node.Content, &conditionKeyNode, &conditionValueNode)

	return &node, nil
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

	rule.OriginalSource = string(data)

	return rule, nil
}

func (e *SigmaRule) IsCorrelationRule() bool {
	return e.RuleType == "correlation" && e.Correlation != nil
}

func (e *SigmaRule) Validate() error {
	requiredFields := []string{}

	if e.ID == nil || len(*e.ID) == 0 {
		requiredFields = append(requiredFields, "id")
	}

	if len(e.Title) == 0 {
		requiredFields = append(requiredFields, "title")
	}

	if e.IsCorrelationRule() {
		if e.Correlation.HasRequiredFields() {
			if err := e.validateCorrelation(); err != nil {
				return err
			}
			return checkNoError(requiredFields)
		}
		correlation := e.Correlation
		if correlation.Type == "" {
			requiredFields = append(requiredFields, "correlation.type")
		}
		if !correlation.Rules.HasValue() {
			requiredFields = append(requiredFields, "correlation.rules")
		}
		if correlation.Timespan == nil || *correlation.Timespan == "" {
			requiredFields = append(requiredFields, "correlation.timespan")
		}
	} else {
		if e.LogSource == (LogSource{}) {
			requiredFields = append(requiredFields, "logsource")
		}
		if len(e.Detection.Condition.Values) == 0 && e.Detection.Condition.Value == "" {
			requiredFields = append(requiredFields, "detection.condition")
		}
	}

	if len(requiredFields) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(requiredFields, ", "))
	}

	return nil
}

func checkNoError(requiredFields []string) error {
	if len(requiredFields) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(requiredFields, ", "))
	}
	return nil
}

func (e *SigmaRule) validateCorrelation() error {
	c := e.Correlation

	switch c.Type {
	case SigmaCorrelationEventCount, SigmaCorrelationValueCount,
		SigmaCorrelationTemporal, SigmaCorrelationTemporalOrdered:
	default:
		return fmt.Errorf("unsupported correlation type: %q", c.Type)
	}

	if c.Timespan != nil {
		if _, err := ParseTimespan(*c.Timespan); err != nil {
			return fmt.Errorf("invalid correlation timespan %q: %w", *c.Timespan, err)
		}
	}

	if c.Type == SigmaCorrelationValueCount && c.Field == nil {
		return fmt.Errorf("value_count correlation must specify a 'field'")
	}

	return nil
}

func ParseTimespan(s string) (*TimeFrame, error) {
	if len(s) < 2 {
		return nil, fmt.Errorf("timespan too short")
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return nil, fmt.Errorf("invalid number in timespan: %w", err)
	}

	tf := &TimeFrame{}

	switch unit {
	case 's':
		tf.SetSeconds(num)
	case 'm':
		tf.SetMinutes(num)
	case 'h':
		tf.SetHours(num)
	case 'd':
		tf.SetDays(num)
	default:
		return nil, fmt.Errorf("unknown timespan unit: %c", unit)
	}

	return tf, nil
}

func (r *SigmaRule) ToDetection(ruleset string, license string, isCommunity bool) *model.Detection {
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

	var content []byte

	if len(r.OriginalSource) > 0 {
		content = []byte(r.OriginalSource)
	} else {
		content, _ = yaml.Marshal(r)
	}

	author := "unknown"
	if r.Author != nil {
		author = *r.Author
	}

	det := &model.Detection{
		Author:      author,
		Engine:      model.EngineNameElastAlert,
		PublicID:    id,
		Title:       r.Title,
		Severity:    sev,
		Content:     string(content),
		IsCommunity: isCommunity,
		Language:    model.SigLangSigma,
		Ruleset:     ruleset,
		License:     license,
	}

	formats := []string{"2006-01-02", "2006/01/02", "2006_01_02"}

	if r.Date != nil {
		t, err := util.ParseDate(*r.Date, formats)
		if err == nil {
			det.SourceCreated = &t
		}
	}

	if r.Modified != nil {
		t, err := util.ParseDate(*r.Modified, formats)
		if err == nil {
			det.SourceUpdated = &t
		}
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
