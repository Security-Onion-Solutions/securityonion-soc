// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

type SigmaRule struct {
	Title          string                 `yaml:"title"`
	ID             *string                `yaml:"id"`
	Name           *string                `yaml:"name,omitempty"`
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
	Summary        *string                `yaml:"summary,omitempty"`
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

// SigmaRuleCollection is a detection's documents: one rule, or a correlation and the rules it references.
type SigmaRuleCollection struct {
	Primary *SigmaRule
	// resolved by the correlation; never deployed alone
	Referenced []*SigmaRule
}

func (c *SigmaRuleCollection) IsCorrelation() bool {
	return c.Primary != nil && c.Primary.Correlation != nil
}

// decodeDocuments decodes every non-empty YAML document; yaml.Unmarshal keeps only the first.
func decodeDocuments[T any](r io.Reader) ([]*T, error) {
	decoder := yaml.NewDecoder(r)

	docs := []*T{}

	for {
		node := &yaml.Node{}

		err := decoder.Decode(node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(node.Content) == 0 || node.Content[0].Tag == "!!null" {
			continue
		}

		doc := new(T)

		err = node.Decode(doc)
		if err != nil {
			return nil, err
		}

		docs = append(docs, doc)
	}

	return docs, nil
}

func encodeDocuments[T any](docs []T) (string, error) {
	buf := &bytes.Buffer{}
	encoder := yaml.NewEncoder(buf)
	encoder.SetIndent(4)

	for _, doc := range docs {
		err := encoder.Encode(doc)
		if err != nil {
			return "", err
		}
	}

	err := encoder.Close()
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func parseRuleCollection(data []byte) (*SigmaRuleCollection, error) {
	rules, err := decodeDocuments[SigmaRule](bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no Sigma rule documents found")
	}

	return &SigmaRuleCollection{Primary: rules[0], Referenced: rules[1:]}, nil
}

// Validate also checks that every rule a correlation references is present.
func (c *SigmaRuleCollection) Validate() error {
	err := c.Primary.Validate()
	if err != nil {
		return err
	}

	if !c.IsCorrelation() {
		if len(c.Referenced) > 0 {
			return fmt.Errorf("only a correlation rule may contain multiple YAML documents; found %d additional document(s)", len(c.Referenced))
		}

		return nil
	}

	// A reference may name either the id or the name of another document.
	known := map[string]struct{}{}
	for _, rule := range c.Referenced {
		if rule.ID != nil && *rule.ID != "" {
			known[*rule.ID] = struct{}{}
		}
		if rule.Name != nil && *rule.Name != "" {
			known[*rule.Name] = struct{}{}
		}
	}

	unresolved := []string{}
	for _, ref := range c.Primary.Correlation.Rules {
		if _, ok := known[ref]; !ok {
			unresolved = append(unresolved, ref)
		}
	}

	if len(unresolved) > 0 {
		return fmt.Errorf("correlation references %d rule(s) not defined in this detection: %s; "+
			"add each referenced rule as an additional YAML document (separated by ---) with a matching id or name",
			len(unresolved), strings.Join(unresolved, ", "))
	}

	for i, rule := range c.Referenced {
		label := fmt.Sprintf("document %d", i+2)
		if rule.Name != nil && *rule.Name != "" {
			label = fmt.Sprintf("referenced rule %q", *rule.Name)
		}

		if rule.Correlation != nil {
			return fmt.Errorf("%s is itself a correlation, which is not supported; refer to the rules it correlates directly", label)
		}

		err = rule.validateReferenced()
		if err != nil {
			return fmt.Errorf("%s is invalid: %w", label, err)
		}
	}

	return nil
}

// ParseElastAlertRuleCollection parses and validates every document of a detection.
func ParseElastAlertRuleCollection(data []byte) (*SigmaRuleCollection, error) {
	collection, err := parseRuleCollection(data)
	if err != nil {
		return nil, err
	}

	err = collection.Validate()
	if err != nil {
		return nil, err
	}

	collection.Primary.OriginalSource = string(data)

	return collection, nil
}

// ParseElastAlertRule validates the whole detection and returns its primary document.
func ParseElastAlertRule(data []byte) (*SigmaRule, error) {
	collection, err := ParseElastAlertRuleCollection(data)
	if err != nil {
		return nil, err
	}

	return collection.Primary, nil
}

func (e *SigmaRule) Validate() error {
	requiredFields := []string{}

	if e.ID == nil || len(*e.ID) == 0 {
		requiredFields = append(requiredFields, "id")
	}

	return e.validate(requiredFields)
}

// validateReferenced checks a referenced rule, which may have a name in place of an id.
func (e *SigmaRule) validateReferenced() error {
	requiredFields := []string{}

	hasID := e.ID != nil && len(*e.ID) > 0
	hasName := e.Name != nil && len(*e.Name) > 0

	if !hasID && !hasName {
		requiredFields = append(requiredFields, "id or name")
	}

	return e.validate(requiredFields)
}

func (e *SigmaRule) validate(requiredFields []string) error {
	if len(e.Title) == 0 {
		requiredFields = append(requiredFields, "title")
	}

	if e.Correlation == nil {
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

	// after required fields, so all missing fields are reported together
	if e.Correlation != nil {
		return e.Correlation.Validate()
	}

	return nil
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

	r.setRuleType(det)

	return det
}

// setRuleType records whether the detection is a correlation, and if so its type and timespan.
func (r *SigmaRule) setRuleType(det *model.Detection) {
	det.RuleType = model.RuleTypeSingle
	det.CorrelationType = ""
	det.CorrelationTimespan = ""

	if r.Correlation == nil {
		return
	}

	det.RuleType = model.RuleTypeCorrelation
	det.CorrelationType = r.Correlation.Type

	if r.Correlation.Timespan != nil {
		det.CorrelationTimespan = *r.Correlation.Timespan
	}
}
