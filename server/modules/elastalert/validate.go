package elastalert

import (
	"fmt"
	"strings"

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
	LogSource      LogSource              `yaml:"logsource"`
	Detection      Detection              `yaml:"detection"`
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

type Detection struct {
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
