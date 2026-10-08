// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/samber/lo"
)

// Warn-only: each run re-reads timespan + run interval + allowance. Shipped rules use 10m-1h.
const largeCorrelationWindow = 4 * time.Hour

// Only the ES|QL backend counts correlations in event-time windows.
var errCorrelationNeedsEsql = errors.New("ERROR_CORRELATION_REQUIRES_ESQL")

// The correlation types the ES|QL backend can express.
const (
	correlationTypeEventCount      = "event_count"
	correlationTypeValueCount      = "value_count"
	correlationTypeTemporal        = "temporal"
	correlationTypeValueSum        = "value_sum"
	correlationTypeValueAvg        = "value_avg"
	correlationTypeValuePercentile = "value_percentile"
	correlationTypeValueMedian     = "value_median"
)

var supportedCorrelationTypes = []string{
	correlationTypeEventCount,
	correlationTypeValueCount,
	correlationTypeTemporal,
	correlationTypeValueSum,
	correlationTypeValueAvg,
	correlationTypeValuePercentile,
	correlationTypeValueMedian,
}

// Months and years are excluded: they are not fixed durations.
var timespanPattern = regexp.MustCompile(`^([1-9][0-9]*)([smhdw])$`)

var timespanUnits = map[string]time.Duration{
	"s": time.Second,
	"m": time.Minute,
	"h": time.Hour,
	"d": 24 * time.Hour,
	"w": 7 * 24 * time.Hour,
}

func parseTimespan(timespan string) (time.Duration, error) {
	match := timespanPattern.FindStringSubmatch(timespan)
	if match == nil {
		return 0, fmt.Errorf("invalid timespan %q: expected a positive count followed by s, m, h, d or w (e.g. 15m)", timespan)
	}

	unit := timespanUnits[match[2]]

	count, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || count > math.MaxInt64/int64(unit) {
		return 0, fmt.Errorf("invalid timespan %q: too long", timespan)
	}

	return time.Duration(count) * unit, nil
}

// SigmaCorrelationCondition thresholds are float64: metric types allow fractions.
type SigmaCorrelationCondition struct {
	Field      *string                `yaml:"field,omitempty"`
	Percentile *int                   `yaml:"percentile,omitempty"`
	Gt         *float64               `yaml:"gt,omitempty"`
	Gte        *float64               `yaml:"gte,omitempty"`
	Lt         *float64               `yaml:"lt,omitempty"`
	Lte        *float64               `yaml:"lte,omitempty"`
	Eq         *float64               `yaml:"eq,omitempty"`
	Neq        *float64               `yaml:"neq,omitempty"`
	Rest       map[string]interface{} `yaml:",inline"`
}

func (c *SigmaCorrelationCondition) HasComparison() bool {
	if c == nil {
		return false
	}

	return c.Gt != nil || c.Gte != nil || c.Lt != nil || c.Lte != nil || c.Eq != nil || c.Neq != nil
}

func (c *SigmaCorrelationCondition) HasField() bool {
	return c != nil && c.Field != nil && *c.Field != ""
}

// Validate rejects conditions the converter refuses at deploy, or would run without ever matching.
func (c *SigmaCorrelationCondition) Validate() error {
	comparisons := lo.Count([]bool{c.Gt != nil, c.Gte != nil, c.Lt != nil, c.Lte != nil, c.Eq != nil, c.Neq != nil}, true)
	if comparisons > 1 {
		return fmt.Errorf("correlation.condition must have exactly one comparison (gt, gte, lt, lte, eq or neq), found %d; ranges are not supported", comparisons)
	}

	if len(c.Rest) > 0 {
		keys := lo.Keys(c.Rest)
		slices.Sort(keys)

		return fmt.Errorf("unsupported correlation.condition keys: %s; use field, percentile and one of gt, gte, lt, lte, eq or neq", strings.Join(keys, ", "))
	}

	// a percentile outside 0-100 converts but never matches
	if c.Percentile != nil && (*c.Percentile < 0 || *c.Percentile > 100) {
		return fmt.Errorf("correlation.condition.percentile must be between 0 and 100, found %d", *c.Percentile)
	}

	return nil
}

type SigmaCorrelation struct {
	Type      string                     `yaml:"type"`
	Rules     []string                   `yaml:"rules,omitempty"`
	GroupBy   []string                   `yaml:"group-by,omitempty"`
	Timespan  *string                    `yaml:"timespan,omitempty"`
	Condition *SigmaCorrelationCondition `yaml:"condition,omitempty"`
	Generate  *bool                      `yaml:"generate,omitempty"`
	Aliases   map[string]interface{}     `yaml:"aliases,omitempty"`
	Rest      map[string]interface{}     `yaml:",inline"`
}

func (c *SigmaCorrelation) Validate() error {
	missing := []string{}

	if c.Type == "" {
		missing = append(missing, "correlation.type")
	}
	if len(c.Rules) == 0 {
		missing = append(missing, "correlation.rules")
	}
	if len(c.GroupBy) == 0 {
		missing = append(missing, "correlation.group-by")
	}
	if c.Timespan == nil || *c.Timespan == "" {
		missing = append(missing, "correlation.timespan")
	}

	switch c.Type {
	case correlationTypeEventCount, correlationTypeValueCount:
		if !c.Condition.HasComparison() {
			missing = append(missing, "correlation.condition (a count comparison such as gte)")
		}
		if c.Type == correlationTypeValueCount && !c.Condition.HasField() {
			missing = append(missing, "correlation.condition.field")
		}
	case correlationTypeTemporal:
		// without a condition all rules must match; one can relax it, e.g. gte 2 of 3
		if len(c.Rules) == 1 {
			return errors.New("a temporal correlation must reference at least 2 rules, found 1")
		}
		if c.Condition.HasField() {
			return errors.New("a temporal correlation counts matching rules, so its condition cannot name a field")
		}
	case correlationTypeValueSum, correlationTypeValueAvg, correlationTypeValueMedian, correlationTypeValuePercentile:
		if !c.Condition.HasComparison() {
			missing = append(missing, "correlation.condition (a comparison such as gt)")
		}
		if !c.Condition.HasField() {
			missing = append(missing, "correlation.condition.field")
		}
		if c.Type == correlationTypeValuePercentile && (c.Condition == nil || c.Condition.Percentile == nil) {
			missing = append(missing, "correlation.condition.percentile")
		}
	case "":
		// reported as missing above
	default:
		return fmt.Errorf("unsupported correlation type %q; supported types are: %s", c.Type, strings.Join(supportedCorrelationTypes, ", "))
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	if c.Condition != nil {
		err := c.Condition.Validate()
		if err != nil {
			return err
		}
	}

	// each would convert to more than the one query a detection deploys
	if c.Generate != nil && *c.Generate {
		return errors.New("correlation.generate is not supported; to alert on a referenced rule by itself as well, add it as its own detection")
	}
	if len(c.Aliases) > 0 {
		return errors.New("correlation.aliases is not supported; give the referenced rules the same field name instead")
	}

	if c.Timespan != nil {
		if _, err := parseTimespan(*c.Timespan); err != nil {
			return err
		}
	}

	return nil
}

// correlationOutput is a converted correlation as sigma_esql_pipeline.yml emits it.
type correlationOutput struct {
	Query string `json:"query"`
	// as mapped by the pipelines
	GroupBy []string `json:"group_by"`
}

func parseCorrelationOutput(output string) (*correlationOutput, error) {
	out := &correlationOutput{}

	err := json.Unmarshal([]byte(output), out)
	if err != nil || out.Query == "" || len(out.GroupBy) == 0 {
		return nil, errors.New("the converted correlation lacks its group-by columns; check the ES|QL sigma pipeline")
	}

	return out, nil
}

func (e *ElastAlertEngine) applyCorrelation(wrapper *CustomWrapper, publicId string, output string, sigmaRule *SigmaRule) error {
	correlation := sigmaRule.Correlation

	// stored rules are parsed leniently
	err := correlation.Validate()
	if err != nil {
		return fmt.Errorf("invalid correlation: %w", err)
	}

	timespan, err := parseTimespan(*correlation.Timespan)
	if err != nil {
		return err
	}

	converted, err := parseCorrelationOutput(output)
	if err != nil {
		return err
	}

	window := timespan + e.elastAlertRunEvery + e.esqlCorrelationAllowance

	wrapper.SigmaCorrelation = correlation.Type
	wrapper.BufferTime = secondsFrame(window)
	wrapper.Timeframe = secondsFrame(window)
	wrapper.ScanEntireTimeframe = true

	wrapper.Filter = []map[string]interface{}{{"esql": converted.Query}}
	wrapper.QueryKey = converted.GroupBy

	// one alert per burst while it stays in the window
	wrapper.Realert.SetSeconds(int(window.Seconds()))

	wrapper.SummaryTemplate = sigmaRule.Summary

	if timespan > largeCorrelationWindow {
		log.WithFields(log.Fields{
			"detectionPublicId":   publicId,
			"correlationTimespan": *correlation.Timespan,
		}).Warn("correlation timespan requires a large query window; each run of this rule will scan that entire window")
	}

	return nil
}
