// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
)

// Correlation windows beyond this log a warning, since every run scans the whole window.
const largeCorrelationWindow = 4 * time.Hour

// Only the ES|QL backend has the event-time windows correlations are counted in.
var errCorrelationNeedsEsql = errors.New("correlation rules require ES|QL; enable useEsql in the Sigma configuration")

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

// parseTimespan converts a Sigma correlation timespan such as "15m" into a duration.
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

// SigmaCorrelationCondition holds float64 thresholds, since metric types allow fractions.
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
		// An optional condition lowers the bar: gte 2 of 3 rules. Without one, all must match.
		if len(c.Rules) == 1 {
			return fmt.Errorf("a temporal correlation must reference at least 2 rules, found 1")
		}
		if c.Condition.HasComparison() && c.Condition.HasField() {
			return fmt.Errorf("a temporal correlation counts matching rules, so its condition cannot name a field")
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
		// Already reported as missing above.
	default:
		return fmt.Errorf("unsupported correlation type %q; supported types are: %s", c.Type, strings.Join(supportedCorrelationTypes, ", "))
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	// Each would convert to more than the single query a detection deploys.
	if c.Generate != nil && *c.Generate {
		return fmt.Errorf("correlation.generate is not supported; to alert on a referenced rule by itself as well, add it as its own detection")
	}
	if len(c.Aliases) > 0 {
		return fmt.Errorf("correlation.aliases is not supported; give the referenced rules the same field name instead")
	}

	if c.Timespan != nil {
		if _, err := parseTimespan(*c.Timespan); err != nil {
			return err
		}
	}

	return nil
}

// esqlStatsGroupBy matches the columns a stats command groups by.
var esqlStatsGroupBy = regexp.MustCompile(`(?m)\|\s*stats\s[^\n]*?\sby\s+([^\n|)]+)`)

// esqlGroupColumns returns the unquoted columns the query's last stats groups by.
func esqlGroupColumns(query string) []string {
	matches := esqlStatsGroupBy.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return nil
	}

	columns := strings.Split(matches[len(matches)-1][1], ",")
	for i, column := range columns {
		column = strings.TrimSpace(column)
		if unquoted, ok := strings.CutPrefix(column, "`"); ok {
			column = strings.ReplaceAll(strings.TrimSuffix(unquoted, "`"), "``", "`")
		}

		columns[i] = column
	}

	return columns
}

// applyCorrelation runs a correlation at the grid interval over its timespan, the last run and the allowance.
func (e *ElastAlertEngine) applyCorrelation(wrapper *CustomWrapper, publicId string, rule string, sigmaRule *SigmaRule) error {
	correlation := sigmaRule.Correlation

	timespan, err := parseTimespan(*correlation.Timespan)
	if err != nil {
		return err
	}

	window := timespan + e.elastAlertRunEvery + e.esqlCorrelationAllowance

	wrapper.SigmaCorrelation = correlation.Type
	wrapper.BufferTime = secondsFrame(window)
	wrapper.Timeframe = secondsFrame(window)
	wrapper.ScanEntireTimeframe = true

	// the pipeline may rename group-by fields, so key on the query's columns
	columns := esqlGroupColumns(rule)
	if len(columns) != len(correlation.GroupBy) {
		return fmt.Errorf("unable to read the group-by columns %v from the converted query", correlation.GroupBy)
	}

	wrapper.QueryKey = columns

	// a burst stays in view for the whole window
	wrapper.Realert.SetSeconds(int(window.Seconds()))

	wrapper.SummaryTemplate = sigmaRule.Summary

	if timespan > largeCorrelationWindow {
		log.WithFields(log.Fields{
			"detectionPublicId": publicId,
			"timespan":          *correlation.Timespan,
		}).Warn("correlation timespan requires a large query window; each run of this rule will scan that entire window")
	}

	return nil
}
