package assistant

import (
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

func parseRangeAllowRelative(rangeStart string, rangeEnd string, rangeFormat string) string {
	start := "-24h"
	end := "now"
	format := "2006/01/02 3:04:05 PM"

	if rangeStart != "" {
		start = rangeStart
	}
	if rangeEnd != "" {
		end = rangeEnd
	}
	if rangeFormat != "" {
		format = rangeFormat
	}

	var startFormatted, endFormatted string

	// Parse and format times
	startParsed, err := time.Parse(format, start)
	if err != nil {
		startFormatted = util.ParseRelativeTimeString(start)
	} else {
		startFormatted = util.FormatSOTime(startParsed)
	}

	endParsed, err := time.Parse(format, end)
	if err != nil {
		endFormatted = util.ParseRelativeTimeString(end)
	} else {
		endFormatted = util.FormatSOTime(endParsed)
	}

	return fmt.Sprintf("%s - %s", startFormatted, endFormatted)
}

func populateOverridesFromMaps(inputMaps []map[string]any, includeTimes bool) []*model.Override {

	var populatedOverrides []*model.Override

	for _, overrideMap := range inputMaps {
		override := &model.Override{}

		if v, ok := overrideMap["type"].(string); ok {
			override.Type = model.OverrideType(v)
		}
		if v, ok := overrideMap["isEnabled"].(bool); ok {
			override.IsEnabled = v
		}
		if v, ok := overrideMap["note"].(string); ok {
			override.Note = v
		}
		if includeTimes {
			if v, ok := overrideMap["createdAt"].(string); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					override.CreatedAt = t
				}
			}

			if v, ok := overrideMap["updatedAt"].(string); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					override.UpdatedAt = t
				}
			}
		}
		if v, ok := overrideMap["regex"].(string); ok {
			override.Regex = &v
		}
		if v, ok := overrideMap["value"].(string); ok {
			override.Value = &v
		}
		if v, ok := overrideMap["track"].(string); ok {
			override.Track = &v
		}
		if v, ok := overrideMap["ip"].(string); ok {
			override.IP = &v
		}
		if v, ok := overrideMap["thresholdType"].(string); ok {
			override.ThresholdType = &v
		}
		if v, ok := overrideMap["count"].(float64); ok {
			count := int(v)
			override.Count = &count
		}
		if v, ok := overrideMap["seconds"].(float64); ok {
			seconds := int(v)
			override.Seconds = &seconds
		}
		if v, ok := overrideMap["customFilter"].(string); ok {
			override.CustomFilter = &v
		}
		populatedOverrides = append(populatedOverrides, override)
	}

	return populatedOverrides
}
