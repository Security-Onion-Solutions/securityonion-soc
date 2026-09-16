package assistant

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

// flexibleString is a tool parameter declared to the model as a string that is
// also accepted as an array, scalar or object. Models reached over the
// OpenAI-compatible chat adapter routinely send a JSON array for a string-typed
// parameter whose description reads like a list -- an empty "constraints": []
// is the common case. A plain string field rejects that, and because one bad
// field fails the whole json.Unmarshal the entire tool call is lost.
type flexibleString string

func (s *flexibleString) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*s = flexibleString(text)
		return nil
	}

	var items []any
	if err := json.Unmarshal(data, &items); err == nil {
		lines := make([]string, 0, len(items))
		for _, item := range items {
			if line, ok := stringifyValue(item); ok {
				lines = append(lines, line)
			}
		}

		*s = flexibleString(strings.Join(lines, "\n"))

		return nil
	}

	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	text, _ = stringifyValue(value)
	*s = flexibleString(text)

	return nil
}

// stringifyValue renders a decoded JSON value as text. ok is false for values
// that carry nothing to record, so callers can drop the key entirely.
func stringifyValue(value any) (text string, ok bool) {
	switch typed := value.(type) {
	case nil:
		return "", false
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case float64:
		// 'f' rather than 'g' so a large count stays 1000000 instead of 1e+06.
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", false
		}

		return string(encoded), true
	}
}

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
