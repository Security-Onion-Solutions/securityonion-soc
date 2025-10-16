package assistant

import (
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/util"
)

func parseRangeAllowRelative(rangeStart string, rangeEnd string, format string) string {
	start := "-24h"
	end := "now"

	if rangeStart != "" {
		start = rangeStart
	}
	if rangeEnd != "" {
		end = rangeEnd
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
