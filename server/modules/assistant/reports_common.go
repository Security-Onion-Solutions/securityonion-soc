// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const customReportSlotPrefix = "generic_report"

const reportSaltModule = "sensoroni"

type reportSlot struct {
	Setting  *model.Setting
	Filename string
	Kind     string
	Slot     int
}

func (r reportSlot) effectiveContent() string {
	if strings.TrimSpace(r.Setting.Value) != "" {
		return r.Setting.Value
	}
	return r.Setting.Default
}

func (r reportSlot) isEmpty() bool {
	return strings.TrimSpace(r.effectiveContent()) == ""
}

func loadReportSlots(ctx context.Context, srv *server.Server) ([]reportSlot, error) {
	settings, err := srv.Configstore.GetSettings(ctx, false)
	if err != nil {
		return nil, err
	}

	slots := []reportSlot{}
	for _, s := range settings {
		if !s.File || !strings.HasSuffix(s.Id, "__md") {
			continue
		}

		var kind string
		switch {
		case strings.Contains(s.Id, ".reports.custom."):
			kind = "custom"
		case strings.Contains(s.Id, ".reports.standard."):
			kind = "standard"
		default:
			continue
		}

		filename := reportSettingFilename(s.Id)
		slot := reportSlot{Setting: s, Filename: filename, Kind: kind}

		if kind == "custom" {
			n, ok := customReportSlotNumber(filename)
			if !ok {
				continue
			}
			slot.Slot = n
		}

		slots = append(slots, slot)
	}

	return slots, nil
}

func reportSettingFilename(id string) string {
	last := id
	if idx := strings.LastIndex(id, "."); idx >= 0 {
		last = id[idx+1:]
	}
	return strings.ReplaceAll(last, "__", ".")
}

func customReportSlotNumber(filename string) (int, bool) {
	if !strings.HasPrefix(filename, customReportSlotPrefix) || !strings.HasSuffix(filename, ".md") {
		return 0, false
	}
	numStr := strings.TrimSuffix(strings.TrimPrefix(filename, customReportSlotPrefix), ".md")
	n, err := strconv.Atoi(numStr)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

func titleUnderlineIndex(lines []string) int {
	prevLine := ""
	for i, line := range lines {
		if strings.HasPrefix(line, "===") && prevLine != "" {
			return i
		}
		prevLine = strings.TrimSpace(line)
	}
	return -1
}

func parseReportTitle(content []byte, deflt string) string {
	lines := strings.Split(string(content), "\n")

	if i := titleUnderlineIndex(lines); i > 0 {
		return strings.TrimSpace(lines[i-1])
	}

	return deflt
}
