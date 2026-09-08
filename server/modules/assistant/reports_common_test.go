// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestParseReportTitle(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		deflt    string
		expected string
	}{
		{
			name: "Valid title with equals underline",
			content: []byte(`My Report Title
===============
Some content here`),
			deflt:    "default.md",
			expected: "My Report Title",
		},
		{
			name: "Multiple underlines, first one wins",
			content: []byte(`First Title
===========
Content
Second Title
============
More content`),
			deflt:    "default.md",
			expected: "First Title",
		},
		{
			name: "No valid title format",
			content: []byte(`# Header
Some content
## Another header`),
			deflt:    "fallback.md",
			expected: "fallback.md",
		},
		{
			name:     "Empty content",
			content:  []byte(``),
			deflt:    "empty.md",
			expected: "empty.md",
		},
		{
			name: "Only underline without title",
			content: []byte(`===============
Content`),
			deflt:    "noTitle.md",
			expected: "noTitle.md",
		},
		{
			name: "Title with whitespace",
			content: []byte(`   Trimmed Title
===================
Content`),
			deflt:    "default.md",
			expected: "Trimmed Title",
		},
		{
			name: "Underline too short",
			content: []byte(`Title Here
===
Content`),
			deflt:    "short.md",
			expected: "Title Here",
		},
		{
			name:     "Single line content",
			content:  []byte(`Just one line`),
			deflt:    "single.md",
			expected: "single.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseReportTitle(tt.content, tt.deflt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReportSettingFilename(t *testing.T) {
	tests := []struct {
		id       string
		expected string
	}{
		{"sensoroni.files.templates.reports.custom.generic_report2__md", "generic_report2.md"},
		{"sensoroni.files.templates.reports.standard.case_report__md", "case_report.md"},
		{"generic_report1__md", "generic_report1.md"},
		{"noprefix", "noprefix"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.expected, reportSettingFilename(tt.id))
		})
	}
}

func TestCustomReportSlotNumber(t *testing.T) {
	tests := []struct {
		filename string
		num      int
		ok       bool
	}{
		{"generic_report1.md", 1, true},
		{"generic_report9.md", 9, true},
		{"generic_report10.md", 10, true},
		{"addl_generic_report.md", 0, false},
		{"generic_report.md", 0, false},
		{"generic_report0.md", 0, false},
		{"generic_reportx.md", 0, false},
		{"generic_report2.txt", 0, false},
		{"case_report.md", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			n, ok := customReportSlotNumber(tt.filename)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.num, n)
		})
	}
}

func TestReportSlotContentAndEmpty(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		deflt   string
		content string
		empty   bool
	}{
		{"value set", "real content", "", "real content", false},
		{"falls back to default", "", "example", "example", false},
		{"value over default", "override", "example", "override", false},
		{"both empty", "", "", "", true},
		{"whitespace only", "   \n  ", "", "", true},
		{"whitespace value falls back to default", "  ", "example", "example", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot := reportSlot{Setting: &model.Setting{Value: tt.value, Default: tt.deflt}}
			assert.Equal(t, tt.content, slot.effectiveContent())
			assert.Equal(t, tt.empty, slot.isEmpty())
		})
	}
}

func TestLoadReportSlots(t *testing.T) {
	settings := []*model.Setting{
		{Id: "sensoroni.files.templates.reports.custom.generic_report1__md", File: true, Default: "Example\n===\ncontent"},
		{Id: "sensoroni.files.templates.reports.custom.generic_report2__md", File: true, Value: ""},
		{Id: "sensoroni.files.templates.reports.custom.addl_generic_report__md", File: true},
		{Id: "sensoroni.files.templates.reports.standard.case_report__md", File: true, Default: "Case"},
		{Id: "sensoroni.files.templates.reports.custom.generic_report3__md", File: false},
		{Id: "sensoroni.some.other.setting", File: false},
		{Id: "sensoroni.files.templates.reports.custom.notnumbered__md", File: true},
	}

	srv := &server.Server{Configstore: server.NewMemConfigStore(settings)}

	slots, err := loadReportSlots(context.Background(), srv)
	assert.NoError(t, err)
	assert.Len(t, slots, 3)

	byFilename := map[string]reportSlot{}
	for _, s := range slots {
		byFilename[s.Filename] = s
	}

	r1, ok := byFilename["generic_report1.md"]
	assert.True(t, ok)
	assert.Equal(t, "custom", r1.Kind)
	assert.Equal(t, 1, r1.Slot)
	assert.False(t, r1.isEmpty())

	r2, ok := byFilename["generic_report2.md"]
	assert.True(t, ok)
	assert.Equal(t, "custom", r2.Kind)
	assert.Equal(t, 2, r2.Slot)
	assert.True(t, r2.isEmpty())

	cr, ok := byFilename["case_report.md"]
	assert.True(t, ok)
	assert.Equal(t, "standard", cr.Kind)
	assert.Equal(t, 0, cr.Slot)

	for _, skipped := range []string{"addl_generic_report.md", "generic_report3.md", "notnumbered.md"} {
		_, ok := byFilename[skipped]
		assert.False(t, ok, "expected %s to be skipped", skipped)
	}
}
