// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatPlainTextBody(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2026-08-17T12:00:00Z")
	require.NoError(t, err)

	payload := &model.NotificationPayload{
		ID:        "notif-test-1",
		Source:    model.SourceDetection,
		Title:     "ET SCAN Potential SSH Scan",
		Summary:   "Inbound SSH scan detected from 192.168.1.100.",
		Severity:  model.NotificationSeverityHigh,
		Timestamp: ts,
		Fields: map[string]string{
			"src_ip": "192.168.1.100",
			"dst_ip": "10.0.0.1",
		},
		Links: map[string]string{
			"View in SOC": "https://soc.example.com/#/alerts/123",
		},
		Attachments: []model.Attachment{
			{
				Filename:    "report.pdf",
				ContentType: "application/pdf",
				URL:         "https://soc.example.com/api/reports/1/download",
			},
		},
	}

	body := FormatPlainTextBody(payload, model.AttachmentModeBoth)
	assert.Contains(t, body, "[HIGH] [ET SCAN Potential SSH Scan]")
	assert.Contains(t, body, "2026-08-17 12:00:00 UTC")
	assert.Contains(t, body, "Inbound SSH scan detected from 192.168.1.100.")
	assert.Contains(t, body, "src_ip: 192.168.1.100")
	assert.Contains(t, body, "dst_ip: 10.0.0.1")
	assert.Contains(t, body, "View in SOC: https://soc.example.com/#/alerts/123")
	assert.Contains(t, body, "report.pdf (application/pdf): https://soc.example.com/api/reports/1/download")
	assert.Contains(t, body, "Security Onion • SOC • detection")
}

func TestFormatHTMLBody(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2026-08-17T12:00:00Z")
	require.NoError(t, err)

	payload := &model.NotificationPayload{
		ID:        "notif-test-2",
		Source:    model.SourceMetric,
		Title:     "CPU Exceeded Threshold",
		Summary:   "Node node-1 CPU is at 95%.",
		Severity:  model.NotificationSeverityCritical,
		Timestamp: ts,
		Fields: map[string]string{
			"node":  "node-1",
			"usage": "95%",
		},
		Links: map[string]string{
			"Grid Metrics": "https://soc.example.com/#/grid",
		},
	}

	htmlBody := FormatHTMLBody(payload, model.AttachmentModeBoth)
	assert.Contains(t, htmlBody, "<!DOCTYPE html>")
	assert.Contains(t, htmlBody, "header-badge")
	assert.Contains(t, htmlBody, "CRITICAL")
	assert.Contains(t, htmlBody, "header-title")
	assert.Contains(t, htmlBody, "#DC2626")
	assert.Contains(t, htmlBody, "CPU Exceeded Threshold")
	assert.Contains(t, htmlBody, "Node node-1 CPU is at 95%.")
	assert.Contains(t, htmlBody, "node")
	assert.Contains(t, htmlBody, "node-1")
	assert.Contains(t, htmlBody, "Grid Metrics")
	assert.Contains(t, htmlBody, "https://soc.example.com/#/grid")
	assert.Contains(t, htmlBody, "Security Onion • SOC • metric")
}

func TestBuildMIMEMessageNoAttachments(t *testing.T) {
	from := "soc-alerts@example.com"
	to := []string{"analyst@example.com"}
	subject := "[SOC] [HIGH] Alert Test"
	plain := "Plain body content"
	html := "<p>HTML body content</p>"

	msgBytes, err := BuildMIMEMessage(from, to, subject, plain, html, nil, model.AttachmentModeBoth)
	require.NoError(t, err)

	msg := string(msgBytes)
	assert.Contains(t, msg, "From: soc-alerts@example.com")
	assert.Contains(t, msg, "To: analyst@example.com")
	assert.Contains(t, msg, "Subject:")
	assert.Contains(t, msg, "Content-Type: multipart/alternative")
	assert.Contains(t, msg, "Content-Type: text/plain; charset=UTF-8")
	assert.Contains(t, msg, plain)
	assert.Contains(t, msg, "Content-Type: text/html; charset=UTF-8")
	assert.Contains(t, msg, html)
}

func TestBuildMIMEMessageWithAttachments(t *testing.T) {
	from := "SOC Alerts <soc-alerts@example.com>"
	to := []string{"analyst1@example.com", "analyst2@example.com"}
	subject := "[SOC] [CRITICAL] Alert With PDF"
	plain := "Plain body content"
	html := "<p>HTML body content</p>"

	attachments := []model.Attachment{
		{
			Filename:    "incident.csv",
			ContentType: "text/csv",
			Data:        []byte("col1,col2\nval1,val2\n"),
		},
	}

	msgBytes, err := BuildMIMEMessage(from, to, subject, plain, html, attachments, model.AttachmentModeBoth)
	require.NoError(t, err)

	msg := string(msgBytes)
	assert.Contains(t, msg, "From: SOC Alerts <soc-alerts@example.com>")
	assert.Contains(t, msg, "To: analyst1@example.com, analyst2@example.com")
	assert.Contains(t, msg, "Content-Type: multipart/mixed")
	assert.Contains(t, msg, "Content-Type: multipart/alternative")
	assert.Contains(t, msg, "Content-Type: text/csv; name=\"incident.csv\"")
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"incident.csv\"")
	assert.Contains(t, msg, "Content-Transfer-Encoding: base64")
	assert.Contains(t, msg, "Y29sMSxjb2wyCnZhbDEsdmFsMgo=")
}

func TestBuildMIMEMessageAttachmentModeLink(t *testing.T) {
	from := "soc@example.com"
	to := []string{"analyst@example.com"}
	subject := "Test"
	plain := "Plain text"
	html := "<p>HTML</p>"

	attachments := []model.Attachment{
		{
			Filename:    "test.txt",
			ContentType: "text/plain",
			Data:        []byte("raw text"),
		},
	}

	msgBytes, err := BuildMIMEMessage(from, to, subject, plain, html, attachments, model.AttachmentModeLink)
	require.NoError(t, err)

	msg := string(msgBytes)
	assert.Contains(t, msg, "Content-Type: multipart/alternative")
	assert.NotContains(t, msg, "Content-Type: multipart/mixed")
	assert.NotContains(t, msg, "filename=\"test.txt\"")
}

func TestBuildMIMEMessageValidationErrors(t *testing.T) {
	_, err := BuildMIMEMessage("", []string{"a@b.com"}, "Sub", "p", "h", nil, "")
	assert.Error(t, err)

	_, err = BuildMIMEMessage("from@b.com", nil, "Sub", "p", "h", nil, "")
	assert.Error(t, err)
}

func TestFormatEmailSubject(t *testing.T) {
	assert.Equal(t, "SOC Notification", FormatEmailSubject(nil))

	payload := &model.NotificationPayload{
		Title:    "Custom Alert",
		Severity: "high",
	}
	assert.Equal(t, "[HIGH] Custom Alert", FormatEmailSubject(payload))
}
