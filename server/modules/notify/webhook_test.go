// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHTTPClient struct {
	lastRequest *http.Request
	lastBody    []byte
	respStatus  int
	respBody    string
	err         error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	if req.Body != nil {
		m.lastBody, _ = io.ReadAll(req.Body)
	}
	if m.err != nil {
		return nil, m.err
	}
	status := m.respStatus
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(m.respBody)),
		Header:     make(http.Header),
	}, nil
}

func TestWebhookChannelValidation(t *testing.T) {
	ch := NewWebhookChannel(nil)

	assert.Equal(t, "generic_webhook", ch.Type())
	assert.False(t, ch.SupportsRecipients())
	assert.False(t, ch.SupportsAttachments())
	assert.True(t, ch.SupportsLinks())

	// Nil params
	assert.Error(t, ch.ValidateConfig(nil))

	// Missing url
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{}))

	// Invalid URL scheme
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"url": "ftp://example.com/webhook",
	}))

	// Invalid format
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"url":    "https://example.com/webhook",
		"format": "invalid_format",
	}))

	// Valid generic format
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"url": "https://example.com/webhook",
	}))

	// Valid webhookUrl alias
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"webhookUrl": "https://example.com/webhook",
		"format":     "slack",
		"headers": map[string]string{
			"Authorization": "Bearer token",
		},
	}))
}

func TestWebhookChannelSendGeneric(t *testing.T) {
	mock := &mockHTTPClient{}
	ch := NewWebhookChannel(nil)
	ch.client = mock

	payload := &model.NotificationPayload{
		ID:        "notif-123",
		Source:    model.SourceDetection,
		Title:     "Suricata Alert",
		Summary:   "Inbound SSH scan detected",
		Severity:  model.NotificationSeverityHigh,
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"src_ip": "1.2.3.4",
		},
		Links: map[string]string{
			"View Alert": "https://soc.example.com/#/alerts/123",
		},
	}

	params := map[string]interface{}{
		"url": "https://my-siem.example.com/api/v1/alerts",
		"headers": map[string]string{
			"X-API-Key": "secret-key",
		},
	}

	err := ch.Send(context.Background(), params, payload)
	require.NoError(t, err)

	assert.Equal(t, "https://my-siem.example.com/api/v1/alerts", mock.lastRequest.URL.String())
	assert.Equal(t, "POST", mock.lastRequest.Method)
	assert.Equal(t, "application/json", mock.lastRequest.Header.Get("Content-Type"))
	assert.Equal(t, "secret-key", mock.lastRequest.Header.Get("X-API-Key"))

	var decoded model.NotificationPayload
	err = json.Unmarshal(mock.lastBody, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "Suricata Alert", decoded.Title)
	assert.Equal(t, "high", decoded.Severity)
	assert.Equal(t, "1.2.3.4", decoded.Fields["src_ip"])
}

func TestWebhookChannelSendSlack(t *testing.T) {
	mock := &mockHTTPClient{}
	slackCh := NewSlackChannel(nil)
	slackCh.client = mock

	assert.Equal(t, "slack_webhook", slackCh.Type())

	payload := &model.NotificationPayload{
		Title:     "Database High CPU",
		Summary:   "PostgreSQL CPU usage reached 98%",
		Severity:  model.NotificationSeverityCritical,
		Timestamp: time.Unix(1723896000, 0).UTC(),
		Fields: map[string]string{
			"host": "db-primary",
		},
		Links: map[string]string{
			"View Grid": "https://soc.example.com/#/grid",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://hooks.slack.com/services/T00/B00/X00",
	}

	err := slackCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	assert.Equal(t, "https://hooks.slack.com/services/T00/B00/X00", mock.lastRequest.URL.String())

	var slackMsg slackMessage
	err = json.Unmarshal(mock.lastBody, &slackMsg)
	require.NoError(t, err)

	assert.Equal(t, "", slackMsg.Text)

	require.Len(t, slackMsg.Attachments, 1)
	att := slackMsg.Attachments[0]
	assert.Equal(t, "#DC2626", att.Color)
	assert.Equal(t, "*[CRITICAL] Database High CPU*\n\nPostgreSQL CPU usage reached 98%", att.Text)
	assert.Equal(t, []string{"text", "fields"}, att.MrkdwnIn)
	assert.Contains(t, att.Footer, "Security Onion • SOC")

	// Fields verify (severity is removed as it's in the title)
	var hasSev, hasHost, hasLink bool
	for _, f := range att.Fields {
		if f.Title == "Severity" {
			hasSev = true
		}
		if f.Title == "host" && f.Value == "db-primary" {
			hasHost = true
		}
		if strings.Contains(f.Value, "View Grid") {
			hasLink = true
			assert.False(t, f.Short)
		}
	}
	assert.False(t, hasSev)
	assert.True(t, hasHost)
	assert.True(t, hasLink)

	// Verify links field appears after payload fields
	require.Len(t, att.Fields, 2)
	assert.Equal(t, "host", att.Fields[0].Title)
	assert.Contains(t, att.Fields[1].Value, "<https://soc.example.com/#/grid|View Grid>")

	// Actions verify
	require.Len(t, att.Actions, 1)
	assert.Equal(t, "button", att.Actions[0].Type)
	assert.Equal(t, "View Grid", att.Actions[0].Text)
	assert.Equal(t, "https://soc.example.com/#/grid", att.Actions[0].URL)
}

func TestWebhookChannelSendMatrixHookshot(t *testing.T) {
	mock := &mockHTTPClient{}
	matrixCh := NewMatrixChannel(nil)
	matrixCh.client = mock

	assert.Equal(t, "matrix_hookshot_webhook", matrixCh.Type())

	payload := &model.NotificationPayload{
		Source:   "detection",
		Title:    "Suricata Detection",
		Summary:  "Malware traffic detected",
		Severity: model.NotificationSeverityMedium,
		Fields: map[string]string{
			"alert_id": "9999",
		},
		Links: map[string]string{
			"View": "https://soc.example.com/#/alerts/9999",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://matrix.example.com/_matrix/hookshot/123",
	}

	err := matrixCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var hookshotMsg matrixHookshotMessage
	err = json.Unmarshal(mock.lastBody, &hookshotMsg)
	require.NoError(t, err)

	assert.Contains(t, hookshotMsg.Text, "### [MEDIUM] Suricata Detection")
	assert.Contains(t, hookshotMsg.Text, "Malware traffic detected")
	assert.NotContains(t, hookshotMsg.Text, "Severity")
	assert.NotContains(t, hookshotMsg.Text, "* **Source**:")
	assert.Contains(t, hookshotMsg.Text, "* **alert_id**: 9999")
	assert.Contains(t, hookshotMsg.Text, "[View](https://soc.example.com/#/alerts/9999)")
	assert.Contains(t, hookshotMsg.Text, "Security Onion • SOC • detection")

	assert.Contains(t, hookshotMsg.HTML, "<span style=\"color:#F59E0B;\">[MEDIUM]</span> Suricata Detection")
	assert.Contains(t, hookshotMsg.HTML, "<p>Malware traffic detected</p>")
	assert.NotContains(t, hookshotMsg.HTML, "Severity")
	assert.NotContains(t, hookshotMsg.HTML, "<li><b>Source:</b>")
	assert.Contains(t, hookshotMsg.HTML, "<li><b>alert_id:</b> 9999</li>")
	assert.Contains(t, hookshotMsg.HTML, "<a href=\"https://soc.example.com/#/alerts/9999\">View</a>")
	assert.Contains(t, hookshotMsg.HTML, "<sub><font color=\"#737373\">Security Onion • SOC • detection</font></sub>")
}


func TestWebhookChannelSendSlackAbsoluteLinks(t *testing.T) {
	mock := &mockHTTPClient{}
	slackCh := NewSlackChannel(nil)
	slackCh.client = mock

	payload := &model.NotificationPayload{
		Title:    "PCAP #1002",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"🌐": "https://soc.example.com/#/job/1002",
			"⬇": "https://soc.example.com/api/stream/1002?ext=pcap",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://hooks.slack.com/services/T00/B00/X00",
	}

	err := slackCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var slackMsg slackMessage
	err = json.Unmarshal(mock.lastBody, &slackMsg)
	require.NoError(t, err)

	att := slackMsg.Attachments[0]
	assert.NotContains(t, att.Text, "<https://soc.example.com")
	require.NotEmpty(t, att.Fields)
	linkField := att.Fields[len(att.Fields)-1]
	assert.Contains(t, linkField.Value, "<https://soc.example.com/api/stream/1002?ext=pcap|⬇>")
	assert.Contains(t, linkField.Value, "<https://soc.example.com/#/job/1002|🌐>")
}

func TestWebhookChannelSendSlackWithRelativeLinkNoBaseUrl_NoCorruptedHtmlChars(t *testing.T) {
	mock := &mockHTTPClient{}
	slackCh := NewSlackChannel(nil)
	slackCh.client = mock

	payload := &model.NotificationPayload{
		Title:    "PCAP #1002",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"🌐": "/#/job/1002",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://hooks.slack.com/services/T00/B00/X00",
	}

	err := slackCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var slackMsg slackMessage
	err = json.Unmarshal(mock.lastBody, &slackMsg)
	require.NoError(t, err)

	att := slackMsg.Attachments[0]
	assert.NotContains(t, att.Text, "🌐")
	require.NotEmpty(t, att.Fields)
	linkField := att.Fields[len(att.Fields)-1]
	// When URL is not absolute, it should NOT output <relative_url|label> which Slack shows as raw HTML chars
	assert.NotContains(t, linkField.Value, "</#/")
	assert.Contains(t, linkField.Value, "🌐: /#/job/1002")
}

func TestWebhookChannelSendErrors(t *testing.T) {
	mock := &mockHTTPClient{
		respStatus: 500,
		respBody:   "Internal Server Error",
	}

	ch := NewWebhookChannel(nil)
	ch.client = mock

	payload := &model.NotificationPayload{Title: "Test"}
	params := map[string]interface{}{
		"url": "https://example.com/hook",
	}

	// 500 error response
	err := ch.Send(context.Background(), params, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status code 500")

	// Network error
	mock.err = errors.New("connection reset by peer")
	err = ch.Send(context.Background(), params, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webhook request failed")
}

func TestWebhookChannelSendSlack_WithBaseUrl_PrefixesRelativeLink(t *testing.T) {
	mock := &mockHTTPClient{respStatus: 200}
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}
	slackCh := NewSlackChannel(srv)
	slackCh.client = mock

	payload := &model.NotificationPayload{
		Title:    "PCAP #1002",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"🌐": "/#/job/1002",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://hooks.slack.com/services/T00/B00/X00",
	}

	err := slackCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var slackMsg slackMessage
	err = json.Unmarshal(mock.lastBody, &slackMsg)
	require.NoError(t, err)

	att := slackMsg.Attachments[0]
	// With BaseUrl set, relative link should be prefixed and formatted as <url|label> in fields
	assert.NotContains(t, att.Text, "<https://soc.example.com")
	require.NotEmpty(t, att.Fields)
	linkField := att.Fields[len(att.Fields)-1]
	assert.Contains(t, linkField.Value, "<https://soc.example.com/#/job/1002|🌐>")
}

func TestWebhookChannelSendMatrix_WithBaseUrl_PrefixesRelativeLink(t *testing.T) {
	mock := &mockHTTPClient{respStatus: 200}
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}
	matrixCh := NewMatrixChannel(srv)
	matrixCh.client = mock

	payload := &model.NotificationPayload{
		Title:    "PCAP #1002",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"🌐": "/#/job/1002",
		},
	}

	params := map[string]interface{}{
		"webhookUrl": "https://matrix.example.com/hookshot",
	}

	err := matrixCh.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var hookshotMsg matrixHookshotMessage
	err = json.Unmarshal(mock.lastBody, &hookshotMsg)
	require.NoError(t, err)

	assert.Contains(t, hookshotMsg.Text, "[🌐](https://soc.example.com/#/job/1002)")
	assert.Contains(t, hookshotMsg.HTML, "<a href=\"https://soc.example.com/#/job/1002\">🌐</a>")
}

func TestWebhookChannelSendGeneric_WithBaseUrl_PrefixesRelativeLink(t *testing.T) {
	mock := &mockHTTPClient{respStatus: 200}
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}
	ch := NewWebhookChannel(srv)
	ch.client = mock

	payload := &model.NotificationPayload{
		Title:    "PCAP #1002",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"🌐": "/#/job/1002",
		},
		Attachments: []model.Attachment{
			{Filename: "data.pcap", URL: "/api/stream/1002"},
		},
	}

	params := map[string]interface{}{
		"url": "https://example.com/generic-hook",
	}

	err := ch.Send(context.Background(), params, payload)
	require.NoError(t, err)

	var sentPayload model.NotificationPayload
	err = json.Unmarshal(mock.lastBody, &sentPayload)
	require.NoError(t, err)

	assert.Equal(t, "https://soc.example.com/#/job/1002", sentPayload.Links["🌐"])
	assert.Equal(t, "https://soc.example.com/api/stream/1002", sentPayload.Attachments[0].URL)
}

