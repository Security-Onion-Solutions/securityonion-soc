// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const (
	FormatGeneric        = "generic"
	FormatSlack          = "slack"
	FormatMatrixHookshot = "matrix_hookshot"
)

// HTTPDoer interface for testing HTTP requests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// WebhookChannel implements NotificationChannel for webhook endpoints.
type WebhookChannel struct {
	server        *server.Server
	channelType   string
	defaultFormat string
	client        HTTPDoer
}

// NewWebhookChannel constructs a generic webhook notification channel.
func NewWebhookChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "generic_webhook",
		defaultFormat: FormatGeneric,
	}
}

// NewSlackChannel constructs a Slack-specific webhook channel.
func NewSlackChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "slack_webhook",
		defaultFormat: FormatSlack,
	}
}

// NewMatrixChannel constructs a Matrix Hookshot webhook channel.
func NewMatrixChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "matrix_hookshot_webhook",
		defaultFormat: FormatMatrixHookshot,
	}
}

func (c *WebhookChannel) Type() string {
	if c.channelType != "" {
		return c.channelType
	}
	return "generic_webhook"
}

func (c *WebhookChannel) SupportsRecipients() bool {
	return false
}

func (c *WebhookChannel) SupportsAttachments() bool {
	return false
}

func (c *WebhookChannel) SupportsLinks() bool {
	return true
}

// ValidateConfig verifies that the webhook parameters are valid.
func (c *WebhookChannel) ValidateConfig(params map[string]interface{}) error {
	if params == nil {
		return errors.New("webhook configuration parameters cannot be nil")
	}

	targetURL := extractWebhookURL(params)
	if targetURL == "" {
		return errors.New("webhook url is required")
	}

	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid webhook url: %s (must be a valid http or https URL)", targetURL)
	}

	format := c.resolveFormat(params)
	switch normalizeFormat(format) {
	case FormatGeneric, FormatSlack, FormatMatrixHookshot:
		// Valid
	default:
		return fmt.Errorf("unsupported webhook format '%s' (must be 'generic', 'slack', or 'matrix_hookshot')", format)
	}

	if headersVal, ok := params["headers"]; ok && headersVal != nil {
		if _, ok := headersVal.(map[string]interface{}); !ok {
			if _, ok := headersVal.(map[string]string); !ok {
				return errors.New("webhook headers must be a key-value map")
			}
		}
	}

	return nil
}

// Send transmits the notification payload to the webhook endpoint.
func (c *WebhookChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}

	if err := c.ValidateConfig(params); err != nil {
		return fmt.Errorf("invalid webhook config: %w", err)
	}

	payload = ResolveOutboundPayload(c.server, payload)

	targetURL := extractWebhookURL(params)
	format := normalizeFormat(c.resolveFormat(params))

	bodyBytes, err := c.formatPayload(format, params, payload)
	if err != nil {
		return fmt.Errorf("failed to format webhook payload: %w", err)
	}

	method := "POST"
	if m, ok := params["method"].(string); ok && strings.TrimSpace(m) != "" {
		method = strings.ToUpper(strings.TrimSpace(m))
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SecurityOnion-Notifier/1.0")

	// Apply custom headers
	if headersVal, ok := params["headers"]; ok && headersVal != nil {
		switch h := headersVal.(type) {
		case map[string]string:
			for k, v := range h {
				req.Header.Set(k, v)
			}
		case map[string]interface{}:
			for k, v := range h {
				if strVal, ok := v.(string); ok {
					req.Header.Set(k, strVal)
				}
			}
		}
	}

	insecureSkipVerify := false
	if skipVal, ok := params["insecureSkipVerify"]; ok {
		insecureSkipVerify, _ = skipVal.(bool)
	} else if skipVal, ok := params["skipVerify"]; ok {
		insecureSkipVerify, _ = skipVal.(bool)
	}

	client := c.client
	if client == nil {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
			},
		}
		timeout := 15 * time.Second
		if timeoutVal, ok := params["timeoutSeconds"]; ok {
			if t, err := parsePort(timeoutVal); err == nil && t > 0 {
				timeout = time.Duration(t) * time.Second
			}
		}
		client = &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook returned non-2xx status code %d: %s", resp.StatusCode, strings.TrimSpace(string(bodySnippet)))
	}

	return nil
}

func (c *WebhookChannel) resolveFormat(params map[string]interface{}) string {
	if params != nil {
		if formatVal, ok := params["format"].(string); ok && strings.TrimSpace(formatVal) != "" {
			return formatVal
		}
	}
	if c.defaultFormat != "" {
		return c.defaultFormat
	}
	return FormatGeneric
}

func normalizeFormat(fmtStr string) string {
	lower := strings.ToLower(strings.TrimSpace(fmtStr))
	lower = strings.ReplaceAll(lower, "-", "_")
	switch lower {
	case "slack":
		return FormatSlack
	case "matrix", "matrix_hookshot", "hookshot":
		return FormatMatrixHookshot
	case "generic":
		return FormatGeneric
	default:
		return lower
	}
}

func extractWebhookURL(params map[string]interface{}) string {
	if params == nil {
		return ""
	}
	if urlVal, ok := params["webhookUrl"].(string); ok && strings.TrimSpace(urlVal) != "" {
		return strings.TrimSpace(urlVal)
	}
	if urlVal, ok := params["url"].(string); ok && strings.TrimSpace(urlVal) != "" {
		return strings.TrimSpace(urlVal)
	}
	return ""
}

func (c *WebhookChannel) formatPayload(format string, params map[string]interface{}, payload *model.NotificationPayload) ([]byte, error) {
	switch format {
	case FormatSlack:
		return formatSlackPayload(params, payload)
	case FormatMatrixHookshot:
		return formatMatrixHookshotPayload(params, payload)
	default:
		return json.Marshal(payload)
	}
}

type slackAttachmentField struct {
	Title string `json:"title,omitempty"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type slackAction struct {
	Type string `json:"type"`
	Text string `json:"text"`
	URL  string `json:"url"`
}

type slackAttachment struct {
	Color    string                 `json:"color,omitempty"`
	Title    string                 `json:"title,omitempty"`
	Text     string                 `json:"text,omitempty"`
	Fields   []slackAttachmentField `json:"fields,omitempty"`
	Actions  []slackAction          `json:"actions,omitempty"`
	Ts       int64                  `json:"ts,omitempty"`
	Footer   string                 `json:"footer,omitempty"`
	MrkdwnIn []string               `json:"mrkdwn_in,omitempty"`
}

type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func formatSlackPayload(params map[string]interface{}, payload *model.NotificationPayload) ([]byte, error) {
	sev := strings.ToUpper(strings.TrimSpace(payload.Severity))
	if sev == "" {
		sev = "INFO"
	}
	color := GetSeverityColor(payload.Severity)

	title := strings.TrimSpace(payload.Title)
	if title == "" {
		title = NOTIFICATION_DEFAULT_TITLE
	}

	attText := fmt.Sprintf("*[%s] %s*", sev, title)
	if payload.Summary != "" {
		attText = fmt.Sprintf("*[%s] %s*\n\n%s", sev, title, payload.Summary)
	}

	att := slackAttachment{
		Color:    color,
		Text:     attText,
		Footer:   NOTIFICATION_ATTRIBUTION,
		MrkdwnIn: []string{"text", "fields"},
	}

	if !payload.Timestamp.IsZero() {
		att.Ts = payload.Timestamp.Unix()
	} else {
		att.Ts = time.Now().UTC().Unix()
	}

	if payload.Source != "" {
		att.Footer += fmt.Sprintf(" • %s", payload.Source)
	}

	if len(payload.Fields) > 0 {
		keys := make([]string, 0, len(payload.Fields))
		for k := range payload.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			att.Fields = append(att.Fields, slackAttachmentField{
				Title: k,
				Value: payload.Fields[k],
				Short: true,
			})
		}
	}

	if len(payload.Links) > 0 {
		keys := make([]string, 0, len(payload.Links))
		for k := range payload.Links {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var linkParts []string
		for _, k := range keys {
			u := payload.Links[k]
			if u != "" {
				if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
					linkParts = append(linkParts, fmt.Sprintf("<%s|%s>", u, k))
				} else {
					linkParts = append(linkParts, fmt.Sprintf("%s: %s", k, u))
				}
			}
		}
		if len(linkParts) > 0 {
			att.Fields = append(att.Fields, slackAttachmentField{
				Value: strings.Join(linkParts, "   "),
				Short: false,
			})
		}
	}

	// Add actions for links
	if len(payload.Links) > 0 {
		keys := make([]string, 0, len(payload.Links))
		for k := range payload.Links {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			att.Actions = append(att.Actions, slackAction{
				Type: "button",
				Text: k,
				URL:  payload.Links[k],
			})
		}
	}

	msg := slackMessage{
		Attachments: []slackAttachment{att},
	}

	return json.Marshal(msg)
}

type matrixHookshotMessage struct {
	Text string `json:"text"`
	HTML string `json:"html,omitempty"`
}

func formatMatrixHookshotPayload(params map[string]interface{}, payload *model.NotificationPayload) ([]byte, error) {
	sev := strings.ToUpper(strings.TrimSpace(payload.Severity))
	if sev == "" {
		sev = "INFO"
	}
	color := GetSeverityColor(payload.Severity)

	title := strings.TrimSpace(payload.Title)
	if title == "" {
		title = NOTIFICATION_DEFAULT_TITLE
	}

	footer := NOTIFICATION_ATTRIBUTION
	if payload.Source != "" {
		footer += fmt.Sprintf(" • %s", payload.Source)
	}

	// Markdown plain text
	var mdBuf bytes.Buffer
	mdBuf.WriteString(fmt.Sprintf("### [%s] %s\n\n", sev, title))
	if payload.Summary != "" {
		mdBuf.WriteString(fmt.Sprintf("%s\n\n", payload.Summary))
	}
	if len(payload.Fields) > 0 {
		keys := make([]string, 0, len(payload.Fields))
		for k := range payload.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			mdBuf.WriteString(fmt.Sprintf("* **%s**: %s\n", k, payload.Fields[k]))
		}
	}
	if len(payload.Links) > 0 {
		mdBuf.WriteString("\n")
		keys := make([]string, 0, len(payload.Links))
		for k := range payload.Links {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			mdBuf.WriteString(fmt.Sprintf("[%s](%s) ", k, payload.Links[k]))
		}
		mdBuf.WriteString("\n")
	}
	mdBuf.WriteString(fmt.Sprintf("\n<sub>%s</sub>\n", footer))

	// HTML
	var htmlBuf bytes.Buffer
	htmlBuf.WriteString(fmt.Sprintf("<h3><span style=\"color:%s;\">[%s]</span> %s</h3>",
		color, html.EscapeString(sev), html.EscapeString(title)))
	if payload.Summary != "" {
		htmlBuf.WriteString(fmt.Sprintf("<p>%s</p>", html.EscapeString(payload.Summary)))
	}
	if len(payload.Fields) > 0 {
		htmlBuf.WriteString("<ul>")
		keys := make([]string, 0, len(payload.Fields))
		for k := range payload.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			htmlBuf.WriteString(fmt.Sprintf("<li><b>%s:</b> %s</li>",
				html.EscapeString(k), html.EscapeString(payload.Fields[k])))
		}
		htmlBuf.WriteString("</ul>")
	}

	if len(payload.Links) > 0 {
		htmlBuf.WriteString("<p>")
		keys := make([]string, 0, len(payload.Links))
		for k := range payload.Links {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			htmlBuf.WriteString(fmt.Sprintf("<a href=\"%s\">%s</a> ",
				html.EscapeString(payload.Links[k]), html.EscapeString(k)))
		}
		htmlBuf.WriteString("</p>")
	}

	htmlBuf.WriteString(fmt.Sprintf("<p><sub><font color=\"#737373\">%s</font></sub></p>", html.EscapeString(footer)))

	msg := matrixHookshotMessage{
		Text: strings.TrimSpace(mdBuf.String()),
		HTML: htmlBuf.String(),
	}

	return json.Marshal(msg)
}
