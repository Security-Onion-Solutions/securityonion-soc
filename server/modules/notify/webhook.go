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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apex/log"
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
	timeout       time.Duration
}

// NewWebhookChannel constructs a generic webhook notification channel.
func NewWebhookChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "generic_webhook",
		defaultFormat: FormatGeneric,
		timeout:       time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second,
	}
}

// NewSlackChannel constructs a Slack-specific webhook channel.
func NewSlackChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "slack_webhook",
		defaultFormat: FormatSlack,
		timeout:       time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second,
	}
}

// NewMatrixChannel constructs a Matrix Hookshot webhook channel.
func NewMatrixChannel(srv *server.Server) *WebhookChannel {
	return &WebhookChannel{
		server:        srv,
		channelType:   "matrix_hookshot_webhook",
		defaultFormat: FormatMatrixHookshot,
		timeout:       time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second,
	}
}

// SetTimeout sets the default request timeout for the webhook client.
func (c *WebhookChannel) SetTimeout(d time.Duration) {
	if d > 0 {
		c.timeout = d
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

	// The URL is the credential, so it never goes in the error, which is logged.
	parsed, err := url.ParseRequestURI(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("invalid webhook url (must be a valid http or https URL)")
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

	headers := webhookHeaders(params)
	redactor := newWebhookRedactor(targetURL, headers)

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return redactor.wrap("failed to create http request", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SecurityOnion-Notifier/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := c.client
	if client == nil {
		client = c.buildHTTPClient(params)
	}

	resp, err := client.Do(req)
	if err != nil {
		return redactor.wrap("webhook request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, webhookErrorBodyReadMax))
		return fmt.Errorf("webhook returned non-2xx status code %d: %s", resp.StatusCode, redactor.body(body))
	}

	return nil
}

func webhookHeaders(params map[string]interface{}) map[string]string {
	headers := map[string]string{}
	switch h := params["headers"].(type) {
	case map[string]string:
		for k, v := range h {
			headers[k] = v
		}
	case map[string]interface{}:
		for k, v := range h {
			if strVal, ok := v.(string); ok {
				headers[k] = strVal
			}
		}
	}
	return headers
}

const (
	webhookErrorBodyReadMax = 2048
	webhookErrorBodyMax     = 1024
	// Shorter values are too likely to be ordinary text in an error.
	webhookRedactMinLength = 4
)

// webhookRedactor removes a webhook's credentials, its URL and header values, from error text.
type webhookRedactor struct {
	terms []string
}

func newWebhookRedactor(targetURL string, headers map[string]string) *webhookRedactor {
	values := []string{targetURL}
	if parsed, err := url.Parse(targetURL); err == nil {
		values = append(values, parsed.Path, parsed.EscapedPath(), parsed.RawQuery)
		if parsed.RawQuery != "" {
			values = append(values, parsed.Path+"?"+parsed.RawQuery, parsed.EscapedPath()+"?"+parsed.RawQuery)
		}
		values = append(values, strings.Split(parsed.Path, "/")...)
		for _, queryValues := range parsed.Query() {
			values = append(values, queryValues...)
		}
		if parsed.User != nil {
			if password, ok := parsed.User.Password(); ok {
				values = append(values, password, base64.StdEncoding.EncodeToString([]byte(parsed.User.Username()+":"+password)))
			}
		}
	}
	for _, value := range headers {
		values = append(values, value)
		values = append(values, strings.Fields(value)...)
	}

	r := &webhookRedactor{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "/" || utf8.RuneCountInString(value) < webhookRedactMinLength {
			continue
		}
		quoted, _ := json.Marshal(value)
		forms := []string{value, string(quoted[1 : len(quoted)-1]), strings.ReplaceAll(value, "/", `\/`), url.QueryEscape(value), url.PathEscape(value)}
		for _, form := range forms {
			if !seen[form] {
				seen[form] = true
				r.terms = append(r.terms, form)
			}
		}
	}
	// Longest first, so a term inside a longer one never leaves the rest of it behind.
	slices.SortFunc(r.terms, func(a, b string) int { return len(b) - len(a) })

	return r
}

func (r *webhookRedactor) redact(text string) string {
	for _, term := range r.terms {
		text = strings.ReplaceAll(text, term, "[redacted]")
	}
	return text
}

// wrap drops a *url.Error's URL, then redacts what remains.
func (r *webhookRedactor) wrap(msg string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return errors.New(msg + ": " + r.redact(err.Error()))
}

// body redacts before cutting, so a secret across the cut can't leave a prefix behind.
func (r *webhookRedactor) body(body []byte) string {
	text := r.redact(string(body))
	if len(body) >= webhookErrorBodyReadMax {
		// Only the tail can hold a copy cut off by the read.
		text = r.trimPartialTerm(text)
	}
	if len(text) > webhookErrorBodyMax {
		text = text[:webhookErrorBodyMax]
	}
	return strings.TrimSpace(strings.ToValidUTF8(text, ""))
}

// trimPartialTerm drops the longest end of text that is the start of a term.
func (r *webhookRedactor) trimPartialTerm(text string) string {
	cut := 0
	for _, term := range r.terms {
		for n := min(len(term)-1, len(text)); n > cut; n-- {
			if strings.HasSuffix(text, term[:n]) {
				cut = n
				break
			}
		}
	}
	return text[:len(text)-cut]
}

func (c *WebhookChannel) buildHTTPClient(params map[string]interface{}) *http.Client {
	insecureSkipVerify := false
	if params != nil {
		if skipVal, ok := params["insecureSkipVerify"]; ok {
			insecureSkipVerify, _ = skipVal.(bool)
		}
	}

	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	} else {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		}
	}

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}

	if c.server != nil && c.server.Config != nil && c.server.Config.Proxy != "" {
		p, err := url.Parse(c.server.Config.Proxy)
		if err != nil {
			log.WithError(err).WithField("proxy", c.server.Config.Proxy).Error("unable to parse proxy URL, not using proxy")
		} else {
			transport.Proxy = http.ProxyURL(p)
		}
	}

	timeout := c.timeout
	if timeout <= 0 {
		timeout = time.Duration(DEFAULT_CONNECTION_TIMEOUT_SECONDS) * time.Second
	}
	if params != nil {
		if timeoutVal, ok := params["timeoutSeconds"]; ok {
			if t, err := parsePort(timeoutVal); err == nil && t > 0 {
				timeout = time.Duration(t) * time.Second
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
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

type slackAttachment struct {
	Color    string                 `json:"color,omitempty"`
	Title    string                 `json:"title,omitempty"`
	Text     string                 `json:"text,omitempty"`
	Fields   []slackAttachmentField `json:"fields,omitempty"`
	Ts       int64                  `json:"ts,omitempty"`
	Footer   string                 `json:"footer,omitempty"`
	MrkdwnIn []string               `json:"mrkdwn_in,omitempty"`
}

type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func formatSlackPayload(params map[string]interface{}, payload *model.NotificationPayload) ([]byte, error) {
	sev, title := defaultSeverityAndTitle(payload)
	color := GetSeverityColor(payload.Severity)

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
		for _, k := range sortedKeys(payload.Fields) {
			att.Fields = append(att.Fields, slackAttachmentField{
				Title: k,
				Value: payload.Fields[k],
				Short: true,
			})
		}
	}

	if len(payload.Links) > 0 {
		var linkParts []string
		for _, k := range sortedKeys(payload.Links) {
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
	sev, title := defaultSeverityAndTitle(payload)
	color := GetSeverityColor(payload.Severity)

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
		for _, k := range sortedKeys(payload.Fields) {
			mdBuf.WriteString(fmt.Sprintf("* **%s**: %s\n", k, payload.Fields[k]))
		}
	}
	if len(payload.Links) > 0 {
		mdBuf.WriteString("\n")
		for _, k := range sortedKeys(payload.Links) {
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
		for _, k := range sortedKeys(payload.Fields) {
			htmlBuf.WriteString(fmt.Sprintf("<li><b>%s:</b> %s</li>",
				html.EscapeString(k), html.EscapeString(payload.Fields[k])))
		}
		htmlBuf.WriteString("</ul>")
	}

	if len(payload.Links) > 0 {
		htmlBuf.WriteString("<p>")
		for _, k := range sortedKeys(payload.Links) {
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
