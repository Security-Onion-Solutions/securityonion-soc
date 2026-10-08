// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// SeverityColors maps notification severity to HTML hex colors.
var SeverityColors = map[string]string{
	model.NotificationSeverityCritical: "#DC2626", // Red
	model.NotificationSeverityHigh:     "#EA580C", // Orange-Red
	model.NotificationSeverityMedium:   "#F59E0B", // Amber
	model.NotificationSeverityLow:      "#3B82F6", // Blue
	model.NotificationSeverityInfo:     "#6B7280", // Gray
}

// GetSeverityColor returns the hex color for a given severity level.
func GetSeverityColor(severity string) string {
	if color, ok := SeverityColors[strings.ToLower(strings.TrimSpace(severity))]; ok {
		return color
	}
	return "#6B7280"
}

// FormatEmailSubject creates a standardized email subject line.
func FormatEmailSubject(payload *model.NotificationPayload) string {
	if payload == nil {
		return NOTIFICATION_DEFAULT_TITLE
	}
	sev, title := defaultSeverityAndTitle(payload)
	return fmt.Sprintf("[%s] %s", sev, title)
}

// FormatPlainTextBody generates a plain text email body from a NotificationPayload.
func FormatPlainTextBody(payload *model.NotificationPayload) string {
	if payload == nil {
		return ""
	}

	var buf bytes.Buffer
	sev, title := defaultSeverityAndTitle(payload)
	buf.WriteString(fmt.Sprintf("[%s] [%s]\r\n", sev, title))
	ts := payload.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	buf.WriteString(fmt.Sprintf("🗓️ %s\r\n\r\n", ts.UTC().Format("2006-01-02 15:04:05 UTC")))

	if payload.Summary != "" {
		buf.WriteString(payload.Summary)
		buf.WriteString("\r\n\r\n")
	}

	if len(payload.Fields) > 0 {
		buf.WriteString("🛈\r\n")
		for _, k := range sortedKeys(payload.Fields) {
			buf.WriteString(fmt.Sprintf("  * %s: %s\r\n", k, payload.Fields[k]))
		}
		buf.WriteString("\r\n")
	}

	if len(payload.Links) > 0 {
		buf.WriteString("🔗\r\n")
		for _, k := range sortedKeys(payload.Links) {
			buf.WriteString(fmt.Sprintf("  * %s: %s\r\n", k, payload.Links[k]))
		}
		buf.WriteString("\r\n")
	}

	if len(payload.Attachments) > 0 {
		buf.WriteString("📎\r\n")
		for _, att := range payload.Attachments {
			if att.URL != "" {
				buf.WriteString(fmt.Sprintf("  * %s (%s): %s\r\n", att.Filename, att.ContentType, att.URL))
			} else {
				buf.WriteString(fmt.Sprintf("  * %s (%s)\r\n", att.Filename, att.ContentType))
			}
		}
		buf.WriteString("\r\n")
	}

	buf.WriteString("----------------------------------------------------------------------\r\n")
	suffix := ""
	if payload.Source != "" {
		suffix = fmt.Sprintf(" • %s", payload.Source)
	}
	buf.WriteString(fmt.Sprintf("%s%s\r\n", NOTIFICATION_ATTRIBUTION, suffix))

	return buf.String()
}

// FormatHTMLBody generates a styled, responsive HTML email body from a NotificationPayload.
func FormatHTMLBody(payload *model.NotificationPayload) string {
	if payload == nil {
		return ""
	}

	sev, title := defaultSeverityAndTitle(payload)
	color := GetSeverityColor(payload.Severity)

	ts := payload.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	timeFormatted := ts.UTC().Format("2006-01-02 15:04:05 UTC")

	var buf bytes.Buffer
	buf.WriteString("<!DOCTYPE html>\r\n<html>\r\n<head>\r\n")
	buf.WriteString("<meta charset=\"UTF-8\">\r\n")
	buf.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n")
	buf.WriteString("<style>\r\n")
	buf.WriteString("  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.5; color: #1f2937; background-color: #f3f4f6; margin: 0; padding: 20px; }\r\n")
	buf.WriteString("  .container { width: 100%; max-width: 800px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #e5e7eb; box-sizing: border-box; }\r\n")
	buf.WriteString("  .header { padding: 18px 24px; color: #ffffff; display: flex; align-items: center; flex-wrap: wrap; word-break: break-word; }\r\n")
	buf.WriteString("  .header-badge { display: inline-block; padding: 4px 10px; margin-right: 12px; border-radius: 4px; background-color: rgba(255,255,255,0.25); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; flex-shrink: 0; vertical-align: middle; }\r\n")
	buf.WriteString("  .header-title { font-size: 18px; font-weight: 700; color: #ffffff; margin: 0; flex: 1 1 auto; min-width: 0; word-break: break-word; vertical-align: middle; }\r\n")
	buf.WriteString("  .content { padding: 24px; }\r\n")
	buf.WriteString("  .meta { font-size: 13px; color: #6b7280; margin-bottom: 20px; }\r\n")
	buf.WriteString("  .summary { font-size: 15px; line-height: 1.6; color: #374151; margin-bottom: 20px; white-space: pre-wrap; word-break: break-word; }\r\n")
	buf.WriteString("  .section-heading { font-size: 14px; font-weight: 700; text-transform: uppercase; color: #4b5563; margin: 20px 0 10px 0; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }\r\n")
	buf.WriteString("  table.fields { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }\r\n")
	buf.WriteString("  table.fields td { padding: 8px 12px; border-bottom: 1px solid #f3f4f6; }\r\n")
	buf.WriteString("  table.fields td.key { font-weight: 600; color: #4b5563; width: 30%; background-color: #f9fafb; }\r\n")
	buf.WriteString("  table.fields td.val { color: #111827; word-break: break-all; }\r\n")
	buf.WriteString("  .btn-link { display: inline-block; padding: 9px 18px; background-color: #2563eb; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; margin-right: 10px; margin-bottom: 8px; cursor: pointer; }\r\n")
	buf.WriteString("  .attachments-list { font-size: 14px; color: #4b5563; margin-bottom: 20px; }\r\n")
	buf.WriteString("  .attachments-list a { color: #2563eb; text-decoration: underline; }\r\n")
	buf.WriteString("  .footer { padding: 16px 24px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }\r\n")
	buf.WriteString("</style>\r\n</head>\r\n<body>\r\n")

	buf.WriteString("<div class=\"container\">\r\n")
	buf.WriteString(fmt.Sprintf("  <div class=\"header\" style=\"background-color: %s;\">\r\n", color))
	buf.WriteString(fmt.Sprintf("    <span class=\"header-badge\">%s</span>\r\n", html.EscapeString(sev)))
	buf.WriteString(fmt.Sprintf("    <span class=\"header-title\">%s</span>\r\n", html.EscapeString(title)))
	buf.WriteString("  </div>\r\n")

	buf.WriteString("  <div class=\"content\">\r\n")
	buf.WriteString(fmt.Sprintf("    <div class=\"meta\">🗓️ %s", html.EscapeString(timeFormatted)))
	buf.WriteString("</div>\r\n")

	if payload.Summary != "" {
		buf.WriteString(fmt.Sprintf("    <div class=\"summary\">%s</div>\r\n", html.EscapeString(payload.Summary)))
	}

	if len(payload.Fields) > 0 {
		buf.WriteString("    <div class=\"section-heading\">🛈</div>\r\n")
		buf.WriteString("    <table class=\"fields\">\r\n")
		for _, k := range sortedKeys(payload.Fields) {
			buf.WriteString(fmt.Sprintf("      <tr><td class=\"key\">%s</td><td class=\"val\">%s</td></tr>\r\n",
				html.EscapeString(k), html.EscapeString(payload.Fields[k])))
		}
		buf.WriteString("    </table>\r\n")
	}

	if len(payload.Links) > 0 {
		buf.WriteString("    <div class=\"section-heading\">🔗</div>\r\n")
		buf.WriteString("    <div style=\"margin: 20px 0;\">\r\n")
		for _, k := range sortedKeys(payload.Links) {
			url := payload.Links[k]
			// Duplicate button styling inline as well as in .btn-link CSS class because
			// many email clients strip head style blocks and require inline styles.
			buf.WriteString(fmt.Sprintf("      <a class=\"btn-link\" style=\"display: inline-block; padding: 9px 18px; background-color: #2563eb; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; margin-right: 10px; margin-bottom: 8px; cursor: pointer;\" href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a>\r\n",
				html.EscapeString(url), html.EscapeString(k)))
		}
		buf.WriteString("    </div>\r\n")
	}

	if len(payload.Attachments) > 0 {
		buf.WriteString("    <div class=\"section-heading\">📎</div>\r\n")
		buf.WriteString("    <div class=\"attachments-list\">\r\n      <ul>\r\n")
		for _, att := range payload.Attachments {
			if att.URL != "" {
				buf.WriteString(fmt.Sprintf("        <li><a href=\"%s\" target=\"_blank\">%s</a> (%s)</li>\r\n",
					html.EscapeString(att.URL), html.EscapeString(att.Filename), html.EscapeString(att.ContentType)))
			} else {
				buf.WriteString(fmt.Sprintf("        <li>%s (%s)</li>\r\n",
					html.EscapeString(att.Filename), html.EscapeString(att.ContentType)))
			}
		}
		buf.WriteString("      </ul>\r\n    </div>\r\n")
	}

	buf.WriteString("  </div>\r\n")
	buf.WriteString("  <div class=\"footer\">\r\n")
	buf.WriteString("    " + NOTIFICATION_ATTRIBUTION)
	if payload.Source != "" {
		buf.WriteString(fmt.Sprintf(" • %s", html.EscapeString(payload.Source)))
	}
	buf.WriteString("\r\n")
	buf.WriteString("  </div>\r\n")
	buf.WriteString("</div>\r\n</body>\r\n</html>\r\n")

	return buf.String()
}

func encodeQuotedPrintable(s string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.String()
}

func writeAlternativePart(buf *bytes.Buffer, altBoundary string, plainBody, htmlBody string) {
	// Plain text part
	buf.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	buf.WriteString(encodeQuotedPrintable(plainBody))
	buf.WriteString("\r\n\r\n")

	// HTML part
	buf.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	buf.WriteString(encodeQuotedPrintable(htmlBody))
	buf.WriteString("\r\n\r\n")

	buf.WriteString(fmt.Sprintf("--%s--\r\n", altBoundary))
}

// BuildMIMEMessage formats a full RFC 2045/2046/5322 MIME multipart message.
func BuildMIMEMessage(from string, to []string, subject string, plainBody string, htmlBody string, attachments []model.Attachment, attachmentMode string) ([]byte, error) {
	if from == "" {
		return nil, fmt.Errorf("from address cannot be empty")
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("to recipient list cannot be empty")
	}

	var buf bytes.Buffer

	// Headers
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	buf.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", uuid.New().String(), extractHostFromEmail(from)))
	buf.WriteString("MIME-Version: 1.0\r\n")

	includeRawAttachments := (attachmentMode == model.AttachmentModeAttach || attachmentMode == model.AttachmentModeBoth || attachmentMode == "") && hasRawAttachments(attachments)

	if includeRawAttachments {
		mixedBoundary := fmt.Sprintf("mixed_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
		altBoundary := fmt.Sprintf("alt_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))

		buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", mixedBoundary))

		// Alternative body part
		buf.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", altBoundary))
		writeAlternativePart(&buf, altBoundary, plainBody, htmlBody)
		buf.WriteString("\r\n")

		// Attachments
		for _, att := range attachments {
			if len(att.Data) == 0 {
				continue
			}
			contentType := att.ContentType
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			filename := att.Filename
			if filename == "" {
				filename = "attachment"
			}

			buf.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))
			buf.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, filename))
			buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", filename))
			buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

			encodedData := base64.StdEncoding.EncodeToString(att.Data)
			for i := 0; i < len(encodedData); i += 76 {
				end := i + 76
				if end > len(encodedData) {
					end = len(encodedData)
				}
				buf.WriteString(encodedData[i:end])
				buf.WriteString("\r\n")
			}
			buf.WriteString("\r\n")
		}

		buf.WriteString(fmt.Sprintf("--%s--\r\n", mixedBoundary))
	} else {
		altBoundary := fmt.Sprintf("alt_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", altBoundary))
		writeAlternativePart(&buf, altBoundary, plainBody, htmlBody)
	}

	return buf.Bytes(), nil
}

func hasRawAttachments(attachments []model.Attachment) bool {
	for _, att := range attachments {
		if len(att.Data) > 0 {
			return true
		}
	}
	return false
}

func extractHostFromEmail(emailAddr string) string {
	parsed, err := mail.ParseAddress(emailAddr)
	if err == nil && parsed.Address != "" {
		emailAddr = parsed.Address
	}
	parts := strings.Split(emailAddr, "@")
	if len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return "securityonion.local"
}
