// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

const (
	NotificationSeverityInfo     = "info"
	NotificationSeverityLow      = "low"
	NotificationSeverityMedium   = "medium"
	NotificationSeverityHigh     = "high"
	NotificationSeverityCritical = "critical"

	SourceDetection = "detection"
	SourceMetric    = "metric"
	SourceAgentAI   = "agent_ai"
	SourceReport    = "report"

	AttachmentModeLink   = "link"
	AttachmentModeAttach = "attach"
	AttachmentModeBoth   = "both"

	DefaultDestinationSOCBell = "soc-bell"
	ChannelTypeSOC            = "soc"
)

// @Description Attachment represents a file or graph payload to be sent with a notification.
type Attachment struct {
	// The filename of the attachment.
	Filename string `json:"filename" example:"alert-report.pdf"`
	// The MIME content type of the attachment.
	ContentType string `json:"contentType" example:"application/pdf"`
	// The raw binary data of the attachment when embedded directly.
	Data []byte `json:"data,omitempty" swaggerignore:"true"`
	// Direct download URL if the attachment is hosted by SOC.
	URL string `json:"url,omitempty" example:"https://soc.example.com/api/reports/123/download"`
}

// @Description NotificationPayload is the context-agnostic structure sent to notification destinations.
type NotificationPayload struct {
	// The unique identifier for this notification.
	ID string `json:"id" example:"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`
	// The source subsystem that originated this notification.
	Source string `json:"source" example:"detection" enums:"detection,metric,agent_ai,report"`
	// The brief title or headline of the notification.
	Title string `json:"title" example:"ET SCAN Potential SSH Scan"`
	// A human-readable summary describing the notification details.
	Summary string `json:"summary" example:"Inbound SSH scan detected from 192.168.1.100 against multiple internal hosts."`
	// The severity classification of this notification.
	Severity string `json:"severity" example:"high" enums:"info,low,medium,high,critical"`
	// The timestamp when this notification event occurred.
	Timestamp time.Time `json:"timestamp" example:"2026-08-17T12:00:00Z"`
	// Structured key-value fields providing context (e.g. host, IP, metric name).
	Fields map[string]string `json:"fields,omitempty" example:"src_ip:192.168.1.100,dst_ip:10.0.0.1"`
	// Deep-links back to relevant views or dashboards in SOC.
	Links map[string]string `json:"links,omitempty" example:"View in SOC:https://soc.example.com/#/alerts/123"`
	// Optional binary or URL attachments associated with this notification.
	Attachments []Attachment `json:"attachments,omitempty"`
	// Unique key used for duration silencing and debouncing.
	SilenceKey string `json:"silenceKey,omitempty" example:"detection:sigma:12345:192.168.1.100"`
}

// @Description SilenceParams specifies duration silencing parameters for debouncing alerts.
type SilenceParams struct {
	// Unique key used to evaluate suppression (e.g. source + rule ID + target).
	SilenceKey string `json:"silenceKey" example:"detection:sigma:12345:192.168.1.100"`
	// The duration window to suppress subsequent notifications after a trigger.
	SilenceDuration time.Duration `json:"silenceDuration" swaggertype:"primitive,integer" example:"900000000000"`
	// Number of triggers within the window before a notification is dispatched.
	ThresholdCount int `json:"thresholdCount,omitempty" example:"3"`
}

// @Description DestinationConfig defines the configuration for an individual notification destination channel.
type DestinationConfig struct {
	// Human-readable display name for this destination.
	Name string `json:"name" example:"SOC Notification Bell"`
	// The channel driver type (e.g. soc, smtp, slack, matrix, msteams, pagerduty, webhook).
	Type string `json:"type" example:"soc" enums:"soc,smtp,slack,matrix,msteams,pagerduty,webhook"`
	// Indicates whether this destination is currently active and receiving alerts.
	Enabled bool `json:"enabled" example:"true"`
	// Channel-specific driver parameters (e.g. webhook URLs, hostnames, credentials).
	Params map[string]interface{} `json:"params,omitempty"`
}

// @Description NotificationConfig defines the top-level configuration for the notification subsystem.
type NotificationConfig struct {
	// Indicates whether the notification subsystem is globally enabled.
	Enabled bool `json:"enabled" example:"true"`
	// The list of default destination names used when no specific destination is requested.
	DefaultDestinations []string `json:"defaultDestinations" example:"soc-bell"`
	// Global silence window in seconds applied to debounced notifications.
	GlobalSilenceWindowSeconds int `json:"globalSilenceWindowSeconds" example:"300"`
	// Map of configured notification destinations keyed by destination identifier.
	Destinations map[string]DestinationConfig `json:"destinations,omitempty"`
}
