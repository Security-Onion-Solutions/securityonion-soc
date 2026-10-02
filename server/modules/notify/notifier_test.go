// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

type mockChannel struct {
	channelType         string
	supportsRecipients  bool
	supportsAttachments bool
	supportsLinks       bool
	mu                  sync.Mutex
	sentPayload         *model.NotificationPayload
	sentParams          map[string]interface{}
	sendErr             error
}

func (m *mockChannel) Type() string {
	return m.channelType
}

func (m *mockChannel) SupportsRecipients() bool {
	return m.supportsRecipients
}

func (m *mockChannel) SupportsAttachments() bool {
	return m.supportsAttachments
}

func (m *mockChannel) SupportsLinks() bool {
	return m.supportsLinks
}

func (m *mockChannel) ValidateConfig(params map[string]interface{}) error {
	return nil
}

func (m *mockChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentPayload = payload
	m.sentParams = params
	return m.sendErr
}

func TestNotifierSendNilPayload(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	cfg := model.NotificationConfig{Enabled: true}
	notifier := NewNotifier(nil, reg, cfg)

	count, err := notifier.Send(context.Background(), nil)
	assert.Error(t, err)
	assert.Equal(t, 0, count)
}

func TestNotifierSendDisabled(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	cfg := model.NotificationConfig{Enabled: false}
	notifier := NewNotifier(nil, reg, cfg)

	payload := &model.NotificationPayload{Title: "Test"}
	count, err := notifier.Send(context.Background(), payload)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestNotifierSend_Unlicensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_API, 0, 0, "", "")

	reg := NewChannelRegistry()
	mockCh := &mockChannel{channelType: "soc"}
	_ = reg.Register(mockCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"soc-bell": {
				Name:    "SOC Bell",
				Type:    "soc",
				Enabled: true,
				Params:  map[string]interface{}{"storeInPostgres": true},
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	payload := &model.NotificationPayload{
		Title:    "Alert 1",
		Severity: model.NotificationSeverityHigh,
	}

	// Without NTF license, Send should skip dispatch and not invoke the channel driver
	count, err := notifier.Send(context.Background(), payload)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, mockCh.sentPayload)
}

func TestNotifierSendAllConfiguredDestinations(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	mockCh := &mockChannel{channelType: "soc"}
	_ = reg.Register(mockCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"soc-bell": {
				Name:    "SOC Bell",
				Type:    "soc",
				Enabled: true,
				Params:  map[string]interface{}{"storeInPostgres": true},
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	payload := &model.NotificationPayload{
		Title:    "Alert 1",
		Severity: model.NotificationSeverityHigh,
	}

	count, err := notifier.Send(context.Background(), payload)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, mockCh.sentPayload)
	assert.Equal(t, true, mockCh.sentParams["storeInPostgres"])
}

func TestNotifierSendExplicitDestinations(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	slackCh := &mockChannel{channelType: "slack"}
	emailCh := &mockChannel{channelType: "smtp"}
	_ = reg.Register(slackCh)
	_ = reg.Register(emailCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"default-email": {
				Name:    "Email",
				Type:    "smtp",
				Enabled: true,
			},
			"slack-sec": {
				Name:    "Slack",
				Type:    "slack",
				Enabled: true,
			},
			"disabled-dest": {
				Name:    "Disabled",
				Type:    "slack",
				Enabled: false,
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	payload := &model.NotificationPayload{Title: "Security Finding"}

	// Send explicitly to slack-sec and disabled-dest
	count, err := notifier.Send(context.Background(), payload, "slack-sec", "disabled-dest")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, slackCh.sentPayload)
	assert.Nil(t, emailCh.sentPayload)
}

func TestNotifierSendErrors(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	failingCh := &mockChannel{
		channelType: "smtp",
		sendErr:     errors.New("SMTP connection timeout"),
	}
	_ = reg.Register(failingCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"email-dest": {
				Name:    "Email",
				Type:    "smtp",
				Enabled: true,
			},
			"missing-driver": {
				Name:    "Matrix",
				Type:    "matrix",
				Enabled: true,
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	payload := &model.NotificationPayload{Title: "Error Test"}
	count, err := notifier.Send(context.Background(), payload, "email-dest", "missing-dest", "missing-driver")
	assert.Error(t, err)
	assert.Equal(t, 0, count)
	assert.Contains(t, err.Error(), "destination 'missing-dest' not found")
	assert.Contains(t, err.Error(), "channel driver 'matrix' not found for destination 'missing-driver'")
	assert.Contains(t, err.Error(), "destination 'email-dest' send failed")
}

func TestNotifierSendWithSilence(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	mockCh := &mockChannel{channelType: "soc"}
	_ = reg.Register(mockCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"soc-bell": {
				Name:    "SOC Bell",
				Type:    "soc",
				Enabled: true,
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	// First send: should succeed and dispatch
	payload1 := &model.NotificationPayload{Source: "detection", Title: "Silenced Alert 1"}
	silence1 := &model.SilenceParams{
		SilenceKey:      "unique-silence-key",
		SilenceDuration: 15 * time.Minute,
		ThresholdCount:  1,
	}

	err := notifier.SendWithSilence(context.Background(), payload1, silence1)
	assert.NoError(t, err)
	assert.Equal(t, "unique-silence-key", payload1.SilenceKey)
	assert.Equal(t, payload1, mockCh.sentPayload)

	// Second send with same key within window: should suppress (sentPayload remains payload1)
	mockCh.sentPayload = nil
	payload2 := &model.NotificationPayload{Source: "detection", Title: "Silenced Alert 2"}
	err = notifier.SendWithSilence(context.Background(), payload2, silence1)
	assert.NoError(t, err)
	assert.Nil(t, mockCh.sentPayload)

	// Send with ThresholdCount = 3: should suppress first 2 times, then dispatch on 3rd
	mockCh.sentPayload = nil
	silence3 := &model.SilenceParams{
		SilenceKey:      "threshold-silence-key",
		SilenceDuration: 15 * time.Minute,
		ThresholdCount:  3,
	}

	p1 := &model.NotificationPayload{Source: "detection", Title: "T1"}
	p2 := &model.NotificationPayload{Source: "detection", Title: "T2"}
	p3 := &model.NotificationPayload{Source: "detection", Title: "T3"}

	// Trigger 1 (suppressed)
	err = notifier.SendWithSilence(context.Background(), p1, silence3)
	assert.NoError(t, err)
	assert.Nil(t, mockCh.sentPayload)

	// Trigger 2 (suppressed)
	err = notifier.SendWithSilence(context.Background(), p2, silence3)
	assert.NoError(t, err)
	assert.Nil(t, mockCh.sentPayload)

	// Trigger 3 (dispatched!)
	err = notifier.SendWithSilence(context.Background(), p3, silence3)
	assert.NoError(t, err)
	assert.Equal(t, p3, mockCh.sentPayload)
}

func TestNotifierGettersAndUpdateConfig(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"soc-bell": {
				Name:    "SOC Bell",
				Type:    "soc",
				Enabled: true,
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	dests := notifier.GetDestinations()
	assert.Len(t, dests, 1)

	// Test RegisterChannel & GetChannel via notifier
	ch := &mockChannel{channelType: "test-ch"}
	notifier.RegisterChannel(ch)
	retrieved, found := notifier.GetChannel("test-ch")
	assert.True(t, found)
	assert.Equal(t, ch, retrieved)

	// UpdateConfig
	newCfg := model.NotificationConfig{
		Enabled:      false,
		Destinations: map[string]model.DestinationConfig{},
	}
	notifier.UpdateConfig(newCfg)
	assert.Empty(t, notifier.GetDestinations())
}

func TestNotifierSendSeverityFiltering(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	mockCh := &mockChannel{channelType: "soc"}
	_ = reg.Register(mockCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"critical-only": {
				Name:       "Critical Alerts Only",
				Type:       "soc",
				Enabled:    true,
				Severities: []string{model.NotificationSeverityHigh, model.NotificationSeverityCritical},
			},
		},
	}
	notifier := NewNotifier(nil, reg, cfg)

	// Low severity should be skipped
	lowPayload := &model.NotificationPayload{
		Title:    "Low alert",
		Severity: model.NotificationSeverityLow,
	}
	count, err := notifier.Send(context.Background(), lowPayload)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, mockCh.sentPayload)

	// High severity should be delivered
	highPayload := &model.NotificationPayload{
		Title:    "High alert",
		Severity: model.NotificationSeverityHigh,
	}
	count, err = notifier.Send(context.Background(), highPayload)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, highPayload, mockCh.sentPayload)

	// Critical severity should be delivered
	mockCh.sentPayload = nil
	critPayload := &model.NotificationPayload{
		Title:    "Critical alert",
		Severity: model.NotificationSeverityCritical,
	}
	count, err = notifier.Send(context.Background(), critPayload)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, critPayload, mockCh.sentPayload)

	// Client notification with filtered severity should still be filtered out
	mockCh.sentPayload = nil
	testLowPayload := &model.NotificationPayload{
		Title:    "Client Low Alert",
		Severity: model.NotificationSeverityLow,
		Source:   model.SourceClient,
	}
	count, err = notifier.Send(context.Background(), testLowPayload)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, mockCh.sentPayload)
}

func TestNotifierSendScheduleEvaluation(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	mockCh := &mockChannel{channelType: "soc"}
	_ = reg.Register(mockCh)

	activeSched := model.Schedule{
		ID:       "sched-active",
		Name:     "Always Active Schedule",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []model.ScheduleDefinition{
			{
				Type:   model.ScheduleTypeDaily,
				AllDay: true,
			},
		},
	}

	inactiveSched := model.Schedule{
		ID:          "sched-inactive",
		Name:        "Disabled Schedule",
		Enabled:     false,
		Timezone:    "UTC",
		Definitions: []model.ScheduleDefinition{},
	}

	schedulesJSON, _ := json.Marshal([]model.Schedule{activeSched, inactiveSched})
	srv := &server.Server{
		Configstore: server.NewMemConfigStore([]*model.Setting{
			{
				Id:    "soc.config.server.schedules",
				Value: string(schedulesJSON),
			},
		}),
	}

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"dest-active": {
				Name:        "Active Scheduled Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{"sched-active"},
			},
			"dest-inactive": {
				Name:        "Inactive Scheduled Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{"sched-inactive"},
			},
			"dest-multi": {
				Name:        "Multi Scheduled Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{"sched-inactive", "sched-active"},
			},
			"dest-no-sched": {
				Name:        "No Schedule Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{},
			},
			"dest-all-inactive": {
				Name:        "All Inactive Multi Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{"sched-inactive", "sched-inactive"},
			},
			"dest-unknown": {
				Name:        "Unknown Schedule Dest",
				Type:        "soc",
				Enabled:     true,
				ScheduleIDs: []string{"sched-does-not-exist"},
			},
		},
	}
	notifier := NewNotifier(srv, reg, cfg)

	payload := &model.NotificationPayload{
		Title:    "Scheduled Alert",
		Severity: model.NotificationSeverityInfo,
	}

	// Active schedule dest should receive payload
	count, err := notifier.Send(context.Background(), payload, "dest-active")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, mockCh.sentPayload)

	// Multi schedule dest with at least one active schedule should receive payload
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-multi")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, mockCh.sentPayload)

	// Destination with no schedules (empty ScheduleIDs) is always active
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-no-sched")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, mockCh.sentPayload)

	// Inactive schedule dest should be skipped when BypassSchedules is false
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-inactive")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, mockCh.sentPayload)

	// Inactive schedule dest should NOT be skipped when BypassSchedules is true
	bypassPayload := &model.NotificationPayload{
		Title:           "Bypass Notification",
		Severity:        model.NotificationSeverityInfo,
		Source:          model.SourceClient,
		BypassSchedules: true,
	}
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), bypassPayload, "dest-inactive")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, bypassPayload, mockCh.sentPayload)

	// Multi schedule with all inactive schedules should be skipped
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-all-inactive")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, mockCh.sentPayload)

	// Unknown schedule ID should fail open and receive payload
	mockCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-unknown")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, payload, mockCh.sentPayload)
}

func TestNotifierSend_RecipientTargeting(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	socCh := &mockChannel{channelType: "soc", supportsRecipients: true}
	webhookCh := &mockChannel{channelType: "webhook", supportsRecipients: false}
	_ = reg.Register(socCh)
	_ = reg.Register(webhookCh)

	enableTrue := true
	enableFalse := false

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"soc-default": {
				Type:    "soc",
				Enabled: true,
			},
			"soc-enabled": {
				Type:             "soc",
				Enabled:          true,
				EnableRecipients: &enableTrue,
			},
			"soc-disabled-noskip": {
				Type:             "soc",
				Enabled:          true,
				EnableRecipients: &enableFalse,
				SkipIfRecipients: false,
			},
			"soc-disabled-skip": {
				Type:             "soc",
				Enabled:          true,
				EnableRecipients: &enableFalse,
				SkipIfRecipients: true,
			},
			"webhook-noskip": {
				Type:             "webhook",
				Enabled:          true,
				SkipIfRecipients: false,
			},
			"webhook-skip": {
				Type:             "webhook",
				Enabled:          true,
				SkipIfRecipients: true,
			},
		},
	}

	notifier := NewNotifier(nil, reg, cfg)
	targetedPayload := &model.NotificationPayload{
		ID:         "target-1",
		Source:     model.SourcePcap,
		Title:      "PCAP #100",
		Severity:   model.NotificationSeverityInfo,
		Recipients: []string{"user-123"},
	}

	// 1. SOC Default (supports and defaults to enabled): receives targeted payload
	socCh.sentPayload = nil
	count, err := notifier.Send(context.Background(), targetedPayload, "soc-default")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, socCh.sentPayload)
	assert.Equal(t, []string{"user-123"}, socCh.sentPayload.Recipients)

	// 2. SOC Explicitly Enabled: receives targeted payload
	socCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), targetedPayload, "soc-enabled")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, socCh.sentPayload)
	assert.Equal(t, []string{"user-123"}, socCh.sentPayload.Recipients)

	// 3. SOC Disabled, SkipIfRecipients=false: receives untargeted payload (Recipients = nil)
	socCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), targetedPayload, "soc-disabled-noskip")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, socCh.sentPayload)
	assert.Nil(t, socCh.sentPayload.Recipients)

	// 4. SOC Disabled, SkipIfRecipients=true: skipped
	socCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), targetedPayload, "soc-disabled-skip")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, socCh.sentPayload)

	// 5. Webhook (unsupported), SkipIfRecipients=false: receives untargeted payload
	webhookCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), targetedPayload, "webhook-noskip")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, webhookCh.sentPayload)
	assert.Nil(t, webhookCh.sentPayload.Recipients)

	// 6. Webhook (unsupported), SkipIfRecipients=true: skipped
	webhookCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), targetedPayload, "webhook-skip")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Nil(t, webhookCh.sentPayload)

	// 7. Untargeted payload with SkipIfRecipients=true: delivered normally
	untargetedPayload := &model.NotificationPayload{
		ID:       "untargeted-1",
		Source:   model.SourceDetection,
		Title:    "Global Alert",
		Severity: model.NotificationSeverityHigh,
	}
	webhookCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), untargetedPayload, "webhook-skip")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, webhookCh.sentPayload)
	assert.Equal(t, "untargeted-1", webhookCh.sentPayload.ID)
}

func TestNotifierSend_AttachmentsAndLinksFiltering(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	reg := NewChannelRegistry()
	fullCh := &mockChannel{channelType: "full", supportsAttachments: true, supportsLinks: true}
	noAttCh := &mockChannel{channelType: "no-att", supportsAttachments: false, supportsLinks: true}
	noLinkCh := &mockChannel{channelType: "no-link", supportsAttachments: true, supportsLinks: false}
	_ = reg.Register(fullCh)
	_ = reg.Register(noAttCh)
	_ = reg.Register(noLinkCh)

	cfg := model.NotificationConfig{
		Enabled: true,
		Destinations: map[string]model.DestinationConfig{
			"dest-full": {
				Type:    "full",
				Enabled: true,
			},
			"dest-no-att": {
				Type:    "no-att",
				Enabled: true,
			},
			"dest-no-link": {
				Type:    "no-link",
				Enabled: true,
			},
		},
	}

	notifier := NewNotifier(nil, reg, cfg)
	payload := &model.NotificationPayload{
		ID:       "payload-1",
		Source:   model.SourceReport,
		Title:    "Report Complete",
		Severity: model.NotificationSeverityInfo,
		Links: map[string]string{
			"view": "https://example.com/report",
		},
		Attachments: []model.Attachment{
			{Filename: "report.pdf", ContentType: "application/pdf"},
		},
	}

	// 1. Full channel receives attachments and links
	fullCh.sentPayload = nil
	count, err := notifier.Send(context.Background(), payload, "dest-full")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, fullCh.sentPayload)
	assert.Len(t, fullCh.sentPayload.Attachments, 1)
	assert.Len(t, fullCh.sentPayload.Links, 1)

	// 2. Channel without attachment support has attachments stripped
	noAttCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-no-att")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, noAttCh.sentPayload)
	assert.Empty(t, noAttCh.sentPayload.Attachments)
	assert.Len(t, noAttCh.sentPayload.Links, 1)

	// 3. Channel without link support has links stripped
	noLinkCh.sentPayload = nil
	count, err = notifier.Send(context.Background(), payload, "dest-no-link")
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.NotNil(t, noLinkCh.sentPayload)
	assert.Len(t, noLinkCh.sentPayload.Attachments, 1)
	assert.Empty(t, noLinkCh.sentPayload.Links)
}
