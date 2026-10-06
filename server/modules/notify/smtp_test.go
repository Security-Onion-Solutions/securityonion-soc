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
	"errors"
	"io"
	"net/smtp"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSMTPClient struct {
	extensions    map[string]string
	startTLSCalled bool
	authCalled     bool
	mailFrom       string
	rcptTo         []string
	dataBuffer     *bytes.Buffer
	quitCalled     bool
	closed         bool
	failAt         string
}

func (m *mockSMTPClient) Extension(ext string) (bool, string) {
	if val, ok := m.extensions[ext]; ok {
		return true, val
	}
	return false, ""
}

func (m *mockSMTPClient) StartTLS(config *tls.Config) error {
	m.startTLSCalled = true
	if m.failAt == "starttls" {
		return errors.New("starttls failed")
	}
	return nil
}

func (m *mockSMTPClient) Auth(a smtp.Auth) error {
	m.authCalled = true
	if m.failAt == "auth" {
		return errors.New("auth failed")
	}
	return nil
}

func (m *mockSMTPClient) Mail(from string) error {
	m.mailFrom = from
	if m.failAt == "mail" {
		return errors.New("mail from rejected")
	}
	return nil
}

func (m *mockSMTPClient) Rcpt(to string) error {
	m.rcptTo = append(m.rcptTo, to)
	if m.failAt == "rcpt" {
		return errors.New("rcpt to rejected")
	}
	return nil
}

type nopWriteCloser struct {
	io.Writer
}

func (n *nopWriteCloser) Close() error {
	return nil
}

func (m *mockSMTPClient) Data() (io.WriteCloser, error) {
	if m.failAt == "data" {
		return nil, errors.New("data command failed")
	}
	if m.dataBuffer == nil {
		m.dataBuffer = new(bytes.Buffer)
	}
	return &nopWriteCloser{Writer: m.dataBuffer}, nil
}

func (m *mockSMTPClient) Quit() error {
	m.quitCalled = true
	return nil
}

func (m *mockSMTPClient) Close() error {
	m.closed = true
	return nil
}

func TestSMTPChannelValidateConfig(t *testing.T) {
	ch := NewSMTPChannel(nil)

	assert.Equal(t, "smtp", ch.Type())
	assert.True(t, ch.SupportsRecipients())
	assert.True(t, ch.SupportsAttachments())
	assert.True(t, ch.SupportsLinks())

	// Nil params
	assert.Error(t, ch.ValidateConfig(nil))

	// Missing host
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"from": "alerts@example.com",
	}))

	// Missing from
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"host": "mail.example.com",
	}))

	// Invalid from email
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"host": "mail.example.com",
		"from": "not-an-email",
	}))

	// Invalid port
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"host": "mail.example.com",
		"from": "alerts@example.com",
		"port": 99999,
	}))

	// Invalid recipient in to list
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"host": "mail.example.com",
		"from": "alerts@example.com",
		"to":   []string{"valid@example.com", "not valid"},
	}))

	// Invalid attachmentMode
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"host":           "mail.example.com",
		"from":           "alerts@example.com",
		"attachmentMode": "invalid_mode",
	}))

	// Valid minimal config
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"host": "mail.example.com",
		"from": "alerts@example.com",
	}))

	// Valid full config
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"host":           "mail.example.com",
		"port":           587,
		"from":           "Security Onion Alerts <alerts@example.com>",
		"to":             []interface{}{"admin@example.com", "oncall@example.com"},
		"username":       "socbot",
		"password":       "secret",
		"useTls":         true,
		"attachmentMode": "both",
	}))
}

func TestSMTPChannelSendSuccess(t *testing.T) {
	mockClient := &mockSMTPClient{
		extensions: map[string]string{
			"AUTH":     "PLAIN LOGIN",
			"STARTTLS": "",
		},
	}

	ch := NewSMTPChannel(nil)
	ch.dialer = func(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error) {
		return mockClient, nil
	}

	payload := &model.NotificationPayload{
		ID:        "test-smtp-1",
		Title:     "High Severity Threat Detected",
		Summary:   "Inbound exploit attempt observed",
		Severity:  model.NotificationSeverityCritical,
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"src_ip": "10.10.10.10",
		},
		Links: map[string]string{
			"View Alert": "https://soc.example.com/#/alerts/123",
		},
	}

	params := map[string]interface{}{
		"host":     "smtp.example.com",
		"port":     587,
		"from":     "alerts@example.com",
		"to":       "analyst1@example.com, analyst2@example.com",
		"username": "alertuser",
		"password": "secretpassword",
		"useTls":   true,
	}

	err := ch.Send(context.Background(), params, payload)
	require.NoError(t, err)

	assert.True(t, mockClient.startTLSCalled)
	assert.True(t, mockClient.authCalled)
	assert.Equal(t, "alerts@example.com", mockClient.mailFrom)
	assert.Equal(t, []string{"analyst1@example.com", "analyst2@example.com"}, mockClient.rcptTo)
	assert.True(t, mockClient.quitCalled)
	assert.True(t, mockClient.closed)

	data := mockClient.dataBuffer.String()
	assert.Contains(t, data, "Subject: [CRITICAL] High Severity Threat Detected")
	assert.Contains(t, data, "Inbound exploit attempt observed")
	assert.Contains(t, data, "src_ip")
	assert.Contains(t, data, "https://soc.example.com/#/alerts/123")
}

func TestSMTPChannelSendWithPayloadRecipients(t *testing.T) {
	mockClient := &mockSMTPClient{}

	ch := NewSMTPChannel(nil)
	ch.dialer = func(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error) {
		return mockClient, nil
	}

	payload := &model.NotificationPayload{
		Title:      "Alert to Target",
		Severity:   model.NotificationSeverityInfo,
		Recipients: []string{"targeted@example.com"},
	}

	params := map[string]interface{}{
		"host": "smtp.example.com",
		"from": "alerts@example.com",
	}

	err := ch.Send(context.Background(), params, payload)
	require.NoError(t, err)
	assert.Equal(t, []string{"targeted@example.com"}, mockClient.rcptTo)
}

func TestSMTPChannelSendFailures(t *testing.T) {
	ch := NewSMTPChannel(nil)

	payload := &model.NotificationPayload{
		Title: "Test",
	}

	// Connection failure
	ch.dialer = func(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error) {
		return nil, errors.New("connection refused")
	}

	err := ch.Send(context.Background(), map[string]interface{}{
		"host": "smtp.example.com",
		"from": "a@b.com",
		"to":   "c@d.com",
	}, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")

	// No recipients
	err = ch.Send(context.Background(), map[string]interface{}{
		"host": "smtp.example.com",
		"from": "a@b.com",
	}, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid recipient email addresses")

	// Auth failure
	mockClient := &mockSMTPClient{failAt: "auth"}
	ch.dialer = func(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error) {
		return mockClient, nil
	}
	err = ch.Send(context.Background(), map[string]interface{}{
		"host":     "smtp.example.com",
		"from":     "a@b.com",
		"to":       "c@d.com",
		"username": "user",
		"password": "bad",
	}, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}
