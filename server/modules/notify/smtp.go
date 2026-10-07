// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

// SMTPClientInterface abstracts net/smtp.Client for testing.
type SMTPClientInterface interface {
	Extension(ext string) (bool, string)
	StartTLS(config *tls.Config) error
	Auth(a smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}

type smtpDialerFunc func(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error)

type loginAuth struct {
	username, password string
}

// LoginAuth implements smtp.Auth for the LOGIN mechanism.
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		challenge := strings.ToLower(string(fromServer))
		if strings.Contains(challenge, "username") {
			return []byte(a.username), nil
		} else if strings.Contains(challenge, "password") {
			return []byte(a.password), nil
		}
		return []byte(a.password), nil
	}
	return nil, nil
}

// SMTPChannel implements NotificationChannel for email notifications.
type SMTPChannel struct {
	server *server.Server
	dialer smtpDialerFunc
}

// NewSMTPChannel constructs a new SMTP notification channel driver.
func NewSMTPChannel(srv *server.Server) *SMTPChannel {
	return &SMTPChannel{
		server: srv,
		dialer: defaultSMTPDialer,
	}
}

func (c *SMTPChannel) Type() string {
	return "smtp"
}

func (c *SMTPChannel) SupportsRecipients() bool {
	return true
}

func (c *SMTPChannel) SupportsAttachments() bool {
	return true
}

func (c *SMTPChannel) SupportsLinks() bool {
	return true
}

// ValidateConfig verifies that the SMTP destination configuration contains valid parameters.
func (c *SMTPChannel) ValidateConfig(params map[string]interface{}) error {
	if params == nil {
		return errors.New("smtp configuration parameters cannot be nil")
	}

	host, _ := params["host"].(string)
	if strings.TrimSpace(host) == "" {
		return errors.New("smtp host is required")
	}

	if portVal, ok := params["port"]; ok {
		port, err := parsePort(portVal)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid smtp port: %v", portVal)
		}
	}

	from, _ := params["from"].(string)
	if strings.TrimSpace(from) == "" {
		return errors.New("smtp from address is required")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return fmt.Errorf("invalid smtp from address: %w", err)
	}

	if toVal, ok := params["to"]; ok && toVal != nil {
		toAddresses := parseStringSlice(toVal)
		for _, addr := range toAddresses {
			if _, err := mail.ParseAddress(addr); err != nil {
				return fmt.Errorf("invalid smtp recipient address '%s': %w", addr, err)
			}
		}
	}

	if modeVal, ok := params["attachmentMode"]; ok && modeVal != nil {
		modeStr, isStr := modeVal.(string)
		if !isStr {
			return errors.New("attachmentMode must be a string")
		}
		switch modeStr {
		case model.AttachmentModeLink, model.AttachmentModeAttach, model.AttachmentModeBoth:
			// Valid
		default:
			return fmt.Errorf("invalid attachmentMode: %s (must be '%s', '%s', or '%s')",
				modeStr, model.AttachmentModeLink, model.AttachmentModeAttach, model.AttachmentModeBoth)
		}
	}

	return nil
}

// Send formats and transmits an email notification via SMTP.
func (c *SMTPChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}

	if err := c.ValidateConfig(params); err != nil {
		return fmt.Errorf("invalid smtp config: %w", err)
	}

	payload = ResolveOutboundPayload(c.server, payload)

	host, _ := params["host"].(string)
	host = strings.TrimSpace(host)

	port := 25
	if portVal, ok := params["port"]; ok {
		if p, err := parsePort(portVal); err == nil && p > 0 {
			port = p
		}
	}

	from, _ := params["from"].(string)
	from = strings.TrimSpace(from)
	parsedFrom, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("invalid from address '%s': %w", from, err)
	}
	fromEmail := parsedFrom.Address

	username, _ := params["username"].(string)
	password, _ := params["password"].(string)
	authType, _ := params["auth"].(string)
	if authType == "" {
		authType, _ = params["authType"].(string)
	}

	useTLS := false
	if tlsVal, ok := params["useTls"]; ok {
		useTLS, _ = tlsVal.(bool)
	} else if tlsVal, ok := params["tls"]; ok {
		useTLS, _ = tlsVal.(bool)
	} else if port == 465 {
		useTLS = true
	}

	insecureSkipVerify := false
	if skipVal, ok := params["insecureSkipVerify"]; ok {
		insecureSkipVerify, _ = skipVal.(bool)
	} else if skipVal, ok := params["skipVerify"]; ok {
		insecureSkipVerify, _ = skipVal.(bool)
	}

	attachmentMode := model.AttachmentModeBoth
	if modeVal, ok := params["attachmentMode"].(string); ok && modeVal != "" {
		attachmentMode = modeVal
	}

	// Resolve recipients: if recipients have been targeted in the payload, deliver
	// specifically to them and DO NOT include the destination's default recipient address (params["to"]).
	// Only use params["to"] when no recipients are targeted.
	var recipients []string
	if len(payload.Recipients) > 0 {
		for _, rec := range payload.Recipients {
			rec = strings.TrimSpace(rec)
			if strings.Contains(rec, "@") {
				recipients = append(recipients, rec)
			} else if c.server != nil && c.server.Userstore != nil && rec != "" {
				if u, err := c.server.Userstore.GetUserById(ctx, rec); err == nil && u != nil && strings.TrimSpace(u.Email) != "" {
					recipients = append(recipients, strings.TrimSpace(u.Email))
				}
			}
		}
	} else if toVal, ok := params["to"]; ok && toVal != nil {
		recipients = parseStringSlice(toVal)
	}

	recipients = deduplicateAddresses(recipients)
	if len(recipients) == 0 {
		return errors.New("no valid recipient email addresses found")
	}

	subject := FormatEmailSubject(payload)
	plainBody := FormatPlainTextBody(payload, attachmentMode)
	htmlBody := FormatHTMLBody(payload, attachmentMode)

	msgBytes, err := BuildMIMEMessage(from, recipients, subject, plainBody, htmlBody, payload.Attachments, attachmentMode)
	if err != nil {
		return fmt.Errorf("failed to build MIME message: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecureSkipVerify,
	}

	directTLS := (port == 465) || (useTLS && port != 587 && port != 25)

	client, err := c.dialer(ctx, host, port, tlsConfig, directTLS)
	if err != nil {
		return fmt.Errorf("failed to connect to smtp server %s:%d: %w", host, port, err)
	}
	defer client.Close()

	// If not already in direct TLS mode, try STARTTLS if requested or available
	if !directTLS {
		hasStartTLS, _ := client.Extension("STARTTLS")
		if useTLS || hasStartTLS || port == 587 {
			if err := client.StartTLS(tlsConfig); err != nil {
				if useTLS || port == 587 {
					return fmt.Errorf("failed to negotiate STARTTLS: %w", err)
				}
				log.WithError(err).Debug("STARTTLS failed on opportunistic connection; continuing unencrypted")
			}
		}
	}

	// Authenticate if credentials provided
	if username != "" {
		auth := selectSMTPAuth(authType, username, password, host, client)
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp authentication failed: %w", err)
			}
		}
	}

	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}

	var acceptedRecipients []string
	var rcptErrors []error
	seenRcpt := make(map[string]bool)
	for _, toAddr := range recipients {
		parsedTo, err := mail.ParseAddress(toAddr)
		if err == nil && parsedTo.Address != "" {
			toAddr = parsedTo.Address
		}
		lowerAddr := strings.ToLower(toAddr)
		if seenRcpt[lowerAddr] {
			continue
		}
		seenRcpt[lowerAddr] = true
		if err := client.Rcpt(toAddr); err != nil {
			log.WithError(err).WithField("recipient", toAddr).Warn("SMTP server rejected recipient")
			rcptErrors = append(rcptErrors, fmt.Errorf("RCPT TO <%s>: %w", toAddr, err))
		} else {
			acceptedRecipients = append(acceptedRecipients, toAddr)
		}
	}

	if len(acceptedRecipients) == 0 {
		return fmt.Errorf("all recipients rejected by SMTP server: %w", errors.Join(rcptErrors...))
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA command failed: %w", err)
	}

	if _, err := writer.Write(msgBytes); err != nil {
		_ = writer.Close()
		return fmt.Errorf("failed writing smtp message data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed closing smtp message data writer: %w", err)
	}

	_ = client.Quit()
	return nil
}

func selectSMTPAuth(authType, username, password, host string, client SMTPClientInterface) smtp.Auth {
	authTypeLower := strings.ToLower(strings.TrimSpace(authType))
	hasAuth, authExt := client.Extension("AUTH")

	if authTypeLower == "login" {
		return LoginAuth(username, password)
	}
	if authTypeLower == "cram-md5" || authTypeLower == "crammd5" {
		return smtp.CRAMMD5Auth(username, password)
	}
	if authTypeLower == "plain" {
		return smtp.PlainAuth("", username, password, host)
	}

	// Auto-detect based on server capabilities
	if hasAuth {
		authExtUpper := strings.ToUpper(authExt)
		if strings.Contains(authExtUpper, "PLAIN") {
			return smtp.PlainAuth("", username, password, host)
		}
		if strings.Contains(authExtUpper, "LOGIN") {
			return LoginAuth(username, password)
		}
		if strings.Contains(authExtUpper, "CRAM-MD5") {
			return smtp.CRAMMD5Auth(username, password)
		}
	}

	// Default fallback
	return smtp.PlainAuth("", username, password, host)
}

func defaultSMTPDialer(ctx context.Context, host string, port int, tlsConfig *tls.Config, directTLS bool) (SMTPClientInterface, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
	}

	var conn net.Conn
	var err error

	if directTLS {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsConfig,
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return nil, err
	}

	return smtp.NewClient(conn, host)
}

func parsePort(val interface{}) (int, error) {
	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	default:
		return 0, fmt.Errorf("unsupported port type: %T", val)
	}
}

func parseStringSlice(val interface{}) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []string:
		var result []string
		for _, s := range v {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	case string:
		parts := strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ';'
		})
		var result []string
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	case []interface{}:
		var result []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(str); trimmed != "" {
					result = append(result, trimmed)
				}
			}
		}
		return result
	default:
		return nil
	}
}

func deduplicateAddresses(addrs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, a := range addrs {
		cleaned := strings.TrimSpace(a)
		if cleaned == "" {
			continue
		}
		target := strings.ToLower(cleaned)
		if parsed, err := mail.ParseAddress(cleaned); err == nil && parsed.Address != "" {
			target = strings.ToLower(parsed.Address)
		}
		if !seen[target] {
			seen[target] = true
			result = append(result, cleaned)
		}
	}
	return result
}
