// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func resolveUserEmail(ctx context.Context, srv *Server, userId string) string {
	if userId == "" {
		return ""
	}
	if srv != nil && srv.Userstore != nil {
		readCtx := ctx
		if srv.Context != nil {
			readCtx = srv.Context
		}
		if u, err := srv.Userstore.GetUserById(readCtx, userId); err == nil && u != nil && u.Email != "" {
			return u.Email
		}
	}
	return userId
}

func parseReportTitleFromMarkdown(content []byte, deflt string) string {
	title := deflt
	prevLine := ""
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "===") && prevLine != "" {
			title = strings.TrimSpace(prevLine)
			break
		}
		prevLine = line
	}
	return title
}

func resolveReportName(srv *Server, job *model.Job) string {
	if job == nil || job.Filter == nil || job.Filter.Parameters == nil {
		return "Report"
	}
	if desc, ok := job.Filter.Parameters["description"].(string); ok && strings.TrimSpace(desc) != "" {
		return strings.TrimSpace(desc)
	}
	if title, ok := job.Filter.Parameters["reportTitle"].(string); ok && strings.TrimSpace(title) != "" {
		return strings.TrimSpace(title)
	}
	if title, ok := job.Filter.Parameters["title"].(string); ok && strings.TrimSpace(title) != "" {
		return strings.TrimSpace(title)
	}
	if name, ok := job.Filter.Parameters["name"].(string); ok && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	if t, ok := job.Filter.Parameters["type"].(string); ok && strings.TrimSpace(t) != "" {
		typeName := strings.TrimSpace(t)
		if srv != nil && srv.Config != nil && srv.Config.CustomReportsPath != "" && strings.HasSuffix(typeName, ".md") {
			filePath := filepath.Join(srv.Config.CustomReportsPath, typeName)
			if content, err := os.ReadFile(filePath); err == nil {
				if title := parseReportTitleFromMarkdown(content, typeName); title != typeName {
					return title
				}
			}
		}
		switch strings.ToLower(typeName) {
		case "case":
			return "Case"
		case "productivity":
			return "Productivity"
		case "assistant_session":
			return "Assistant Session"
		case "tabular":
			return "Tabular"
		}
		return typeName
	}
	return "Report"
}

// BuildJobCompletionNotification constructs a notification payload for completed PCAP or Report jobs.
func BuildJobCompletionNotification(ctx context.Context, srv *Server, job *model.Job) *model.NotificationPayload {
	if job == nil || job.Status != model.JobStatusCompleted {
		return nil
	}

	kind := job.GetKind()
	switch kind {
	case model.DEFAULT_JOB_KIND:
		return buildPcapCompletionNotification(ctx, srv, job)
	case model.JOB_KIND_EXPORT:
		return buildReportCompletionNotification(ctx, srv, job)
	default:
		return nil
	}
}

func buildPcapCompletionNotification(ctx context.Context, srv *Server, job *model.Job) *model.NotificationPayload {
	userEmail := resolveUserEmail(ctx, srv, job.UserId)

	fields := make(map[string]string)
	fields["jobId"] = strconv.Itoa(job.Id)
	fields["nodeId"] = job.GetNodeId()
	if userEmail != "" {
		fields["user"] = userEmail
	}
	if job.Size > 0 {
		fields["size"] = strconv.Itoa(job.Size)
	}
	if job.Filter != nil && len(job.Filter.Parameters) > 0 {
		if timeframe, ok := job.Filter.Parameters["timeframe"].(string); ok && timeframe != "" {
			fields["timeframe"] = timeframe
		}
	}

	links := make(map[string]string)
	links["👁"] = fmt.Sprintf("/#/job/%d", job.Id)
	links["⬇"] = fmt.Sprintf("/api/stream/%d?ext=pcap", job.Id)

	title := fmt.Sprintf("PCAP #%d", job.Id)
	if userEmail != "" {
		title = fmt.Sprintf("PCAP #%d (%s)", job.Id, userEmail)
	}

	return &model.NotificationPayload{
		ID:        uuid.NewString(),
		Source:    model.SourcePcap,
		Title:     title,
		Severity:  model.NotificationSeverityInfo,
		Timestamp: time.Now().UTC(),
		Fields:    fields,
		Links:     links,
	}
}

func buildReportCompletionNotification(ctx context.Context, srv *Server, job *model.Job) *model.NotificationPayload {
	reportName := resolveReportName(srv, job)
	userEmail := resolveUserEmail(ctx, srv, job.UserId)

	fields := make(map[string]string)
	fields["jobId"] = strconv.Itoa(job.Id)
	fields["nodeId"] = job.GetNodeId()
	if userEmail != "" {
		fields["user"] = userEmail
	}
	if reportName != "" {
		fields["report"] = reportName
	}
	if job.Size > 0 {
		fields["size"] = strconv.Itoa(job.Size)
	}
	if job.Filter != nil && len(job.Filter.Parameters) > 0 {
		if timeframe, ok := job.Filter.Parameters["timeframe"].(string); ok && timeframe != "" {
			fields["timeframe"] = timeframe
		}
	}

	ext := job.FileExtension
	if ext == "" || ext == "bin" {
		ext = "pdf"
	}

	links := make(map[string]string)
	links["👁"] = "/#/reports"
	links["⬇"] = fmt.Sprintf("/api/stream/%d?ext=%s", job.Id, ext)

	var attachments []model.Attachment
	if srv != nil && srv.Datastore != nil {
		readCtx := ctx
		if srv.Context != nil {
			readCtx = srv.Context
		}
		reader, filename, _, mimeType, err := srv.Datastore.GetJobStream(readCtx, job.Id, false)
		if err == nil && reader != nil {
			defer reader.Close()
			data, readErr := io.ReadAll(reader)
			if readErr == nil && len(data) > 0 {
				if mimeType == "" || mimeType == "application/octet-stream" {
					mimeType = "application/pdf"
				}
				if filename == "" {
					filename = fmt.Sprintf("report_%d.%s", job.Id, ext)
				}
				attachments = append(attachments, model.Attachment{
					Filename:    filename,
					ContentType: mimeType,
					Data:        data,
					URL:         fmt.Sprintf("/api/stream/%d?ext=%s", job.Id, ext),
				})
			}
		}
	}

	title := reportName
	if userEmail != "" {
		title = fmt.Sprintf("%s (%s)", reportName, userEmail)
	}

	return &model.NotificationPayload{
		ID:          uuid.NewString(),
		Source:      model.SourceReport,
		Title:       title,
		Severity:    model.NotificationSeverityInfo,
		Timestamp:   time.Now().UTC(),
		Fields:      fields,
		Links:       links,
		Attachments: attachments,
	}
}

// SendJobCompletionNotification dispatches an INFO severity notification when a PCAP or Report job completes.
func SendJobCompletionNotification(ctx context.Context, srv *Server, job *model.Job) error {
	if srv == nil || srv.Notifier == nil {
		return nil
	}
	if !licensing.IsEnabled(licensing.FEAT_NTF) {
		return nil
	}

	payload := BuildJobCompletionNotification(ctx, srv, job)
	if payload == nil {
		return nil
	}

	sendCtx := ctx
	if srv.Context != nil {
		sendCtx = srv.Context
	}

	err := srv.Notifier.Send(sendCtx, payload)
	if err != nil {
		log.FromContext(ctx).WithError(err).WithField("jobId", job.Id).Error("Failed to send job completion notification")
		return err
	}

	return nil
}
