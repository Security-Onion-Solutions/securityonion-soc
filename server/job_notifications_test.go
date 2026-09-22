// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestBuildJobCompletionNotification_NilOrIncompleteJob(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)

	// Nil job
	assert.Nil(t, BuildJobCompletionNotification(context.Background(), srv, nil))

	// Incomplete / pending / deleted jobs
	pendingJob := &model.Job{
		Id:     1001,
		Status: model.JobStatusPending,
		Kind:   "pcap",
	}
	assert.Nil(t, BuildJobCompletionNotification(context.Background(), srv, pendingJob))

	failedJob := &model.Job{
		Id:     1002,
		Status: model.JobStatusIncomplete,
		Kind:   "pcap",
	}
	assert.Nil(t, BuildJobCompletionNotification(context.Background(), srv, failedJob))

	deletedJob := &model.Job{
		Id:     1003,
		Status: model.JobStatusDeleted,
		Kind:   "pcap",
	}
	assert.Nil(t, BuildJobCompletionNotification(context.Background(), srv, deletedJob))

	// Unsupported job kind
	analyzeJob := &model.Job{
		Id:     1004,
		Status: model.JobStatusCompleted,
		Kind:   "analyze",
	}
	assert.Nil(t, BuildJobCompletionNotification(context.Background(), srv, analyzeJob))
}

func TestBuildJobCompletionNotification_PcapJob(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)

	// Case 1: User ID resolved to User Email via Userstore
	job1 := &model.Job{
		Id:         1005,
		Status:     model.JobStatusCompleted,
		Kind:       "",
		NodeId:     "sensor-node-1",
		UserId:     "user-id-1",
		Size:       4096,
		Filter:     model.NewFilter(),
		CreateTime: time.Now().Add(-time.Minute),
	}
	job1.Filter.Parameters["timeframe"] = "2026-09-18 10:00:00 - 2026-09-18 11:00:00"

	payload1 := BuildJobCompletionNotification(context.Background(), srv, job1)
	assert.NotNil(t, payload1)
	assert.NotEmpty(t, payload1.ID)
	assert.Equal(t, model.SourcePcap, payload1.Source)
	assert.Equal(t, model.NotificationSeverityInfo, payload1.Severity)
	assert.Equal(t, "PCAP #1005 (user1@somewhere.invalid)", payload1.Title)
	assert.Empty(t, payload1.Summary)
	assert.Equal(t, "1005", payload1.Fields["jobId"])
	assert.Equal(t, "sensor-node-1", payload1.Fields["nodeId"])
	assert.Equal(t, "user1@somewhere.invalid", payload1.Fields["user"])
	assert.Equal(t, "4096", payload1.Fields["size"])
	assert.Equal(t, "2026-09-18 10:00:00 - 2026-09-18 11:00:00", payload1.Fields["timeframe"])
	assert.Equal(t, "/#/job/1005", payload1.Links["👁"])
	assert.Equal(t, "/api/stream/1005?ext=pcap", payload1.Links["⬇"])
	assert.Empty(t, payload1.Attachments)
	assert.Equal(t, []string{"user-id-1"}, payload1.Recipients)

	// Case 2: Explicit "pcap" kind without user
	job2 := &model.Job{
		Id:     1006,
		Status: model.JobStatusCompleted,
		Kind:   "pcap",
		NodeId: "sensor-node-2",
	}
	payload2 := BuildJobCompletionNotification(context.Background(), srv, job2)
	assert.NotNil(t, payload2)
	assert.Equal(t, model.SourcePcap, payload2.Source)
	assert.Equal(t, "PCAP #1006", payload2.Title)
	assert.Empty(t, payload2.Summary)
	assert.Nil(t, payload2.Recipients)

	// Case 3: System-generated job (no recipients)
	job3 := &model.Job{
		Id:     1007,
		Status: model.JobStatusCompleted,
		Kind:   "pcap",
		NodeId: "sensor-node-1",
		UserId: SYSTEM_ID,
	}
	payload3 := BuildJobCompletionNotification(context.Background(), srv, job3)
	assert.NotNil(t, payload3)
	assert.Nil(t, payload3.Recipients)
}

func TestBuildJobCompletionNotification_ReportJob_WithPdfStream(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	pdfContent := []byte("%PDF-1.4 test report pdf content bytes")

	fakeDs := srv.Datastore.(*FakeDatastore)
	fakeDs.JobStreamReader = io.NopCloser(bytes.NewReader(pdfContent))
	fakeDs.JobStreamFilename = "sensoroni_manager_1007.pdf"
	fakeDs.JobStreamLength = int64(len(pdfContent))
	fakeDs.JobStreamMimeType = "application/pdf"

	job := &model.Job{
		Id:            1007,
		Status:        model.JobStatusCompleted,
		Kind:          model.JOB_KIND_EXPORT,
		NodeId:        "manager-01",
		UserId:        "user-id-2",
		FileExtension: "pdf",
		Size:          len(pdfContent),
		Filter:        model.NewFilter(),
	}
	job.Filter.Parameters["description"] = "Executive Summary"
	job.Filter.Parameters["type"] = "generic_report1.md"
	job.Filter.Parameters["timeframe"] = "Last 24 Hours"

	payload := BuildJobCompletionNotification(context.Background(), srv, job)
	assert.NotNil(t, payload)
	assert.NotEmpty(t, payload.ID)
	assert.Equal(t, model.SourceReport, payload.Source)
	assert.Equal(t, model.NotificationSeverityInfo, payload.Severity)
	assert.Equal(t, "Executive Summary (user2@somewhere.invalid)", payload.Title)
	assert.Empty(t, payload.Summary)
	assert.Equal(t, "1007", payload.Fields["jobId"])
	assert.Equal(t, "manager-01", payload.Fields["nodeId"])
	assert.Equal(t, "user2@somewhere.invalid", payload.Fields["user"])
	assert.Equal(t, "Executive Summary", payload.Fields["report"])
	assert.Equal(t, "Last 24 Hours", payload.Fields["timeframe"])
	assert.Equal(t, "/#/reports", payload.Links["👁"])
	assert.Equal(t, "/api/stream/1007?ext=pdf", payload.Links["⬇"])
	assert.Equal(t, []string{"user-id-2"}, payload.Recipients)

	assert.Len(t, payload.Attachments, 1)
	att := payload.Attachments[0]
	assert.Equal(t, "sensoroni_manager_1007.pdf", att.Filename)
	assert.Equal(t, "application/pdf", att.ContentType)
	assert.Equal(t, pdfContent, att.Data)
	assert.Equal(t, "/api/stream/1007?ext=pdf", att.URL)
}

func TestBuildJobCompletionNotification_ReportJob_CustomReportMarkdownParsing(t *testing.T) {
	tempDir := t.TempDir()
	reportFile := filepath.Join(tempDir, "generic_report2.md")
	_ = os.WriteFile(reportFile, []byte("Threat Hunting Summary\n===\nReport Content Here"), 0644)

	srv := NewFakeAuthorizedServer(nil)
	srv.Config = &config.ServerConfig{
		CustomReportsPath: tempDir,
	}

	job := &model.Job{
		Id:     1008,
		Status: model.JobStatusCompleted,
		Kind:   model.JOB_KIND_EXPORT,
		NodeId: "manager-01",
		UserId: "user-id-1",
		Filter: model.NewFilter(),
	}
	job.Filter.Parameters["type"] = "generic_report2.md"

	payload := BuildJobCompletionNotification(context.Background(), srv, job)
	assert.NotNil(t, payload)
	assert.Equal(t, model.SourceReport, payload.Source)
	assert.Equal(t, "Threat Hunting Summary (user1@somewhere.invalid)", payload.Title)
	assert.Equal(t, "Threat Hunting Summary", payload.Fields["report"])
	assert.Equal(t, "user1@somewhere.invalid", payload.Fields["user"])
	assert.Empty(t, payload.Summary)
	assert.Empty(t, payload.Attachments)
	assert.Equal(t, "/#/reports", payload.Links["👁"])
	assert.Equal(t, "/api/stream/1008?ext=pdf", payload.Links["⬇"])
	assert.Equal(t, []string{"user-id-1"}, payload.Recipients)
}

func TestSendJobCompletionNotification(t *testing.T) {
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	fakeNotif := NewFakeNotifier()
	srv.Notifier = fakeNotif

	// Nil server or nil notifier
	assert.NoError(t, SendJobCompletionNotification(context.Background(), nil, &model.Job{Status: model.JobStatusCompleted}))
	srvNoNotif := NewFakeAuthorizedServer(nil)
	assert.NoError(t, SendJobCompletionNotification(context.Background(), srvNoNotif, &model.Job{Status: model.JobStatusCompleted}))

	// Unlicensed
	licensing.Test(licensing.FEAT_API, 0, 0, "", "")
	assert.NoError(t, SendJobCompletionNotification(context.Background(), srv, &model.Job{Status: model.JobStatusCompleted}))
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	// Valid PCAP Job Notification
	job := &model.Job{
		Id:     1009,
		Status: model.JobStatusCompleted,
		Kind:   "pcap",
		NodeId: "sensor-node-1",
	}
	err := SendJobCompletionNotification(context.Background(), srv, job)
	assert.NoError(t, err)
	assert.Len(t, fakeNotif.InputPayloads, 1)
	assert.Equal(t, model.SourcePcap, fakeNotif.InputPayloads[0].Source)

	// Notifier Send Error
	fakeNotif.Err = errors.New("send failed")
	err = SendJobCompletionNotification(context.Background(), srv, job)
	assert.Error(t, err)
	assert.Equal(t, "send failed", err.Error())
}
