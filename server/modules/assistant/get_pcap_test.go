// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runGetPcap(t *testing.T, ctx context.Context, srv *server.Server, params string) (*model.ToolResponse, error) {
	t.Helper()
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "test-user-id")
	return (&GetPcapTool{}).Execute(ctx, srv, &model.ToolRequest{Params: json.RawMessage(params)})
}

func framePayload(headerLen int, app string) (string, int) {
	frame := append(make([]byte, headerLen), []byte(app)...)
	return base64.StdEncoding.EncodeToString(frame), headerLen
}

func TestGetPcapTool_JobStates(t *testing.T) {
	testCases := []struct {
		name    string
		job     *model.Job
		want    map[string]any
		wantErr string
	}{
		{
			name:    "missing job",
			wantErr: "job 7 was not found or is not accessible",
		},
		{
			name: "pending",
			job:  &model.Job{Id: 7, Status: model.JobStatusPending},
			want: map[string]any{
				"job_id": 7,
				"status": "pending",
				"next":   "The sensor has not processed this job yet. Call get_pcap again, optionally with wait_seconds.",
			},
		},
		{
			name: "incomplete",
			job:  &model.Job{Id: 7, Status: model.JobStatusIncomplete, Failure: "no data available for the requested dates", FailCount: 2},
			want: map[string]any{
				"job_id":     7,
				"status":     "incomplete",
				"failure":    "no data available for the requested dates",
				"fail_count": 2,
			},
		},
		{
			name:    "deleted",
			job:     &model.Job{Id: 7, Status: model.JobStatusDeleted},
			wantErr: "job 7 has been deleted",
		},
		{
			name: "completed with no packets",
			job:  &model.Job{Id: 7, Status: model.JobStatusCompleted},
			want: map[string]any{
				"job_id": 7,
				"status": "completed",
				"note":   "The job completed but no packets matched the filter.",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := server.NewFakeDatastore()
			ds.GetJobResult = tc.job
			ds.GetPacketsResult = []*model.Packet{}
			srv := &server.Server{Datastore: ds}

			result, err := runGetPcap(t, context.Background(), srv, `{"job_id": 7}`)
			if tc.wantErr != "" {
				assert.Nil(t, result)
				assert.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, result.Result)
		})
	}
}

func TestGetPcapTool_PermissionDenied(t *testing.T) {
	ds := server.NewFakeDatastore()
	ds.GetJobResult = &model.Job{Id: 7, Status: model.JobStatusCompleted}
	ds.GetPacketsErr = model.NewUnauthorized("test-user-id", "read", "jobs")

	result, err := runGetPcap(t, context.Background(), &server.Server{Datastore: ds}, `{"job_id": 7}`)
	assert.Nil(t, result)
	assert.EqualError(t, err, "ERROR_PERMISSION_DENIED")
}

func TestGetPcapTool_Completed(t *testing.T) {
	ts := time.Date(2026, 10, 6, 19, 29, 39, 0, time.UTC)
	httpReq, httpOffset := framePayload(54, "GET / HTTP/1.1\r\nHost: example.com\r\n\x00\x01")
	httpResp, httpRespOffset := framePayload(54, "HTTP/1.1 200 OK")

	ds := server.NewFakeDatastore()
	ds.GetJobResult = &model.Job{Id: 7, Status: model.JobStatusCompleted}
	ds.HasErrors = true
	ds.GetPacketsResult = []*model.Packet{
		{Number: 1, Type: "TCP", SrcIp: "10.0.0.5", SrcPort: 51000, DstIp: "93.184.216.34", DstPort: 80, Length: 66, Timestamp: ts, Flags: []string{"SYN"}},
		{Number: 2, Type: "TCP", SrcIp: "93.184.216.34", SrcPort: 80, DstIp: "10.0.0.5", DstPort: 51000, Length: 66, Timestamp: ts.Add(time.Millisecond), Flags: []string{"SYN", "ACK"}},
		{Number: 3, Type: "HTTP", SrcIp: "10.0.0.5", SrcPort: 51000, DstIp: "93.184.216.34", DstPort: 80, Length: 100, Timestamp: ts.Add(2 * time.Millisecond), Flags: []string{"PSH", "ACK"}, Payload: httpReq, PayloadOffset: httpOffset},
		{Number: 4, Type: "HTTP", SrcIp: "93.184.216.34", SrcPort: 80, DstIp: "10.0.0.5", DstPort: 51000, Length: 69, Timestamp: ts.Add(3 * time.Millisecond), Payload: httpResp, PayloadOffset: httpRespOffset},
		{Number: 5, Type: "DNS", SrcIp: "10.0.0.5", SrcPort: 53000, DstIp: "10.0.0.1", DstPort: 53, Length: 80, Timestamp: ts.Add(-time.Second)},
	}
	srv := &server.Server{Datastore: ds}

	result, err := runGetPcap(t, context.Background(), srv, `{"job_id": 7, "max_packets": 4, "payload_bytes": 20, "unwrap": true}`)
	require.NoError(t, err)

	assert.Equal(t, 7, ds.LastJobId)
	assert.Equal(t, config.DEFAULT_MAX_PACKET_COUNT+1, ds.LastCount, "one extra packet is requested to detect truncation")
	assert.True(t, ds.LastUnwrap)
	assert.True(t, ds.LastExcludeErrors)

	res := result.Result.(map[string]any)
	assert.Equal(t, "completed", res["status"])
	assert.Equal(t, false, res["truncated"])
	assert.Equal(t, "Some packets could not be decoded and were omitted.", res["note"])

	summary := res["summary"].(*pcapSummary)
	assert.Equal(t, 5, summary.Packets, "the summary covers every packet, not just the ones listed")
	assert.Equal(t, 381, summary.Bytes)
	assert.Equal(t, ts.Add(-time.Second), summary.FirstPacket)
	assert.Equal(t, ts.Add(3*time.Millisecond), summary.LastPacket)
	assert.Equal(t, map[string]int{"TCP": 2, "HTTP": 2, "DNS": 1}, summary.Types)
	assert.Equal(t, []string{"ACK", "PSH", "SYN"}, summary.TcpFlags)
	assert.Equal(t, []pcapConversation{
		{SrcIp: "10.0.0.5", SrcPort: 51000, DstIp: "93.184.216.34", DstPort: 80, Packets: 4, Bytes: 301},
		{SrcIp: "10.0.0.5", SrcPort: 53000, DstIp: "10.0.0.1", DstPort: 53, Packets: 1, Bytes: 80},
	}, summary.Conversations)

	packets := res["packets"].([]pcapPacket)
	require.Len(t, packets, 4)
	assert.Empty(t, packets[0].PayloadPreview)
	assert.Zero(t, packets[0].PayloadLength)
	assert.Equal(t, "GET / HTTP/1.1\r\nHost", packets[2].PayloadPreview)
	assert.Equal(t, 37, packets[2].PayloadLength)
	assert.Equal(t, "HTTP/1.1 200 OK", packets[3].PayloadPreview)
}

func TestGetPcapTool_PayloadBytesZeroOmitsPreview(t *testing.T) {
	payload, offset := framePayload(14, "hello")
	ds := server.NewFakeDatastore()
	ds.GetJobResult = &model.Job{Id: 7, Status: model.JobStatusCompleted}
	ds.GetPacketsResult = []*model.Packet{{Number: 1, Type: "UDP", Payload: payload, PayloadOffset: offset}}

	result, err := runGetPcap(t, context.Background(), &server.Server{Datastore: ds}, `{"job_id": 7, "payload_bytes": 0}`)
	require.NoError(t, err)

	res := result.Result.(map[string]any)
	assert.Equal(t, false, res["truncated"])
	packets := res["packets"].([]pcapPacket)
	assert.Empty(t, packets[0].PayloadPreview)
	assert.Equal(t, 5, packets[0].PayloadLength)
}

func TestGetPcapTool_Truncated(t *testing.T) {
	packets := make([]*model.Packet, 11)
	for i := range packets {
		packets[i] = &model.Packet{Number: i + 1, Type: "UDP", Length: 10}
	}
	ds := server.NewFakeDatastore()
	ds.GetJobResult = &model.Job{Id: 7, Status: model.JobStatusCompleted}
	ds.GetPacketsResult = packets

	srv := &server.Server{Datastore: ds, Config: &config.ServerConfig{MaxPacketCount: 10}}

	result, err := runGetPcap(t, context.Background(), srv, `{"job_id": 7, "max_packets": 3}`)
	require.NoError(t, err)

	assert.Equal(t, 11, ds.LastCount)
	res := result.Result.(map[string]any)
	assert.Equal(t, true, res["truncated"])
	assert.Equal(t, 10, res["summary"].(*pcapSummary).Packets)
	assert.Len(t, res["packets"].([]pcapPacket), 3)
}

func TestGetPcapTool_WaitStopsOnContextCancel(t *testing.T) {
	ds := server.NewFakeDatastore()
	ds.GetJobResult = &model.Job{Id: 7, Status: model.JobStatusPending}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	result, err := runGetPcap(t, ctx, &server.Server{Datastore: ds}, `{"job_id": 7, "wait_seconds": 30}`)
	require.NoError(t, err)

	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, "pending", result.Result.(map[string]any)["status"])
}

type completesAfterDatastore struct {
	*server.FakeDatastore
	calls      int
	pendingFor int
}

func (d *completesAfterDatastore) GetJob(ctx context.Context, jobId int) *model.Job {
	d.calls++
	if d.calls <= d.pendingFor {
		return &model.Job{Id: jobId, Status: model.JobStatusPending}
	}
	return &model.Job{Id: jobId, Status: model.JobStatusCompleted}
}

func TestGetPcapTool_WaitSeesCompletion(t *testing.T) {
	orig := getPcapPollInterval
	getPcapPollInterval = time.Millisecond
	defer func() { getPcapPollInterval = orig }()

	fake := server.NewFakeDatastore()
	fake.GetPacketsResult = []*model.Packet{}
	ds := &completesAfterDatastore{FakeDatastore: fake, pendingFor: 3}

	result, err := runGetPcap(t, context.Background(), &server.Server{Datastore: ds}, `{"job_id": 7, "wait_seconds": 5}`)
	require.NoError(t, err)
	assert.Equal(t, 4, ds.calls)
	assert.Equal(t, "completed", result.Result.(map[string]any)["status"])
}

func TestClampInt(t *testing.T) {
	v := func(i int) *int { return &i }
	assert.Equal(t, 50, clampInt(nil, 50, 1, 500))
	assert.Equal(t, 1, clampInt(v(0), 50, 1, 500))
	assert.Equal(t, 500, clampInt(v(9999), 50, 1, 500))
	assert.Equal(t, 0, clampInt(v(0), 256, 0, 4096), "an explicit zero is kept when allowed")
	assert.Equal(t, 120, clampInt(v(120), 50, 1, 500))
}

func TestPrintablePreview(t *testing.T) {
	assert.Equal(t, "ab..\tc\r\n", printablePreview([]byte("ab\x00\xff\tc\r\n"), 100))
	assert.Equal(t, "abc", printablePreview([]byte("abcdef"), 3))
	assert.Equal(t, "", printablePreview(nil, 10))
}
