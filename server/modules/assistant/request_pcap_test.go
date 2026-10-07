// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeJobPopulatorEventstore struct {
	*server.FakeEventstore
	err         error
	idField     string
	idValue     string
	timestamp   string
	populatedTo *model.Job
}

func (f *fakeJobPopulatorEventstore) PopulateJobFromDocQuery(ctx context.Context, idField string, idValue string, timestampStr string, job *model.Job) error {
	f.idField, f.idValue, f.timestamp, f.populatedTo = idField, idValue, timestampStr, job
	if f.err != nil {
		return f.err
	}
	job.SetNodeId("Sensor1")
	job.Filter.SrcIp = "10.0.0.5"
	job.Filter.DstIp = "93.184.216.34"
	return nil
}

func runRequestPcap(t *testing.T, srv *server.Server, params string) (*model.ToolResponse, error) {
	t.Helper()
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")
	return (&RequestPcapTool{}).Execute(ctx, srv, &model.ToolRequest{Params: json.RawMessage(params)})
}

func TestRequestPcapTool_ByEvent(t *testing.T) {
	ds := server.NewFakeDatastore()
	ds.CreateJobResult = model.NewJob()
	ds.CreateJobResult.Id = 1004
	es := &fakeJobPopulatorEventstore{FakeEventstore: server.NewFakeEventstore()}
	srv := &server.Server{Datastore: ds, Eventstore: es, Config: &config.ServerConfig{BaseUrl: "https://so/"}}

	result, err := runRequestPcap(t, srv, `{"event_id": "abc123", "timestamp": "2026-10-06T19:29:39.332Z"}`)
	require.NoError(t, err)

	assert.Equal(t, "_id", es.idField)
	assert.Equal(t, "abc123", es.idValue)
	assert.Equal(t, "2026-10-06T19:29:39.332Z", es.timestamp)
	assert.Same(t, ds.CreateJobResult, ds.LastPivotJob)
	assert.Nil(t, ds.LastAddedJob, "event requests go through the pivot path")
	assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

	res := result.Result.(map[string]any)
	assert.Equal(t, 1004, res["job_id"])
	assert.Equal(t, "sensor1", res["node_id"])
	assert.Equal(t, "pending", res["status"])
	assert.Equal(t, "https://so/#/job/1004", res["job_url"])
}

func TestRequestPcapTool_ByCommunityId(t *testing.T) {
	ds := server.NewFakeDatastore()
	es := &fakeJobPopulatorEventstore{FakeEventstore: server.NewFakeEventstore()}
	srv := &server.Server{Datastore: ds, Eventstore: es}

	_, err := runRequestPcap(t, srv, `{"community_id": "1:URggUwcolUh/BgIWApL6rUUZUK4=", "timestamp": "2026-10-06T19:29:39Z"}`)
	require.NoError(t, err)

	assert.Equal(t, "network.community_id", es.idField)
	assert.Equal(t, "1:URggUwcolUh/BgIWApL6rUUZUK4=", es.idValue)
	assert.NotNil(t, ds.LastPivotJob)
}

func TestRequestPcapTool_ByFilter(t *testing.T) {
	ds := server.NewFakeDatastore()
	srv := &server.Server{Datastore: ds, Eventstore: server.NewFakeEventstore()}

	_, err := runRequestPcap(t, srv, `{"node_id": "Sensor1", "begin_time": "2026-10-06T19:29:00Z", "end_time": "2026-10-06T19:31:00Z",
		"src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "TCP"}`)
	require.NoError(t, err)

	job := ds.LastAddedJob
	require.NotNil(t, job)
	assert.Nil(t, ds.LastPivotJob)
	assert.Equal(t, "sensor1", job.GetNodeId())
	assert.Equal(t, time.Date(2026, 10, 6, 19, 29, 0, 0, time.UTC), job.Filter.BeginTime)
	assert.Equal(t, time.Date(2026, 10, 6, 19, 31, 0, 0, time.UTC), job.Filter.EndTime)
	assert.Equal(t, "10.0.0.5", job.Filter.SrcIp)
	assert.Equal(t, "93.184.216.34", job.Filter.DstIp)
	assert.Equal(t, 443, job.Filter.DstPort)
	assert.Equal(t, model.PROTOCOL_TCP, job.Filter.Protocol)
}

func TestRequestPcapTool_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		params  string
		setup   func(ds *server.FakeDatastore, es *fakeJobPopulatorEventstore)
		noPop   bool
		wantErr string
	}{
		{
			name:    "bad json",
			params:  `{`,
			wantErr: "ERROR_ASSISTANT_UNMARSHAL_PARAMS",
		},
		{
			name:    "event without timestamp",
			params:  `{"event_id": "abc"}`,
			wantErr: "timestamp is required when requesting by event",
		},
		{
			name:    "event with bad timestamp",
			params:  `{"event_id": "abc", "timestamp": "yesterday"}`,
			wantErr: "timestamp must be RFC3339",
		},
		{
			name:    "event store cannot populate jobs",
			params:  `{"event_id": "abc", "timestamp": "2026-10-06T19:29:39Z"}`,
			noPop:   true,
			wantErr: "the configured event store cannot look up PCAP by event",
		},
		{
			name:   "event has no tuple",
			params: `{"event_id": "abc", "timestamp": "2026-10-06T19:29:39Z"}`,
			setup: func(ds *server.FakeDatastore, es *fakeJobPopulatorEventstore) {
				es.err = errors.New("No TCP/UDP/ICMP record was found for retrieving PCAP")
			},
			wantErr: "No TCP/UDP/ICMP record was found for retrieving PCAP",
		},
		{
			name:   "pivot permission denied",
			params: `{"event_id": "abc", "timestamp": "2026-10-06T19:29:39Z"}`,
			setup: func(ds *server.FakeDatastore, es *fakeJobPopulatorEventstore) {
				ds.AddPivotJobErr = model.NewUnauthorized("test-user-id", "pivot", "jobs")
			},
			wantErr: "ERROR_PERMISSION_DENIED",
		},
		{
			name:    "no event and no node",
			params:  `{"src_ip": "10.0.0.5"}`,
			wantErr: "provide event_id or community_id, or node_id with a time window when requesting by filter",
		},
		{
			name:    "filter without ips",
			params:  `{"node_id": "s1", "begin_time": "2026-10-06T19:29:00Z", "end_time": "2026-10-06T19:31:00Z"}`,
			wantErr: "src_ip or dst_ip is required when requesting by filter",
		},
		{
			name:    "filter with bad begin",
			params:  `{"node_id": "s1", "src_ip": "10.0.0.5", "begin_time": "-1h", "end_time": "2026-10-06T19:31:00Z"}`,
			wantErr: "begin_time must be RFC3339",
		},
		{
			name:    "filter with end before begin",
			params:  `{"node_id": "s1", "src_ip": "10.0.0.5", "begin_time": "2026-10-06T19:31:00Z", "end_time": "2026-10-06T19:29:00Z"}`,
			wantErr: "end_time must be after begin_time",
		},
		{
			name:    "filter window too large",
			params:  `{"node_id": "s1", "src_ip": "10.0.0.5", "begin_time": "2026-10-06T18:00:00Z", "end_time": "2026-10-06T19:00:01Z"}`,
			wantErr: "the capture window cannot exceed 1 hour",
		},
		{
			name:    "filter with bad protocol",
			params:  `{"node_id": "s1", "src_ip": "10.0.0.5", "begin_time": "2026-10-06T19:29:00Z", "end_time": "2026-10-06T19:31:00Z", "protocol": "sctp"}`,
			wantErr: "protocol must be tcp, udp or icmp",
		},
		{
			name:   "filter permission denied",
			params: `{"node_id": "s1", "src_ip": "10.0.0.5", "begin_time": "2026-10-06T19:29:00Z", "end_time": "2026-10-06T19:31:00Z"}`,
			setup: func(ds *server.FakeDatastore, es *fakeJobPopulatorEventstore) {
				ds.AddJobErr = model.NewUnauthorized("test-user-id", "write", "jobs")
			},
			wantErr: "ERROR_PERMISSION_DENIED",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := server.NewFakeDatastore()
			es := &fakeJobPopulatorEventstore{FakeEventstore: server.NewFakeEventstore()}
			if tc.setup != nil {
				tc.setup(ds, es)
			}
			srv := &server.Server{Datastore: ds, Eventstore: es}
			if tc.noPop {
				srv.Eventstore = server.NewFakeEventstore()
			}

			result, err := runRequestPcap(t, srv, tc.params)
			assert.Nil(t, result)
			assert.EqualError(t, err, tc.wantErr)
		})
	}
}
