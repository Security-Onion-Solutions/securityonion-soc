// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

// Keeps a model-built filter from asking a sensor to scan hours of PCAP; event-based
// requests derive their own window and are not subject to it.
const requestPcapMaxWindow = time.Hour

func init() {
	t := &RequestPcapTool{}
	knownTools[t.GetName()] = t
}

type RequestPcapTool struct{}

func (t *RequestPcapTool) GetName() string {
	return "request_pcap"
}

func (t *RequestPcapTool) GetDescription() string {
	return "- Request full packet capture (PCAP) from a sensor. This creates a PCAP job; retrieval is asynchronous.\n" +
		"- After requesting, call `get_pcap` with the returned `job_id` to read the packets.\n" +
		"- **Preferred**: request by event. Pass the event `_id` as `event_id` (or its `network.community_id` as `community_id`) " +
		"and the event `@timestamp` as `timestamp`. The sensor, 5-tuple and time window are derived from the event.\n" +
		"  - `{\"event_id\": \"P5mgnpEB0JpjNDZz1bIN\", \"timestamp\": \"2026-10-06T19:29:39.332Z\"}`\n" +
		"- Otherwise request by filter: `node_id` (the sensor, from `observer.name`), `begin_time` and `end_time` (RFC3339, at most 1 hour apart), " +
		"and at least one of `src_ip`/`dst_ip`. Ports and `protocol` (tcp, udp, icmp) narrow the match. Direction does not matter.\n" +
		"  - `{\"node_id\": \"sensor1\", \"begin_time\": \"2026-10-06T19:29:00Z\", \"end_time\": \"2026-10-06T19:31:00Z\", \"src_ip\": \"10.0.0.5\", \"dst_ip\": \"93.184.216.34\", \"dst_port\": 443, \"protocol\": \"tcp\"}`"
}

func (t *RequestPcapTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"event_id": {
					Type:        "string",
					Description: "The _id of the event to pull PCAP for",
				},
				"community_id": {
					Type:        "string",
					Description: "The network.community_id of the event to pull PCAP for; ignored when event_id is set",
				},
				"timestamp": {
					Type:        "string",
					Description: "The @timestamp of the event, RFC3339",
				},
				"node_id": {
					Type:        "string",
					Description: "The sensor to pull PCAP from when requesting by filter",
				},
				"begin_time": {
					Type:        "string",
					Description: "Start of the capture window when requesting by filter, RFC3339",
				},
				"end_time": {
					Type:        "string",
					Description: "End of the capture window when requesting by filter, RFC3339",
				},
				"src_ip": {
					Type: "string",
				},
				"src_port": {
					Type: "integer",
				},
				"dst_ip": {
					Type: "string",
				},
				"dst_port": {
					Type: "integer",
				},
				"protocol": {
					Type:        "string",
					Description: "tcp, udp or icmp",
				},
			},
		},
	}
}

type requestPcapArgs struct {
	EventId     string `json:"event_id,omitempty"`
	CommunityId string `json:"community_id,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
	NodeId      string `json:"node_id,omitempty"`
	BeginTime   string `json:"begin_time,omitempty"`
	EndTime     string `json:"end_time,omitempty"`
	SrcIp       string `json:"src_ip,omitempty"`
	SrcPort     int    `json:"src_port,omitempty"`
	DstIp       string `json:"dst_ip,omitempty"`
	DstPort     int    `json:"dst_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

func (t *RequestPcapTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &requestPcapArgs{}
	result = &model.ToolResponse{
		ToolName:       t.GetName(),
		OnBehalfOfUser: userId,
	}

	start := time.Now()
	defer func() {
		if result != nil {
			result.TimeToExecute = time.Since(start)
		}
	}()

	err = json.Unmarshal([]byte(req.Params), args)
	if err != nil {
		logger.WithError(err).WithField("toolParams", req.Params).Error("failed to unmarshal tool params")
		return nil, errors.New("ERROR_ASSISTANT_UNMARSHAL_PARAMS")
	}

	result.Parameters = args

	var job *model.Job
	if args.EventId != "" || args.CommunityId != "" {
		job, err = t.createPivotJob(ctx, srv, args)
	} else {
		job, err = t.createFilterJob(ctx, srv, args)
	}
	if err != nil {
		var unauthorized *model.Unauthorized
		if errors.As(err, &unauthorized) {
			return nil, errors.New("ERROR_PERMISSION_DENIED")
		}
		logger.WithError(err).Error("failed to create pcap job")
		return nil, err
	}

	if srv.Host != nil {
		srv.Host.Broadcast("job", "jobs", job)
	}

	jobUrl := "#/job/" + strconv.Itoa(job.Id)
	if srv.Config != nil {
		jobUrl = srv.Config.BaseUrl + jobUrl
	}

	result.Result = map[string]any{
		"job_id":  job.Id,
		"node_id": job.GetNodeId(),
		"filter":  job.Filter,
		"status":  "pending",
		"job_url": jobUrl,
		"next":    "Call get_pcap with this job_id to read the packets once the sensor has processed the job.",
	}

	return result, nil
}

// Validation errors from these helpers are returned to the model as the tool result so
// it can correct its parameters; they are not shown to users, so they are not localized.
func (t *RequestPcapTool) createPivotJob(ctx context.Context, srv *server.Server, args *requestPcapArgs) (*model.Job, error) {
	if args.Timestamp == "" {
		return nil, errors.New("timestamp is required when requesting by event")
	}
	if _, err := time.Parse(time.RFC3339, args.Timestamp); err != nil {
		return nil, errors.New("timestamp must be RFC3339")
	}

	populator, ok := srv.Eventstore.(server.JobPopulator)
	if !ok {
		return nil, errors.New("the configured event store cannot look up PCAP by event")
	}

	idField, idValue := "_id", args.EventId
	if idValue == "" {
		idField, idValue = "network.community_id", args.CommunityId
	}

	job := srv.Datastore.CreateJob(ctx)
	if err := populator.PopulateJobFromDocQuery(ctx, idField, idValue, args.Timestamp, job); err != nil {
		return nil, err
	}

	if err := srv.Datastore.AddPivotJob(ctx, job); err != nil {
		return nil, err
	}

	return job, nil
}

func (t *RequestPcapTool) createFilterJob(ctx context.Context, srv *server.Server, args *requestPcapArgs) (*model.Job, error) {
	if args.NodeId == "" {
		return nil, errors.New("provide event_id or community_id, or node_id with a time window when requesting by filter")
	}
	if args.SrcIp == "" && args.DstIp == "" {
		return nil, errors.New("src_ip or dst_ip is required when requesting by filter")
	}

	begin, err := time.Parse(time.RFC3339, args.BeginTime)
	if err != nil {
		return nil, errors.New("begin_time must be RFC3339")
	}
	end, err := time.Parse(time.RFC3339, args.EndTime)
	if err != nil {
		return nil, errors.New("end_time must be RFC3339")
	}
	if !end.After(begin) {
		return nil, errors.New("end_time must be after begin_time")
	}
	if end.Sub(begin) > requestPcapMaxWindow {
		return nil, errors.New("the capture window cannot exceed 1 hour")
	}

	protocol := strings.ToLower(args.Protocol)
	switch protocol {
	case "", model.PROTOCOL_TCP, model.PROTOCOL_UDP, model.PROTOCOL_ICMP:
	default:
		return nil, errors.New("protocol must be tcp, udp or icmp")
	}

	job := srv.Datastore.CreateJob(ctx)
	job.SetNodeId(args.NodeId)
	job.Filter = model.NewFilter()
	job.Filter.BeginTime = begin
	job.Filter.EndTime = end
	job.Filter.SrcIp = args.SrcIp
	job.Filter.SrcPort = args.SrcPort
	job.Filter.DstIp = args.DstIp
	job.Filter.DstPort = args.DstPort
	job.Filter.Protocol = protocol

	if err := srv.Datastore.AddJob(ctx, job); err != nil {
		return nil, err
	}

	return job, nil
}
