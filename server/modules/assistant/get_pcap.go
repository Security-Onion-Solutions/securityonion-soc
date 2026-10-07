// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

// These bound how much of a capture is put in front of the model per call, not what
// the grid can serve, so they are fixed rather than admin-configurable.
const (
	getPcapDefaultMaxPackets   = 50
	getPcapMaxMaxPackets       = 500
	getPcapDefaultPayloadBytes = 256
	getPcapMaxPayloadBytes     = 4096
	getPcapMaxWaitSeconds      = 30
	getPcapMaxConversations    = 25
)

var getPcapPollInterval = 2 * time.Second

func init() {
	t := &GetPcapTool{}
	knownTools[t.GetName()] = t
}

type GetPcapTool struct{}

func (t *GetPcapTool) GetName() string {
	return "get_pcap"
}

func (t *GetPcapTool) GetDescription() string {
	return "- Read the packets of a PCAP job created by `request_pcap`.\n" +
		"- Returns a `summary` of the capture (packet and byte counts, time span, packet types, conversations, TCP flags seen) " +
		"and the first `max_packets` packets with a printable preview of each application payload. `truncated` means the capture was larger than the packet viewer limit and the summary covers only its start.\n" +
		"- If the job is still `pending`, the sensor has not processed it yet. Pass `wait_seconds` (up to 30) to wait, or call again later.\n" +
		"- An `incomplete` job failed on the sensor; `failure` says why (for example, no PCAP retained for that time range).\n" +
		"- Examples:\n" +
		"  - `{\"job_id\": 1004, \"wait_seconds\": 20}`\n" +
		"  - `{\"job_id\": 1004, \"max_packets\": 200, \"payload_bytes\": 1024}`"
}

func (t *GetPcapTool) GetSchema() model.JSONSchema {
	return model.JSONSchema{
		Json: &model.ToolSchema{
			Type: "object",
			Properties: map[string]model.ToolSchemaProperty{
				"job_id": {
					Type:        "integer",
					Description: "The job_id returned by request_pcap",
				},
				"wait_seconds": {
					Type:        "integer",
					Description: "How long to wait for a pending job to complete, at most 30",
					Default:     0,
				},
				"max_packets": {
					Type:        "integer",
					Description: "The maximum number of packets to return, at most 500",
					Default:     getPcapDefaultMaxPackets,
				},
				"payload_bytes": {
					Type:        "integer",
					Description: "How many application payload bytes to preview per packet; 0 omits payloads",
					Default:     getPcapDefaultPayloadBytes,
				},
				"unwrap": {
					Type:        "boolean",
					Description: "Unwrap encapsulated (e.g. VXLAN) packets",
					Default:     false,
				},
			},
			Required: []string{"job_id"},
		},
	}
}

type getPcapArgs struct {
	JobId        int  `json:"job_id"`
	WaitSeconds  int  `json:"wait_seconds,omitempty"`
	MaxPackets   *int `json:"max_packets,omitempty"`
	PayloadBytes *int `json:"payload_bytes,omitempty"`
	Unwrap       bool `json:"unwrap,omitempty"`
}

type pcapPacket struct {
	Number         int       `json:"number"`
	Timestamp      time.Time `json:"timestamp"`
	Type           string    `json:"type"`
	SrcIp          string    `json:"src_ip,omitempty"`
	SrcPort        int       `json:"src_port,omitempty"`
	DstIp          string    `json:"dst_ip,omitempty"`
	DstPort        int       `json:"dst_port,omitempty"`
	Length         int       `json:"length"`
	Flags          []string  `json:"flags,omitempty"`
	PayloadLength  int       `json:"payload_length,omitempty"`
	PayloadPreview string    `json:"payload_preview,omitempty"`
}

type pcapConversation struct {
	SrcIp   string `json:"src_ip"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIp   string `json:"dst_ip"`
	DstPort int    `json:"dst_port,omitempty"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

type pcapSummary struct {
	Packets       int                `json:"packets"`
	Bytes         int                `json:"bytes"`
	FirstPacket   time.Time          `json:"first_packet"`
	LastPacket    time.Time          `json:"last_packet"`
	Types         map[string]int     `json:"types"`
	Conversations []pcapConversation `json:"conversations"`
	TcpFlags      []string           `json:"tcp_flags,omitempty"`
}

func (t *GetPcapTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (result *model.ToolResponse, err error) {
	logger := log.FromContext(ctx).WithFields(log.Fields{
		"sessionId": req.SessionId,
		"toolUseId": req.ToolUseId,
	})

	logger.WithField("toolParameters", req.Params).Info("running tool for assistant")

	userId := ctx.Value(web.ContextKeyRequestorId).(string)

	args := &getPcapArgs{}
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

	maxPackets := clampInt(args.MaxPackets, getPcapDefaultMaxPackets, 1, getPcapMaxMaxPackets)
	payloadBytes := clampInt(args.PayloadBytes, getPcapDefaultPayloadBytes, 0, getPcapMaxPayloadBytes)
	wait := time.Duration(min(max(args.WaitSeconds, 0), getPcapMaxWaitSeconds)) * time.Second

	job, err := waitForJob(ctx, srv, args.JobId, wait)
	if err != nil {
		return nil, err
	}

	switch job.Status {
	case model.JobStatusPending:
		result.Result = map[string]any{
			"job_id": job.Id,
			"status": "pending",
			"next":   "The sensor has not processed this job yet. Call get_pcap again, optionally with wait_seconds.",
		}
		return result, nil
	case model.JobStatusIncomplete:
		result.Result = map[string]any{
			"job_id":     job.Id,
			"status":     "incomplete",
			"failure":    job.Failure,
			"fail_count": job.FailCount,
		}
		return result, nil
	case model.JobStatusDeleted:
		return nil, fmt.Errorf("job %d has been deleted", job.Id)
	}

	summaryLimit := config.DEFAULT_MAX_PACKET_COUNT
	if srv.Config != nil {
		summaryLimit = srv.Config.MaxPacketCount
	}

	// Ask for one extra packet so a capture at the summary limit can be told apart from a larger one.
	packets, hasErrors, err := srv.Datastore.GetPackets(ctx, job.Id, 0, summaryLimit+1, args.Unwrap, true)
	if err != nil {
		var unauthorized *model.Unauthorized
		if errors.As(err, &unauthorized) {
			return nil, errors.New("ERROR_PERMISSION_DENIED")
		}
		logger.WithError(err).Error("failed to read pcap packets")
		return nil, err
	}

	truncated := len(packets) > summaryLimit
	if truncated {
		packets = packets[:summaryLimit]
	}

	if len(packets) == 0 {
		result.Result = map[string]any{
			"job_id": job.Id,
			"status": "completed",
			"note":   "The job completed but no packets matched the filter.",
		}
		return result, nil
	}

	result.Result = map[string]any{
		"job_id":    job.Id,
		"status":    "completed",
		"truncated": truncated,
		"summary":   summarizePackets(packets),
		"packets":   toPcapPackets(packets[:min(len(packets), maxPackets)], payloadBytes),
	}
	if hasErrors {
		result.Result.(map[string]any)["note"] = "Some packets could not be decoded and were omitted."
	}

	return result, nil
}

func clampInt(value *int, def int, lo int, hi int) int {
	if value == nil {
		return def
	}
	return min(max(*value, lo), hi)
}

func waitForJob(ctx context.Context, srv *server.Server, jobId int, wait time.Duration) (*model.Job, error) {
	deadline := time.Now().Add(wait)
	for {
		job := srv.Datastore.GetJob(ctx, jobId)
		if job == nil {
			return nil, fmt.Errorf("job %d was not found or is not accessible", jobId)
		}
		if job.Status != model.JobStatusPending || !time.Now().Before(deadline) {
			return job, nil
		}

		select {
		case <-ctx.Done():
			return job, nil
		case <-time.After(min(getPcapPollInterval, time.Until(deadline))):
		}
	}
}

func summarizePackets(packets []*model.Packet) *pcapSummary {
	summary := &pcapSummary{
		Types: map[string]int{},
	}

	convs := map[string]*pcapConversation{}
	order := []*pcapConversation{}
	flags := map[string]bool{}

	for _, p := range packets {
		summary.Packets++
		summary.Bytes += p.Length
		summary.Types[p.Type]++

		if summary.FirstPacket.IsZero() || p.Timestamp.Before(summary.FirstPacket) {
			summary.FirstPacket = p.Timestamp
		}
		if p.Timestamp.After(summary.LastPacket) {
			summary.LastPacket = p.Timestamp
		}

		for _, f := range p.Flags {
			flags[f] = true
		}

		if p.SrcIp == "" && p.DstIp == "" {
			continue
		}

		// Both directions of a flow share one conversation, keyed by the side seen first.
		key := fmt.Sprintf("%s:%d-%s:%d", p.SrcIp, p.SrcPort, p.DstIp, p.DstPort)
		reverse := fmt.Sprintf("%s:%d-%s:%d", p.DstIp, p.DstPort, p.SrcIp, p.SrcPort)
		conv, ok := convs[key]
		if !ok {
			conv, ok = convs[reverse]
		}
		if !ok {
			conv = &pcapConversation{SrcIp: p.SrcIp, SrcPort: p.SrcPort, DstIp: p.DstIp, DstPort: p.DstPort}
			convs[key] = conv
			order = append(order, conv)
		}
		conv.Packets++
		conv.Bytes += p.Length
	}

	sort.SliceStable(order, func(i, j int) bool {
		return order[i].Bytes > order[j].Bytes
	})
	for _, c := range order {
		summary.Conversations = append(summary.Conversations, *c)
	}
	if len(summary.Conversations) > getPcapMaxConversations {
		summary.Conversations = summary.Conversations[:getPcapMaxConversations]
	}

	for f := range flags {
		summary.TcpFlags = append(summary.TcpFlags, f)
	}
	sort.Strings(summary.TcpFlags)

	return summary
}

func toPcapPackets(packets []*model.Packet, payloadBytes int) []pcapPacket {
	out := make([]pcapPacket, 0, len(packets))
	for _, p := range packets {
		pp := pcapPacket{
			Number:    p.Number,
			Timestamp: p.Timestamp,
			Type:      p.Type,
			SrcIp:     p.SrcIp,
			SrcPort:   p.SrcPort,
			DstIp:     p.DstIp,
			DstPort:   p.DstPort,
			Length:    p.Length,
			Flags:     p.Flags,
		}

		if p.PayloadOffset > 0 {
			if frame, err := base64.StdEncoding.DecodeString(p.Payload); err == nil && p.PayloadOffset < len(frame) {
				app := frame[p.PayloadOffset:]
				pp.PayloadLength = len(app)
				if payloadBytes > 0 {
					pp.PayloadPreview = printablePreview(app, payloadBytes)
				}
			}
		}

		out = append(out, pp)
	}
	return out
}

// printablePreview keeps the payload readable for the model: printable ASCII and
// common whitespace pass through, everything else becomes '.', as in a hexdump.
func printablePreview(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	var sb strings.Builder
	sb.Grow(len(data))
	for _, b := range data {
		if (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
