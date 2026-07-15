// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/tidwall/gjson"
)

// Shards typically fail in groups for the same reason, so only one shard is
// explained per group, capped at this many ES calls.
const MAX_ALLOCATION_EXPLAINS = 5

const ESHEALTH_TIMEOUT = 30 * time.Second

type EsHealthHandler struct {
	server *server.Server
	store  *ElasticEventstore
}

// EsHealth aggregates live Elasticsearch diagnostics. HealthReport is always
// present; the remaining fields are best-effort.
type EsHealth struct {
	HealthReport     json.RawMessage     `json:"healthReport" swaggertype:"object"`
	ClusterSettings  json.RawMessage     `json:"clusterSettings,omitempty" swaggertype:"object"`
	CatNodes         json.RawMessage     `json:"catNodes,omitempty" swaggertype:"object"`
	UnassignedShards *EsUnassignedShards `json:"unassignedShards,omitempty"`
}

// EsUnassignedShards groups the cluster's unassigned shards by primary/replica
// and unassigned reason.
type EsUnassignedShards struct {
	Total     int                       `json:"total"`
	Primaries int                       `json:"primaries"`
	Replicas  int                       `json:"replicas"`
	Groups    []*EsUnassignedShardGroup `json:"groups"`
}

// EsUnassignedShardGroup is one group of unassigned shards, with the allocation
// explanation for one sampled shard. CanAllocate and Deciders are digested from
// the explanation's stable fields; the raw Explanation is retained for support.
type EsUnassignedShardGroup struct {
	Reason      string          `json:"reason"`
	Primary     bool            `json:"primary"`
	Count       int             `json:"count"`
	CanAllocate string          `json:"canAllocate,omitempty"`
	Deciders    []*EsDecider    `json:"deciders,omitempty"`
	Explanation json.RawMessage `json:"explanation,omitempty" swaggertype:"object"`

	sampleIndex string
	sampleShard int64
}

// EsDecider is one distinct allocation decider that returned a NO decision for
// the sampled shard, along with the nodes it rejected.
type EsDecider struct {
	Name        string   `json:"name"`
	Explanation string   `json:"explanation"`
	Nodes       []string `json:"nodes"`
}

func RegisterEsHealthRoutes(srv *server.Server, store *ElasticEventstore, r chi.Router, prefix string) {
	h := &EsHealthHandler{
		server: srv,
		store:  store,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Get("/", h.getEsHealth)
	})
}

// @Summary      Get Elasticsearch Health
// @Description  Retrieves the live Elasticsearch health report, along with the cluster settings and node listing
// @Description  for support purposes. When the health report indicates a shard availability problem, the unassigned
// @Description  shards are inventoried and an allocation explanation is included for one sampled shard from each
// @Description  group of unassigned shards, along with a digest of the allocation verdict and blocking deciders.
// @Tags         Grid
// @Security     bearer[nodes/read]
// @Produce      json
// @Success      200  {object}  EsHealth  "The aggregated Elasticsearch health details"
// @Failure      401            "Request was not properly authenticated"
// @Failure      403            "Insufficient permissions for this request"
// @Failure      500            "Elasticsearch health report could not be retrieved; review SOC logs"
// @Router       /connect/eshealth/ [get]
func (h *EsHealthHandler) getEsHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ESHEALTH_TIMEOUT)
	defer cancel()
	logger := log.FromContext(ctx)

	if err := h.server.CheckAuthorized(ctx, "read", "nodes"); err != nil {
		web.Respond(w, r, http.StatusUnauthorized, err)
		return
	}

	report, err := h.store.clusterHealthReport(ctx)
	if err != nil {
		logger.WithError(err).Error("unable to retrieve Elasticsearch health report")
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	health := &EsHealth{
		HealthReport: json.RawMessage(report),
	}

	// Remaining diagnostics are best-effort; a failure shouldn't hide the report.
	if settings, err := h.store.clusterSettings(ctx); err == nil {
		health.ClusterSettings = json.RawMessage(settings)
	} else {
		logger.WithError(err).Warn("unable to retrieve Elasticsearch cluster settings")
	}

	if nodes, err := h.store.catNodes(ctx); err == nil {
		health.CatNodes = json.RawMessage(nodes)
	} else {
		logger.WithError(err).Warn("unable to retrieve Elasticsearch node listing")
	}

	// Only yellow/red: during master elections the status is "unknown" and the
	// shard listing itself would block waiting on master discovery.
	shardStatus := gjson.Get(report, "indicators.shards_availability.status").String()
	if shardStatus == "yellow" || shardStatus == "red" {
		health.UnassignedShards = h.buildUnassignedShards(ctx)
	}

	web.Respond(w, r, http.StatusOK, health)
}

func (h *EsHealthHandler) buildUnassignedShards(ctx context.Context) *EsUnassignedShards {
	logger := log.FromContext(ctx)

	shardsJson, err := h.store.catShards(ctx)
	if err != nil {
		logger.WithError(err).Warn("unable to retrieve Elasticsearch shard listing")
		return nil
	}

	unassigned := &EsUnassignedShards{
		Groups: make([]*EsUnassignedShardGroup, 0),
	}
	groupsByKey := make(map[string]*EsUnassignedShardGroup)
	gjson.Parse(shardsJson).ForEach(func(_, shard gjson.Result) bool {
		if shard.Get("state").String() != "UNASSIGNED" {
			return true
		}
		unassigned.Total++
		primary := shard.Get("prirep").String() == "p"
		if primary {
			unassigned.Primaries++
		} else {
			unassigned.Replicas++
		}
		reason := shard.Get(`unassigned\.reason`).String()
		key := fmt.Sprintf("%t|%s", primary, reason)
		group, exists := groupsByKey[key]
		if !exists {
			group = &EsUnassignedShardGroup{
				Reason:      reason,
				Primary:     primary,
				sampleIndex: shard.Get("index").String(),
				sampleShard: shard.Get("shard").Int(),
			}
			groupsByKey[key] = group
			unassigned.Groups = append(unassigned.Groups, group)
		}
		group.Count++
		return true
	})

	if unassigned.Total == 0 {
		return nil
	}

	// Explain the largest groups first, primaries before replicas.
	sort.SliceStable(unassigned.Groups, func(i, j int) bool {
		a, b := unassigned.Groups[i], unassigned.Groups[j]
		if a.Primary != b.Primary {
			return a.Primary
		}
		return a.Count > b.Count
	})

	for i, group := range unassigned.Groups {
		if i >= MAX_ALLOCATION_EXPLAINS {
			break
		}
		body := fmt.Sprintf(`{"index":%q,"shard":%d,"primary":%t}`, group.sampleIndex, group.sampleShard, group.Primary)
		if explain, err := h.store.allocationExplain(ctx, body); err == nil {
			group.Explanation = json.RawMessage(explain)
			group.digestExplanation(explain)
		} else {
			logger.WithError(err).WithField("shard", body).Warn("unable to retrieve Elasticsearch allocation explanation for sampled shard")
		}
	}

	return unassigned
}

// digestExplanation extracts the allocation verdict and distinct NO deciders,
// keyed on stable fields (can_allocate, decider names), never free-text prose.
// Deciders sharing a name but differing in explanation (e.g. per-node disk
// watermarks) stay separate so no node is attributed another node's details.
func (group *EsUnassignedShardGroup) digestExplanation(explain string) {
	group.CanAllocate = gjson.Get(explain, "can_allocate").String()

	decidersByKey := make(map[string]*EsDecider)
	gjson.Get(explain, "node_allocation_decisions").ForEach(func(_, node gjson.Result) bool {
		nodeName := node.Get("node_name").String()
		node.Get("deciders").ForEach(func(_, result gjson.Result) bool {
			if result.Get("decision").String() != "NO" {
				return true
			}
			name := result.Get("decider").String()
			explanation := result.Get("explanation").String()
			decider, exists := decidersByKey[name+"|"+explanation]
			if !exists {
				decider = &EsDecider{
					Name:        name,
					Explanation: explanation,
					Nodes:       make([]string, 0),
				}
				decidersByKey[name+"|"+explanation] = decider
				group.Deciders = append(group.Deciders, decider)
			}
			if nodeName != "" && !slices.Contains(decider.Nodes, nodeName) {
				decider.Nodes = append(decider.Nodes, nodeName)
			}
			return true
		})
		return true
	})
}
