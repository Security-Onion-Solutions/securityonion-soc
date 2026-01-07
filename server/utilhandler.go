// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	lop "github.com/samber/lo/parallel"
)

type UtilHandler struct {
	server *Server
}

func NewUtilHandler(srv *Server) *UtilHandler {
	return &UtilHandler{
		server: srv,
	}
}

func RegisterUtilRoutes(srv *Server, r chi.Router, prefix string) {
	h := &UtilHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Put("/reverse-lookup", h.PutReverseLookup)
	})
}

// @Summary      DNS Reverse Lookup
// @Description  Performs a reverse name lookup query on a list of provided IP addresses. The configured list of DNS overrides is checked first, and if no match is found a DNS reverse lookup is performed. The input listed is deduplicated first to avoid repeated lookups in the same request.
// @Security     bearer
// @Tags         Query
// @Param        request  body  []string  true "List of IP addresses to reverse lookup"
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string][]string   "Outputs mapping of IP address to a list of resolved domain names"
// @Failure      400         "The provided input object or parameters are malformed or invalid"
// @Failure      401         "Request was not properly authenticated"
// @Failure      500         "Internal SOC error; review SOC logs"
// @Router       /connect/util/reverse-lookup [put]
func (h *UtilHandler) PutReverseLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)

	var body []string
	results := map[string][]string{}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		logger.WithError(err).Error("failed to decode request body")
		web.Respond(w, r, http.StatusBadRequest, err)

		return
	}

	// ensure we only look up each IP once
	dedup := map[string]struct{}{}
	for _, ip := range body {
		if net.ParseIP(ip) != nil {
			dedup[ip] = struct{}{}
		}
	}

	msearchRequests := make([]*model.EventMSearchCriteria, 0, len(dedup))

	// build search criteria for ES lookup
	for ip := range dedup {
		criteria := model.NewEventMSearchCriteria()

		err = criteria.Populate("so-ip-mappings", "so.ip_address:"+ip)
		if err != nil {
			logger.WithError(err).Error("failed to populate search criteria")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}

		msearchRequests = append(msearchRequests, criteria)
	}

	logger.WithField("ipsToLookup", len(msearchRequests)).Info("starting ES lookup")

	result, err := h.server.Eventstore.MSearch(ctx, msearchRequests)
	if err != nil {
		if strings.Contains(err.Error(), "no such index") {
			logger.WithError(err).Warn("index not found, skipping ES lookup")
		} else {
			logger.WithError(err).Error("failed to perform ES lookup")
			web.Respond(w, r, http.StatusInternalServerError, err)

			return
		}
	}

	// parse results from ES lookup and remove results from dedup
	for _, response := range result.Responses {
		for _, result := range response.Events {
			ip, ok := result.Payload["so.ip_address"].(string)
			if !ok {
				continue
			}

			desc, ok := result.Payload["so.description"].(string)
			if !ok {
				continue
			}

			results[ip] = []string{desc}

			delete(dedup, ip)
		}
	}

	logger.WithFields(log.Fields{
		"ipsFoundInES":     len(results),
		"esSearchTimeInMS": result.ElapsedMs,
	}).Info("completed ES lookup")

	if h.server.Config.EnableReverseLookup {
		// build list of IPs to lookup with DNS
		ips := make([]string, 0, len(dedup))
		for ip := range dedup {
			ips = append(ips, ip)
		}

		if len(ips) != 0 {
			logger.WithField("ipsToLookup", len(ips)).Info("starting DNS lookup")

			var resolver *net.Resolver

			if h.server.Config.Dns != "" {
				dnsServer := h.server.Config.Dns

				_, _, err = net.SplitHostPort(dnsServer)
				if err != nil && err.Error() == "missing port in address" {
					dnsServer = net.JoinHostPort(dnsServer, "53")
					err = nil
				}

				if err == nil {
					resolver = &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							d := net.Dialer{
								Timeout: time.Millisecond * time.Duration(3000),
							}
							return d.DialContext(ctx, network, dnsServer)
						},
					}
				}
			}

			if resolver == nil {
				resolver = net.DefaultResolver
			}

			mapLock := sync.Mutex{}
			resolved := int32(0)

			lop.ForEach(ips, func(ip string, _ int) {
				addrs, err := resolver.LookupAddr(ctx, ip)
				if err != nil && !strings.Contains(err.Error(), "Name or service not known") {
					logger.WithField("ip", ip).WithError(err).Warn("Failed to lookup address")
				}
				if len(addrs) == 0 {
					addrs = []string{ip}
				} else {
					atomic.AddInt32(&resolved, 1)
				}

				mapLock.Lock()
				results[ip] = addrs
				mapLock.Unlock()
			})

			logger.WithField("ipsResolvedByDNS", resolved).Info("completed DNS lookup")
		}
	} else {
		logger.Info("skipping DNS lookup, reverse lookup is disabled")
	}

	web.Respond(w, r, http.StatusOK, results)
}
