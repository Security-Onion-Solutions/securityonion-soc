package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	lop "github.com/samber/lo/parallel"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type UtilHandler struct {
	server *Server
}

func RegisterUtilRoutes(srv *Server, r chi.Router, prefix string) {
	h := &UtilHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Put("/reverse-lookup", h.putReverseLookup)
	})
}

func (h *UtilHandler) putReverseLookup(w http.ResponseWriter, r *http.Request) {
	var body []string
	results := map[string][]string{}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	dedup := map[string]struct{}{}
	for _, ip := range body {
		dedup[ip] = struct{}{}
	}

	ips := make([]string, 0, len(dedup))
	for ip := range dedup {
		ips = append(ips, ip)
	}

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
	lop.ForEach(ips, func(ip string, _ int) {
		addrs, err := resolver.LookupAddr(context.Background(), ip)
		if err != nil && !strings.Contains(err.Error(), "Name or service not known") {
			log.WithField("ip", ip).WithError(err).Warn("Failed to lookup address")
		}
		if addrs == nil {
			addrs = []string{}
		}

		mapLock.Lock()
		results[ip] = addrs
		mapLock.Unlock()
	})

	// every entry gets something, even if it's just the original IP
	for k, v := range results {
		if len(v) == 0 {
			results[k] = []string{k}
		}
	}

	web.Respond(w, r, http.StatusOK, results)
}
