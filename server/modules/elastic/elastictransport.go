// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type ElasticTransport struct {
	internal http.RoundTripper
}

func NewElasticTransport(user string, pass string, timeoutMs time.Duration, verifyCert bool) http.RoundTripper {
	httpTransport := &http.Transport{
		MaxIdleConnsPerHost:   10,
		ResponseHeaderTimeout: timeoutMs,
		DialContext:           (&net.Dialer{Timeout: timeoutMs}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifyCert,
		},
	}

	if len(user) > 0 && len(pass) > 0 {
		return &ElasticTransport{
			internal: httpTransport,
		}
	}

	return httpTransport
}

func (transport *ElasticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if username, ok := req.Context().Value(web.ContextKeyRunAsUsername).(string); ok {
		log.WithFields(log.Fields{
			"runAsUsername": username,
			"requestId":     req.Context().Value(web.ContextKeyRequestId),
		}).Debug("Executing Elastic request on behalf of user")
		req.Header.Set("es-security-runas-user", username)
	} else {
		log.Debug("Elastic request without es-security-runas-user")
	}
	return transport.internal.RoundTrip(req)
}
