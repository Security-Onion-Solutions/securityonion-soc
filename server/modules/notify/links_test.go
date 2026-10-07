// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestPrefixRelativeLink(t *testing.T) {
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}

	assert.Equal(t, "", PrefixRelativeLink("", srv))
	assert.Equal(t, "https://other.com/foo", PrefixRelativeLink("https://other.com/foo", srv))
	assert.Equal(t, "http://other.com/foo", PrefixRelativeLink("http://other.com/foo", srv))
	assert.Equal(t, "https://soc.example.com/#/job/123", PrefixRelativeLink("/#/job/123", srv))
	assert.Equal(t, "https://soc.example.com/#/job/123", PrefixRelativeLink("#/job/123", srv))
	assert.Equal(t, "https://soc.example.com/api/stream/123", PrefixRelativeLink("api/stream/123", srv))

	// Without trailing slash in BaseUrl
	srvNoSlash := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com",
		},
	}
	assert.Equal(t, "https://soc.example.com/#/job/123", PrefixRelativeLink("/#/job/123", srvNoSlash))

	// BaseUrl is "/"
	srvRoot := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "/",
		},
	}
	assert.Equal(t, "/#/job/123", PrefixRelativeLink("/#/job/123", srvRoot))

	// Nil server or nil config
	assert.Equal(t, "/#/job/123", PrefixRelativeLink("/#/job/123", nil))
	assert.Equal(t, "/#/job/123", PrefixRelativeLink("/#/job/123", &server.Server{}))
}

func TestResolveOutboundPayload(t *testing.T) {
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}

	payload := &model.NotificationPayload{
		Title: "Test",
		Links: map[string]string{
			"View": "/#/job/123",
			"Ext":  "https://external.com",
		},
		Attachments: []model.Attachment{
			{Filename: "data.pcap", URL: "/api/stream/123"},
		},
	}

	resolved := ResolveOutboundPayload(srv, payload)
	assert.NotNil(t, resolved)
	assert.Equal(t, "https://soc.example.com/#/job/123", resolved.Links["View"])
	assert.Equal(t, "https://external.com", resolved.Links["Ext"])
	assert.Equal(t, "https://soc.example.com/api/stream/123", resolved.Attachments[0].URL)

	// Original payload should not be modified
	assert.Equal(t, "/#/job/123", payload.Links["View"])

	// Nil cases
	assert.Nil(t, ResolveOutboundPayload(srv, nil))

	srvEmpty := &server.Server{Config: &config.ServerConfig{BaseUrl: "/"}}
	resolvedEmpty := ResolveOutboundPayload(srvEmpty, payload)
	assert.Equal(t, "/#/job/123", resolvedEmpty.Links["View"])
	assert.Equal(t, "https://external.com", resolvedEmpty.Links["Ext"])
}

func TestResolveOutboundPayload_SanitizesUnsafeLinks(t *testing.T) {
	srv := &server.Server{
		Config: &config.ServerConfig{
			BaseUrl: "https://soc.example.com/",
		},
	}

	payload := &model.NotificationPayload{
		Title: "Test Unsafe",
		Links: map[string]string{
			"Safe":   "/#/job/123",
			"BadJS":  "javascript:alert('xss')",
			"BadVBS": "vbscript:msgbox('hi')",
			"BadDat": "data:text/html,<script>alert(1)</script>",
		},
		Attachments: []model.Attachment{
			{Filename: "good.pcap", URL: "/api/stream/123"},
			{Filename: "bad.pcap", URL: "javascript:alert(1)"},
			{Filename: "data.pcap", URL: "data:text/plain;base64,abc"},
		},
	}

	resolved := ResolveOutboundPayload(srv, payload)
	assert.NotNil(t, resolved)
	assert.Equal(t, "https://soc.example.com/#/job/123", resolved.Links["Safe"])
	assert.NotContains(t, resolved.Links, "BadJS")
	assert.NotContains(t, resolved.Links, "BadVBS")
	assert.NotContains(t, resolved.Links, "BadDat")

	assert.Len(t, resolved.Attachments, 1)
	assert.Equal(t, "good.pcap", resolved.Attachments[0].Filename)
	assert.Equal(t, "https://soc.example.com/api/stream/123", resolved.Attachments[0].URL)

	// Even when srv is nil, unsafe links must be stripped
	resolvedNilSrv := ResolveOutboundPayload(nil, payload)
	assert.NotNil(t, resolvedNilSrv)
	assert.Equal(t, "/#/job/123", resolvedNilSrv.Links["Safe"])
	assert.NotContains(t, resolvedNilSrv.Links, "BadJS")
	assert.NotContains(t, resolvedNilSrv.Links, "BadVBS")
	assert.NotContains(t, resolvedNilSrv.Links, "BadDat")
	assert.Len(t, resolvedNilSrv.Attachments, 1)
	assert.Equal(t, "/api/stream/123", resolvedNilSrv.Attachments[0].URL)
}
