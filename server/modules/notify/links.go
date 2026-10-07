// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

// PrefixRelativeLink checks if the provided link is relative (i.e. does not start with http:// or https://),
// and if so, prefixes it with the configured server.Config.BaseUrl.
func PrefixRelativeLink(link string, srv *server.Server) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return ""
	}
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if srv != nil && srv.Config != nil && srv.Config.BaseUrl != "" && srv.Config.BaseUrl != "/" {
		base := strings.TrimRight(srv.Config.BaseUrl, "/")
		return base + "/" + strings.TrimLeft(link, "/")
	}
	return link
}

// ResolveOutboundPayload returns a copy of the notification payload with any relative
// links in payload.Links and payload.Attachments prefixed with the server's configured BaseUrl.
func ResolveOutboundPayload(srv *server.Server, payload *model.NotificationPayload) *model.NotificationPayload {
	if payload == nil {
		return nil
	}
	if srv == nil || srv.Config == nil || srv.Config.BaseUrl == "" || srv.Config.BaseUrl == "/" {
		return payload
	}

	clone := *payload
	if len(payload.Links) > 0 {
		clone.Links = make(map[string]string, len(payload.Links))
		for k, v := range payload.Links {
			clone.Links[k] = PrefixRelativeLink(v, srv)
		}
	}
	if len(payload.Attachments) > 0 {
		clone.Attachments = make([]model.Attachment, len(payload.Attachments))
		for i, att := range payload.Attachments {
			attClone := att
			if attClone.URL != "" {
				attClone.URL = PrefixRelativeLink(attClone.URL, srv)
			}
			clone.Attachments[i] = attClone
		}
	}
	return &clone
}
