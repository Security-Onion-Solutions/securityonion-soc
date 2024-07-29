// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type StaticKeyAuthImpl struct {
	apiKey           string
	skipCidrCheck    bool
	anonymousNetwork *net.IPNet
	server           *server.Server
}

func NewStaticKeyAuthImpl(srv *server.Server) *StaticKeyAuthImpl {
	return &StaticKeyAuthImpl{
		server: srv,
	}
}

func (auth *StaticKeyAuthImpl) Init(apiKey string, anonymousCidr string) error {
	var err error
	auth.apiKey = apiKey
	if anonymousCidr == "*" {
		auth.skipCidrCheck = true
		log.Warn("Bypassing all anonymous CIDR traffic checks. This is only intended for development use.")
	} else {
		auth.skipCidrCheck = false
		_, auth.anonymousNetwork, err = net.ParseCIDR(anonymousCidr)
	}
	return err
}

func (auth *StaticKeyAuthImpl) PreprocessPriority() int {
	return 100
}

func (auth *StaticKeyAuthImpl) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
	var statusCode int
	var err error

	if !auth.IsAuthorized(ctx, req) {
		statusCode = http.StatusUnauthorized
		err = errors.New("Access denied")
	} else {
		// Remote agents will assume the role of this server until the implementation
		// is enhanced to support unique agent keys and roles.
		ctx = context.WithValue(ctx, web.ContextKeyRequestor, auth.server.Agent)
		ctx = context.WithValue(ctx, web.ContextKeyRequestorId, auth.server.Agent.Id)
	}
	return ctx, statusCode, err
}

func (auth *StaticKeyAuthImpl) IsAuthorized(ctx context.Context, request *http.Request) bool {
	apiKey := request.Header.Get("Authorization")
	remoteIp := request.RemoteAddr
	return auth.validateAuthorization(ctx, apiKey, remoteIp)
}

func (auth *StaticKeyAuthImpl) validateAuthorization(ctx context.Context, key string, ipStr string) bool {
	// If API key has been provided, it must match
	if len(key) > 0 {
		isApiKeyAccepted := auth.validateApiKey(key)
		log.WithFields(log.Fields{
			"isApiKeyAccepted": isApiKeyAccepted,
			"requestId":        ctx.Value(web.ContextKeyRequestId),
		}).Debug("Authorization check via API key")
		return isApiKeyAccepted
	}

	// API Key was not provided, check for anon network access
	if auth.skipCidrCheck {
		return true
	}

	idx := strings.LastIndex(ipStr, ":")
	if idx > 0 {
		ipStr = ipStr[0:idx]
		ipStr = strings.TrimPrefix(ipStr, "[")
		ipStr = strings.TrimSuffix(ipStr, "]")
	}
	remoteIp := net.ParseIP(ipStr)
	isAnonymousIp := auth.anonymousNetwork.Contains(remoteIp)
	log.WithFields(log.Fields{
		"anonymousNetwork": auth.anonymousNetwork,
		"remoteIp":         remoteIp,
		"ipStr":            ipStr,
		"isAnonymousIp":    isAnonymousIp,
		"requestId":        ctx.Value(web.ContextKeyRequestId),
	}).Debug("Authorization check via remote IP")
	return isAnonymousIp
}

func (auth *StaticKeyAuthImpl) validateApiKey(key string) bool {
	pieces := strings.Split(key, " ")
	if len(pieces) > 0 {
		key = pieces[len(pieces)-1]
	}
	return key == auth.apiKey
}
