// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
	"context"
	"errors"
	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"net"
	"net/http"
	"strings"
)

type StaticKeyAuthImpl struct {
	apiKey           string
	anonymousNetwork *net.IPNet
}

func NewStaticKeyAuthImpl() *StaticKeyAuthImpl {
	return &StaticKeyAuthImpl{}
}

func (auth *StaticKeyAuthImpl) Init(apiKey string, anonymousCidr string) error {
	var err error
	auth.apiKey = apiKey
	_, auth.anonymousNetwork, err = net.ParseCIDR(anonymousCidr)
	return err
}

func (auth *StaticKeyAuthImpl) PreprocessPriority() int {
	return 100
}

func (auth *StaticKeyAuthImpl) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
	var statusCode int
	var err error

	if !auth.IsAuthorized(req) {
		statusCode = http.StatusUnauthorized
		err = errors.New("Access denied")
	} else {
		// Currently all static auth clients are sensors
		sensorUser := model.NewUser()
		sensorUser.Id = "sensor"
		sensorUser.Email = "sensor"
		ctx = context.WithValue(ctx, web.ContextKeyRequestor, sensorUser)
	}
	return ctx, statusCode, err
}

func (auth *StaticKeyAuthImpl) IsAuthorized(request *http.Request) bool {
	apiKey := request.Header.Get("Authorization")
	remoteIp := request.RemoteAddr
	return auth.validateAuthorization(apiKey, remoteIp)
}

func (auth *StaticKeyAuthImpl) validateAuthorization(key string, ipStr string) bool {
	// If API key has been provided, it must match
	if len(key) > 0 {
		isApiKeyAccepted := auth.validateApiKey(key)
		log.WithFields(log.Fields{
			"isApiKeyAccepted": isApiKeyAccepted,
		}).Debug("Authorization check via API key")
		return isApiKeyAccepted
	}

	// API Key was not provided, check for anon network access
	pieces := strings.Split(ipStr, ":")
	if pieces != nil && len(pieces) > 0 {
		ipStr = pieces[0]
	}
	remoteIp := net.ParseIP(ipStr)
	isAnonymousIp := auth.anonymousNetwork.Contains(remoteIp)
	log.WithFields(log.Fields{
		"anonymousNetwork": auth.anonymousNetwork,
		"remoteIp":         remoteIp,
		"isAnonymousIp":    isAnonymousIp,
	}).Debug("Authorization check via remote IP")
	return isAnonymousIp
}

func (auth *StaticKeyAuthImpl) validateApiKey(key string) bool {
	pieces := strings.Split(key, " ")
	if pieces != nil && len(pieces) > 0 {
		key = pieces[len(pieces)-1]
	}
	return key == auth.apiKey
}
