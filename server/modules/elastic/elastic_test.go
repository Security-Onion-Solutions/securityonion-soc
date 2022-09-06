// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestElasticInit(tester *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	elastic := NewElastic(srv)
	cfg := make(module.ModuleConfig)
	err := elastic.Init(cfg)
	assert.Nil(tester, err)
	assert.NotNil(tester, srv.Eventstore)
	assert.Len(tester, elastic.store.hostUrls, 1)
	assert.Equal(tester, "elasticsearch", elastic.store.hostUrls[0])
	assert.Len(tester, elastic.store.esRemoteClients, 0)
	assert.Len(tester, elastic.store.esAllClients, 1)
	assert.Equal(tester, DEFAULT_TIME_SHIFT_MS, elastic.store.timeShiftMs)
	assert.Equal(tester, DEFAULT_DURATION_MS, elastic.store.defaultDurationMs)
	assert.Equal(tester, DEFAULT_ES_SEARCH_OFFSET_MS, elastic.store.esSearchOffsetMs)
	expectedTimeout := time.Duration(DEFAULT_TIMEOUT_MS) * time.Millisecond
	assert.Equal(tester, expectedTimeout, elastic.store.timeoutMs)
	expectedCache := time.Duration(DEFAULT_CACHE_MS) * time.Millisecond
	assert.Equal(tester, expectedCache, elastic.store.cacheMs)
	assert.Equal(tester, DEFAULT_INDEX, elastic.store.index)
	assert.Equal(tester, DEFAULT_INTERVALS, elastic.store.intervals)
	assert.Equal(tester, DEFAULT_MAX_LOG_LENGTH, elastic.store.maxLogLength)

	// Ensure casestore has been setup
	assert.NotNil(tester, srv.Casestore)

	// Ensure failure it attempting to init when a casestore is already setup
	err = elastic.Init(cfg)
	assert.Error(tester, err)
}
