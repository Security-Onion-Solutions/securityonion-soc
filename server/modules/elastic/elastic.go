// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_CASE_INDEX = "*:so-case"
const DEFAULT_CASE_AUDIT_INDEX = "*:so-casehistory"
const DEFAULT_CASE_ASSOCIATIONS_MAX = 1000
const DEFAULT_TIME_SHIFT_MS = 120000
const DEFAULT_DURATION_MS = 1800000
const DEFAULT_ES_SEARCH_OFFSET_MS = 1800000
const DEFAULT_TIMEOUT_MS = 300000
const DEFAULT_CACHE_MS = 86400000
const DEFAULT_INDEX = "*:so-*"
const DEFAULT_ASYNC_THRESHOLD = 10
const DEFAULT_INTERVALS = 25
const DEFAULT_MAX_LOG_LENGTH = 1024
const DEFAULT_CASE_SCHEMA_PREFIX = "so_"

type Elastic struct {
  config module.ModuleConfig
  server *server.Server
  store  *ElasticEventstore
}

func NewElastic(srv *server.Server) *Elastic {
  return &Elastic{
    server: srv,
    store:  NewElasticEventstore(srv),
  }
}

func (elastic *Elastic) PrerequisiteModules() []string {
  return nil
}

func (elastic *Elastic) Init(cfg module.ModuleConfig) error {
  elastic.config = cfg
  host := module.GetStringDefault(cfg, "hostUrl", "elasticsearch")
  remoteHosts := module.GetStringArrayDefault(cfg, "remoteHostUrls", make([]string, 0, 0))
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  username := module.GetStringDefault(cfg, "username", "")
  password := module.GetStringDefault(cfg, "password", "")
  timeShiftMs := module.GetIntDefault(cfg, "timeShiftMs", DEFAULT_TIME_SHIFT_MS)
  defaultDurationMs := module.GetIntDefault(cfg, "defaultDurationMs", DEFAULT_DURATION_MS)
  esSearchOffsetMs := module.GetIntDefault(cfg, "esSearchOffsetMs", DEFAULT_ES_SEARCH_OFFSET_MS)
  timeoutMs := module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
  if timeoutMs == 0 {
    timeoutMs = DEFAULT_TIMEOUT_MS
  }
  cacheMs := module.GetIntDefault(cfg, "cacheMs", DEFAULT_CACHE_MS)
  index := module.GetStringDefault(cfg, "index", DEFAULT_INDEX)
  asyncThreshold := module.GetIntDefault(cfg, "asyncThreshold", DEFAULT_ASYNC_THRESHOLD)
  intervals := module.GetIntDefault(cfg, "intervals", DEFAULT_INTERVALS)
  maxLogLength := module.GetIntDefault(cfg, "maxLogLength", DEFAULT_MAX_LOG_LENGTH)
  casesEnabled := module.GetBoolDefault(cfg, "casesEnabled", true)
  err := elastic.store.Init(host, remoteHosts, username, password, verifyCert, timeShiftMs, defaultDurationMs,
    esSearchOffsetMs, timeoutMs, cacheMs, index, asyncThreshold, intervals, maxLogLength)
  if err == nil && elastic.server != nil {
    elastic.server.Eventstore = elastic.store
    if casesEnabled {
      if elastic.server.Casestore != nil {
        err = errors.New("Multiple case modules cannot be enabled concurrently")
      } else {
        caseIndex := module.GetStringDefault(cfg, "caseIndex", DEFAULT_CASE_INDEX)
        auditIndex := module.GetStringDefault(cfg, "auditIndex", DEFAULT_CASE_AUDIT_INDEX)
        maxCaseAssociations := module.GetIntDefault(cfg, "maxCaseAssociations", DEFAULT_CASE_ASSOCIATIONS_MAX)
        schemaPrefix := module.GetStringDefault(cfg, "schemaPrefix", DEFAULT_CASE_SCHEMA_PREFIX)
        casestore := NewElasticCasestore(elastic.server)
        err = casestore.Init(caseIndex, auditIndex, maxCaseAssociations, schemaPrefix)
        if err == nil {
          elastic.server.Casestore = casestore
        }
      }
    }
  }
  return err
}

func (elastic *Elastic) Start() error {
  handler := NewJobLookupHandler(elastic.server, elastic.store)
  elastic.server.Host.Register("/joblookup", handler)
  elastic.server.Host.Register("/securityonion/joblookup", handler) // deprecated
  return nil
}

func (elastic *Elastic) Stop() error {
  return nil
}

func (somodule *Elastic) IsRunning() bool {
  return false
}
