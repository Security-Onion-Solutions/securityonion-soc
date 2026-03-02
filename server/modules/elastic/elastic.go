// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"errors"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

const (
	DEFAULT_CASE_INDEX                 = "*:so-case"
	DEFAULT_CASE_AUDIT_INDEX           = "*:so-casehistory"
	DEFAULT_CASE_ASSOCIATIONS_MAX      = 1000
	DEFAULT_TIME_SHIFT_MS              = 120000
	DEFAULT_DURATION_MS                = 1800000
	DEFAULT_ES_SEARCH_OFFSET_MS        = 1800000
	DEFAULT_TIMEOUT_MS                 = 300000
	DEFAULT_CACHE_MS                   = 86400000
	DEFAULT_INDEX                      = "*:so-*"
	DEFAULT_ASYNC_THRESHOLD            = 10
	DEFAULT_INTERVALS                  = 25
	DEFAULT_MAX_LOG_LENGTH             = 1024
	DEFAULT_CASE_SCHEMA_PREFIX         = "so_"
	DEFAULT_DETECTION_INDEX            = "*:so-detection"
	DEFAULT_DETECTION_AUDIT_INDEX      = "*:so-detectionhistory"
	DEFAULT_DETECTION_ASSOCIATIONS_MAX = 1000
	DEFAULT_DETECTION_SCHEMA_PREFIX    = "so_"
	DEFAULT_ASSISTANT_CHAT_INDEX       = "*:so-assistant-chat"
	DEFAULT_ASSISTANT_SESSION_INDEX    = "*:so-assistant-session"
	DEFAULT_ASSISTANT_SCHEMA_PREFIX    = "so_"
)

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
	remoteHosts := module.GetStringArrayDefault(cfg, "remoteHostUrls", []string{})
	commonObservables := module.GetStringArrayDefault(cfg, "extractCommonObservables", []string{})
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
	lookupTunnelParent := module.GetBoolDefault(cfg, "lookupTunnelParent", true)
	detectionsEnabled := module.GetBoolDefault(cfg, "detectionsEnabled", true)
	assistantEnabled := module.GetBoolDefault(cfg, "assistantEnabled", true)
	maxScrollSize := module.GetIntDefault(cfg, "maxScrollSize", 10000)
	err := elastic.store.Init(host, remoteHosts, username, password, verifyCert, timeShiftMs, defaultDurationMs,
		esSearchOffsetMs, timeoutMs, cacheMs, index, asyncThreshold, intervals, maxLogLength, lookupTunnelParent,
		maxScrollSize)
	if err == nil && elastic.server != nil {
		elastic.server.Eventstore = elastic.store
		if casesEnabled {
			if elastic.server.Casestore != nil {
				return errors.New("Multiple case modules cannot be enabled concurrently")
			} else {
				caseIndex := module.GetStringDefault(cfg, "caseIndex", DEFAULT_CASE_INDEX)
				auditIndex := module.GetStringDefault(cfg, "auditIndex", DEFAULT_CASE_AUDIT_INDEX)
				maxCaseAssociations := module.GetIntDefault(cfg, "maxCaseAssociations", DEFAULT_CASE_ASSOCIATIONS_MAX)
				schemaPrefix := module.GetStringDefault(cfg, "schemaPrefix", DEFAULT_CASE_SCHEMA_PREFIX)
				casestore := NewElasticCasestore(elastic.server, elastic.store.esClient)
				bulkIndexerWorkerCount := module.GetIntDefault(cfg, "bulkIndexerWorkerCount", -1)

				err = casestore.Init(caseIndex, auditIndex, maxCaseAssociations, schemaPrefix, commonObservables, bulkIndexerWorkerCount)
				if err != nil {
					return err
				}
				elastic.server.Casestore = casestore
			}
		}
		if detectionsEnabled {
			if elastic.server.Detectionstore != nil {
				return errors.New("Multiple detection modules cannot be enabled concurrently")
			} else {
				detIndex := module.GetStringDefault(cfg, "detectionIndex", DEFAULT_DETECTION_INDEX)
				detAuditIndex := module.GetStringDefault(cfg, "detectionAuditIndex", DEFAULT_DETECTION_AUDIT_INDEX)
				maxDetAssociations := module.GetIntDefault(cfg, "maxDetectionAssociations", DEFAULT_DETECTION_ASSOCIATIONS_MAX)
				schemaPrefix := module.GetStringDefault(cfg, "schemaPrefix", DEFAULT_DETECTION_SCHEMA_PREFIX)
				detstore := NewElasticDetectionstore(elastic.server, elastic.store.esClient, maxLogLength)
				bulkIndexerWorkerCount := module.GetIntDefault(cfg, "bulkIndexerWorkerCount", -1)

				err = detstore.Init(detIndex, detAuditIndex, maxDetAssociations, schemaPrefix, bulkIndexerWorkerCount)
				if err != nil {
					return err
				}
				elastic.server.Detectionstore = detstore
			}
		}
		if assistantEnabled {
			if elastic.server.Assistantstore != nil {
				return errors.New("Multiple assistant modules cannot be enabled concurrently")
			} else {
				assistChatIndex := module.GetStringDefault(cfg, "assistantChatIndex", DEFAULT_ASSISTANT_CHAT_INDEX)
				assistSessionIndex := module.GetStringDefault(cfg, "assistantSessionIndex", DEFAULT_ASSISTANT_SESSION_INDEX)
				schemaPrefix := module.GetStringDefault(cfg, "schemaPrefix", DEFAULT_ASSISTANT_SCHEMA_PREFIX)
				assiststore := NewElasticAssistantstore(elastic.server, elastic.store.esClient, maxLogLength)

				err = assiststore.Init(assistChatIndex, assistSessionIndex, schemaPrefix)
				if err != nil {
					return err
				}
				elastic.server.Assistantstore = assiststore
			}
		}
	}

	licensing.ValidateDataUrl(host)

	// Register routes in same thread as server init to avoid multi-threading issues
	// with Chi route registration.
	r := chi.NewMux()
	r.Use(web.Middleware(elastic.server.Host, false, elastic.server.Config.Subgrids))
	RegisterJobLookupRoutes(elastic.server, elastic.store, r, "/joblookup")
	elastic.server.Host.RegisterRouter("/joblookup", r)

	RegisterJobLookupRoutes(elastic.server, elastic.store, elastic.server.ApiRouter, "/api/joblookup")

	return err
}

func (elastic *Elastic) Start() error {
	return nil
}

func (elastic *Elastic) Stop() error {
	return nil
}

func (somodule *Elastic) IsRunning() bool {
	return false
}
