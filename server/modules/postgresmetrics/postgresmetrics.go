// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
)

type PostgresMetrics struct {
	server              *server.Server
	dbStore             *database.Store
	cacheLock           sync.Mutex
	cacheExpirationMs   int
	maxMetricAgeSeconds int

	lastUpdate time.Time

	// Cached node-specific statuses/metrics
	raidStatus           map[string]int
	processStatus        map[string]int
	processJson          map[string]string
	consumptionEps       map[string]int
	productionEps        map[string]int
	failedEvents         map[string]int
	eventstoreStatus     map[string]string
	osNeedsRestart       map[string]int
	osUptime             map[string]int
	diskTotalRootGB      map[string]float64
	diskUsedRootPct      map[string]float64
	diskTotalNsmGB       map[string]float64
	diskUsedNsmPct       map[string]float64
	cpuIdlePct           map[string]float64
	memoryTotalGB        map[string]float64
	memoryUsedPct        map[string]float64
	swapTotalGB          map[string]float64
	swapUsedPct          map[string]float64
	pcapDays             map[string]float64
	suriLossPct          map[string]float64
	suriRulesLoaded      map[string]int
	suriRulesFailed      map[string]int
	suriRulesReloadTime  map[string]string
	suriRulesStatus      map[string]string
	zeekLossPct          map[string]float64
	captureLossPct       map[string]float64
	trafficMonInMbs      map[string]float64
	trafficMonInDropsMbs map[string]float64
	trafficManInMbs      map[string]float64
	trafficManOutMbs     map[string]float64
	redisQueueSize       map[string]int
	ioWaitPct            map[string]float64
	load1m               map[string]float64
	load5m               map[string]float64
	load15m              map[string]float64
	diskUsedElasticGB    map[string]float64
	diskUsedInfluxDbGB   map[string]float64
	highstateAgeSeconds  map[string]int
	fpsEnabled           map[string]int
	lksEnabled           map[string]int
}

func NewPostgresMetrics(srv *server.Server) *PostgresMetrics {
	var store *database.Store
	if srv != nil && srv.DB != nil {
		store = database.New(srv.DB)
	}
	return &PostgresMetrics{
		server:               srv,
		dbStore:              store,
		raidStatus:           make(map[string]int),
		processStatus:        make(map[string]int),
		processJson:          make(map[string]string),
		consumptionEps:       make(map[string]int),
		productionEps:        make(map[string]int),
		failedEvents:         make(map[string]int),
		eventstoreStatus:     make(map[string]string),
		osNeedsRestart:       make(map[string]int),
		osUptime:             make(map[string]int),
		diskTotalRootGB:      make(map[string]float64),
		diskUsedRootPct:      make(map[string]float64),
		diskTotalNsmGB:       make(map[string]float64),
		diskUsedNsmPct:       make(map[string]float64),
		cpuIdlePct:           make(map[string]float64),
		memoryTotalGB:        make(map[string]float64),
		memoryUsedPct:        make(map[string]float64),
		swapTotalGB:          make(map[string]float64),
		swapUsedPct:          make(map[string]float64),
		pcapDays:             make(map[string]float64),
		suriLossPct:          make(map[string]float64),
		suriRulesLoaded:      make(map[string]int),
		suriRulesFailed:      make(map[string]int),
		suriRulesReloadTime:  make(map[string]string),
		suriRulesStatus:      make(map[string]string),
		zeekLossPct:          make(map[string]float64),
		captureLossPct:       make(map[string]float64),
		trafficMonInMbs:      make(map[string]float64),
		trafficMonInDropsMbs: make(map[string]float64),
		trafficManInMbs:      make(map[string]float64),
		trafficManOutMbs:     make(map[string]float64),
		redisQueueSize:       make(map[string]int),
		ioWaitPct:            make(map[string]float64),
		load1m:               make(map[string]float64),
		load5m:               make(map[string]float64),
		load15m:              make(map[string]float64),
		diskUsedElasticGB:    make(map[string]float64),
		diskUsedInfluxDbGB:   make(map[string]float64),
		highstateAgeSeconds:  make(map[string]int),
		fpsEnabled:           make(map[string]int),
		lksEnabled:           make(map[string]int),
	}
}

func (pm *PostgresMetrics) Init(cacheExpirationMs, maxMetricAgeSeconds int) {
	pm.cacheExpirationMs = cacheExpirationMs
	pm.maxMetricAgeSeconds = maxMetricAgeSeconds
	if pm.dbStore == nil && pm.server != nil && pm.server.DB != nil {
		pm.dbStore = database.New(pm.server.DB)
	}
}

func (pm *PostgresMetrics) SetStore(store *database.Store) {
	pm.dbStore = store
}

func (pm *PostgresMetrics) GetGridEps(ctx context.Context) int {
	pm.updateCache(ctx)
	pm.cacheLock.Lock()
	defer pm.cacheLock.Unlock()

	eps := 0
	for _, hostEps := range pm.consumptionEps {
		eps += hostEps
	}
	return eps
}

func (pm *PostgresMetrics) UpdateNodeMetrics(ctx context.Context, node *model.Node) bool {
	pm.updateCache(ctx)
	pm.cacheLock.Lock()
	defer pm.cacheLock.Unlock()

	host := node.Id

	node.RaidStatus = pm.getRaidStatus(host)
	node.ProcessStatus = pm.getProcessStatus(host)
	node.ProcessJson = pm.getProcessJson(host)
	node.EventstoreStatus = pm.getEventstoreStatus(host)

	if val, exists := pm.osNeedsRestart[host]; exists {
		node.OsNeedsRestart = val
	}
	if val, exists := pm.osUptime[host]; exists {
		node.OsUptimeSeconds = val
	}

	if val, exists := pm.diskTotalRootGB[host]; exists {
		node.DiskTotalRootGB = val
	}
	if val, exists := pm.diskUsedRootPct[host]; exists {
		node.DiskUsedRootPct = val
	}
	if val, exists := pm.diskTotalNsmGB[host]; exists {
		node.DiskTotalNsmGB = val
	}
	if val, exists := pm.diskUsedNsmPct[host]; exists {
		node.DiskUsedNsmPct = val
	}

	if val, exists := pm.cpuIdlePct[host]; exists {
		node.CpuUsedPct = 100.0 - val
	}
	if val, exists := pm.memoryTotalGB[host]; exists {
		node.MemoryTotalGB = val
	}
	if val, exists := pm.memoryUsedPct[host]; exists {
		node.MemoryUsedPct = val
	}
	if val, exists := pm.swapTotalGB[host]; exists {
		node.SwapTotalGB = val
	}
	if val, exists := pm.swapUsedPct[host]; exists {
		node.SwapUsedPct = val
	}

	if val, exists := pm.pcapDays[host]; exists {
		node.PcapDays = val
	}
	if val, exists := pm.suriLossPct[host]; exists {
		node.SuriLossPct = val
	}
	if val, exists := pm.zeekLossPct[host]; exists {
		node.ZeekLossPct = val
	}
	if val, exists := pm.captureLossPct[host]; exists {
		node.CaptureLossPct = val
	}

	if val, exists := pm.suriRulesLoaded[host]; exists {
		node.SuriRulesLoaded = val
	}
	if val, exists := pm.suriRulesFailed[host]; exists {
		node.SuriRulesFailed = val
	}
	if val, exists := pm.suriRulesReloadTime[host]; exists {
		node.SuriRulesReloadTime = val
	}
	if val, exists := pm.suriRulesStatus[host]; exists {
		node.SuriRulesStatus = val
	}

	if val, exists := pm.redisQueueSize[host]; exists {
		node.RedisQueueSize = val
	}
	if val, exists := pm.diskUsedElasticGB[host]; exists {
		node.DiskUsedElasticGB = val
	}
	if val, exists := pm.diskUsedInfluxDbGB[host]; exists {
		node.DiskUsedInfluxDbGB = val
	}
	if val, exists := pm.highstateAgeSeconds[host]; exists {
		node.HighstateAgeSeconds = val
	}

	if val, exists := pm.fpsEnabled[host]; exists {
		node.FpsEnabled = val
	}
	if val, exists := pm.lksEnabled[host]; exists {
		node.LksEnabled = val
	}

	if val, exists := pm.trafficMonInMbs[host]; exists {
		node.TrafficMonInMbs = val
	}
	if val, exists := pm.trafficMonInDropsMbs[host]; exists {
		node.TrafficMonInDropsMbs = val
	}
	if val, exists := pm.trafficManInMbs[host]; exists {
		node.TrafficManInMbs = val
	}
	if val, exists := pm.trafficManOutMbs[host]; exists {
		node.TrafficManOutMbs = val
	}

	if val, exists := pm.load1m[host]; exists {
		node.Load1m = val
	}
	if val, exists := pm.load5m[host]; exists {
		node.Load5m = val
	}
	if val, exists := pm.load15m[host]; exists {
		node.Load15m = val
	}
	if val, exists := pm.ioWaitPct[host]; exists {
		node.IoWaitPct = val
	}

	node.HistoricalMetricsEnabled = true
	enhancedStatusEnabled := (pm.server.DB != nil)
	status := node.UpdateOverallStatus(enhancedStatusEnabled)

	return status
}

func (pm *PostgresMetrics) updateCache(ctx context.Context) {
	pm.cacheLock.Lock()
	defer pm.cacheLock.Unlock()

	now := time.Now()
	if now.Sub(pm.lastUpdate).Milliseconds() < int64(pm.cacheExpirationMs) {
		return
	}

	if pm.server.DB == nil {
		log.Warn("Postgres metrics: database connection not available")
		return
	}

	if pm.dbStore == nil {
		pm.dbStore = database.New(pm.server.DB)
	}

	startTime := now.Add(-time.Duration(pm.maxMetricAgeSeconds) * time.Second)

	// CPU usage
	pm.cpuIdlePct = pm.dbStore.FetchFloatValues(ctx, "cpu", "usage_idle", "cpu", "cpu-total", startTime)
	pm.ioWaitPct = pm.dbStore.FetchFloatValues(ctx, "cpu", "usage_iowait", "cpu", "cpu-total", startTime)

	// Memory & Swap
	pm.memoryTotalGB = pm.dbStore.FetchFloatValues(ctx, "mem", "total", "", "", startTime, 1.0/(1000.0*1000.0*1000.0))
	pm.memoryUsedPct = pm.dbStore.FetchFloatValues(ctx, "mem", "used_percent", "", "", startTime)
	pm.swapTotalGB = pm.dbStore.FetchFloatValues(ctx, "swap", "total", "", "", startTime, 1.0/(1000.0*1000.0*1000.0))
	pm.swapUsedPct = pm.dbStore.FetchFloatValues(ctx, "swap", "used_percent", "", "", startTime)

	// Load and uptime
	pm.load1m = pm.dbStore.FetchFloatValues(ctx, "system", "load1", "", "", startTime)
	pm.load5m = pm.dbStore.FetchFloatValues(ctx, "system", "load5", "", "", startTime)
	pm.load15m = pm.dbStore.FetchFloatValues(ctx, "system", "load15", "", "", startTime)
	pm.osUptime = pm.dbStore.FetchIntValues(ctx, "system", "uptime", "", "", startTime)

	// Disk / and /nsm
	pm.diskTotalRootGB = pm.dbStore.FetchFloatValues(ctx, "disk", "total", "path", "/", startTime, 1.0/(1000.0*1000.0*1000.0))
	pm.diskUsedRootPct = pm.dbStore.FetchFloatValues(ctx, "disk", "used_percent", "path", "/", startTime)
	pm.diskTotalNsmGB = pm.dbStore.FetchFloatValues(ctx, "disk", "total", "path", "/nsm", startTime, 1.0/(1000.0*1000.0*1000.0))
	pm.diskUsedNsmPct = pm.dbStore.FetchFloatValues(ctx, "disk", "used_percent", "path", "/nsm", startTime)

	// RAID, Process, EPS
	pm.raidStatus = pm.dbStore.FetchIntValues(ctx, "raid", "nsmraid", "", "", startTime)
	pm.processStatus = pm.dbStore.FetchIntValues(ctx, "sostatus", "status", "", "", startTime)
	pm.processJson = pm.dbStore.FetchStringValues(ctx, "sostatus", "json", "", "", startTime)
	pm.consumptionEps = pm.dbStore.FetchIntValues(ctx, "consumptioneps", "eps", "", "", startTime)

	// Filebeat & Elasticsearch
	pm.productionEps = pm.dbStore.FetchIntValues(ctx, "fbstats", "eps", "", "", startTime)
	pm.failedEvents = pm.dbStore.FetchIntValues(ctx, "fbstats", "failed", "", "", startTime)
	pm.eventstoreStatus = pm.dbStore.FetchStringValues(ctx, "elasticsearch_cluster_health", "status", "", "", startTime)

	// Pcap age, Suricata rules, drops, Zeek loss
	pm.pcapDays = pm.dbStore.FetchFloatValues(ctx, "pcapage", "seconds", "", "", startTime, 1.0/(24.0*60.0*60.0))
	pm.suriLossPct = pm.dbStore.FetchFloatValues(ctx, "suridrop", "drop", "", "", startTime, 100.0)
	pm.zeekLossPct = pm.dbStore.FetchFloatValues(ctx, "zeekdrop", "drop", "", "", startTime, 100.0)
	pm.captureLossPct = pm.dbStore.FetchFloatValues(ctx, "zeekcaptureloss", "loss", "", "", startTime)

	pm.suriRulesLoaded = pm.dbStore.FetchIntValues(ctx, "surirules", "loaded", "", "", startTime)
	pm.suriRulesFailed = pm.dbStore.FetchIntValues(ctx, "surirules", "failed", "", "", startTime)
	pm.suriRulesReloadTime = pm.dbStore.FetchStringValues(ctx, "surirules", "reload_time", "", "", startTime)
	pm.suriRulesStatus = pm.dbStore.FetchStringValues(ctx, "surirules", "status", "", "", startTime)

	pm.redisQueueSize = pm.dbStore.FetchIntValues(ctx, "redisqueue", "unparsed", "", "", startTime)
	pm.diskUsedElasticGB = pm.dbStore.FetchFloatValues(ctx, "elasticsearch_indices", "store_size_in_bytes", "", "", startTime, 1.0/(1000.0*1000.0*1000.0))
	pm.diskUsedInfluxDbGB = pm.dbStore.FetchFloatValues(ctx, "influxsize", "kbytes", "", "", startTime, 1.0/(1000.0*1000.0))
	pm.highstateAgeSeconds = pm.dbStore.FetchIntValues(ctx, "salt", "highstate_age_seconds", "", "", startTime)

	pm.osNeedsRestart = pm.dbStore.FetchIntValues(ctx, "os", "restart", "", "", startTime)
	pm.fpsEnabled = pm.dbStore.FetchIntValues(ctx, "features", "fps", "", "", startTime)
	pm.lksEnabled = pm.dbStore.FetchIntValues(ctx, "features", "lks", "", "", startTime)

	if rates, err := pm.dbStore.FetchNetworkRates(ctx, startTime); err == nil {
		pm.trafficMonInMbs = rates.TrafficMonInMbs
		pm.trafficMonInDropsMbs = rates.TrafficMonInDropsMbs
		pm.trafficManInMbs = rates.TrafficManInMbs
		pm.trafficManOutMbs = rates.TrafficManOutMbs
	}

	pm.lastUpdate = now
}

func (pm *PostgresMetrics) getRaidStatus(host string) string {
	status := model.NodeStatusUnknown
	if val, exists := pm.raidStatus[host]; exists {
		switch val {
		case 0:
			status = model.NodeStatusOk
		case 1:
			status = model.NodeStatusFault
		}
	}
	return status
}

func (pm *PostgresMetrics) getProcessStatus(host string) string {
	status := model.NodeStatusUnknown
	if val, exists := pm.processStatus[host]; exists {
		switch val {
		case 0:
			status = model.NodeStatusOk
		case 1:
			status = model.NodeStatusFault
		}
	}
	return status
}

func (pm *PostgresMetrics) getProcessJson(host string) string {
	return pm.processJson[host]
}

func (pm *PostgresMetrics) getEventstoreStatus(host string) string {
	status := model.NodeStatusUnknown
	if val, exists := pm.eventstoreStatus[host]; exists {
		switch val {
		case "green":
			status = model.NodeStatusOk
		case "red":
			status = model.NodeStatusFault
		case "yellow":
			status = model.NodeStatusPending
		}
	}
	return status
}

func (pm *PostgresMetrics) GetTimeSeriesMetrics(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
	if err := pm.server.CheckAuthorized(ctx, "read", "nodes"); err != nil {
		return nil, err
	}
	if pm.server.DB == nil {
		return nil, errors.New("database not available")
	}

	if pm.dbStore == nil {
		pm.dbStore = database.New(pm.server.DB)
	}

	return pm.dbStore.GetTimeSeriesMetrics(ctx, nodeId, metricType, startTime, endTime)
}
