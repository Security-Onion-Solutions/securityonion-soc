// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package influxdb

import (
	"context"
	"crypto/tls"
	"strconv"
	"sync"
	"time"

	"github.com/apex/log"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type InfluxDBMetrics struct {
	client   influxdb2.Client
	server   *server.Server
	token    string
	org      string
	bucket   string
	queryApi api.QueryAPI

	cacheLock                sync.Mutex
	cacheExpirationMs        int
	maxMetricAgeSeconds      int
	lastRaidUpdateTime       time.Time
	lastProcessUpdateTime    time.Time
	lastEpsUpdateTime        time.Time
	lastEventstoreUpdateTime time.Time
	lastOsUpdateTime         time.Time
	raidStatus               map[string]int
	processStatus            map[string]int
	processJson              map[string]string
	consumptionEps           map[string]int
	productionEps            map[string]int
	failedEvents             map[string]int
	eventstoreStatus         map[string]string
	osNeedsRestart           map[string]int
	osUptime                 map[string]int
	diskTotalRootGB          map[string]float64
	diskUsedRootPct          map[string]float64
	diskTotalNsmGB           map[string]float64
	diskUsedNsmPct           map[string]float64
	cpuIdlePct               map[string]float64
	memoryTotalGB            map[string]float64
	memoryUsedPct            map[string]float64
	swapTotalGB              map[string]float64
	swapUsedPct              map[string]float64
	pcapDays                 map[string]float64
	stenoLossPct             map[string]float64
	suriLossPct              map[string]float64
	zeekLossPct              map[string]float64
	captureLossPct           map[string]float64
	trafficMonInMbs          map[string]float64
	trafficManInMbs          map[string]float64
	trafficManOutMbs         map[string]float64
	trafficMonInDropsMbs     map[string]float64
	redisQueueSize           map[string]int
	ioWaitPct                map[string]float64
	load1m                   map[string]float64
	load5m                   map[string]float64
	load15m                  map[string]float64
	diskUsedElasticGB        map[string]float64
	diskUsedInfluxDbGB       map[string]float64
	highstateAgeSeconds      map[string]int
	lksEnabled               map[string]int
	fpsEnabled               map[string]int
}

func NewInfluxDBMetrics(srv *server.Server) *InfluxDBMetrics {
	return &InfluxDBMetrics{
		server:           srv,
		raidStatus:       make(map[string]int),
		processStatus:    make(map[string]int),
		processJson:      make(map[string]string),
		consumptionEps:   make(map[string]int),
		productionEps:    make(map[string]int),
		failedEvents:     make(map[string]int),
		eventstoreStatus: make(map[string]string),
		osNeedsRestart:   make(map[string]int),
		osUptime:         make(map[string]int),
	}
}

func (metrics *InfluxDBMetrics) Init(hostUrl string,
	token string,
	org string,
	bucket string,
	verifyCert bool,
	cacheExpirationMs int,
	maxMetricAgeSeconds int) error {
	options := influxdb2.DefaultOptions()
	options.SetTLSConfig(&tls.Config{
		InsecureSkipVerify: !verifyCert,
	})
	if hostUrl != "" {
		metrics.client = influxdb2.NewClientWithOptions(hostUrl, token, options)
		metrics.queryApi = metrics.client.QueryAPI(org)
	}
	metrics.bucket = bucket
	metrics.org = org
	metrics.cacheExpirationMs = cacheExpirationMs
	metrics.maxMetricAgeSeconds = maxMetricAgeSeconds

	return nil
}

func (metrics *InfluxDBMetrics) Stop() {
	if metrics.client != nil {
		metrics.client.Close()
		metrics.client = nil
	}
}

func (metrics *InfluxDBMetrics) fetchLatestValuesByHost(measurement string, field string, valueField string, additionalFilter string) map[string]interface{} {
	filter := `
		from(bucket:"` + metrics.bucket + `")
		|> range(start: -` + strconv.Itoa(metrics.maxMetricAgeSeconds) + `s)
		|> filter(fn: (r) => r._measurement == "` + measurement + `" and r._field == "` + field + `") 
		` + additionalFilter + `
		|> group(columns: ["host"]) 
		|> last()
		`
	return metrics.fetchLatestValuesByHostDirect(filter, valueField)
}

func (metrics *InfluxDBMetrics) fetchLatestValuesByHostDirect(filter string, valueField string) map[string]interface{} {
	values := make(map[string]interface{})
	if metrics.client != nil {
		log.WithFields(log.Fields{
			"filter":     filter,
			"valueField": valueField,
		}).Debug("Fetching latest values by host")
		result, err := metrics.queryApi.Query(context.Background(), filter)
		if err == nil {
			for result.Next() {
				log.WithField("result.Record", result.Record()).Debug("Got an influxdb result")
				host := result.Record().ValueByKey("host")
				if hostname, ok := host.(string); ok {
					if valueField == "" {
						values[hostname] = result.Record().Value()
					} else {
						values[hostname] = result.Record().ValueByKey(valueField)
					}
				} else {
					log.Warn("Host key is not of the expected type 'string'")
				}
			}
			if result.Err() != nil {
				log.WithError(result.Err()).Error("Unable to determine latest value due to result error")
			}
		} else {
			log.WithError(err).Error("Unable to determine latest value")
		}
	} else {
		log.Debug("Skipping InfluxDB fetch due to disconnected InfluxDB client")
	}
	return values
}

func (metrics *InfluxDBMetrics) convertValuesToString(values map[string]interface{}) map[string]string {
	results := make(map[string]string)
	for k, v := range values {
		if str, ok := v.(string); ok {
			results[k] = str
		} else {
			log.WithFields(log.Fields{"key": k, "value": v}).Warn("Unexpected value type; expected string")
		}
	}
	return results
}

func (metrics *InfluxDBMetrics) convertValuesToInt(values map[string]interface{}) map[string]int {
	results := make(map[string]int)
	for k, v := range values {
		if num, ok := v.(float64); ok {
			results[k] = int(num)
		} else if num, ok := v.(int64); ok {
			results[k] = int(num)
		} else if num, ok := v.(int); ok {
			results[k] = num
		} else {
			log.WithFields(log.Fields{"key": k, "value": v}).Warn("Unexpected value type; expected float64, int64, or int")
		}
	}
	return results
}

func (metrics *InfluxDBMetrics) convertValuesToFloat64(values map[string]interface{}, multiplier float64) map[string]float64 {
	results := make(map[string]float64)
	for k, v := range values {
		if num, ok := v.(float64); ok {
			results[k] = num * multiplier
		} else if num, ok := v.(int64); ok {
			results[k] = float64(num) * multiplier
		} else if num, ok := v.(int); ok {
			results[k] = float64(num) * multiplier
		} else {
			log.WithFields(log.Fields{"key": k, "value": v}).Warn("Unexpected value type; expected float64, int64, or int")
		}
	}
	return results
}

func (metrics *InfluxDBMetrics) updateRaidStatus() {
	metrics.cacheLock.Lock()
	defer metrics.cacheLock.Unlock()
	now := time.Now()
	if now.Sub(metrics.lastRaidUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
		values := metrics.fetchLatestValuesByHost("raid", "nsmraid", "", "")
		metrics.raidStatus = metrics.convertValuesToInt(values)
		metrics.lastRaidUpdateTime = now
	}
}

func (metrics *InfluxDBMetrics) updateProcessStatus() {
	metrics.cacheLock.Lock()
	defer metrics.cacheLock.Unlock()
	now := time.Now()
	if now.Sub(metrics.lastProcessUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
		values := metrics.fetchLatestValuesByHost("sostatus", "status", "", "")
		metrics.processStatus = metrics.convertValuesToInt(values)

		details := metrics.fetchLatestValuesByHost("sostatus", "json", "", "")
		metrics.processJson = metrics.convertValuesToString(details)

		metrics.lastProcessUpdateTime = now
	}
}

func (metrics *InfluxDBMetrics) updateEps() {
	metrics.cacheLock.Lock()
	defer metrics.cacheLock.Unlock()
	now := time.Now()
	if now.Sub(metrics.lastEpsUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
		values := metrics.fetchLatestValuesByHost("consumptioneps", "eps", "", "")
		metrics.consumptionEps = metrics.convertValuesToInt(values)

		values = metrics.fetchLatestValuesByHost("fbstats", "eps", "", "")
		metrics.productionEps = metrics.convertValuesToInt(values)

		values = metrics.fetchLatestValuesByHost("fbstats", "failed", "", "")
		metrics.failedEvents = metrics.convertValuesToInt(values)
		metrics.lastEpsUpdateTime = now
	}
}

func (metrics *InfluxDBMetrics) updateEventstoreStatus() {
	metrics.cacheLock.Lock()
	defer metrics.cacheLock.Unlock()
	now := time.Now()
	if now.Sub(metrics.lastEventstoreUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
		values := metrics.fetchLatestValuesByHost("elasticsearch_clusterstats_nodes", "os_mem_free_percent", "status", "")
		metrics.eventstoreStatus = metrics.convertValuesToString(values)
		metrics.lastEventstoreUpdateTime = now
	}
}

func (metrics *InfluxDBMetrics) generateNetFilter(ifaceType string, metric string) string {
	return `
	import "join"

	manints = from(bucket: "telegraf/so_short_term")
	  |> range(start: -` + strconv.Itoa(metrics.maxMetricAgeSeconds) + `s)
	  |> filter(fn: (r) => r["_measurement"] == "node_config")
	  |> filter(fn: (r) => r["_field"] == "` + ifaceType + `")
	  |> duplicate(column: "_value", as: "interface")
	  |> group(columns: ["host","interface"])
	
	traffic = from(bucket: "telegraf/so_short_term")
	  |> range(start: -` + strconv.Itoa(metrics.maxMetricAgeSeconds) + `s)
	  |> filter(fn: (r) => r["_measurement"] == "net")
	  |> filter(fn: (r) => r["_field"] == "` + metric + `")
	  |> derivative(unit: 1s, nonNegative: true, columns: ["_value"], timeColumn: "_time")
	  |> group(columns: ["host","interface"])
	
	join.inner(left: traffic, right: manints,
	  on: (l,r) => l.interface == r.interface and l.host == r.host,
	  as: (l, r) => ({l with _value: l._value}))
	  |> last()
	`
}

func (metrics *InfluxDBMetrics) updateOsStatus() {
	metrics.cacheLock.Lock()
	defer metrics.cacheLock.Unlock()
	now := time.Now()
	if now.Sub(metrics.lastOsUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
		bytesToGB := 1.0 / (1000.0 * 1000.0 * 1000.0)
		KBToGB := 1.0 / (1000.0 * 1000.0)
		bytesToMb := 8.0 / (1000.0 * 1000.0)
		secondsToDays := 1.0 / (24.0 * 60.0 * 60.0)
		toPercent := 100.0
		identity := 1.0

		metrics.osNeedsRestart = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("os", "restart", "", ""))
		metrics.lksEnabled = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("features", "lks", "", ""))
		metrics.fpsEnabled = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("features", "fps", "", ""))
		metrics.osUptime = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("system", "uptime", "", ""))
		metrics.diskTotalRootGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("disk", "total", "", "|> filter(fn: (r) => r[\"path\"] == \"/\")"), bytesToGB)
		metrics.diskUsedRootPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("disk", "used_percent", "", "|> filter(fn: (r) => r[\"path\"] == \"/\")"), identity)
		metrics.diskTotalNsmGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("disk", "total", "", "|> filter(fn: (r) => r[\"path\"] == \"/nsm\")"), bytesToGB)
		metrics.diskUsedNsmPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("disk", "used_percent", "", "|> filter(fn: (r) => r[\"path\"] == \"/nsm\")"), identity)
		metrics.cpuIdlePct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("cpu", "usage_idle", "", "|> filter(fn: (r) => r[\"cpu\"] == \"cpu-total\")"), identity)
		metrics.memoryTotalGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("mem", "total", "", ""), bytesToGB)
		metrics.memoryUsedPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("mem", "used_percent", "", ""), identity)
		metrics.swapTotalGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("swap", "total", "", ""), bytesToGB)
		metrics.swapUsedPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("swap", "used_percent", "", ""), identity)
		metrics.pcapDays = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("pcapage", "seconds", "", ""), secondsToDays)
		metrics.stenoLossPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("stenodrop", "drop", "", ""), toPercent)
		metrics.suriLossPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("suridrop", "drop", "", ""), toPercent)
		metrics.zeekLossPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("zeekdrop", "drop", "", ""), toPercent)
		metrics.captureLossPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("zeekcaptureloss", "loss", "", ""), identity)
		metrics.trafficMonInMbs = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHostDirect(metrics.generateNetFilter("monint", "bytes_recv"), ""), bytesToMb)
		metrics.trafficMonInDropsMbs = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHostDirect(metrics.generateNetFilter("monint", "drop_in"), ""), bytesToMb)
		metrics.trafficManInMbs = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHostDirect(metrics.generateNetFilter("manint", "bytes_recv"), ""), bytesToMb)
		metrics.trafficManOutMbs = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHostDirect(metrics.generateNetFilter("manint", "bytes_sent"), ""), bytesToMb)
		metrics.redisQueueSize = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("redisqueue", "unparsed", "", ""))
		metrics.ioWaitPct = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("cpu", "usage_iowait", "", "|> filter(fn: (r) => r[\"cpu\"] == \"cpu-total\")"), identity)
		metrics.load1m = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("system", "load1", "", ""), identity)
		metrics.load5m = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("system", "load5", "", ""), identity)
		metrics.load15m = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("system", "load15", "", ""), identity)
		metrics.diskUsedElasticGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("elasticsearch_indices", "store_size_in_bytes", "", ""), bytesToGB)
		metrics.diskUsedInfluxDbGB = metrics.convertValuesToFloat64(metrics.fetchLatestValuesByHost("influxsize", "kbytes", "", ""), KBToGB)
		metrics.highstateAgeSeconds = metrics.convertValuesToInt(metrics.fetchLatestValuesByHost("salt", "highstate_age_seconds", "", ""))

		metrics.lastOsUpdateTime = now
	}
}

func (metrics *InfluxDBMetrics) getRaidStatus(host string) string {
	status := model.NodeStatusUnknown

	metrics.updateRaidStatus()

	if len(metrics.raidStatus) > 0 {
		if hostStatus, exists := metrics.raidStatus[host]; exists {
			switch hostStatus {
			case 0:
				status = model.NodeStatusOk
			case 1:
				status = model.NodeStatusFault
			}
		} else {
			log.WithFields(log.Fields{
				"host":       host,
				"raidStatus": metrics.raidStatus,
			}).Warn("Host not found in raid status metrics")
		}
	}

	return status
}

func (metrics *InfluxDBMetrics) getProcessStatus(host string) string {
	status := model.NodeStatusUnknown

	metrics.updateProcessStatus()

	if hostStatus, exists := metrics.processStatus[host]; exists {
		switch hostStatus {
		case 0:
			status = model.NodeStatusOk
		case 1:
			status = model.NodeStatusFault
		}
	} else {
		log.WithFields(log.Fields{
			"host":          host,
			"processStatus": metrics.processStatus,
		}).Warn("Host not found in process status metrics")
	}

	return status
}

func (metrics *InfluxDBMetrics) getProcessJson(host string) string {
	details := ""

	metrics.updateProcessStatus()

	if hostJson, exists := metrics.processJson[host]; exists {
		details = hostJson
	} else {
		log.WithFields(log.Fields{
			"host": host,
		}).Warn("Host not found in process details metrics")
	}

	return details
}

func (metrics *InfluxDBMetrics) getProductionEps(host string) int {
	metrics.updateEps()

	return metrics.productionEps[host]
}

func (metrics *InfluxDBMetrics) getConsumptionEps(host string) int {
	metrics.updateEps()

	return metrics.consumptionEps[host]
}

func (metrics *InfluxDBMetrics) getFailedEvents(host string) int {
	metrics.updateEps()

	return metrics.failedEvents[host]
}

func (metrics *InfluxDBMetrics) GetGridEps(ctx context.Context) int {
	eps := 0
	if err := metrics.server.CheckAuthorized(ctx, "read", "nodes"); err == nil {
		metrics.updateEps()
		for _, hostEps := range metrics.consumptionEps {
			eps = eps + hostEps
		}
	}

	return eps
}

func (metrics *InfluxDBMetrics) getEventstoreStatus(host string) string {
	status := model.NodeStatusUnknown
	metrics.updateEventstoreStatus()

	if hostStatus, exists := metrics.eventstoreStatus[host]; exists {
		switch hostStatus {
		case "green":
			status = model.NodeStatusOk
		case "red":
			status = model.NodeStatusFault
		case "yellow":
			status = model.NodeStatusPending
		}
	} else {
		log.WithFields(log.Fields{
			"host":          host,
			"processStatus": metrics.eventstoreStatus,
		}).Warn("Host not found in process status metrics")
	}
	return status
}

func (metrics *InfluxDBMetrics) getOsNeedsRestart(host string) int {
	metrics.updateOsStatus()
	return metrics.osNeedsRestart[host]
}

func (metrics *InfluxDBMetrics) UpdateNodeMetrics(ctx context.Context, node *model.Node) bool {
	var status bool
	if err := metrics.server.CheckAuthorized(ctx, "write", "nodes"); err == nil {
		node.RaidStatus = metrics.getRaidStatus(node.Id)
		node.ProcessStatus = metrics.getProcessStatus(node.Id)
		node.ProcessJson = metrics.getProcessJson(node.Id)
		node.ProductionEps = metrics.getProductionEps(node.Id)
		node.ConsumptionEps = metrics.getConsumptionEps(node.Id)
		node.FailedEvents = metrics.getFailedEvents(node.Id)
		node.EventstoreStatus = metrics.getEventstoreStatus(node.Id)

		node.OsNeedsRestart = metrics.getOsNeedsRestart(node.Id)
		node.OsUptimeSeconds = metrics.osUptime[node.Id]
		node.DiskTotalRootGB = metrics.diskTotalRootGB[node.Id]
		node.DiskUsedRootPct = metrics.diskUsedRootPct[node.Id]
		node.DiskTotalNsmGB = metrics.diskTotalNsmGB[node.Id]
		node.DiskUsedNsmPct = metrics.diskUsedNsmPct[node.Id]
		node.CpuUsedPct = metrics.cpuIdlePct[node.Id]*-1.0 + 100.0
		node.MemoryTotalGB = metrics.memoryTotalGB[node.Id]
		node.MemoryUsedPct = metrics.memoryUsedPct[node.Id]
		node.SwapTotalGB = metrics.swapTotalGB[node.Id]
		node.SwapUsedPct = metrics.swapUsedPct[node.Id]
		node.PcapDays = metrics.pcapDays[node.Id]
		node.StenoLossPct = metrics.stenoLossPct[node.Id]
		node.SuriLossPct = metrics.suriLossPct[node.Id]
		node.ZeekLossPct = metrics.zeekLossPct[node.Id]
		node.CaptureLossPct = metrics.captureLossPct[node.Id]
		node.TrafficMonInMbs = metrics.trafficMonInMbs[node.Id]
		node.TrafficMonInDropsMbs = metrics.trafficMonInDropsMbs[node.Id]
		node.TrafficManInMbs = metrics.trafficManInMbs[node.Id]
		node.TrafficManOutMbs = metrics.trafficManOutMbs[node.Id]
		node.RedisQueueSize = metrics.redisQueueSize[node.Id]
		node.IoWaitPct = metrics.ioWaitPct[node.Id]
		node.Load1m = metrics.load1m[node.Id]
		node.Load5m = metrics.load5m[node.Id]
		node.Load15m = metrics.load15m[node.Id]
		node.DiskUsedElasticGB = metrics.diskUsedElasticGB[node.Id]
		node.DiskUsedInfluxDbGB = metrics.diskUsedInfluxDbGB[node.Id]
		node.HighstateAgeSeconds = metrics.highstateAgeSeconds[node.Id]
		node.LksEnabled = metrics.lksEnabled[node.Id]
		node.FpsEnabled = metrics.fpsEnabled[node.Id]

		enhancedStatusEnabled := (metrics.client != nil)
		status = node.UpdateOverallStatus(enhancedStatusEnabled)

		licensing.ValidateFeature(licensing.FEAT_FPS, node.FpsEnabled == 1)
		licensing.ValidateFeature(licensing.FEAT_LKS, node.LksEnabled == 1)
	}
	return status
}
