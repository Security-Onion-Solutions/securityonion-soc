// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package influxdb

import (
  "context"
  "crypto/tls"
  "github.com/apex/log"
  "github.com/influxdata/influxdb-client-go/v2"
  "github.com/influxdata/influxdb-client-go/v2/api"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "strconv"
  "sync"
  "time"
)

type InfluxDBMetrics struct {
  client   influxdb2.Client
  server   *server.Server
  token    string
  org      string
  bucket   string
  queryApi api.QueryAPI

  cacheLock             sync.Mutex
  cacheExpirationMs     int
  maxMetricAgeSeconds   int
  lastRaidUpdateTime    time.Time
  lastProcessUpdateTime time.Time
  lastEpsUpdateTime     time.Time
  raidStatus            map[string]int
  processStatus         map[string]int
  processJson           map[string]string
  consumptionEps        map[string]int
  productionEps         map[string]int
  failedEvents          map[string]int
}

func NewInfluxDBMetrics(srv *server.Server) *InfluxDBMetrics {
  return &InfluxDBMetrics{
    server:         srv,
    raidStatus:     make(map[string]int),
    processStatus:  make(map[string]int),
    processJson:    make(map[string]string),
    consumptionEps: make(map[string]int),
    productionEps:  make(map[string]int),
    failedEvents:   make(map[string]int),
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

func (metrics *InfluxDBMetrics) fetchLatestValuesByHost(measurement string, field string) map[string]interface{} {
  values := make(map[string]interface{})
  if metrics.client != nil {
    log.WithFields(log.Fields{
      "measurement": measurement,
      "field":       field,
    }).Debug("Fetching latest values by host")
    result, err := metrics.queryApi.Query(context.Background(),
      `from(bucket:"`+metrics.bucket+`")
        |> range(start: -`+strconv.Itoa(metrics.maxMetricAgeSeconds)+`s)
        |> filter(fn: (r) => r._measurement == "`+measurement+`" 
                             and r._field == "`+field+`") 
        |> group(columns: ["host"]) |> last()`)
    if err == nil {
      for result.Next() {
        log.WithField("result.Record", result.Record()).Debug("Got an influxdb result")
        host := result.Record().ValueByKey("host")
        if hostname, ok := host.(string); ok {
          values[hostname] = result.Record().Value()
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

func (metrics *InfluxDBMetrics) updateRaidStatus() {
  metrics.cacheLock.Lock()
  defer metrics.cacheLock.Unlock()
  now := time.Now()
  if now.Sub(metrics.lastRaidUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
    values := metrics.fetchLatestValuesByHost("raid", "nsmraid")
    metrics.raidStatus = metrics.convertValuesToInt(values)
    metrics.lastRaidUpdateTime = now
  }
}

func (metrics *InfluxDBMetrics) updateProcessStatus() {
  metrics.cacheLock.Lock()
  defer metrics.cacheLock.Unlock()
  now := time.Now()
  if now.Sub(metrics.lastProcessUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
    values := metrics.fetchLatestValuesByHost("sostatus", "status")
    metrics.processStatus = metrics.convertValuesToInt(values)

    details := metrics.fetchLatestValuesByHost("sostatus", "json")
    metrics.processJson = metrics.convertValuesToString(details)

    metrics.lastProcessUpdateTime = now
  }
}

func (metrics *InfluxDBMetrics) updateEps() {
  metrics.cacheLock.Lock()
  defer metrics.cacheLock.Unlock()
  now := time.Now()
  if now.Sub(metrics.lastEpsUpdateTime).Milliseconds() > int64(metrics.cacheExpirationMs) {
    values := metrics.fetchLatestValuesByHost("consumptioneps", "eps")
    metrics.consumptionEps = metrics.convertValuesToInt(values)

    values = metrics.fetchLatestValuesByHost("fbstats", "eps")
    metrics.productionEps = metrics.convertValuesToInt(values)

    values = metrics.fetchLatestValuesByHost("fbstats", "failed")
    metrics.failedEvents = metrics.convertValuesToInt(values)

    metrics.lastEpsUpdateTime = now
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

func (metrics *InfluxDBMetrics) UpdateNodeMetrics(ctx context.Context, node *model.Node) bool {
  var status bool
  if err := metrics.server.CheckAuthorized(ctx, "write", "nodes"); err == nil {
    node.RaidStatus = metrics.getRaidStatus(node.Id)
    node.ProcessStatus = metrics.getProcessStatus(node.Id)
    node.ProcessJson = metrics.getProcessJson(node.Id)
    node.ProductionEps = metrics.getProductionEps(node.Id)
    node.ConsumptionEps = metrics.getConsumptionEps(node.Id)
    node.FailedEvents = metrics.getFailedEvents(node.Id)

    enhancedStatusEnabled := (metrics.client != nil)
    status = node.UpdateOverallStatus(enhancedStatusEnabled)
  }
  return status
}
