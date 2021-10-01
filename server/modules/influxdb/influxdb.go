// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package influxdb

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_ORG = ""
const DEFAULT_BUCKET = "telegraf"
const DEFAULT_CACHE_EXPIRATION_MS = 60000
const DEFAULT_MAX_METRIC_AGE_SECONDS = 1200

type InfluxDB struct {
  config  module.ModuleConfig
  server  *server.Server
  metrics *InfluxDBMetrics
}

func NewInfluxDB(srv *server.Server) *InfluxDB {
  return &InfluxDB{
    server:  srv,
    metrics: NewInfluxDBMetrics(srv),
  }
}

func (influxdb *InfluxDB) PrerequisiteModules() []string {
  return nil
}

func (influxdb *InfluxDB) Init(cfg module.ModuleConfig) error {
  influxdb.config = cfg
  host, _ := module.GetString(cfg, "hostUrl")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  token, _ := module.GetString(cfg, "token")
  org := module.GetStringDefault(cfg, "org", DEFAULT_ORG)
  bucket := module.GetStringDefault(cfg, "bucket", DEFAULT_BUCKET)
  cacheExpirationMs := module.GetIntDefault(cfg, "cacheExpirationMs", DEFAULT_CACHE_EXPIRATION_MS)
  maxMetricAgeSeconds := module.GetIntDefault(cfg, "maxMetricAgeSeconds", DEFAULT_MAX_METRIC_AGE_SECONDS)
  err := influxdb.metrics.Init(host, token, org, bucket, verifyCert, cacheExpirationMs, maxMetricAgeSeconds)
  if err == nil && influxdb.server != nil {
    influxdb.server.Metrics = influxdb.metrics
  }
  return err
}

func (influxdb *InfluxDB) Start() error {
  return nil
}

func (influxdb *InfluxDB) Stop() error {
  influxdb.metrics.Stop()
  return nil
}

func (influxdb *InfluxDB) IsRunning() bool {
  return influxdb.metrics.client != nil
}
