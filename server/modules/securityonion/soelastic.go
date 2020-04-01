// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package securityonion

import (
  "bytes"
  "context"
  "crypto/tls"
  "errors"
  "fmt"
  "math"
  "net"
  "net/http"
  "strconv"
  "strings"
  "time"
  "github.com/apex/log"
  "github.com/elastic/go-elasticsearch/v7"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/tidwall/gjson"
)

type SoElastic struct {
  esConfig		elasticsearch.Config
  esClient		*elasticsearch.Client
  timeShiftMs	int
  timeoutMs   time.Duration
  index       string
}

func NewSoElastic() *SoElastic {
  return &SoElastic{}
}

func (elastic *SoElastic) Init(host string, user string, pass string, verifyCert bool, timeShiftMs int, timeoutMs int, index string) error {
  hosts := make([]string, 1)
  elastic.timeShiftMs = timeShiftMs
  elastic.index = index
  elastic.timeoutMs = time.Duration(timeoutMs) * time.Millisecond
  hosts[0] = host
  elastic.esConfig = elasticsearch.Config {
    Addresses: hosts,
    Username: user,
    Password: pass,
    Transport: &http.Transport{
      MaxIdleConnsPerHost:   10,
      ResponseHeaderTimeout: elastic.timeoutMs,
      DialContext:           (&net.Dialer{Timeout: elastic.timeoutMs}).DialContext,
      TLSClientConfig: &tls.Config{
        InsecureSkipVerify: !verifyCert,
      },
    },
  }
  maskedPassword := "*****"
  if len(elastic.esConfig.Password) == 0 {
    maskedPassword = ""
  }

  esClient, err := elasticsearch.NewClient(elastic.esConfig)
  fields := log.Fields {
    "InsecureSkipVerify": !verifyCert,
    "Host": hosts[0],
    "Username": elastic.esConfig.Username,
    "Password": maskedPassword,
    "Index": index,
    "TimeoutMs": timeoutMs,
  }
  if err == nil {
    elastic.esClient = esClient
    log.WithFields(fields).Info("Initialized Elasticsearch Client")
  } else {
    log.WithFields(fields).Error("Failed to initialize Elasticsearch Client")
  }
  return err
}

func (elastic *SoElastic) Search(query string) (string, error) {
  indexes := strings.Split(elastic.index, ",")
  var json string
  res, err := elastic.esClient.Search(
    elastic.esClient.Search.WithContext(context.Background()),
    elastic.esClient.Search.WithIndex(indexes...),
    elastic.esClient.Search.WithBody(strings.NewReader(query)),
    elastic.esClient.Search.WithTrackTotalHits(true),
    elastic.esClient.Search.WithPretty(),
  )
  if err == nil {
    defer res.Body.Close()

    var b bytes.Buffer
    b.ReadFrom(res.Body)
    json = b.String()

    if res.IsError() {
      errorType := gjson.Get(json, "error.type").String()
      errorReason := gjson.Get(json, "error.reason").String()
      err = errors.New(errorType + ": " + errorReason)
    }
  }
  return json, err
}

func (elastic *SoElastic) LookupEsId(esId string) (string, *model.Filter, error) {
  var outputSensorId string
  filter := model.NewFilter()
  query := fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "_id" : "%s" }}}}}`, esId)
  json, err := elastic.Search(query)
  log.WithFields(log.Fields{
    "query": query,
    "response": json,
    }).Debug("Elasticsearch primary search finished")
  if err == nil {
    hits := gjson.Get(json, "hits.total.value").Int()
    if hits > 0 {
      timestampStr := gjson.Get(json, "hits.hits.0._source.\\@timestamp").String()
      var timestamp time.Time
      timestamp, err = time.Parse(time.RFC3339, timestampStr)
      if err == nil {
        srcIp := gjson.Get(json, "hits.hits.0._source.source.ip").String()
        srcPort := gjson.Get(json, "hits.hits.0._source.source.port").Int()
        dstIp := gjson.Get(json, "hits.hits.0._source.destination.ip").String()
        dstPort := gjson.Get(json, "hits.hits.0._source.destination.port").Int()
        uid := gjson.Get(json, "hits.hits.0._source.log.id.uid").String()
        x509id := gjson.Get(json, "hits.hits.0._source.log.id.id").String()
        fuid := gjson.Get(json, "hits.hits.0._source.log.id.fuid").String()

        // Select first uid if multiple were provided
        if len(uid) > 0 && uid[0] == '[' {
          uid = gjson.Get(json, "hits.hits.0._source.log.id.uid.0").String()
        }

        // Initialize default query params
        esType := "conn"
        broQuery := fmt.Sprintf("%s AND %d AND %s AND %d", srcIp, srcPort, dstIp, dstPort)

        // Override the defaults with special search queries
        if len(uid) > 0 && uid[0] == 'C' {
          broQuery = uid
        } else if len(x509id) > 0 && x509id[0] == 'F' {
          esType = "files"
          broQuery = x509id
        } else if len(fuid) > 0 && fuid[0] == 'F' {
          esType = "files"
          broQuery = fuid
        }

        startTime := timestamp.Add(time.Duration(-30) * time.Minute).Unix() * 1000
        endTime := timestamp.Add(time.Duration(30) * time.Minute).Unix() * 1000
        query = fmt.Sprintf(`{"query":{"bool":{"must":[{"query_string":{"query":"event.module:zeek AND event.dataset:%s AND %s","analyze_wildcard":true}},{"range":{"@timestamp":{"gte":"%d","lte":"%d","format":"epoch_millis"}}}]}}}`,
          esType, broQuery, startTime, endTime)
        json, err = elastic.Search(query)
        log.WithFields(log.Fields{
          "query": query,
          "response": json,
          }).Debug("Elasticsearch secondary search finished")
        if err == nil {
          hits = gjson.Get(json, "hits.total.value").Int()
          if hits > 0 {
            results := gjson.Get(json, "hits.hits.#._source.\\@timestamp").Array()
            closestIdx := 0
            var closestDeltaNs int64
            var closestTimestamp time.Time
            closestDeltaNs = 0
            for idx, ts := range results {
              var matchTs time.Time
              matchTs, err = time.Parse(time.RFC3339, ts.String())
              if err == nil {
                delta := timestamp.Sub(matchTs)
                deltaNs := delta.Nanoseconds()
                if deltaNs < 0 {
                  deltaNs = -deltaNs
                }
                if closestDeltaNs == 0 || deltaNs < closestDeltaNs {
                  closestDeltaNs = deltaNs
                  closestIdx = idx
                  closestTimestamp = matchTs
                }
              }
            }
            idxStr := strconv.Itoa(closestIdx)
            filter.SrcIp = gjson.Get(json, "hits.hits." + idxStr + "._source.source.ip").String()
            filter.SrcPort = int(gjson.Get(json, "hits.hits." + idxStr + "._source.source.port").Int())
            filter.DstIp = gjson.Get(json, "hits.hits." + idxStr + "._source.destination.ip").String()
            filter.DstPort = int(gjson.Get(json, "hits.hits." + idxStr + "._source.destination.port").Int())
            durationFloat := gjson.Get(json, "hits.hits." + idxStr + "._source.event.duration").Float()
            duration := int64(math.Round(durationFloat * 1000.0))
            filter.BeginTime = closestTimestamp.Add(time.Duration(-duration - int64(elastic.timeShiftMs)) * time.Millisecond)
            filter.EndTime = closestTimestamp.Add(time.Duration(duration + int64(elastic.timeShiftMs)) * time.Millisecond)
            outputSensorId = gjson.Get(json, "hits.hits." + idxStr + "._source.observer.name").String()
            log.WithFields(log.Fields{
              "sensorId": outputSensorId,
              }).Info("Obtained output parameters")
          }
        }
      }
    } else {
      err = errors.New("EsId not found in Elasticsearch: " + esId)
    }
  }

  if err != nil {
    log.WithError(err).Warn("Failed to lookup elasticsearch document")
  }

  return outputSensorId, filter, err
}

