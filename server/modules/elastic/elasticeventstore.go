// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "bytes"
  "context"
  "crypto/tls"
  "encoding/json"
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

type FieldDefinition struct {
  name          string
  fieldType     string
  aggregatable  bool
  searchable    bool
}

type ElasticEventstore struct {
  esConfig		elasticsearch.Config
  esClient		*elasticsearch.Client
  timeShiftMs	int
  timeoutMs   time.Duration
  index       string
  cacheMs     time.Duration
  cacheTime   time.Time
  fieldDefs   map[string]*FieldDefinition
}

func NewElasticEventstore() *ElasticEventstore {
  return &ElasticEventstore{}
}

func (store *ElasticEventstore) Init(hostUrl string, user string, pass string, verifyCert bool, timeShiftMs int, timeoutMs int, cacheMs int, index string) error {
  hosts := make([]string, 1)
  store.timeShiftMs = timeShiftMs
  store.index = index
  store.timeoutMs = time.Duration(timeoutMs) * time.Millisecond
  store.cacheMs = time.Duration(cacheMs) * time.Millisecond
  hosts[0] = hostUrl
  store.esConfig = elasticsearch.Config {
    Addresses: hosts,
    Username: user,
    Password: pass,
    Transport: &http.Transport{
      MaxIdleConnsPerHost:   10,
      ResponseHeaderTimeout: store.timeoutMs,
      DialContext:           (&net.Dialer{Timeout: store.timeoutMs}).DialContext,
      TLSClientConfig: &tls.Config{
        InsecureSkipVerify: !verifyCert,
      },
    },
  }
  maskedPassword := "*****"
  if len(store.esConfig.Password) == 0 {
    maskedPassword = ""
  }

  esClient, err := elasticsearch.NewClient(store.esConfig)
  fields := log.Fields {
    "InsecureSkipVerify": !verifyCert,
    "HostUrl": hosts[0],
    "Username": store.esConfig.Username,
    "Password": maskedPassword,
    "Index": index,
    "TimeoutMs": timeoutMs,
  }
  if err == nil {
    store.esClient = esClient
    log.WithFields(fields).Info("Initialized Elasticsearch Client")
  } else {
    log.WithFields(fields).Error("Failed to initialize Elasticsearch Client")
  }
  return err
}

func (store *ElasticEventstore) mapElasticField(field string) string {
  mappedField := store.fieldDefs[field]
  if mappedField != nil && !mappedField.aggregatable {
    keyword := field + ".keyword"
    mappedField = store.fieldDefs[keyword]
    if mappedField != nil && mappedField.aggregatable {
      field = keyword
    }
  }
  return field
}

func (store *ElasticEventstore) unmapElasticField(field string) string {
  suffix := ".keyword"
  if strings.HasSuffix(field, suffix) {
    newField := strings.TrimSuffix(field, suffix)
    mappedField := store.fieldDefs[newField]
    if mappedField != nil && !mappedField.aggregatable {
      field = newField
    }
  }
  return field
}

func (store *ElasticEventstore) Search(criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
  results := model.NewEventSearchResults()
  query, err := convertToElasticRequest(store, criteria)
  if err == nil {
    var response string
    store.refreshCache()
    response, err = store.luceneSearch(query)
    if err == nil {
      err = convertFromElasticResults(store, response, results)
      results.Criteria = criteria
    }
  }

  results.Complete()
  return results, err
}

func (store *ElasticEventstore) luceneSearch(query string) (string, error) {
  return store.indexSearch(query, strings.Split(store.index, ","))
}

func (store *ElasticEventstore) indexSearch(query string, indexes []string) (string, error) {
  log.WithField("query", query).Debug("Searching Elasticsearch")
  var json string
  res, err := store.esClient.Search(
    store.esClient.Search.WithContext(context.Background()),
    store.esClient.Search.WithIndex(indexes...),
    store.esClient.Search.WithBody(strings.NewReader(query)),
    store.esClient.Search.WithTrackTotalHits(true),
    store.esClient.Search.WithPretty(),
  )
  if err == nil {
    defer res.Body.Close()

    var b bytes.Buffer
    b.ReadFrom(res.Body)
    json = b.String()

    if res.IsError() {
      errorType := gjson.Get(json, "error.type").String()
      errorReason := gjson.Get(json, "error.reason").String()
      errorDetails := json
      if len(json) > 255 {
        errorDetails = json[0:512]
      }
      err = errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
    }
  }
  log.WithFields(log.Fields{"response": json}).Debug("Search Finished")
  return json, err
}

func (store *ElasticEventstore) refreshCache() {
  if store.cacheTime.IsZero() || time.Now().Sub(store.cacheTime) > store.cacheMs {
    err := store.refreshCacheFromIndexPatterns()
    if err == nil {
      store.cacheTime = time.Now()
    }
  }
}

func (store *ElasticEventstore) refreshCacheFromIndexPatterns() error {
  query := fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "type" : "index-pattern" }}}}}`)
  json, err := store.indexSearch(query, []string{".kibana*"})
  if err != nil {
    log.WithError(err).Error("Failed to refresh cache from index patterns")
  } else {
    store.cacheFieldsFromJson(json)
  }
  return err
}

func (store *ElasticEventstore) cacheFieldsFromJson(json string) {
  store.fieldDefs = make(map[string]*FieldDefinition)
  gjson.Get(json, "hits.hits.#._source.index-pattern.fields").ForEach(store.cacheFields)
}

func (store *ElasticEventstore) cacheFields(name gjson.Result, fields gjson.Result) bool {
  fieldList := make([]map[string]interface{}, 0, 0)
  json.NewDecoder(strings.NewReader(fields.String())).Decode(&fieldList)
  for _, field := range fieldList {
    name := field["name"].(string)
    fieldType := field["type"].(string)

    fieldDef := &FieldDefinition {
      name: name, 
      fieldType: fieldType, 
      aggregatable: field["aggregatable"].(bool), 
      searchable: field["searchable"].(bool),
    }
    store.fieldDefs[name] = fieldDef

    log.WithFields(log.Fields {
      "name": name,
      "type": fieldType,
    }).Debug("Added field definition")
  }
  return true
}

func (store *ElasticEventstore) clusterState() (string, error) {
  log.WithField("cacheMs", store.cacheMs).Debug("Refreshing field definitions")
  indexes := strings.Split(store.index, ",")
  var json string
  res, err := store.esClient.Cluster.State(
    store.esClient.Cluster.State.WithContext(context.Background()),
    store.esClient.Cluster.State.WithIndex(indexes...),
  )
  if err == nil {
    defer res.Body.Close()

    var b bytes.Buffer
    b.ReadFrom(res.Body)
    json = b.String()

    if res.IsError() {
      errorType := gjson.Get(json, "error.type").String()
      errorReason := gjson.Get(json, "error.reason").String()
      errorDetails := json
      if len(json) > 255 {
        errorDetails = json[0:512]
      }
      err = errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
    }
  }
  log.WithFields(log.Fields{"response": json}).Debug("Refresh Finished")
  return json, err
}

func (store *ElasticEventstore) PopulateJobFromEventId(esId string, job *model.Job) error {
  var outputSensorId string
  filter := model.NewFilter()
  query := fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "_id" : "%s" }}}}}`, esId)
  json, err := store.luceneSearch(query)
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
        json, err = store.luceneSearch(query)
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
            filter.BeginTime = closestTimestamp.Add(time.Duration(-duration - int64(store.timeShiftMs)) * time.Millisecond)
            filter.EndTime = closestTimestamp.Add(time.Duration(duration + int64(store.timeShiftMs)) * time.Millisecond)
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
  } else {
    job.SensorId = outputSensorId
    job.Filter = filter
  }

  return err
}

