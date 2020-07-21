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
  "sync"
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
  esConfig		      elasticsearch.Config
  esClient		      *elasticsearch.Client
  timeShiftMs	      int
  defaultDurationMs int
  esSearchOffsetMs  int
  timeoutMs         time.Duration
  index             string
  cacheMs           time.Duration
  cacheTime         time.Time
  cacheLock         sync.Mutex
  fieldDefs         map[string]*FieldDefinition
}

func NewElasticEventstore() *ElasticEventstore {
  return &ElasticEventstore{}
}

func (store *ElasticEventstore) Init(hostUrl string, user string, pass string, verifyCert bool, timeShiftMs int, defaultDurationMs int, esSearchOffsetMs int, timeoutMs int, cacheMs int, index string) error {
  hosts := make([]string, 1)
  store.timeShiftMs = timeShiftMs
  store.defaultDurationMs = defaultDurationMs
  store.esSearchOffsetMs = esSearchOffsetMs
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
  store.refreshCache()

  results := model.NewEventSearchResults()
  query, err := convertToElasticRequest(store, criteria)
  if err == nil {
    var response string
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
  store.cacheLock.Lock()
  defer store.cacheLock.Unlock()
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

func (store *ElasticEventstore) parseFirst(json string, name string) string {
  result := gjson.Get(json, "hits.hits.0._source." + name).String()
  // Select first uid if multiple were provided
  if len(result) > 0 && result[0] == '[' {
    result = gjson.Get(json, "hits.hits.0._source." + name + ".0").String()
  }
  return result
}

/**
 * Fetch record via provided Elasticsearch document ID.
 * If the record has a tunnel_parent, search for a UID=tunnel_parent[0]
 *   - If found, discard original record and replace with the new record
 * If the record has source IP/port and destination IP/port, use it as the filter.
 * Else if the record has a Zeek x509 "ID" search for the first Zeek record with this ID.
 * Else if the record has a Zeek file "FUID" search for the first Zeek record with this FUID.
 * Search for the Zeek record with a matching log.id.uid equal to the UID from the previously found record
 *   - If multiple UIDs exist in the record, use the first UID in the list.
 * Review the results from the Zeek search and find the record with the timestamp nearest
   to the original ES ID record and use the IP/port details as the filter.
 */
func (store *ElasticEventstore) PopulateJobFromEventId(esId string, job *model.Job) error {
  var outputSensorId string
  filter := model.NewFilter()
  query := fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "_id" : "%s" }}}}}`, esId)
  json, err := store.luceneSearch(query)
  log.WithFields(log.Fields{
    "query": query,
    "response": json,
    }).Debug("Elasticsearch primary search finished")
  if err != nil {
    log.WithField("esId", esId).WithError(err).Error("Unable to lookup initial document record")
    return err
  }

  hits := gjson.Get(json, "hits.total.value").Int()
  if hits == 0 {
    log.WithField("esId", esId).Error("Pivoted document record was not found")
    return errors.New("Unable to locate document record")
  }

  // Check if user has pivoted to a PCAP that is encapsulated in a tunnel. The best we 
  // can do in this situation is respond with the tunnel PCAP data, which could be excessive.
  tunnelParent := gjson.Get(json, "hits.hits.0._source.log.id.tunnel_parents").String()
  if len(tunnelParent) > 0 {
    log.Info("Document is inside of a tunnel; attempting to lookup tunnel connection log")
    if tunnelParent[0] == '[' {
      tunnelParent = gjson.Get(json, "hits.hits.0._source.log.id.tunnel_parents.0").String()
    }
    query := fmt.Sprintf(`{"query" : { "bool": { "must": { "match" : { "log.id.uid" : "%s" }}}}}`, tunnelParent)
    json, err = store.luceneSearch(query)
    log.WithFields(log.Fields{
      "query": query,
      "response": json,
      }).Debug("Elasticsearch tunnel search finished")
    if err != nil {
      log.WithField("esId", esId).WithError(err).Error("Unable to lookup tunnel record")
      return err
    }
    hits := gjson.Get(json, "hits.total.value").Int()
    if hits == 0 {
      log.WithField("esId", esId).Error("Tunnel record was not found")
      return errors.New("Unable to locate encapsulating tunnel record")
    }
  }

  timestampStr := gjson.Get(json, "hits.hits.0._source.\\@timestamp").String()
  var timestamp time.Time
  timestamp, err = time.Parse(time.RFC3339, timestampStr)
  if err != nil {
    log.WithFields(log.Fields {
      "esId": esId,
      "timestamp": timestamp,
    }).WithError(err).Error("Unable to parse document timestamp")
    return err
  }

  filter.ImportId = gjson.Get(json, "hits.hits.0._source.import.id").String()
  filter.SrcIp = gjson.Get(json, "hits.hits.0._source.source.ip").String()
  filter.SrcPort = int(gjson.Get(json, "hits.hits.0._source.source.port").Int())
  filter.DstIp = gjson.Get(json, "hits.hits.0._source.destination.ip").String()
  filter.DstPort = int(gjson.Get(json, "hits.hits.0._source.destination.port").Int())
  uid := store.parseFirst(json, "log.id.uid")
  x509id := store.parseFirst(json, "log.id.id")
  fuid := store.parseFirst(json, "log.id.fuid")
  outputSensorId = gjson.Get(json, "hits.hits.0._source.observer.name").String()
  duration := int64(store.defaultDurationMs)

  // If source and destination IP/port details aren't available search ES again for a correlating Zeek record
  if len(filter.SrcIp) == 0 || len(filter.DstIp) == 0 || filter.SrcPort == 0 || filter.DstPort == 0 {
    startTime := timestamp.Add(time.Duration(-store.esSearchOffsetMs) * time.Millisecond).Unix() * 1000
    endTime := timestamp.Add(time.Duration(store.esSearchOffsetMs) * time.Millisecond).Unix() * 1000

    if len(uid) == 0 || uid[0] != 'C' {
      zeekFileQuery := ""
      if len(x509id) > 0 && x509id[0] == 'F' {
        zeekFileQuery = x509id
      } else if len(fuid) > 0 && fuid[0] == 'F' {
        zeekFileQuery = fuid
      }

      if len(zeekFileQuery) > 0 {
        query = fmt.Sprintf(`{"query":{"bool":{"must":[{"query_string":{"query":"event.module:zeek AND event.dataset:file AND %s","analyze_wildcard":true}},{"range":{"@timestamp":{"gte":"%d","lte":"%d","format":"epoch_millis"}}}]}}}`,
          zeekFileQuery, startTime, endTime)
        json, err = store.luceneSearch(query)
        log.WithFields(log.Fields{
          "query": query,
          "response": json,
          }).Debug("Elasticsearch Zeek File search finished")

        if err != nil {
          log.WithFields(log.Fields {
            "esId": esId,
            "zeekFileQuery": zeekFileQuery,
          }).WithError(err).Error("Unable to lookup Zeek File record")
          return err
        }

        hits = gjson.Get(json, "hits.total.value").Int()
        if hits == 0 {
          log.WithFields(log.Fields {
            "esId": esId,
            "zeekFileQuery": zeekFileQuery,
          }).Error("Zeek File record was not found")
          return errors.New("Unable to locate Zeek File record")
        }

        uid = store.parseFirst(json, "log.id.uid")
      }

      if len(uid) == 0 {
        log.WithFields(log.Fields {
          "esId": esId,
          "zeekFileQuery": zeekFileQuery,
        }).Warn("Zeek File record is missing a UID")
        return errors.New("No valid Zeek connection ID found")
      }
    }

    // Search for the Zeek connection ID
    query = fmt.Sprintf(`{"query":{"bool":{"must":[{"query_string":{"query":"event.module:zeek AND %s","analyze_wildcard":true}},{"range":{"@timestamp":{"gte":"%d","lte":"%d","format":"epoch_millis"}}}]}}}`,
      uid, startTime, endTime)
    json, err = store.luceneSearch(query)
    log.WithFields(log.Fields{
      "query": query,
      "response": json,
      }).Debug("Elasticsearch Zeek search finished")

    if err != nil {
      log.WithFields(log.Fields {
        "esId": esId,
        "uid": uid,
      }).WithError(err).Error("Unable to lookup Zeek record")
      return err
    }

    hits = gjson.Get(json, "hits.total.value").Int()
    if hits == 0 {
      log.WithFields(log.Fields {
        "esId": esId,
        "uid": uid,
      }).Error("Zeek record was not found")
      return errors.New("Unable to locate Zeek record")
    }

    results := gjson.Get(json, "hits.hits.#._source.\\@timestamp").Array()
    var closestDeltaNs int64
    closestDeltaNs = 0
    for idx, ts := range results {
      var matchTs time.Time
      matchTs, err = time.Parse(time.RFC3339, ts.String())
      if err == nil {
        idxStr := strconv.Itoa(idx)
        srcIp := gjson.Get(json, "hits.hits." + idxStr + "._source.source.ip").String()
        srcPort := int(gjson.Get(json, "hits.hits." + idxStr + "._source.source.port").Int())
        dstIp := gjson.Get(json, "hits.hits." + idxStr + "._source.destination.ip").String()
        dstPort := int(gjson.Get(json, "hits.hits." + idxStr + "._source.destination.port").Int())

        if len(srcIp) > 0 && len(dstIp) > 0 && srcPort > 0 && dstPort > 0 {
          delta := timestamp.Sub(matchTs)
          deltaNs := delta.Nanoseconds()
          if deltaNs < 0 {
            deltaNs = -deltaNs
          }
          if closestDeltaNs == 0 || deltaNs < closestDeltaNs {
            closestDeltaNs = deltaNs

            timestamp = matchTs
            filter.SrcIp = srcIp
            filter.SrcPort = srcPort
            filter.DstIp = dstIp
            filter.DstPort = dstPort
            durationFloat := gjson.Get(json, "hits.hits." + idxStr + "._source.event.duration").Float()
            if durationFloat > 0 {
              duration = int64(math.Round(durationFloat * 1000.0))
            }
          }
        }
      }
    }
    
    log.WithFields(log.Fields{
      "sensorId": outputSensorId,
      }).Info("Obtained output parameters")
  }

  if len(filter.SrcIp) == 0 || len(filter.DstIp) == 0 || filter.SrcPort == 0 || filter.DstPort == 0 {
    log.WithFields(log.Fields {
      "esId": esId,
      "uid": uid,
    }).Warn("Unable to lookup PCAP due to missing TCP/UDP parameters")
    return errors.New("No TCP/UDP record was found for retrieving PCAP")
  }

  filter.BeginTime = timestamp.Add(time.Duration(-duration - int64(store.timeShiftMs)) * time.Millisecond)
  filter.EndTime = timestamp.Add(time.Duration(duration + int64(store.timeShiftMs)) * time.Millisecond)
  job.SensorId = outputSensorId
  job.Filter = filter

  return nil
}

