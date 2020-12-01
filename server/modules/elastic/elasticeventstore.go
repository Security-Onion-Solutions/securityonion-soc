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
  "github.com/elastic/go-elasticsearch/v7/esapi"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/tidwall/gjson"
)

const MAX_ERROR_LENGTH = 4096

type FieldDefinition struct {
  name          string
  fieldType     string
  aggregatable  bool
  searchable    bool
}

type ElasticEventstore struct {
  hostUrls          []string
  esClient		      *elasticsearch.Client
  esRemoteClients   []*elasticsearch.Client
  esAllClients      []*elasticsearch.Client
  timeShiftMs	      int
  defaultDurationMs int
  esSearchOffsetMs  int
  timeoutMs         time.Duration
  index             string
  cacheMs           time.Duration
  cacheTime         time.Time
  cacheLock         sync.Mutex
  fieldDefs         map[string]*FieldDefinition
  asyncThreshold int
}

func NewElasticEventstore() *ElasticEventstore {
  return &ElasticEventstore{
    hostUrls: make([]string, 0),
    esRemoteClients: make([]*elasticsearch.Client, 0),
    esAllClients: make([]*elasticsearch.Client, 0),
  }
}

func (store *ElasticEventstore) Init(hostUrl string,
                                      remoteHosts []string, 
                                      user string, 
                                      pass string, 
                                      verifyCert bool, 
                                      timeShiftMs int, 
                                      defaultDurationMs int, 
                                      esSearchOffsetMs int, 
                                      timeoutMs int, 
                                      cacheMs int, 
                                      index string, 
                                      asyncThreshold int) error {
  store.timeShiftMs = timeShiftMs
  store.defaultDurationMs = defaultDurationMs
  store.esSearchOffsetMs = esSearchOffsetMs
  store.index = index
  store.asyncThreshold = asyncThreshold
  store.timeoutMs = time.Duration(timeoutMs) * time.Millisecond
  store.cacheMs = time.Duration(cacheMs) * time.Millisecond

  var err error
  store.esClient, err = store.makeEsClient(hostUrl, user, pass, verifyCert)
  if err == nil {
    store.hostUrls = append(store.hostUrls, hostUrl)
    store.esAllClients = append(store.esAllClients, store.esClient)
    for _, remoteHostUrl := range(remoteHosts) {
      client, err := store.makeEsClient(remoteHostUrl, user, pass, verifyCert)
      if err == nil {
        store.hostUrls = append(store.hostUrls, remoteHostUrl)
        store.esRemoteClients = append(store.esRemoteClients, client)
        store.esAllClients = append(store.esAllClients, client)
      } else {
        break
      }
    }
  }
  return err
}

func (store *ElasticEventstore) makeEsClient(host string, user string, pass string, verifyCert bool) (*elasticsearch.Client, error) {
  var esClient *elasticsearch.Client

  hosts := make([]string, 1)
  hosts[0] = host
  esConfig := elasticsearch.Config {
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
  if len(esConfig.Password) == 0 {
    maskedPassword = ""
  }

  esClient, err := elasticsearch.NewClient(esConfig)
  fields := log.Fields {
    "InsecureSkipVerify": !verifyCert,
    "HostUrl": host,
    "Username": esConfig.Username,
    "Password": maskedPassword,
    "Index": store.index,
    "TimeoutMs": store.timeoutMs,
  }
  if err == nil {
    log.WithFields(fields).Info("Initialized Elasticsearch Client")
  } else {
    log.WithFields(fields).Error("Failed to initialize Elasticsearch Client")
    esClient = nil
  }
  return esClient, err
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

func (store *ElasticEventstore) disableCrossClusterIndexing(indexes []string) []string {
  for idx, index := range(indexes) {
    pieces := strings.SplitN(index, ":", 2)
    if len(pieces) == 2 {
      indexes[idx] = pieces[1]
    }
  }
  return indexes
}

func (store *ElasticEventstore) Update(criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
  store.refreshCache()

  results := model.NewEventUpdateResults()
  results.Criteria = criteria
  query, err := convertToElasticUpdateRequest(store, criteria)
  if err == nil {
    var response string

    for idx, client := range(store.esAllClients) {
      log.WithField("clientHost", store.hostUrls[idx]).Debug("Sending request to client")
      response, err = store.updateDocuments(client, query, store.disableCrossClusterIndexing(strings.Split(store.index, ",")), !criteria.Asynchronous)
      if err == nil {
        if !criteria.Asynchronous {
          currentResults := model.NewEventUpdateResults()
          err = convertFromElasticUpdateResults(store, response, currentResults)
          if err == nil {
            mergeElasticUpdateResults(results, currentResults)
          } else {
            log.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
            results.Errors = append(results.Errors, err.Error())
          }
        }
      } else {
        log.WithError(err).WithField("clientHost", store.hostUrls[idx]).Error("Encountered error while updating elasticsearch")
        results.Errors = append(results.Errors, err.Error())        
      }
    }
  }

  if len(results.Errors) < len(store.esAllClients) {
    // Do not fail this request completely since some hosts succeeded.
    // The results.Errors property contains the list of errors.
    err = nil
  }

  results.Complete()
  return results, err
}

func (store *ElasticEventstore) luceneSearch(query string) (string, error) {
  return store.indexSearch(query, strings.Split(store.index, ","))
}

func (store *ElasticEventstore) transformIndex(index string) string {
  today := time.Now().Format("2006.01.02")
  index = strings.ReplaceAll(index, "{today}", today)
  return index
}

func (store *ElasticEventstore) readErrorFromJson(json string) error {
  errorType := gjson.Get(json, "error.type").String()
  errorReason := gjson.Get(json, "error.reason").String()
  errorDetails := json
  if len(json) > MAX_ERROR_LENGTH {
    errorDetails = json[0:MAX_ERROR_LENGTH]
  }
  err := errors.New(errorType + ": " + errorReason + " -> " + errorDetails)
  return err
}

func (store *ElasticEventstore) readJsonFromResponse(res *esapi.Response) (string, error) {
  var err error
  var b bytes.Buffer
  b.ReadFrom(res.Body)
  json := b.String()
  if res.IsError() {
    err = store.readErrorFromJson(json)
  }
  return json, err
}

func (store *ElasticEventstore) indexSearch(query string, indexes []string) (string, error) {
  log.WithField("query", query).Info("Searching Elasticsearch")
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
    json, err = store.readJsonFromResponse(res)
  }
  log.WithFields(log.Fields{"response": json}).Debug("Search finished")
  return json, err
}

func (store *ElasticEventstore) indexDocument(document string, index string) (string, error) {
  log.WithField("document", document).Debug("Adding document to Elasticsearch")

  res, err := store.esClient.Index(store.transformIndex(index), strings.NewReader(document), store.esClient.Index.WithRefresh("true"))

  if err != nil {
    log.WithError(err).Error("Unable to index acknowledgement into Elasticsearch")
    return "", err
  }
  defer res.Body.Close()
  json, err := store.readJsonFromResponse(res)

  log.WithFields(log.Fields{"response": json}).Debug("Index new document finished")
  return json, err
}

func (store *ElasticEventstore) updateDocuments(client *elasticsearch.Client, query string, indexes []string, waitForCompletion bool) (string, error) {
  log.WithField("query", query).Debug("Updating documents in Elasticsearch")
  var json string
  res, err := client.UpdateByQuery(
    indexes,
    client.UpdateByQuery.WithContext(context.Background()),
    client.UpdateByQuery.WithPretty(),
    client.UpdateByQuery.WithConflicts("proceed"),
    client.UpdateByQuery.WithBody(strings.NewReader(query)),
    client.UpdateByQuery.WithRefresh(true),
    client.UpdateByQuery.WithWaitForCompletion(waitForCompletion),
  )
  if err == nil {
    defer res.Body.Close()
    json, err = store.readJsonFromResponse(res)
  }
  log.WithFields(log.Fields{"response": json}).Debug("Update finished")
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
  query := fmt.Sprintf(`{"query" : { "bool": { "must": [ { "match": { "index-pattern.title" : "` + store.index + `" }}, { "match" : { "type" : "index-pattern" }} ] }}}`)
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
 * Fetch record via provided Elasticsearch document query.
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
func (store *ElasticEventstore) PopulateJobFromDocQuery(query string, job *model.Job) error {
  var outputSensorId string
  filter := model.NewFilter()
  json, err := store.luceneSearch(query)
  log.WithFields(log.Fields{
    "query": query,
    "response": json,
    }).Debug("Elasticsearch primary search finished")
  if err != nil {
    log.WithField("query", query).WithError(err).Error("Unable to lookup initial document record")
    return err
  }

  hits := gjson.Get(json, "hits.total.value").Int()
  if hits == 0 {
    log.WithField("query", query).Error("Pivoted document record was not found")
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
      log.WithField("query", query).WithError(err).Error("Unable to lookup tunnel record")
      return err
    }
    hits := gjson.Get(json, "hits.total.value").Int()
    if hits == 0 {
      log.WithField("query", query).Error("Tunnel record was not found")
      return errors.New("Unable to locate encapsulating tunnel record")
    }
  }

  timestampStr := gjson.Get(json, "hits.hits.0._source.\\@timestamp").String()
  var timestamp time.Time
  timestamp, err = time.Parse(time.RFC3339, timestampStr)
  if err != nil {
    log.WithFields(log.Fields {
      "query": query,
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
            "query": query,
            "zeekFileQuery": zeekFileQuery,
          }).WithError(err).Error("Unable to lookup Zeek File record")
          return err
        }

        hits = gjson.Get(json, "hits.total.value").Int()
        if hits == 0 {
          log.WithFields(log.Fields {
            "query": query,
            "zeekFileQuery": zeekFileQuery,
          }).Error("Zeek File record was not found")
          return errors.New("Unable to locate Zeek File record")
        }

        uid = store.parseFirst(json, "log.id.uid")
      }

      if len(uid) == 0 {
        log.WithFields(log.Fields {
          "query": query,
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
        "query": query,
        "uid": uid,
      }).WithError(err).Error("Unable to lookup Zeek record")
      return err
    }

    hits = gjson.Get(json, "hits.total.value").Int()
    if hits == 0 {
      log.WithFields(log.Fields {
        "query": query,
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
      "query": query,
      "uid": uid,
    }).Warn("Unable to lookup PCAP due to missing TCP/UDP parameters")
    return errors.New("No TCP/UDP record was found for retrieving PCAP")
  }

  filter.BeginTime = timestamp.Add(time.Duration(-duration - int64(store.timeShiftMs)) * time.Millisecond)
  filter.EndTime = timestamp.Add(time.Duration(duration + int64(store.timeShiftMs)) * time.Millisecond)
  job.NodeId = outputSensorId
  job.Filter = filter

  return nil
}

func (store *ElasticEventstore) Acknowledge(ackCriteria *model.EventAckCriteria) (*model.EventUpdateResults, error) {
  var results *model.EventUpdateResults
  var err error
  if len(ackCriteria.EventFilter) > 0 {
    log.WithFields(log.Fields {
      "searchFilter": ackCriteria.SearchFilter,
      "eventFilter": ackCriteria.EventFilter,
      "escalate": ackCriteria.Escalate,
      "acknowledge": ackCriteria.Acknowledge,
    }).Info("Acknowledging event")

    updateCriteria := model.NewEventUpdateCriteria()
    updateCriteria.AddUpdateScript("ctx._source.event.acknowledged=" + strconv.FormatBool(ackCriteria.Acknowledge))
    if ackCriteria.Escalate && ackCriteria.Acknowledge {
      updateCriteria.AddUpdateScript("ctx._source.event.escalated=true")
    }
    updateCriteria.Populate(ackCriteria.SearchFilter, 
                            ackCriteria.DateRange, 
                            ackCriteria.DateRangeFormat, 
                            ackCriteria.Timezone, 
                            "0",
                            "0")

    // Add the event filters to the search query
    var searchSegment *model.SearchSegment
    segment := updateCriteria.ParsedQuery.NamedSegment("search")
    if segment == nil {
      searchSegment = model.NewSearchSegmentEmpty()
    } else {
      searchSegment = segment.(*model.SearchSegment)
    }

    updateCriteria.Asynchronous = false
    for key, value := range ackCriteria.EventFilter {
      if (strings.ToLower(key) != "count") {
        valueStr := fmt.Sprintf("%v", value)
        searchSegment.AddFilter(store.mapElasticField(key), valueStr, model.IsScalar(value), true)
      } else if int(value.(float64)) > store.asyncThreshold {
        log.WithFields(log.Fields {
          key: value,
          "threshold": store.asyncThreshold,
        }).Info("Acknowledging events asynchronously due to large quantity");
        updateCriteria.Asynchronous = true
      }
    }

    // Baseline the query to be based only on the search component
    updateCriteria.ParsedQuery = model.NewQuery()
    updateCriteria.ParsedQuery.AddSegment(searchSegment)

    results, err = store.Update(updateCriteria)
    if err == nil && !updateCriteria.Asynchronous {
      if results.UpdatedCount == 0 {
        if results.UnchangedCount == 0 {
          err = errors.New("No eligible events available to acknowledge")
        } else {
          err = errors.New("All events have already been acknowledged")
        }
      }
    }
  } else {
    err = errors.New("EventFilter must be specified to ack an event")
  }
  return results, err
}

