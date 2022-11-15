// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package web

import (
  "context"
  "errors"
  "github.com/apex/log"
  "github.com/gorilla/websocket"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/rbac"
  "net/http"
  "reflect"
  "sort"
  "strconv"
  "sync"
  "time"
)

type HostHandler interface {
  Handle(responseWriter http.ResponseWriter, request *http.Request)
}

type Preprocessor interface {
  PreprocessPriority() int
  Preprocess(ctx context.Context, request *http.Request) (context.Context, int, error)
}

type Host struct {
  preprocessors           []Preprocessor
  bindAddress             string
  htmlDir                 string
  idleConnectionTimeoutMs int
  httpServer              *http.Server
  running                 bool
  Version                 string
  connections             []*Connection
  lock                    sync.Mutex
  Authorizer              rbac.Authorizer
  SrvKey                  []byte
  SrvExemptId             string
}

func NewHost(address string, htmlDir string, timeoutMs int, version string, srvKey []byte, srvExemptId string) *Host {
  host := &Host{
    preprocessors:           make([]Preprocessor, 0),
    running:                 false,
    bindAddress:             address,
    htmlDir:                 htmlDir,
    idleConnectionTimeoutMs: timeoutMs,
    Version:                 version,
    SrvKey:                  srvKey,
    SrvExemptId:             srvExemptId,
  }
  err := host.AddPreprocessor(NewBasePreprocessor())
  if err != nil {
    log.WithError(err).Error("Unable to add base preprocessor")
  }
  return host
}

func (host *Host) GetSourceIp(request *http.Request) string {
  ip := request.RemoteAddr
  val := request.Header.Get("x-real-ip")
  if len(val) > 0 {
    ip = val
  }
  return ip
}

func (host *Host) Register(route string, handler HostHandler) {
  http.HandleFunc(route, handler.Handle)
}

func (host *Host) Stop() {
  if host.running {
    if err := host.httpServer.Shutdown(context.Background()); err != nil {
      log.WithError(err).Error("Error while shutting down HTTP server")
    }
  }
}

func (host *Host) Start() {
  log.Info("Host starting")
  host.running = true
  host.connections = make([]*Connection, 0)
  http.Handle("/", http.FileServer(http.Dir(host.htmlDir)))
  host.Register("/ws", NewWebSocketHandler(host))
  host.httpServer = &http.Server{Addr: host.bindAddress}
  go host.manageConnections(60000 * time.Millisecond)
  err := host.httpServer.ListenAndServe()
  if err != http.ErrServerClosed {
    log.WithError(err).Error("Unexpected fatal error in host")
  }
  host.running = false
  log.Info("Host exiting")
}

func (host *Host) IsRunning() bool {
  return host.running
}

func (host *Host) AddConnection(user *model.User, wsConn *websocket.Conn, ip string) *Connection {
  host.lock.Lock()
  defer host.lock.Unlock()

  conn := NewConnection(user, wsConn, ip)
  host.connections = append(host.connections, conn)
  log.WithField("Connections", len(host.connections)).Debug("Added WebSocket connection")
  return conn
}

func (host *Host) RemoveConnection(wsConn *websocket.Conn) {
  host.lock.Lock()
  defer host.lock.Unlock()
  remaining := make([]*Connection, 0)
  for _, connection := range host.connections {
    if connection.websocket != wsConn {
      remaining = append(remaining, connection)
    }
  }
  host.connections = remaining
  log.WithField("Connections", len(host.connections)).Debug("Removed WebSocket connection")
}

func (host *Host) Broadcast(kind string, reqPermission string, obj interface{}) {
  host.lock.Lock()
  defer host.lock.Unlock()
  msg := &WebSocketMessage{
    Kind:   kind,
    Object: obj,
  }
  for _, connection := range host.connections {
    if err := host.Authorizer.CheckUserOperationAuthorized(connection.user, "read", reqPermission); err == nil {
      log.WithFields(log.Fields{
        "kind": kind,
        // "remoteAddr": connection.websocket.RemoteAddr().String(),
        "sourceIp": connection.ip,
      }).Debug("Broadcasting message to WebSocket connection")
      connection.websocket.WriteJSON(msg)
    } else {
      log.WithFields(log.Fields{
        "kind":     kind,
        "sourceIp": connection.ip,
      }).Debug("Skipping broadcast due to insufficient authorization")
    }
  }
}

func (host *Host) pruneConnections() {
  host.lock.Lock()
  defer host.lock.Unlock()

  activeConnections := make([]*Connection, 0)
  for _, connection := range host.connections {
    durationSinceLastPing := int(time.Now().Sub(connection.lastPingTime).Milliseconds())
    if durationSinceLastPing < host.idleConnectionTimeoutMs {
      activeConnections = append(activeConnections, connection)
    } else if connection.websocket != nil {
      connection.websocket.Close()
    }
  }

  log.WithFields(log.Fields{
    "before": len(host.connections),
    "after":  len(activeConnections),
  }).Debug("Prune connections complete")

  host.connections = activeConnections
}

func (host *Host) manageConnections(sleepDuration time.Duration) {
  for host.running {
    host.pruneConnections()
    time.Sleep(sleepDuration)
  }
}

func (host *Host) AddPreprocessor(preprocessor Preprocessor) error {
  log.WithFields(log.Fields{
    "priority": preprocessor.PreprocessPriority(),
    "type":     reflect.TypeOf(preprocessor).String(),
  }).Info("Adding new preprocessor")

  unsortedMap := make(map[int]Preprocessor)
  for _, existing := range host.preprocessors {
    unsortedMap[existing.PreprocessPriority()] = existing
  }

  if collider, ok := unsortedMap[preprocessor.PreprocessPriority()]; ok {
    return errors.New("Preprocessor with priority " + strconv.Itoa(collider.PreprocessPriority()) + " already exists; preprocessors cannot share identical priorities")
  }
  unsortedMap[preprocessor.PreprocessPriority()] = preprocessor

  sortedList := make([]Preprocessor, 0, len(unsortedMap))

  priorities := make([]int, 0, len(unsortedMap))
  for priority := range unsortedMap {
    priorities = append(priorities, priority)
  }

  sort.Ints(priorities)

  for _, priority := range priorities {
    preprocessor := unsortedMap[priority]
    log.WithFields(log.Fields{
      "priority": preprocessor.PreprocessPriority(),
      "type":     reflect.TypeOf(preprocessor).String(),
    }).Debug("Prioritized preprocessor")
    sortedList = append(sortedList, preprocessor)
  }

  host.preprocessors = sortedList
  return nil
}

/**
 * Returns a copy of the list of preprocessors, in their current priority order,
 * where the first preprocessor at index 0 is processed first.
 */
func (host *Host) Preprocessors() []Preprocessor {
  procs := make([]Preprocessor, len(host.preprocessors))
  copy(procs, host.preprocessors)
  return procs
}

func (host *Host) Preprocess(ctx context.Context, req *http.Request) (context.Context, int, error) {
  var statusCode int
  var err error

  for _, preprocessor := range host.preprocessors {
    log.WithFields(log.Fields{
      "priority": preprocessor.PreprocessPriority(),
      "type":     reflect.TypeOf(preprocessor).String(),
    }).Debug("Preprocessing request")
    ctx, statusCode, err = preprocessor.Preprocess(ctx, req)
    if err != nil {
      break
    }
  }
  return ctx, statusCode, err
}
