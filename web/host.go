// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package web

import (
  "context"
  "net/http"
  "sync"
  "github.com/apex/log"
  "github.com/gorilla/websocket"
)

type HostHandler interface {
  Handle(responseWriter http.ResponseWriter, request *http.Request)
}

type HostHandlerImpl struct {
}

type HostAuth interface {
  IsAuthorized(request *http.Request) bool
}

type Host struct {
  Auth				HostAuth
  bindAddress	string
  htmlDir			string
  server    	*http.Server
  running			bool
  Version			string
  connections []*websocket.Conn
  lock				sync.Mutex
}

func NewHost(address string, htmlDir string, version string) *Host {
  return &Host {
    running: false,
    bindAddress: address,
    htmlDir: htmlDir,
    Version: version,
  }
}

func (host *Host) Register(route string, handler HostHandler) {
  http.HandleFunc(route, handler.Handle)
}

func (host *Host) Stop() {
  if host.running {
    if err := host.server.Shutdown(context.Background()); err != nil {
      log.WithError(err).Error("Error while shutting down server")
    }
  }
}

func (host *Host) Start() {
  log.Info("Host starting")
  host.running = true
  host.connections = make([]*websocket.Conn, 0)
  http.Handle("/", http.FileServer(http.Dir(host.htmlDir)))
  host.Register("/ws", NewWebSocketHandler(host))
  host.server = &http.Server{Addr: host.bindAddress}
  err := host.server.ListenAndServe()
  if err != http.ErrServerClosed {
    log.WithError(err).Error("Unexpected fatal error in host")
  }
  host.running = false
  log.Info("Host exiting")
}

func (host *Host) IsRunning() bool {
  return host.running
}

func (host *Host) AddConnection(conn *websocket.Conn) {
  host.lock.Lock();
  defer host.lock.Unlock()
  host.connections = append(host.connections, conn);
  log.WithField("Connections", len(host.connections)).Debug("Added WebSocket connection")
}

func (host *Host) RemoveConnection(conn *websocket.Conn) {
  host.lock.Lock();
  defer host.lock.Unlock()
  host.connections = make([]*websocket.Conn, 0)
  for _, connection := range host.connections {
    if connection != conn {
      host.connections = append(host.connections, connection)
    }
  }
  log.WithField("Connections", len(host.connections)).Debug("Removed WebSocket connection")
}

func (host *Host) Broadcast(kind string, obj interface{}) {
  host.lock.Lock()
  defer host.lock.Unlock()
  msg := &WebSocketMessage{
    Kind: kind,
    Object: obj,
  }
  for _, connection := range host.connections {
    log.WithFields(log.Fields {
      "kind": kind,
      "host": connection.RemoteAddr().String(),
    }).Debug("Broadcasting message to WebSocket connection")
    connection.WriteJSON(msg)
  }
}