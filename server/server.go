// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "github.com/apex/log"
  "github.com/sensoroni/sensoroni/config"
  "github.com/sensoroni/sensoroni/web"
)

type Server struct {
  Config 			*config.ServerConfig
  Host				*web.Host
  Datastore 	Datastore
  stoppedChan chan bool
}

func NewServer(cfg *config.ServerConfig, version string) *Server {
  return &Server{
    Config: cfg,
    Host: web.NewHost(cfg.BindAddress, cfg.HtmlDir, version),
    stoppedChan: make(chan bool, 1),
  }
}

func (server *Server) Start() {
  if server.Datastore == nil {
    log.Error("Datastore module has not been initialized; ensure a valid datastore module has been defined in the configuration")
  } else {
    log.Info("Starting server")

    server.Host.Register("/api/info", NewInfoHandler(server))
    server.Host.Register("/api/stream", NewStreamHandler(server))
    server.Host.Register("/api/packets", NewPacketHandler(server))
    server.Host.Register("/api/job", NewJobHandler(server))
    server.Host.Register("/api/jobs", NewJobsHandler(server))
    server.Host.Register("/api/sensor", NewSensorHandler(server))
    server.Host.Register("/api/sensors", NewSensorsHandler(server))

    server.Host.Start()
  }

  server.stoppedChan <- true
}

func (server *Server) Stop() {
  if server.Host != nil {
    log.Info("Stopping server")
    server.Host.Stop()
  }
}

func (server *Server) Wait() {
  <- server.stoppedChan
}
